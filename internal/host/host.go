// Package host is the agent-mcp-host serving core: it stands up one OAuth
// authorization server, spawns each configured family tool as a loopback MCP
// server in delegate mode, and reverse-proxies each behind its own /<name>/mcp
// path. See design-docs/architecture.md.
package host

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"

	oauth "github.com/shhac/lib-agent-oauth"
)

// Config configures a Host.
type Config struct {
	// PublicURL is the externally-reachable https URL the connectors reach —
	// the OAuth issuer and the base of every mount's audience. Required.
	PublicURL string
	// Addr is the local listen address for the front door (e.g. 127.0.0.1:8000).
	Addr string
	// Store persists the AS secrets (Ed25519 signing key, pairing/principal
	// store). Required.
	Store oauth.SecretStore
	// Mounts are the tools to serve. Required (at least one).
	Mounts []*Mount
	// Stderr/Stdout receive the boot banner and each tool's stderr. Default to
	// os.Stderr/os.Stdout.
	Stderr, Stdout io.Writer
}

// Host is a running (or runnable) multi-tool MCP host.
type Host struct {
	publicURL string
	addr      string
	mounts    []*Mount
	oauth     *oauth.Server
	stderr    io.Writer
	stdout    io.Writer

	// start brings a mount's tool up (sets m.port), defaulting to the exec
	// spawn of `<binary> mcp --http … --oauth …`. Tests replace it with an
	// in-process delegate server to exercise the AS + proxy without exec.
	start func(ctx context.Context, m *Mount, verifyKey string) error
	// stopMount tears a mount down, defaulting to killing the spawned process.
	stopMount func(m *Mount)
	// discover reads a mount's manifest, defaulting to `<binary> mcp schema`.
	discover func(ctx context.Context, m *Mount) (*toolManifest, error)
	// enrollBridge hands one enrollment submission to the tool, defaulting to
	// `<binary> mcp enroll` with the request on stdin.
	enrollBridge func(ctx context.Context, m *Mount, req oauth.EnrollRequest) (oauth.EnrollResult, error)

	mountByResource map[string]*Mount
}

// New validates cfg and builds the host: the multi-audience Ed25519
// authorization server whose allowed resources are the mounts' audiences.
func New(cfg Config) (*Host, error) {
	if strings.TrimSpace(cfg.PublicURL) == "" {
		return nil, errors.New("host: PublicURL is required")
	}
	if cfg.Store == nil {
		return nil, errors.New("host: Store is required")
	}
	if len(cfg.Mounts) == 0 {
		return nil, errors.New("host: at least one mount is required")
	}
	publicURL := strings.TrimRight(cfg.PublicURL, "/")
	resources, resourceMount, err := mountResources(publicURL, cfg.Mounts)
	if err != nil {
		return nil, err
	}
	h := &Host{
		publicURL:       publicURL,
		addr:            cfg.Addr,
		mounts:          cfg.Mounts,
		stderr:          orWriter(cfg.Stderr, os.Stderr),
		stdout:          orWriter(cfg.Stdout, os.Stdout),
		mountByResource: make(map[string]*Mount, len(cfg.Mounts)),
	}
	for _, m := range cfg.Mounts {
		h.mountByResource[mountResource(publicURL, m.Name)] = m
	}

	srv, err := oauth.New(oauth.Config{
		Store:      cfg.Store,
		PublicURL:  publicURL,
		Resources:  resources,
		Asymmetric: true, // tools verify with the public key
		// Project the namespaced binding down to each mount's own vocabulary:
		// slack:workspace=acme → workspace=acme in the /slack/mcp token.
		BindingForResource: func(binding map[string]string, resource string) map[string]string {
			return stripNamespace(binding, resourceMount[resource])
		},
		// Each mount's own enrollment (built from its discovered descriptor in
		// handler, validated there), resolved lazily per authorize request.
		EnrollmentForResource: func(resource string) *oauth.Enrollment {
			if m := h.mountByResource[resource]; m != nil {
				return m.enrollment
			}
			return nil
		},
	})
	if err != nil {
		return nil, err
	}
	h.oauth = srv
	h.start = h.spawn
	h.stopMount = h.stop
	h.discover = discoverExec
	h.enrollBridge = enrollExec
	return h, nil
}

// resource is a mount's audience: the exact /mcp URL a connector calls.
func (h *Host) resource(m *Mount) string { return mountResource(h.publicURL, m.Name) }

// mountResource builds a mount's audience from the host's public URL and the
// mount name: the exact /mcp URL a connector calls.
func mountResource(publicURL, name string) string { return publicURL + "/" + name + "/mcp" }

// mountResources validates the mounts and returns their audiences (in order)
// plus the audience→name reverse map the binding projection uses. It rejects a
// mount missing a name or binary, or a duplicate name.
func mountResources(publicURL string, mounts []*Mount) (resources []string, byResource map[string]string, err error) {
	resources = make([]string, 0, len(mounts))
	byResource = make(map[string]string, len(mounts))
	seen := make(map[string]bool, len(mounts))
	for _, m := range mounts {
		if m.Name == "" || m.Binary == "" {
			return nil, nil, fmt.Errorf("host: mount needs a name and a binary (got %+v)", m)
		}
		if seen[m.Name] {
			return nil, nil, fmt.Errorf("host: duplicate mount name %q", m.Name)
		}
		seen[m.Name] = true
		res := mountResource(publicURL, m.Name)
		resources = append(resources, res)
		byResource[res] = m.Name
	}
	return resources, byResource, nil
}

// mcpPath is a mount's front-door path.
func (h *Host) mcpPath(m *Mount) string { return "/" + m.Name + "/mcp" }

// Serve spawns each tool in delegate mode, wires the front-door mux, prints the
// boot banner, and serves until ctx is cancelled — tearing the tools down on
// the way out.
func (h *Host) Serve(ctx context.Context) error {
	handler, cleanup, err := h.handler(ctx)
	if err != nil {
		return err
	}
	defer cleanup()

	if err := h.waitReady(ctx); err != nil {
		return err
	}
	h.printBanner()

	srv := &http.Server{Addr: h.addr, Handler: handler, ReadHeaderTimeout: 10 * time.Second}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// handler starts every mount's tool and builds the front-door mux (AS routes +
// per-mount reverse proxies, CORS-wrapped). It returns a cleanup that stops the
// started tools. Serve and tests both build the handler this way.
func (h *Host) handler(ctx context.Context) (http.Handler, func(), error) {
	verifyKey := base64.RawURLEncoding.EncodeToString(h.oauth.PublicKey())

	mux := http.NewServeMux()
	h.oauth.RegisterRoutes(mux)

	var started []*Mount
	cleanup := func() {
		for _, m := range started {
			h.stopMount(m)
		}
	}
	for _, m := range h.mounts {
		// Discover the manifest first: the descriptor feeds the AS's
		// per-resource enrollment, which must be in place before the first
		// authorize request can arrive.
		manifest, err := h.discover(ctx, m)
		if err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("mount %q: %w", m.Name, err)
		}
		m.descriptor = manifest.CredentialDescriptor
		if m.enrollment, err = h.buildEnrollment(m); err != nil {
			cleanup()
			return nil, nil, err
		}
		if err := h.start(ctx, m, verifyKey); err != nil {
			cleanup()
			return nil, nil, fmt.Errorf("mount %q: %w", m.Name, err)
		}
		started = append(started, m)
		mux.Handle(h.mcpPath(m), h.proxy(m))
	}
	return withCORS(mux), cleanup, nil
}

// proxy reverse-proxies a mount's /<name>/mcp to its loopback /mcp, stripping
// the tool's CORS headers so the host is the single source of them.
func (h *Host) proxy(m *Mount) http.Handler {
	target := &url.URL{Scheme: "http", Host: fmt.Sprintf("127.0.0.1:%d", m.port)}
	rp := httputil.NewSingleHostReverseProxy(target)
	rp.ModifyResponse = func(resp *http.Response) error {
		for k := range resp.Header {
			if strings.HasPrefix(k, "Access-Control-") {
				resp.Header.Del(k)
			}
		}
		return nil
	}
	// StripPrefix turns /<name>/mcp into /mcp before the proxy forwards it.
	return http.StripPrefix("/"+m.Name, rp)
}

// printBanner writes the per-mount connector URLs and the shared pairing code.
func (h *Host) printBanner() {
	code, _ := h.oauth.PairingCode()
	_, _ = fmt.Fprintf(h.stderr, "agent-mcp-host ready · %d tool(s) · authorization: OAuth 2.1 (host)\n", len(h.mounts))
	_, _ = fmt.Fprint(h.stdout, "Connect these MCP tools (add each URL as its own connector):\n")
	for _, m := range h.mounts {
		_, _ = fmt.Fprintf(h.stdout, "  %-10s %s\n", m.Name, h.resource(m))
	}
	_, _ = fmt.Fprintf(h.stdout, "  pairing code : %s\n", code)
	_, _ = fmt.Fprint(h.stdout, "  ⚠ Treat the pairing code like a password. Enter it once; it works across tools.\n")
}

func orWriter(w, dflt io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return dflt
}
