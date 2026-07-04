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
	"sync"
	"time"

	oauth "github.com/shhac/lib-agent-oauth"
)

// sessionTTL is how long one pairing-code entry keeps covering new tool
// connections in the same browser (the AS session cookie's lifetime). Long,
// because the person it identifies proved membership with a per-person
// secret and revocation is immediate: `pair remove` kills the session.
const sessionTTL = 30 * 24 * time.Hour

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
	mounts    []*runningMount
	oauth     *oauth.Server
	stderr    io.Writer
	stdout    io.Writer

	// start brings a mount's tool up (sets m.addr), defaulting to the exec
	// spawn of `<binary> mcp --http … --oauth …`. Tests replace it with an
	// in-process delegate server to exercise the AS + proxy without exec.
	start func(ctx context.Context, m *runningMount, verifyKey string) error
	// stopMount tears a mount down, defaulting to killing the spawned process.
	stopMount func(m *runningMount)
	// discover reads a mount's manifest, defaulting to `<binary> mcp schema`.
	discover func(ctx context.Context, m *runningMount) (*toolManifest, error)
	// enrollBridge hands one enrollment submission to the tool, defaulting to
	// `<binary> mcp enroll` with the request on stdin.
	enrollBridge func(ctx context.Context, m *runningMount, req oauth.EnrollRequest) (oauth.EnrollResult, error)

	mountByResource map[string]*runningMount
	emitMu          sync.Mutex // serializes NDJSON event lines on stdout
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
	resources, mounts, byResource, err := mountResources(publicURL, cfg.Mounts)
	if err != nil {
		return nil, err
	}
	h := &Host{
		publicURL:       publicURL,
		addr:            cfg.Addr,
		mounts:          mounts,
		stderr:          orWriter(cfg.Stderr, os.Stderr),
		stdout:          orWriter(cfg.Stdout, os.Stdout),
		mountByResource: byResource,
	}

	srv, err := oauth.New(oauth.Config{
		Store:      cfg.Store,
		PublicURL:  publicURL,
		Resources:  resources,
		Asymmetric: true,         // tools verify with the public key
		SessionTTL: sessionTTL,   // login once, grow into tools
		OnEvent:    h.oauthEvent, // AS lifecycle → NDJSON on stdout
		// Project the namespaced binding down to each mount's own vocabulary:
		// slack:workspace=acme → workspace=acme in the /slack/mcp token. An
		// unknown resource passes through unchanged — never a stripNamespace
		// against the empty mount name.
		BindingForResource: func(binding map[string]string, resource string) map[string]string {
			if m := h.mountByResource[resource]; m != nil {
				return stripNamespace(binding, m.cfg.Name)
			}
			return binding
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
func (h *Host) resource(m *runningMount) string { return m.resource }

// MountResource builds a mount's audience from the host's public URL and the
// mount name: the exact /mcp URL a connector calls. Exported within the repo
// because it is a cross-command contract — mount-env prints the same audience
// serve mints tokens for.
func MountResource(publicURL, name string) string { return publicURL + "/" + name + "/mcp" }

// mountResources validates the mounts and returns their audiences (in order)
// plus the audience→mount reverse map both per-resource AS hooks read. It
// rejects a mount missing a name or binary, or a duplicate name.
func mountResources(publicURL string, mounts []*Mount) (resources []string, running []*runningMount, byResource map[string]*runningMount, err error) {
	resources = make([]string, 0, len(mounts))
	running = make([]*runningMount, 0, len(mounts))
	byResource = make(map[string]*runningMount, len(mounts))
	seen := make(map[string]bool, len(mounts))
	for _, m := range mounts {
		if m.Name == "" || m.Binary == "" {
			return nil, nil, nil, fmt.Errorf("host: mount needs a name and a binary (got %+v)", m)
		}
		if seen[m.Name] {
			return nil, nil, nil, fmt.Errorf("host: duplicate mount name %q", m.Name)
		}
		seen[m.Name] = true
		res := MountResource(publicURL, m.Name)
		rm := &runningMount{cfg: m, resource: res}
		resources = append(resources, res)
		running = append(running, rm)
		byResource[res] = rm
	}
	return resources, running, byResource, nil
}

// mcpPath is a mount's front-door path.
func (h *Host) mcpPath(m *runningMount) string { return "/" + m.cfg.Name + "/mcp" }

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
	for _, m := range h.mounts {
		h.emit(hostEvent{Event: "mount_ready", Tool: m.cfg.Name, URL: h.resource(m)})
	}
	h.emit(hostEvent{Event: "ready"})

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

	var started []*runningMount
	cleanup := func() {
		for _, m := range started {
			h.stopMount(m)
		}
	}
	for _, m := range h.mounts {
		if err := h.bringUpMount(ctx, m, verifyKey); err != nil {
			cleanup()
			return nil, nil, err
		}
		started = append(started, m)
		mux.Handle(h.mcpPath(m), h.proxy(m))
	}
	return withCORS(mux), cleanup, nil
}

// bringUpMount readies one mount for traffic: it discovers the tool's manifest
// and builds the mount's per-resource enrollment from the descriptor (which
// must be on the AS before the first authorize request can arrive), then starts
// the tool. It leaves mux registration and stop-tracking to the caller.
func (h *Host) bringUpMount(ctx context.Context, m *runningMount, verifyKey string) error {
	manifest, err := h.discover(ctx, m)
	if err != nil {
		return fmt.Errorf("mount %q: %w", m.cfg.Name, err)
	}
	m.descriptor = manifest.CredentialDescriptor
	if m.enrollment, err = h.buildEnrollment(m); err != nil {
		return err
	}
	// Attach mounts proxy to a listener the operator runs themselves (launched
	// with the env `mount-env` prints); everything else — discovery above,
	// enrollment, readiness below — is identical to a spawned mount.
	if m.cfg.Attach != "" {
		m.addr = m.cfg.Attach
		return nil
	}
	if err := h.start(ctx, m, verifyKey); err != nil {
		return fmt.Errorf("mount %q: %w", m.cfg.Name, err)
	}
	return nil
}

// proxy reverse-proxies a mount's /<name>/mcp to its loopback /mcp, stripping
// the tool's CORS headers so the host is the single source of them.
func (h *Host) proxy(m *runningMount) http.Handler {
	target := &url.URL{Scheme: "http", Host: m.addr}
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
	return http.StripPrefix("/"+m.cfg.Name, rp)
}

// printBanner writes the human-facing boot info — connector URLs and the
// shared pairing code — to STDERR. Stdout is reserved for the NDJSON event
// stream, and the pairing code is a secret that must never ride in it.
func (h *Host) printBanner() {
	code, _ := h.oauth.PairingCode()
	_, _ = fmt.Fprintf(h.stderr, "agent-mcp-host ready · %d tool(s) · authorization: OAuth 2.1 (host)\n", len(h.mounts))
	_, _ = fmt.Fprint(h.stderr, "Connect these MCP tools (add each URL as its own connector):\n")
	for _, m := range h.mounts {
		_, _ = fmt.Fprintf(h.stderr, "  %-10s %s\n", m.cfg.Name, h.resource(m))
	}
	_, _ = fmt.Fprintf(h.stderr, "  pairing code : %s\n", code)
	_, _ = fmt.Fprint(h.stderr, "  ⚠ Treat the pairing code like a password. Enter it once in the browser —\n"+
		"    a session then covers connecting the other tools without re-entering it.\n")
}

func orWriter(w, dflt io.Writer) io.Writer {
	if w != nil {
		return w
	}
	return dflt
}
