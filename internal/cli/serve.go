package cli

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/shhac/lib-agent-mcp/tailscale"
	oauth "github.com/shhac/lib-agent-oauth"
	agenterrors "github.com/shhac/lib-agent-output"
	"github.com/spf13/cobra"

	"github.com/shhac/agent-mcp-host/internal/config"
	"github.com/shhac/agent-mcp-host/internal/host"
)

// serveOpts carries the serve command's flag values into runServe.
type serveOpts struct {
	addr          string
	publicURL     string
	tailscaleMode string
	tailscalePort int
	mounts        []string
}

// serveDeps are the effectful seams runServe orchestrates — production wiring
// from prodServeDeps, fakes in tests. Everything between flag parsing and
// blocking-serve is reachable through these.
type serveDeps struct {
	wire      func(ctx context.Context, mode string, port int, httpAddr, publicURL string) (string, func() error, error)
	openStore func() (oauth.SecretStore, error)
	serve     func(ctx context.Context, cfg host.Config) error
}

func prodServeDeps() serveDeps {
	return serveDeps{
		wire:      tailscale.Wire,
		openStore: openStore,
		serve: func(ctx context.Context, cfg host.Config) error {
			h, err := host.New(cfg)
			if err != nil {
				return err
			}
			return h.Serve(ctx)
		},
	}
}

// runServe is the serve command's whole lifecycle: mounts → tunnel →
// public-URL gate → store → host. Kept out of the cobra closure so the
// Tailscale derivation, teardown messaging, and wiring order are testable.
func runServe(ctx context.Context, stdout, stderr io.Writer, opts serveOpts, deps serveDeps) error {
	parsed, err := parseMounts(opts.mounts)
	if err != nil {
		return err
	}
	// --tailscale brings up the funnel/serve tunnel in front of the front door
	// and, when --public-url is unset, derives it from the node's MagicDNS
	// name — the same one-command story as a single tool's `mcp --tailscale`.
	publicURL, tsDown, err := deps.wire(ctx, opts.tailscaleMode, opts.tailscalePort, opts.addr, opts.publicURL)
	if err != nil {
		return err
	}
	if tsDown != nil {
		_, _ = fmt.Fprintf(stderr, "tailscale %s: %s -> http://%s (will shut down on exit)\n", opts.tailscaleMode, publicURL, opts.addr)
		defer func() {
			if err := tsDown(); err != nil {
				_, _ = fmt.Fprintf(stderr, "tailscale %s teardown: %v\n", opts.tailscaleMode, err)
			} else {
				_, _ = fmt.Fprintf(stderr, "tailscale %s: shut down\n", opts.tailscaleMode)
			}
		}()
	}
	if publicURL == "" {
		return agenterrors.New("--public-url <https-url> is required (the externally-reachable URL of this host; the OAuth issuer), or use --tailscale funnel|serve to derive it",
			agenterrors.FixableByHuman)
	}
	store, err := deps.openStore()
	if err != nil {
		return err
	}
	return deps.serve(ctx, host.Config{
		PublicURL: publicURL,
		Addr:      opts.addr,
		Store:     store,
		Mounts:    parsed,
		Stderr:    stderr,
		Stdout:    stdout,
	})
}

// newServeCmd is the host's main command: bring up the reverse proxy + the
// single OAuth authorization server and mount the configured family tools.
func newServeCmd(globals *GlobalFlags) *cobra.Command {
	var opts serveOpts
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the MCP host: reverse proxy + OAuth authorization server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runServe(cmd.Context(), cmd.OutOrStdout(), cmd.ErrOrStderr(), opts, prodServeDeps())
		},
	}
	cmd.Flags().StringVar(&opts.addr, "http", "127.0.0.1:8000", "listen address for the host front door")
	cmd.Flags().StringVar(&opts.publicURL, "public-url", "",
		"externally-reachable https URL (the OAuth issuer; each /<tool>/mcp is a token audience). Derived from MagicDNS with --tailscale.")
	cmd.Flags().StringVar(&opts.tailscaleMode, "tailscale", "",
		`front the host with a Tailscale tunnel: "funnel" (public internet) or "serve" (tailnet-private). `+
			"Derives --public-url from the node's MagicDNS name when unset; tears the tunnel down on exit.")
	cmd.Flags().IntVar(&opts.tailscalePort, "tailscale-port", 443, "public HTTPS port for --tailscale (443, 8443, or 10000)")
	cmd.Flags().StringArrayVar(&opts.mounts, "mount", nil, "mount a family tool as name=binary (spawned), or name=binary@host:port to attach to a listener you run yourself (see mount-env); repeatable")
	return cmd
}

// parseMounts turns repeated name=binary flags into host mounts.
func parseMounts(specs []string) ([]*host.Mount, error) {
	if len(specs) == 0 {
		return nil, agenterrors.New("at least one --mount name=binary is required (e.g. --mount slack=agent-slack)",
			agenterrors.FixableByAgent)
	}
	mounts := make([]*host.Mount, 0, len(specs))
	for _, s := range specs {
		name, target, ok := strings.Cut(s, "=")
		if !ok || name == "" || target == "" {
			return nil, agenterrors.Newf(agenterrors.FixableByAgent, "--mount %q is not name=binary or name=binary@host:port", s)
		}
		// name=binary spawns the tool; name=binary@host:port attaches to a
		// listener the operator runs themselves (see `mount-env`). The binary
		// is needed either way — schema discovery and the enrollment bridge
		// exec it.
		binary, attach, attached := strings.Cut(target, "@")
		if binary == "" || (attached && attach == "") {
			return nil, agenterrors.Newf(agenterrors.FixableByAgent, "--mount %q is not name=binary or name=binary@host:port", s)
		}
		if attached {
			if _, _, err := net.SplitHostPort(attach); err != nil {
				return nil, agenterrors.Newf(agenterrors.FixableByAgent, "--mount %q: attach target %q is not host:port", s, attach)
			}
		}
		mounts = append(mounts, &host.Mount{Name: name, Binary: binary, Attach: attach})
	}
	return mounts, nil
}

// openStore opens the keyring-backed secret store for the host's OAuth secrets,
// erroring when no OS keyring is available.
func openStore() (oauth.SecretStore, error) {
	store := oauth.NewKeyringStore(config.MCPKeychainService())
	if !store.Available() {
		return nil, agenterrors.New("no OS keyring is available on this host, so the host's OAuth signing key can't be stored",
			agenterrors.FixableByHuman).
			WithHint("agent-mcp-host stores its Ed25519 signing key + pairing store in the macOS Keychain")
	}
	return store, nil
}
