package cli

import (
	"fmt"
	"net"
	"strings"

	"github.com/shhac/lib-agent-mcp/tailscale"
	oauth "github.com/shhac/lib-agent-oauth"
	agenterrors "github.com/shhac/lib-agent-output"
	"github.com/spf13/cobra"

	"github.com/shhac/agent-mcp-host/internal/config"
	"github.com/shhac/agent-mcp-host/internal/host"
)

// newServeCmd is the host's main command: bring up the reverse proxy + the
// single OAuth authorization server and mount the configured family tools.
func newServeCmd(globals *GlobalFlags) *cobra.Command {
	var addr, publicURL, tailscaleMode string
	var tailscalePort int
	var mounts []string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the MCP host: reverse proxy + OAuth authorization server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			parsed, err := parseMounts(mounts)
			if err != nil {
				return err
			}
			// --tailscale brings up the funnel/serve tunnel in front of the
			// front door and, when --public-url is unset, derives it from the
			// node's MagicDNS name — the same one-command story as a single
			// tool's `mcp --tailscale funnel`.
			publicURL, tsDown, err := tailscale.Wire(cmd.Context(), tailscaleMode, tailscalePort, addr, publicURL)
			if err != nil {
				return err
			}
			if tsDown != nil {
				_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "tailscale %s: %s -> http://%s (will shut down on exit)\n", tailscaleMode, publicURL, addr)
				defer func() {
					if err := tsDown(); err != nil {
						_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "tailscale %s teardown: %v\n", tailscaleMode, err)
					} else {
						_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "tailscale %s: shut down\n", tailscaleMode)
					}
				}()
			}
			if publicURL == "" {
				return agenterrors.New("--public-url <https-url> is required (the externally-reachable URL of this host; the OAuth issuer), or use --tailscale funnel|serve to derive it",
					agenterrors.FixableByHuman)
			}
			store, err := openStore()
			if err != nil {
				return err
			}
			h, err := host.New(host.Config{
				PublicURL: publicURL,
				Addr:      addr,
				Store:     store,
				Mounts:    parsed,
				Stderr:    cmd.ErrOrStderr(),
				Stdout:    cmd.OutOrStdout(),
			})
			if err != nil {
				return err
			}
			return h.Serve(cmd.Context())
		},
	}
	cmd.Flags().StringVar(&addr, "http", "127.0.0.1:8000", "listen address for the host front door")
	cmd.Flags().StringVar(&publicURL, "public-url", "",
		"externally-reachable https URL (the OAuth issuer; each /<tool>/mcp is a token audience). Derived from MagicDNS with --tailscale.")
	cmd.Flags().StringVar(&tailscaleMode, "tailscale", "",
		`front the host with a Tailscale tunnel: "funnel" (public internet) or "serve" (tailnet-private). `+
			"Derives --public-url from the node's MagicDNS name when unset; tears the tunnel down on exit.")
	cmd.Flags().IntVar(&tailscalePort, "tailscale-port", 443, "public HTTPS port for --tailscale (443, 8443, or 10000)")
	cmd.Flags().StringArrayVar(&mounts, "mount", nil, "mount a family tool as name=binary (spawned), or name=binary@host:port to attach to a listener you run yourself (see mount-env); repeatable")
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
