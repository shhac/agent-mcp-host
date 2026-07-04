package cli

import (
	"strings"

	oauth "github.com/shhac/lib-agent-oauth"
	agenterrors "github.com/shhac/lib-agent-output"
	"github.com/spf13/cobra"

	"github.com/shhac/agent-mcp-host/internal/config"
	"github.com/shhac/agent-mcp-host/internal/host"
)

// newServeCmd is the host's main command: bring up the reverse proxy + the
// single OAuth authorization server and mount the configured family tools.
func newServeCmd(globals *GlobalFlags) *cobra.Command {
	var addr, publicURL string
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
			if publicURL == "" {
				return agenterrors.New("--public-url <https-url> is required (the externally-reachable URL of this host; the OAuth issuer)",
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
	cmd.Flags().StringVar(&publicURL, "public-url", "", "externally-reachable https URL (the OAuth issuer; each /<tool>/mcp is a token audience)")
	cmd.Flags().StringArrayVar(&mounts, "mount", nil, "mount a family tool as name=binary (repeatable), e.g. --mount slack=agent-slack")
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
		name, binary, ok := strings.Cut(s, "=")
		if !ok || name == "" || binary == "" {
			return nil, agenterrors.Newf(agenterrors.FixableByAgent, "--mount %q is not name=binary", s)
		}
		mounts = append(mounts, &host.Mount{Name: name, Binary: binary})
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
