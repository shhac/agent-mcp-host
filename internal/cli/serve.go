package cli

import (
	agenterrors "github.com/shhac/lib-agent-output"
	"github.com/spf13/cobra"
)

// newServeCmd is the host's main command: bring up the reverse proxy + the
// single OAuth authorization server and mount the configured family tools.
// Stub during scaffolding — the serving layer is built in a later milestone
// (see design-docs/architecture.md, build order step 4).
func newServeCmd(globals *GlobalFlags) *cobra.Command {
	var addr, publicURL string
	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Run the MCP host: reverse proxy + OAuth authorization server",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return agenterrors.Newf(agenterrors.FixableByHuman,
				"agent-mcp-host serve is not implemented yet — scaffolding only").
				WithHint("track progress in design-docs/architecture.md (build order)")
		},
	}
	cmd.Flags().StringVar(&addr, "http", "127.0.0.1:8000", "listen address for the host front door")
	cmd.Flags().StringVar(&publicURL, "public-url", "", "externally-reachable https URL (issuer; per-tool /<tool>/mcp = audience)")
	return cmd
}
