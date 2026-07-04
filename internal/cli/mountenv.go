package cli

import (
	"encoding/base64"
	"fmt"
	"strings"
	"time"

	"github.com/shhac/lib-agent-mcp/tailscale"
	oauth "github.com/shhac/lib-agent-oauth"
	agenterrors "github.com/shhac/lib-agent-output"
	"github.com/spf13/cobra"

	"github.com/shhac/agent-mcp-host/internal/host"
)

// newMountEnvCmd is `mount-env <name>=<binary>`: it prints the exact command
// (env + flags) to run a tool yourself so an attach mount (`serve --mount
// <name>=<binary>@host:port`) can front it — the same values serve injects
// when it spawns the tool. Reads the host's persisted Ed25519 key from the
// keyring (creating it on first use, exactly as serve would), so the printed
// verify key always matches what serve signs with.
func newMountEnvCmd() *cobra.Command {
	var addr, publicURL, tailscaleMode string
	var tailscalePort int
	cmd := &cobra.Command{
		Use:   "mount-env <name>=<binary>",
		Short: "Print the env + command to run a tool yourself for an attach mount",
		Long: "For `serve --mount <name>=<binary>@host:port` (attach) the operator launches the tool " +
			"instead of the host spawning it. This prints the launch command with the audience and " +
			"verify-key env the tool needs — the same values serve injects when it spawns. The public " +
			"URL must match what serve runs with: pass --public-url, or --tailscale funnel|serve to " +
			"derive it from MagicDNS just like serve does.",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name, binary, ok := strings.Cut(args[0], "=")
			if !ok || name == "" || binary == "" {
				return agenterrors.Newf(agenterrors.FixableByAgent, "%q is not <name>=<binary> (e.g. lin=lin)", args[0])
			}
			if publicURL == "" && tailscaleMode == "" {
				return agenterrors.New("pass --public-url <https-url>, or --tailscale funnel|serve to derive it from MagicDNS",
					agenterrors.FixableByHuman)
			}
			if publicURL == "" {
				derived, err := tailscale.PublicURL(cmd.Context(), tailscalePort)
				if err != nil {
					return err
				}
				publicURL = derived
			}
			publicURL = strings.TrimRight(publicURL, "/")
			store, err := openStore()
			if err != nil {
				return err
			}
			// Load (or mint) the host's signing key the same way serve does; only
			// the PUBLIC half is printed.
			issuer, err := oauth.NewEd25519Issuer(store, publicURL, publicURL, time.Hour)
			if err != nil {
				return err
			}
			verifyKey := base64.RawURLEncoding.EncodeToString(issuer.PublicKey())
			resource := host.MountResource(publicURL, name)

			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"# Run the tool yourself, then serve with: --mount %s=%s@%s\n"+
					"AGENT_MCP_OAUTH_RESOURCE=%s \\\n"+
					"AGENT_MCP_OAUTH_VERIFY_KEY=%s \\\n"+
					"%s mcp --http %s --oauth %s\n",
				name, binary, addr, resource, verifyKey, binary, addr, publicURL)
			return err
		},
	}
	cmd.Flags().StringVar(&addr, "http", "127.0.0.1:9400", "listen address the tool should bind (the attach target)")
	cmd.Flags().StringVar(&publicURL, "public-url", "", "the host's externally-reachable https URL (must match what serve runs with)")
	cmd.Flags().StringVar(&tailscaleMode, "tailscale", "", `derive --public-url from MagicDNS like serve does: "funnel" or "serve" (no tunnel is started)`)
	cmd.Flags().IntVar(&tailscalePort, "tailscale-port", 443, "public HTTPS port for --tailscale (443, 8443, or 10000)")
	return cmd
}
