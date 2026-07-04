// Command dummytool is the kitchen-sink lib-agent-mcp CLI the host's
// integration test builds and mounts for real: spawned via `mcp --http
// --oauth <url>` in delegate mode, discovered via a real `mcp schema`,
// enrolled through a real `mcp enroll`, and called through the reverse proxy
// with identity binding injected into its tool subprocesses. It exists so the
// host↔lib contract is exercised end-to-end by `go test`, not just held by
// construction. Not shipped: built into a temp dir by the test.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"

	agentmcp "github.com/shhac/lib-agent-mcp"
	oauth "github.com/shhac/lib-agent-oauth"
	"github.com/spf13/cobra"
)

func main() {
	root := &cobra.Command{
		Use:           "dummytool",
		Short:         "Kitchen-sink dummy CLI for agent-mcp-host integration tests",
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	// Family-standard globals: the MCP bridge passes --format to tool
	// subprocesses (this is exactly the kind of contract detail the
	// integration test exists to catch — a bare cobra root breaks it).
	root.PersistentFlags().StringP("format", "f", "", "Output format")
	root.PersistentFlags().Bool("debug", false, "Enable debug logging")

	echo := &cobra.Command{
		Use:   "echo <text>",
		Short: "Echo the argument back",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), args[0])
			return err
		},
	}

	// whoami proves the identity-binding path: the MCP server execs this
	// binary per tool call with the env WithIdentityBinding injected, so the
	// output names the caller's bound workspace.
	whoami := &cobra.Command{
		Use:   "whoami",
		Short: "Print the workspace this call is bound to",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ws := os.Getenv("DUMMY_WORKSPACE")
			if ws == "" {
				ws = "unbound"
			}
			_, err := fmt.Fprintln(cmd.OutOrStdout(), "workspace="+ws)
			return err
		},
	}
	root.AddCommand(echo, whoami)

	root.AddCommand(agentmcp.Command(root,
		agentmcp.WithVersion("0.0.0-test"),
		agentmcp.WithCredentialEnrollment(
			oauth.CredentialDescriptor{
				Title: "Connect Dummy",
				Modes: []oauth.CredentialMode{{
					Key: "token", Label: "API key",
					Fields: []oauth.CredentialField{
						{Key: "api_key", Label: "API key", Secret: true},
					},
				}},
			},
			func(_ context.Context, req oauth.EnrollRequest) (oauth.EnrollResult, error) {
				if req.Values["api_key"] == "bad" {
					return oauth.EnrollResult{}, errors.New("dummy rejected this API key")
				}
				return oauth.EnrollResult{Binding: map[string]string{"workspace": "ws-" + req.Principal}}, nil
			},
		),
		agentmcp.WithIdentityBinding(func(v oauth.Verified) (args []string, env []string) {
			return nil, []string{"DUMMY_WORKSPACE=" + v.Binding["workspace"]}
		}),
	))

	if err := root.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, `{"error":`+fmt.Sprintf("%q", err.Error())+`,"fixable_by":"agent"}`)
		os.Exit(1)
	}
}
