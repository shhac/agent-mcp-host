// Package cli builds agent-mcp-host's command tree. Unlike a domain CLI, the
// host does not reflect itself into an MCP server — it *serves* other tools'
// MCP servers. It uses the family's shared root (libcli) only for consistent
// global flags, output, and the structured-error contract.
package cli

import (
	libcli "github.com/shhac/lib-agent-cli/cli"
	output "github.com/shhac/lib-agent-output"
	"github.com/spf13/cobra"
)

// GlobalFlags carries the family-standard globals. The host adds its own as the
// serve/mount surface lands.
type GlobalFlags struct {
	libcli.Globals // Format, TimeoutMS, Debug

	version string
}

func newRootCmd(version string) *cobra.Command {
	globals := &GlobalFlags{version: version}

	root := libcli.NewRoot(libcli.Options{
		Use:           "agent-mcp-host",
		Short:         "One-origin MCP host for the agent-* CLI family",
		Version:       version,
		Globals:       &globals.Globals,
		DefaultFormat: output.FormatNDJSON,
		UnknownHint:   "run 'agent-mcp-host --help' for available commands",
	})

	root.AddCommand(newServeCmd(globals))
	return root
}

// Run builds the root command and hands it to libcli.Run — the family's single
// entry point, which renders errors and sets the exit code.
func Run(version string) {
	libcli.Run(newRootCmd(version))
}
