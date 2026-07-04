// Command agent-mcp-host serves the agent-* CLI family's MCP tools from one
// machine under one origin, with one OAuth authorization server and per-tool
// logins. See design-docs/architecture.md.
package main

import (
	"github.com/shhac/agent-mcp-host/internal/cli"
)

var version = "dev"

func main() {
	cli.Run(version)
}
