# agent-mcp-host

**One-origin MCP host for the `agent-*` CLI family.** Run every family CLI's
MCP tools from one machine, behind one domain (e.g. one Tailscale funnel), with
one OAuth authorization server and a separate login per tool.

```
                    https://hub.tailnet.example
                                 │
                       agent-mcp-host  (AS + reverse proxy)
                    ┌────────────┴────────────┐
                /slack/mcp                 /lin/mcp
                    │                          │
             agent-slack mcp              lin mcp
             (delegate OAuth)             (delegate OAuth)
```

Each tool keeps being a full MCP server in its own binary — the host mounts it
behind a path rather than re-implementing it. The host owns the shared front
door, the single authorization server, and the unified browser-facing
pairing/enrollment pages. A person adds one Claude connector per tool
(`https://hub…/slack/mcp`, `https://hub…/lin/mcp`), each with its own
credentials; every call thereafter carries that person's identity.

> Status: **scaffolding.** The design is settled in
> [design-docs/architecture.md](design-docs/architecture.md); the serving layer
> is being built. `agent-mcp-host serve` is a stub today.

## How it relates to the rest of the family

The single-tool multi-user story (one server, many humans, self-serve
credentials, fail-closed) already ships in `lib-agent-mcp` and each CLI. This
host is the breadth layer on top: it does not change how a tool authorizes a
principal — it becomes the single authorization server whose tokens those tools
validate (delegate mode), and the single origin they sit behind.

## Install

Once released: `brew install shhac/tap/agent-mcp-host`.

## License

PolyForm Perimeter 1.0.0 — see [LICENSE](LICENSE).
