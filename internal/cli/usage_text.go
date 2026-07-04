package cli

// usageText is the LLM-optimized reference card `agent-mcp-host usage` prints —
// how to run and operate the host, not just flag syntax. Keep in step with the
// README and design-docs/architecture.md.
const usageText = `agent-mcp-host: one-origin MCP host for the agent-* CLI family.

Run several family CLIs' MCP servers behind ONE https origin (typically one
Tailscale funnel), with ONE OAuth 2.1 authorization server and a separate
login per tool. Each tool stays its own MCP server; the host mounts it behind
a path and reverse-proxies to it.

SERVE
  agent-mcp-host serve --public-url https://hub.example \
      --mount slack=agent-slack --mount lin=lin [--http 127.0.0.1:8000]
    · Spawns each tool as '<binary> mcp --http 127.0.0.1:<port> --oauth <url>'
      (delegate mode: the tool validates the HOST's tokens, mints nothing).
    · Mounts each at /<name>/mcp — add EACH url as its own MCP connector:
      https://hub.example/slack/mcp, https://hub.example/lin/mcp, …
    · --public-url must be the externally-reachable https URL (the OAuth
      issuer); front the --http listener with your funnel/reverse proxy.

OUTPUT CONTRACT
  stdout  NDJSON event stream, one line per lifecycle moment:
          {"event":"ready"|"mount_ready"|"client_registered"|"paired"|
           "session_started"|"enrolled"|"authorized", "tool":…, "principal":…,
           "client":…, "via":"code"|"session", "time":…}
          Never contains secrets (no codes, tokens, or credentials).
  stderr  Human boot banner: connector URLs + the shared pairing code
          (treat the code like a password), plus each tool's own stderr
          prefixed with its mount name.

PEOPLE (pairing + per-tool credentials)
  agent-mcp-host pair add <name> [--bind <tool>:<key>=<value> ...]
      Mint a per-person pairing code. Bindings are namespaced per tool
      (slack:workspace=acme); each tool's token carries only its own slice,
      with the prefix stripped. Without --bind for a tool that supports
      enrollment, the person enters their own credentials in the browser the
      first time they connect that tool.
  agent-mcp-host pair list | show [name] | rotate [name] | remove <name>
      remove revokes everything at once: code, refresh tokens, sessions.

HOW A PERSON CONNECTS
  1. Add the connector URL for a tool; the browser opens the approval page.
  2. Enter the pairing code ONCE. If the tool needs credentials and none are
     bound, its own enrollment form appears (fields come from the tool's
     'mcp schema' descriptor; secrets go tool-ward via stdin, never argv).
  3. Adding the NEXT tool skips the code (a 30-day browser session covers
     identity) and prompts only for that tool's enrollment, if any.

REQUIREMENTS PER TOOL
  Any CLI built on lib-agent-mcp ≥ v0.21.1 is mountable with zero extra code:
  'mcp schema' exports its credential descriptor and the hidden 'mcp enroll'
  bridges enrollment. (agent-slack ≥ 0.41.0, lin ≥ 0.36.0.)

SECRETS
  Keychain service: app.paulie.agent-mcp-host.mcp (Ed25519 signing key,
  pairing codes, principals, sessions, refresh tokens). Never printed.`
