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
  agent-mcp-host serve --tailscale funnel \
      --mount slack=agent-slack --mount lin=lin [--http 127.0.0.1:8000]
    · --tailscale funnel|serve fronts the host with a Tailscale tunnel and
      DERIVES --public-url from the node's MagicDNS name — no URL to figure
      out; the tunnel is torn down on exit. (--tailscale-port 443|8443|10000.)
    · Without --tailscale, pass --public-url https://… (the externally-
      reachable OAuth issuer) and front the --http listener yourself.
    · Mounts each tool at /<name>/mcp — add EACH url as its own MCP connector:
      https://<host>/slack/mcp, https://<host>/lin/mcp, …

TOOLS ARE LAUNCHED FOR YOU
  There is NO separate step to start a mounted tool: serve spawns each one as
      <binary> mcp --http 127.0.0.1:<port> --oauth <public-url>
  with its audience and the host's verify key injected via env
  (AGENT_MCP_OAUTH_RESOURCE, AGENT_MCP_OAUTH_VERIFY_KEY) — delegate mode: the
  tool validates the HOST's tokens and mints nothing, and needs no flags,
  URLs, or input of its own. The tool binaries just need to be installed
  (e.g. brew install shhac/tap/agent-slack) and named in --mount; stopping
  the host stops them.

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
  Any current family CLI is mountable with zero extra code: 'mcp schema'
  exports its credential descriptor and the hidden 'mcp enroll' bridges
  enrollment.

SECRETS
  Keychain service: app.paulie.agent-mcp-host.mcp (Ed25519 signing key,
  pairing codes, principals, sessions, refresh tokens). Never printed.`
