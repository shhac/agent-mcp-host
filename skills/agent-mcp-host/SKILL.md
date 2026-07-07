---
name: agent-mcp-host
description: |
  One-origin MCP host for the agent-* CLI family: run several family CLIs' MCP servers behind one https origin (typically a Tailscale funnel) with one OAuth 2.1 authorization server and a separate login per tool. Use when serving, mounting, or debugging family MCP connectors, or managing people and pairing codes. Triggers: "mcp host", "mcp hub", "agent-mcp-host", "mount a tool", "attach mount", "connector url", "pairing code", "principal", "tailscale funnel", "enrollment", "oauth issuer".
when_to_use: |
  Use when the user asks to serve family CLIs as MCP connectors behind one domain, add or mount a tool, run a tool under their own control (attach mount), provision/rotate/revoke a person's pairing code or bindings, explain how someone connects a Claude connector, or debug why a mount, pairing, or enrollment is failing.
allowed-tools: Bash(agent-mcp-host *) Read Grep Glob
---

# MCP hosting with `agent-mcp-host`

`agent-mcp-host` is a CLI binary installed on `$PATH`. It is the **operator
tool** of the `agent-*` family: it runs every mounted tool's MCP server
behind ONE https origin, with ONE OAuth 2.1 authorization server and a
separate login per tool. Each tool stays a full MCP server in its own binary
— the host mounts it behind a path (`/<name>/mcp`) and reverse-proxies to it.

Run `agent-mcp-host usage` for the full LLM-optimized reference card.

## Mental model

- One origin (e.g. `https://hub.tailnet.example`) fronts N tools.
- Each tool is a **mount**: `--mount slack=agent-slack` serves
  `https://<host>/slack/mcp`. A person adds one Claude connector **per tool**.
- The host owns pairing (who may connect), OAuth (token minting), and the
  browser enrollment pages. Tools validate the host's Ed25519 tokens and mint
  nothing themselves (delegate mode). A slack token is useless at `/lin/mcp`
  by construction.

## Serve (long-running — run in the background)

```bash
agent-mcp-host serve --tailscale funnel \
    --mount slack=agent-slack --mount lin=lin
```

- `--tailscale funnel|serve` fronts the host with a Tailscale tunnel and
  **derives `--public-url` from MagicDNS** — no URL to figure out; the tunnel
  is torn down on exit (`--tailscale-port 443|8443|10000`).
- Without `--tailscale`, pass `--public-url https://…` (the OAuth issuer) and
  front the `--http` listener (default `127.0.0.1:8000`) yourself.
- `serve` does not exit. Run it in the background and read **stdout** for
  NDJSON lifecycle events — `{"event":"ready"}` then one
  `{"event":"mount_ready","tool":…,"url":…}` per mount means it's up.
  Connector URLs and the pairing banner go to **stderr**.
- There is no separate step to start mounted tools: `serve` spawns each one
  as `<binary> mcp --http 127.0.0.1:<port> --oauth <public-url>` with its
  audience and verify key injected via env. The binaries just need to be
  installed (`brew install shhac/tap/agent-slack`); stopping the host stops
  them.

## Attach mounts (run a tool yourself)

To run a tool under your own control (debugger, launchd) instead of having
`serve` spawn it:

```bash
agent-mcp-host mount-env lin=lin --http 127.0.0.1:9410 --tailscale funnel
# → prints the exact launch command (env + flags) for that tool; run it, then:
agent-mcp-host serve --tailscale funnel --mount lin=lin@127.0.0.1:9410 ...
```

The binary name is still required (the host execs it for `mcp schema` and
`mcp enroll`). `mount-env`'s `--public-url`/`--tailscale` must match what
`serve` runs with — `--tailscale` here only derives the URL; no tunnel starts.

## People (pairing + per-tool credentials)

```bash
agent-mcp-host pair add alice --bind slack:workspace=acme --bind lin:workspace=acme
agent-mcp-host pair list              # principals + bindings (codes never shown)
agent-mcp-host pair show alice        # prints alice's code (a secret)
agent-mcp-host pair rotate alice      # fresh code, bindings preserved
agent-mcp-host pair remove alice      # revokes code + refresh tokens + sessions
```

Bindings are namespaced per tool (`slack:workspace=acme`); each tool's token
carries only its own slice, prefix stripped. Without `--bind` for a tool that
supports enrollment, the person enters their own credentials in the browser
the first time they connect that tool (fields come from the tool's
`mcp schema`; secrets go tool-ward via stdin, never argv).

**How a person connects:** (1) add the connector URL — the approval page
opens; (2) enter the pairing code once, then the tool's enrollment form if no
binding was provisioned; (3) the next tool skips the code (a 30-day browser
session covers identity) and prompts only for that tool's enrollment.

## Output contract

- **stdout** — NDJSON event stream, one line per lifecycle moment:
  `ready`, `mount_ready`, `client_registered`, `paired`, `session_started`,
  `enrolled`, `authorized` (with `tool`, `principal`, `client`, `via`,
  `time` fields as applicable). **Events never contain secrets.**
- **stderr** — the human boot banner (connector URLs + pairing code) and each
  tool's own stderr prefixed with its mount name.
- `pair` commands print human-readable text, not NDJSON.

## Handling secrets

Pairing codes are passwords. `pair add`, `pair rotate`, and `pair show`
print one, and the `serve` stderr banner shows the shared code — never quote
a code into summaries, commit messages, or shared documents; share it only
with the person it belongs to. If a code may have leaked, `pair rotate
<name>`; to revoke a person entirely, `pair remove <name>`. Stored secrets
(signing key, codes, sessions, refresh tokens) live in the keychain service
`app.paulie.agent-mcp-host.mcp` and are never printed by `list`.

## Global flags

- `--format json|yaml|jsonl` — output format
- `--color auto|always|never`, `--timeout <ms>`, `--debug`

## References

- [references/commands.md](references/commands.md): full command map + all flags
- [references/output.md](references/output.md): event stream + output shapes
