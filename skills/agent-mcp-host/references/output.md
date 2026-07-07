# `agent-mcp-host` output shapes (reference)

## `serve` stdout — NDJSON event stream

One JSON object per line, one line per lifecycle moment. Events **never**
contain secrets (no pairing codes, tokens, or submitted credentials), so
stdout is safe to log, tail, or quote.

```json
{"event":"ready","time":"…"}
{"event":"mount_ready","tool":"slack","url":"https://hub.tailnet.example/slack/mcp","time":"…"}
{"event":"client_registered","tool":"slack","client":"Claude","time":"…"}
{"event":"paired","tool":"slack","principal":"alice","client":"Claude","via":"code","time":"…"}
{"event":"session_started","principal":"alice","time":"…"}
{"event":"enrolled","tool":"slack","principal":"alice","client":"Claude","time":"…"}
{"event":"authorized","tool":"slack","principal":"alice","client":"Claude","via":"code","time":"…"}
```

- `event` — `ready` | `mount_ready` | `client_registered` | `paired` |
  `session_started` | `enrolled` | `authorized`
- `tool` — mount name (the `<name>` in `--mount <name>=<binary>`)
- `principal` — the paired person's name (from `pair add <name>`)
- `client` — the connecting MCP client (e.g. `Claude`)
- `via` — how identity was proven: `code` (pairing code entered) or
  `session` (30-day browser session)
- `time` — RFC 3339 timestamp

Watching for readiness: `ready` fires when the front door is up; one
`mount_ready` per mount follows. A person's first successful connection to a
tool produces `paired` (or `session_started`), optionally `enrolled`, then
`authorized`.

## `serve` stderr — human banner + tool logs

- Boot banner: the connector URL per mount and the pairing guidance,
  **including a pairing code — treat stderr as secret-bearing**.
- Each mounted tool's own stderr, prefixed with its mount name
  (e.g. `[slack] …`).

## `pair` commands — human-readable text

- `pair add <name>` — prints the minted code plus an explanation that anyone
  with the code acts under this principal's bindings (secret output)
- `pair list` — one line per principal: `<name> <tool>:<key>=<value> …`
  (codes never shown); `no named principals` when empty
- `pair show <name>` — the stored code (secret output)
- `pair rotate <name>` — the fresh code (secret output)
- `pair remove <name>` — confirmation of revocation

## Errors

`{error, fixable_by, hint}` JSON on stderr, exit 1 — e.g. addressing a
missing principal yields `fixable_by: agent` with the exact `pair add`
command to run.
