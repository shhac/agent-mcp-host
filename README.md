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

## Install

```sh
brew install shhac/tap/agent-mcp-host
# and the tools you'll mount:
brew install shhac/tap/agent-slack shhac/tap/lin
```

## Quick start

```sh
# 1. Provision a person (bindings are namespaced per tool; both optional —
#    a tool that supports enrollment lets them enter credentials themselves):
agent-mcp-host pair add alice \
    --bind slack:workspace=acme --bind lin:workspace=acme
# → prints alice's pairing code (a secret — share it only with alice)

# 2. Serve — with Tailscale, no URL to figure out (derived from MagicDNS,
#    tunnel torn down on exit):
agent-mcp-host serve --tailscale funnel \
    --mount slack=agent-slack --mount lin=lin
# or bring your own https origin:
#   agent-mcp-host serve --public-url https://hub.example \
#       --mount slack=agent-slack --mount lin=lin
# (then point your reverse proxy at the --http listener, default 127.0.0.1:8000)
```

There is no separate step to start the tools: `serve` spawns each one in
delegate mode with everything it needs injected — the binaries just have to
be installed. To run a tool under your own control instead (debugger,
launchd), use an **attach mount**: `agent-mcp-host mount-env lin=lin` prints
the exact launch command, then `--mount lin=lin@127.0.0.1:9410` proxies to it.

Each mounted tool is spawned as `<binary> mcp --http 127.0.0.1:<port>
--oauth <public-url>` — delegate mode: the tool validates the host's Ed25519
tokens and mints nothing itself.

**What alice does:** she adds `https://hub…/slack/mcp` as a connector, enters
her pairing code once in the browser, and — if no slack binding was
provisioned — fills in slack's own credential form (the fields come from
`agent-slack mcp schema`; her secrets go to the tool over stdin, never argv).
Adding `/lin/mcp` afterwards asks for **no code**: a 30-day browser session
covers her identity, and she is prompted only for lin's delta. Tokens stay
per-tool: a slack token is useless at `/lin/mcp` by construction.

**Revocation:** `agent-mcp-host pair remove alice` kills her pairing code,
refresh tokens, and browser sessions in one step.

## Output contract

- **stdout** — an NDJSON event stream, one line per lifecycle moment:

  ```json
  {"event":"mount_ready","tool":"slack","url":"https://hub…/slack/mcp","time":"…"}
  {"event":"paired","tool":"slack","principal":"alice","client":"Claude","via":"code","time":"…"}
  {"event":"enrolled","tool":"slack","principal":"alice","client":"Claude","time":"…"}
  {"event":"authorized","tool":"slack","principal":"alice","client":"Claude","via":"code","time":"…"}
  ```

  Events never contain secrets — no pairing codes, tokens, or submitted
  credentials.
- **stderr** — the human boot banner (connector URLs + the shared pairing
  code; treat it like a password) and each tool's own stderr, prefixed with
  its mount name.

Run `agent-mcp-host usage` for the full LLM-optimized reference card.

## What makes a tool mountable

Any current family CLI — no tool-side code beyond the
`WithCredentialEnrollment` it already uses for single-tool mode. The host
discovers each tool's credential form from `mcp schema` and bridges
enrollment through the hidden `mcp enroll` subcommand.

## How it relates to the rest of the family

The single-tool multi-user story (one server, many humans, self-serve
credentials, fail-closed) already ships in `lib-agent-mcp` and each CLI. This
host is the breadth layer on top: it does not change how a tool authorizes a
principal — it becomes the single authorization server whose tokens those tools
validate (delegate mode), and the single origin they sit behind. Design:
[design-docs/architecture.md](design-docs/architecture.md).

## License

PolyForm Perimeter 1.0.0 — see [LICENSE](LICENSE).
