# `agent-mcp-host` command map (reference)

Run `agent-mcp-host usage` for the LLM-optimized overview.
Run `agent-mcp-host <command> --help` for per-command flags.

`serve` streams NDJSON lifecycle events on stdout (secret-free) and the human
banner on stderr; `pair` commands print human-readable text. Errors are
`{error, fixable_by, hint}` on stderr with exit 1.

## Serve

- `agent-mcp-host serve --mount <name>=<binary> [--mount ...]` — run the host:
  reverse proxy + OAuth 2.1 authorization server. Long-running.
  - `--mount <name>=<binary>` — spawned mount: the host launches
    `<binary> mcp --http 127.0.0.1:<port> --oauth <public-url>` itself and
    serves it at `/<name>/mcp` (repeatable)
  - `--mount <name>=<binary>@host:port` — attach mount: proxy to a listener
    you run yourself (launch command from `mount-env`); the binary name is
    still execed for `mcp schema` / `mcp enroll`
  - `--tailscale funnel|serve` — front with a Tailscale tunnel (`funnel` =
    public internet, `serve` = tailnet-private); derives `--public-url` from
    MagicDNS when unset; tunnel torn down on exit
  - `--tailscale-port 443|8443|10000` — public HTTPS port for `--tailscale`
    (default 443)
  - `--public-url <https-url>` — externally-reachable OAuth issuer (each
    `/<tool>/mcp` is a token audience); required without `--tailscale`
  - `--http <addr>` — front-door listen address (default `127.0.0.1:8000`);
    front it with your own reverse proxy when not using `--tailscale`

## Attach-mount helper

- `agent-mcp-host mount-env <name>=<binary> [--http <addr>] [--public-url <url> | --tailscale funnel|serve [--tailscale-port <p>]]`
  — print the env + launch command for running a tool yourself
  - `--http <addr>` — address the tool should bind (default `127.0.0.1:9400`)
  - `--public-url`/`--tailscale` must match what `serve` runs with
    (`--tailscale` here only derives the URL; no tunnel starts)

## People (principals + pairing codes)

- `agent-mcp-host pair add <name> [--bind <tool>:<key>=<value> ...]` — mint a
  pairing code for a named principal; prints the code (a secret). Bindings
  are namespaced per tool and carried in that tool's tokens with the prefix
  stripped; omit a tool's binding to let the person enroll in the browser
- `agent-mcp-host pair list` — principals and their bindings (codes never shown)
- `agent-mcp-host pair show <name>` — print one principal's stored pairing
  code (a secret)
- `agent-mcp-host pair rotate <name>` — issue a fresh code, preserving bindings
- `agent-mcp-host pair remove <name>` — revoke everything at once: code,
  refresh tokens, browser sessions

## Meta

- `agent-mcp-host usage` — LLM-optimized reference card
- `agent-mcp-host --version` — version
- `agent-mcp-host completion <shell>` — shell completions

## Global flags

- `--format json|yaml|jsonl` — output format
- `--color auto|always|never` — colorize output
- `--timeout <ms>` — request timeout
- `--debug` — debug diagnostics on stderr

## Secrets

Keychain service `app.paulie.agent-mcp-host.mcp` holds the Ed25519 signing
key, pairing codes, principals, sessions, and refresh tokens. Never printed
except `pair add`/`rotate`/`show` (the code, on request) and the serve
stderr banner.
