# agent-mcp-host

One-origin MCP host for the `agent-*` CLI family. Go + cobra. Serves every
family CLI's MCP tools behind one domain, with one OAuth authorization server
and per-tool logins. See `design-docs/architecture.md`.

## What this is (and isn't)

- It is a **reverse proxy + authorization server**, not a domain CLI. It does
  **not** reflect itself into an MCP server; it *mounts* other tools' MCP
  servers (each running in delegate OAuth mode) behind `/<tool>/mcp`.
- Each mounted tool stays a full MCP server in its own binary — the host owns
  only the shared front door, the single AS, and the unified human-facing
  login/enrollment pages.

## Project Rules

- Same output/error contract as the family: lists default to NDJSON, single
  resources to JSON; errors are structured JSON on stderr with `fixable_by`
  (`agent` | `human` | `retry`) and a `hint`, never unstructured.
- Secrets (the OAuth signing key, pairing/principal store) live in the macOS
  Keychain under `app.paulie.agent-mcp-host.mcp`; never printed. See
  `internal/config`.
- The host **reuses**, never reimplements, tool-specific logic: it discovers a
  tool via `<tool> mcp schema`, renders that tool's enrollment descriptor, and
  performs the enrollment action by exec-ing the tool's own `auth add --stdin`
  + test verb. It links no tool code.
- Mechanism lives in the libraries (`lib-agent-oauth` for the AS,
  `lib-agent-mcp` for the tool contract). The host is orchestration; a fix in a
  library reaches the whole family.

## Verification

```bash
GOCACHE=$(pwd)/.cache/go-build go test ./... -count=1
GOCACHE=$(pwd)/.cache/go-build go vet ./...
golangci-lint run ./...
```

## References

The full design and the CLI↔lib↔host boundary live in `design-docs/`:

- `architecture.md` — the host model, the auth/token model, and the boundary
  (what lives in the CLI vs the libraries vs the host).
