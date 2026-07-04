# agent-mcp-host: architecture

`agent-mcp-host` serves the whole `agent-*` CLI family's MCP tools from one
machine, under one origin (in practice one Tailscale funnel DNS name), with one
OAuth authorization server and per-tool logins. It is the breadth half of the
multi-user MCP vision; the depth half (one tool, many humans, self-serve
credentials, fail-closed) already ships in `lib-agent-mcp` + each CLI.

Status: **design settled, implementation starting.** This doc is the authority
for the host and the CLI↔lib↔host boundary; `lib-agent-mcp/design-docs/host.md`
is the earlier lib-side sketch this supersedes.

## The shape in one picture

```
                    https://hub.tailnet.example   (one Tailscale funnel)
                                  │
                    ┌─────────────┴──────────────┐
                    │        agent-mcp-host       │
                    │  AUTHORIZATION SERVER (AS):  │
                    │   /.well-known/*, /oauth/*   │
                    │   one pairing/principal store│
                    │   unified enrollment+chooser │
                    │  REVERSE PROXY:              │
                    │   /slack/mcp → :A/mcp        │
                    │   /lin/mcp   → :B/mcp        │
                    └───┬──────────────────────┬───┘
              spawns +  │                       │  spawns + proxies
              proxies   │                       │
        ┌───────────────┴──┐          ┌─────────┴────────┐
        │ agent-slack mcp  │          │ lin mcp          │
        │ --http 127.0.0.1:A│          │ --http 127.0.0.1:B│
        │ --oauth <host>   │          │ --oauth <host>   │  ← DELEGATE mode
        │ (RS-only)        │          │ (RS-only)        │    (validates host
        └──────────────────┘          └──────────────────┘     tokens; no AS)
           loopback only                 loopback only
```

Each tool keeps being a full MCP server in its own binary — the thing we
deliberately did not want to lose. The host does not re-implement serving; it
**mounts** each tool's server behind a path and owns only the cross-cutting
concerns: the single front door, the single authorization server, and the
unified human-facing login/enrollment pages.

## Two connectors, not one merged surface

A person adds **one Claude connector per tool** under the shared domain —
`https://hub…/slack/mcp`, `https://hub…/lin/mcp` — each with its own login.
This matches "different tools, different logins" and falls straight out of
reverse-proxy path routing. We deliberately do **not** aggregate every tool's
tools into one merged `/mcp` surface: that would force the host to re-implement
MCP-level dispatch, invent a cross-tool namespace, and collide with each tool's
independent schema/versioning — throwing away the per-tool server we want to
keep. Per-tool mounts keep each tool isolated, independently versioned, and
independently authorized (a token for `/slack/mcp` is useless at `/lin/mcp`).

## The auth model: host is the only AS; tools are RS-only

The host is the single **Authorization Server** for the family. It owns:

- the pairing codes and the named-principal store (one per person, family-wide);
- the human-facing pages: pairing-code entry, credential **enrollment**, and
  the allowed-set **chooser** — rendered once, for every tool, from
  `lib-agent-oauth`;
- token **minting**, with a **per-tool audience**: a token for the Slack mount
  is `aud = <public-url>/slack/mcp` and carries only that tool's binding claims.

Each mounted tool runs in **delegate mode** (`--oauth <issuer-url>`): a
Resource Server that validates the host's tokens and mounts **no** AS routes of
its own. It keeps doing exactly what it does today for a validated principal —
apply its `WithIdentityBinding` and `WithFileRootScope` from the token's
claims — but the token was minted by the host, not by itself.

### Token signing: EdDSA, key handed down at spawn

The host signs tokens with an **Ed25519 private key** held in its OAuth keyring
namespace `app.paulie.agent-mcp-host.mcp`. A delegate tool needs only the
**public** key to verify — it can validate but never mint, a clean AS/RS split.

Because the host **spawns** each tool, it hands the verify key down at spawn
(env var / flag) alongside the issuer and the tool's audience — no shared
keychain coupling and no JWKS-bootstrap ordering problem. (A JWKS endpoint on
the host is a possible future alternative for tools that ever run out-of-process
from their spawner; not needed for same-machine hosting.) Delegate mode in the
lib therefore takes: issuer URL, this tool's audience, and the Ed25519 verify
key.

## The boundary: what lives where (the load-bearing decision)

The goal is **minimal hand-rolling in each CLI; all mechanism in the
libraries**, so the tools look and feel identical and a library fix reaches the
whole family. Everything below is sorted by where it lives and *why it can't
sensibly live elsewhere*.

| Concern | Lives in | Hosted-mode path |
|---|---|---|
| Tool surface (which tools, their schemas) | **lib** (reflection over the cobra tree) | Host discovers via `mcp schema` |
| Identity binding (principal → argv/env) | **CLI** (a Go rule) but *invoked by the lib* | Runs inside the tool's own proxied RS — unchanged |
| File-root scope (principal → fs subtree) | **CLI** (a Go rule) but *invoked by the lib* | Runs inside the tool's own proxied RS — unchanged |
| Enrollment **descriptor** (the form's shape) | **CLI** (a declarative struct) | Travels in `mcp schema`; host renders it |
| Enrollment **action** (validate + store) | **CLI**, as a convention subcommand | Host execs the bridge (`auth add --stdin`) |
| Pairing codes / principal store | **lib-agent-oauth** | The **host** owns it (tools have none in delegate mode) |
| Enrollment / chooser / authorize **pages** | **lib-agent-oauth** | The **host** renders them |
| Token mint / validate, PKCE, DCR | **lib-agent-oauth** | Host mints; tool validates |

Three consequences worth stating plainly:

1. **Identity binding and fs-scope never leave the tool.** They are Go
   callbacks that run *inside the tool's own server process*, which the host
   merely proxies to. Hosted mode changes nothing about them — the tool
   validates a (host-minted) token, pulls the principal's binding from its
   claims, and translates it to `--workspace <alias>` + the fail-closed env
   exactly as in standalone `--oauth local`. Zero new per-CLI code.

2. **Enrollment splits into a shared *shape* and a reused *action*.** The
   descriptor — the only visible part — is one declarative struct that is the
   single source of truth for both standalone and hosted rendering. Standalone
   mode calls the tool's in-process `WithCredentialEnrollment` callback; hosted
   mode can't (the tool has no AS), so the host performs the action by
   **exec-ing a convention subcommand** that already contains all the
   tool-specific validate/derive/converge/store logic. No enrollment logic is
   re-implemented in the host — it is bridged.

3. **The host reuses, it does not reimplement.** Everything tool-specific the
   host needs, it gets by exec-ing the tool: the surface (`mcp schema`), the
   enrollment shape (descriptor in that same schema), and the enrollment action
   (`auth add --alias <principal> --stdin`, then the tool's test verb). The
   host links **no** tool code.

### The hostable-tool contract

A CLI is mountable by the host iff it satisfies this contract — which a tool
already using `agentmcp.Command(root, …)` with enrollment nearly meets:

1. **`mcp schema`** emits its manifest, now including the enrollment
   **descriptor** and the **identity-binding rule** (see the registration
   primitive below).
2. **`mcp --http <addr> --oauth <issuer-url>`** — delegate mode, provided by
   the lib; zero per-CLI code.
3. **`auth add --alias <name> --stdin`** — machine credential entry (secrets on
   stdin, never argv). Most family CLIs have `--stdin` already; the host needs
   the *derive+validate+store* behavior enrollment does, so this may gain a
   verify step (`--verify`) or the CLI keeps that logic in its `auth add`.
4. **A test/identity verb** (`auth test` / `auth status`) the host calls to
   confirm a stored credential.
5. **A per-call selector flag + fail-closed env** (`--workspace <alias>` +
   `AGENT_X_REQUIRE_IDENTITY=1`) — already present wherever multi-user shipped.

Items 2 and most of 1 come free from the lib. The per-CLI delta to become
hostable is therefore: declare the binding rule in the schema (a few lines) and
ensure the `auth add`/test convention verbs exist. That is the "minimal
hand-rolling" target.

## The registration primitive (in lib-agent-mcp, so it's uniform)

"How a CLI registers with the host" is not hand-rolled per tool — it is a
capability the lib grants every tool identically. Concretely, in
`lib-agent-mcp`:

- **`mcp schema` grows** to carry, alongside the existing tool list: the
  enrollment `descriptor` (the exact struct the AS renders) and a declarative
  **identity-binding rule** (binding key → selector flag + fail-closed env), so
  the host can apply per-principal identity without linking Go. Today the
  binding is a Go closure (`WithIdentityBinding`); we add a declarative form the
  schema can serialize while keeping the closure for standalone use. Where a
  binding is pure "key → `--flag value` + env", the declarative form fully
  replaces the closure and the CLI drops even that.
- **Delegate mode** (`--oauth <issuer-url>`) is the transport half of
  registration: it is how a tool accepts the host as its authority.
- The host's side of registration — spawn, `mcp schema` discovery, health,
  proxy wiring — lives in `agent-mcp-host`, built on these lib primitives.

A tool does not actively "announce" itself to a running host; the **host
mounts** tools it is configured to serve (a config list of family binaries),
discovering each one's capabilities by exec-ing `mcp schema`. This keeps every
CLI a passive leaf with no "am I hosted?" ambient state.

## lib-agent-oauth: the extraction

The OAuth AS+RS, pairing/principals, and enrollment/chooser/authorize rendering
currently live in `lib-agent-mcp/oauth`. The host needs *all* of that and
*none* of `lib-agent-mcp`'s cobra-reflection/runner half. Importing the whole
reflection library just to get the auth server is exactly the "implementation
noise in the wrong place" we're avoiding.

So `oauth/` is extracted into a new sibling **`lib-agent-oauth`**:

- **`lib-agent-oauth`** — the self-contained AS+RS, pairing, principals,
  enrollment/chooser/authorize pages, token mint/validate, PKCE, DCR, the
  `SecretStore` seam. Depends only on `lib-agent-keyring` (default store) and
  the stdlib.
- **`lib-agent-mcp`** re-imports it and keeps its public `agentmcp` API stable
  (re-exporting the option adapters `WithCredentialEnrollment`,
  `WithIdentityBinding`, etc.). Existing CLIs recompile unchanged.
- **`agent-mcp-host`** imports `lib-agent-oauth` directly for the AS, plus a
  thin slice of `lib-agent-mcp` (or a shared types package) for the `mcp
  schema` manifest shape it consumes.

This is the "if you feel we should split a library, do it" case, pre-approved.

## Login once, grow into tools (AS session + incremental authorization)

Per-tool audiences mean per-tool **tokens** — unavoidable, since the connector
binds a token's audience to the exact `/…/mcp` URL it calls and each tool is a
separate connector. But a person should not re-prove their identity for every
tool. So the host AS is built **session-first**, following the standard OAuth
SSO + incremental-authorization pattern:

- **The pairing code establishes an AS session, not just one token.** On the
  first tool's approval, entering the code sets a secure session cookie
  (HttpOnly, Secure, SameSite) tied to the verified principal.
- **Subsequent tools reuse the session.** When the same person adds a second
  connector (`/lin/mcp`), its OAuth flow reaches the same AS, which recognizes
  the session, **skips the pairing-code step**, and prompts only for the
  *delta* — the new tool's credential enrollment, if the principal has no
  binding for it yet. They keep every tool they already have.
- **The tokens stay separate and audience-bound.** The session shares the
  *identity proof*, never the tokens: each tool still gets its own
  audience-scoped token from its own flow. Growing to tool N reuses the
  session, enrolls only tool N, and leaves tools 1..N-1 untouched.

Net: enter the pairing code once, prove identity once, grow into each tool by
enrolling only what's new. Revocation (`pair remove alice`) drops the session
and every principal token at once; the session's lifetime is bounded like any
access grant.

**Built (lib-agent-oauth v0.6.0 / host v0.3.0):** `oauth.Config.SessionTTL`
enables the session store; the host sets 30 days. Mechanics as designed, plus:
the session record stores only the principal *name*, re-resolved from the
pairing store on every use (a removed principal's session dies even before the
purge; bindings are always current); an entered pairing code always wins over
a session; a session-resumed flow never re-issues the cookie; the cookie is
`__Host-`-prefixed (Secure, HttpOnly, SameSite=Lax, Path=/).

## Namespaced bindings & per-tool audiences

The operator provisions a person once, family-wide:

```
agent-mcp-host pair add alice \
    --bind slack:workspace=acme \
    --bind lin:workspace=letsdothis
```

Binding keys are namespaced `<tool>:<key>`. When the host mints a token for the
`/slack/mcp` mount it includes only the `slack:`-prefixed bindings, **stripped**
to the tool's own vocabulary (`workspace=acme`) and set as `aud =
<public-url>/slack/mcp`. So the tool receives exactly the claim shape it
already understands, and a Slack token cannot address the Lin mount. A person
minted **without** a tool's binding enrolls that tool's credentials in the
browser the first time they connect to it — the same self-serve flow, now
host-rendered.

## Process & ops model

- The host reads a **mount config** (which family binaries to serve, by path)
  and, at boot, execs `<tool> mcp schema` to discover each one, then spawns
  `<tool> mcp --http 127.0.0.1:<port> --oauth <issuer>` (delegate) and
  reverse-proxies `/<tool>/mcp` to it.
- Crash → restart with backoff; a tool that won't start → its mount returns a
  structured 503, the rest keep serving.
- `agent-mcp-host status` lists mounts, versions (from schema), and listener
  health. The boot banner prints the per-tool connector URLs + the shared
  pairing entry point, mirroring the single-tool banner.
- Tailscale funnel/serve wiring is reused from `lib-agent-mcp`'s tailscale
  helper (candidate for a shared move if both need it).

## Out of scope (deliberately)

- **Merged single-connector surface** — per-tool mounts only (see above).
- **Cross-machine hosting** — tools run as loopback subprocesses of the host;
  remote tools would force JWKS + tailnet ACLs. The audience/claims model
  already permits it later.
- **Per-principal tool ACLs** ("alice may use slack but not stripe") — the
  namespaced bindings make this cheap to add later (no `lin:*` binding ⇒ no lin
  access); today every paired person may reach every mounted tool they enroll.
- **Non-family / arbitrary MCP servers** — the host mounts `agent-*` family
  tools that satisfy the hostable contract; it is not a general MCP gateway.

## Build order

1. **`lib-agent-oauth` extraction** — move `oauth/`, re-point `lib-agent-mcp`,
   re-release both. (task #15)
2. **Delegate mode** in `lib-agent-mcp` — `--oauth <issuer-url>`, RS-only,
   verify key handed in at spawn. Testable against a second in-process AS.
   (task #11)
3. **Registration primitive** — descriptor + binding rule in `mcp schema`;
   convention-verb contract. (task #12)
4. **`agent-mcp-host`** — schema discovery, supervision, reverse proxy, the AS
   with namespaced bindings + per-tool audiences, unified enrollment. (task #13)
5. **Wire agent-slack + lin** and mount both behind one origin end to end.
   (task #14)
