package host

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	oauth "github.com/shhac/lib-agent-oauth"
)

const hostPublicURL = "https://hub.example"

// fakeTool starts an in-process delegate MCP server for a mount: it validates
// the host's token for the mount's audience and echoes the caller's principal.
func fakeTool(t *testing.T, h *Host, m *runningMount, verifyKey string) *httptest.Server {
	t.Helper()
	key, err := base64.RawURLEncoding.DecodeString(verifyKey)
	if err != nil {
		t.Fatal(err)
	}
	rs, err := oauth.NewResourceServer(oauth.RSConfig{IssuerURL: h.publicURL, Resource: h.resource(m), VerifyKey: key})
	if err != nil {
		t.Fatalf("fake tool %q RS: %v", m.cfg.Name, err)
	}
	mux := http.NewServeMux()
	mux.Handle("/mcp", rs.Protect(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		v, _ := oauth.PrincipalFrom(r.Context())
		_ = json.NewEncoder(w).Encode(map[string]any{"tool": m.cfg.Name, "principal": v.Name, "binding": v.Binding})
	})))
	return httptest.NewServer(mux)
}

// buildTestHost wires a host over store with in-process fake tools for each
// mount (no exec, no keyring) and returns it plus its front-door test server.
func buildTestHost(t *testing.T, store oauth.SecretStore, names ...string) (*Host, *httptest.Server) {
	return buildTestHostWith(t, store, nil, names...)
}

// buildTestHostWith is buildTestHost with a configure hook that runs after the
// exec seams are stubbed and before the handler is built — enrollment tests
// override discover/enrollBridge there.
func buildTestHostWith(t *testing.T, store oauth.SecretStore, configure func(h *Host), names ...string) (*Host, *httptest.Server) {
	t.Helper()
	mounts := make([]*Mount, len(names))
	for i, n := range names {
		mounts[i] = &Mount{Name: n, Binary: "unused-in-test"}
	}
	h, err := New(Config{
		PublicURL: hostPublicURL, Addr: "127.0.0.1:0", Store: store,
		Mounts: mounts, Stderr: io.Discard, Stdout: io.Discard,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	fakes := map[string]*httptest.Server{}
	h.discover = func(_ context.Context, m *runningMount) (*toolManifest, error) {
		return &toolManifest{Name: m.cfg.Name, Version: "test"}, nil // no descriptor: not self-serve
	}
	h.start = func(_ context.Context, m *runningMount, verifyKey string) error {
		ts := fakeTool(t, h, m, verifyKey)
		fakes[m.cfg.Name] = ts
		u, _ := url.Parse(ts.URL)
		m.addr = u.Host
		return nil
	}
	h.stopMount = func(m *runningMount) {
		if ts := fakes[m.cfg.Name]; ts != nil {
			ts.Close()
		}
	}
	if configure != nil {
		configure(h)
	}
	handler, cleanup, err := h.handler(context.Background())
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	front := httptest.NewServer(handler)
	t.Cleanup(func() { front.Close(); cleanup() })
	return h, front
}

// runOAuthFlow drives DCR → authorize → token against the host front door for a
// resource, and returns the access token.
func runOAuthFlow(t *testing.T, front *httptest.Server, pairingCode, resource string) string {
	t.Helper()
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	const redirect = "https://client.example/cb"
	const verifier = "a-sufficiently-long-pkce-code-verifier-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	// Dynamic client registration.
	reg, err := client.Post(front.URL+oauth.RegisterPath, "application/json",
		strings.NewReader(`{"redirect_uris":["`+redirect+`"],"client_name":"test"}`))
	if err != nil {
		t.Fatal(err)
	}
	var regOut struct {
		ClientID string `json:"client_id"`
	}
	json.NewDecoder(reg.Body).Decode(&regOut)
	reg.Body.Close()

	// Authorize with the pairing code and the requested resource.
	az, err := client.PostForm(front.URL+oauth.AuthorizePath, url.Values{
		"client_id": {regOut.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"s"},
		"scope": {"mcp"}, "resource": {resource}, "pairing_code": {pairingCode},
	})
	if err != nil {
		t.Fatal(err)
	}
	az.Body.Close()
	if az.StatusCode != http.StatusFound {
		t.Fatalf("authorize (resource=%s) = %d, want 302", resource, az.StatusCode)
	}
	loc, _ := url.Parse(az.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect: %s", loc)
	}

	// Exchange for a token.
	tok, err := client.PostForm(front.URL+oauth.TokenPath, url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirect},
		"client_id": {regOut.ClientID}, "code_verifier": {verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer tok.Body.Close()
	var tokOut struct {
		AccessToken string `json:"access_token"`
	}
	json.NewDecoder(tok.Body).Decode(&tokOut)
	if tokOut.AccessToken == "" {
		t.Fatal("no access token")
	}
	return tokOut.AccessToken
}

// The whole host: a person enters the pairing code once, gets a per-mount token,
// and a call to that mount reaches the tool with the principal attached — while
// the same token is rejected at the other mount.
func TestHostEndToEnd(t *testing.T) {
	store := oauth.NewMemStore()
	_, front := buildTestHost(t, store, "slack", "lin")
	// Pre-bind alice with NAMESPACED per-tool bindings (the host's `pair add`
	// uses this same public path) and use her per-person code to drive the flow.
	aliceCode, err := oauth.NewPairing(store).AddPrincipal("alice",
		map[string]string{"slack:workspace": "acme", "lin:workspace": "letsdothis"})
	if err != nil {
		t.Fatal(err)
	}

	slackTok := runOAuthFlow(t, front, aliceCode, hostPublicURL+"/slack/mcp")

	// The slack token reaches the slack tool with the principal, and its binding
	// is projected to slack's own vocabulary (slack:workspace=acme → workspace=acme).
	body := callMount(t, front, "/slack/mcp", slackTok)
	if body["tool"] != "slack" || body["principal"] != "alice" {
		t.Errorf("slack call body = %v", body)
	}
	if b, _ := body["binding"].(map[string]any); b["workspace"] != "acme" || b["slack:workspace"] != nil {
		t.Errorf("slack binding not projected (want workspace=acme, no namespace): %v", body["binding"])
	}

	// The lin connector's token carries lin's binding — the same person, a
	// different per-tool alias.
	linTok := runOAuthFlow(t, front, aliceCode, hostPublicURL+"/lin/mcp")
	linBody := callMount(t, front, "/lin/mcp", linTok)
	if b, _ := linBody["binding"].(map[string]any); b["workspace"] != "letsdothis" {
		t.Errorf("lin binding not projected (want workspace=letsdothis): %v", linBody["binding"])
	}

	// The same token is rejected at the lin mount (per-tool audience isolation).
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/lin/mcp", strings.NewReader("{}"))
	req.Header.Set("Authorization", "Bearer "+slackTok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("slack token at lin mount = %d, want 401", resp.StatusCode)
	}

	// An unauthenticated call to a mount is challenged, not proxied.
	unauth, err := http.Post(front.URL+"/slack/mcp", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	unauth.Body.Close()
	if unauth.StatusCode != http.StatusUnauthorized {
		t.Errorf("no-token slack call = %d, want 401", unauth.StatusCode)
	}
}

func callMount(t *testing.T, front *httptest.Server, path, token string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, front.URL+path, strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s call = %d, want 200", path, resp.StatusCode)
	}
	var body map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	return body
}

// The host is the single source of CORS: a proxied tool's own Access-Control-*
// response headers are stripped, and the host's are substituted — otherwise a
// tool could widen CORS behind the host's back.
func TestHostStripsProxiedToolCORSHeaders(t *testing.T) {
	h, err := New(Config{
		PublicURL: hostPublicURL, Addr: "127.0.0.1:0", Store: oauth.NewMemStore(),
		Mounts: []*Mount{{Name: "slack", Binary: "unused-in-test"}}, Stderr: io.Discard, Stdout: io.Discard,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// A tool that sets its OWN CORS headers on every response — the host must
	// strip these before they reach the browser.
	tool := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "https://tool.example")
		w.Header().Set("Access-Control-Max-Age", "999")
		_, _ = io.WriteString(w, "ok")
	}))
	t.Cleanup(tool.Close)
	h.discover = func(_ context.Context, m *runningMount) (*toolManifest, error) {
		return &toolManifest{Name: m.cfg.Name, Version: "test"}, nil
	}
	h.start = func(_ context.Context, m *runningMount, _ string) error {
		u, _ := url.Parse(tool.URL)
		m.addr = u.Host
		return nil
	}
	h.stopMount = func(*runningMount) {}
	handler, cleanup, err := h.handler(context.Background())
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	t.Cleanup(cleanup)
	front := httptest.NewServer(handler)
	t.Cleanup(front.Close)

	req, _ := http.NewRequest(http.MethodPost, front.URL+"/slack/mcp", strings.NewReader("{}"))
	req.Header.Set("Origin", "https://client.example")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	// The tool's CORS values are gone; the host's own are present.
	if got := resp.Header.Get("Access-Control-Allow-Origin"); got != "https://client.example" {
		t.Errorf("Access-Control-Allow-Origin = %q, want the host's origin echo (tool's header not stripped?)", got)
	}
	if got := resp.Header.Get("Access-Control-Max-Age"); got != "600" {
		t.Errorf("Access-Control-Max-Age = %q, want the host's 600 (tool's 999 not stripped?)", got)
	}
}

// An attach mount proxies to a listener the operator runs themselves: the
// host never spawns it, but discovery, auth, and projection work identically.
func TestHostAttachMount(t *testing.T) {
	store := oauth.NewMemStore()
	m := &Mount{Name: "lin", Binary: "unused-in-test"}
	h, err := New(Config{
		PublicURL: hostPublicURL, Addr: "127.0.0.1:0", Store: store,
		Mounts: []*Mount{m}, Stderr: io.Discard, Stdout: io.Discard,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// The "operator-run" tool: a real delegate RS listener started outside the
	// host, exactly what `mount-env` would have them launch.
	verifyKey := base64.RawURLEncoding.EncodeToString(h.oauth.PublicKey())
	tool := fakeTool(t, h, h.mounts[0], verifyKey)
	t.Cleanup(tool.Close)
	u, _ := url.Parse(tool.URL)
	m.Attach = u.Host

	h.discover = func(_ context.Context, m *runningMount) (*toolManifest, error) {
		return &toolManifest{Name: m.cfg.Name, Version: "test"}, nil
	}
	h.start = func(context.Context, *runningMount, string) error {
		t.Error("an attach mount must not be spawned")
		return nil
	}
	h.stopMount = func(*runningMount) {}
	handler, cleanup, err := h.handler(context.Background())
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	front := httptest.NewServer(handler)
	t.Cleanup(func() { front.Close(); cleanup() })

	code, err := oauth.NewPairing(store).AddPrincipal("bob", map[string]string{"lin:workspace": "acme"})
	if err != nil {
		t.Fatal(err)
	}
	tok := runOAuthFlow(t, front, code, hostPublicURL+"/lin/mcp")
	body := callMount(t, front, "/lin/mcp", tok)
	if body["tool"] != "lin" || body["principal"] != "bob" {
		t.Errorf("attach-mount call = %v", body)
	}
	if b, _ := body["binding"].(map[string]any); b["workspace"] != "acme" {
		t.Errorf("attach-mount binding not projected: %v", body["binding"])
	}
}
