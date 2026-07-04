package host

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	oauth "github.com/shhac/lib-agent-oauth"
)

// TestIntegrationRealTool is the one test where NOTHING is stubbed: it builds
// the kitchen-sink dummy CLI (internal/dummytool, a real lib-agent-mcp
// binary), and the host spawns it in delegate mode, discovers its schema via
// a real `mcp schema`, renders its enrollment form, bridges the submission
// through a real `mcp enroll` subprocess, and proxies an authenticated MCP
// tool call into it — with the identity binding riding into the tool's own
// subprocess env. This is the host↔lib contract exercised for real, not held
// by construction.
func TestIntegrationRealTool(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test builds and boots a real tool binary")
	}
	bin := buildDummyTool(t)

	store := oauth.NewMemStore()
	h, err := New(Config{
		PublicURL: hostPublicURL, Addr: "127.0.0.1:0", Store: store,
		Mounts: []*Mount{{Name: "dummy", Binary: bin}},
		Stderr: io.Discard, Stdout: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	// Deliberately NO seam overrides: real spawn, real discover, real enroll.
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	handler, cleanup, err := h.handler(ctx)
	if err != nil {
		t.Fatalf("handler (real discovery/spawn): %v", err)
	}
	t.Cleanup(cleanup)
	if err := h.waitReady(ctx); err != nil {
		t.Fatalf("real tool never became ready: %v", err)
	}
	front := httptest.NewServer(handler)
	t.Cleanup(front.Close)

	aliceCode, err := oauth.NewPairing(store).AddPrincipal("alice", nil)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	const redirect = "https://client.example/cb"
	const verifier = "a-sufficiently-long-pkce-code-verifier-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	reg, err := client.Post(front.URL+oauth.RegisterPath, "application/json",
		strings.NewReader(`{"redirect_uris":["`+redirect+`"],"client_name":"integration"}`))
	if err != nil {
		t.Fatal(err)
	}
	var regOut struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(reg.Body).Decode(&regOut); err != nil {
		t.Fatal(err)
	}
	reg.Body.Close()

	form := url.Values{
		"client_id": {regOut.ClientID}, "redirect_uri": {redirect}, "response_type": {"code"},
		"code_challenge": {challenge}, "code_challenge_method": {"S256"}, "state": {"s"},
		"scope": {"mcp"}, "resource": {hostPublicURL + "/dummy/mcp"}, "pairing_code": {aliceCode},
	}

	// Unbound alice → the form the host discovered from the REAL `mcp schema`.
	az, err := client.PostForm(front.URL+oauth.AuthorizePath, form)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := readBody(az)
	if az.StatusCode != http.StatusOK || !strings.Contains(page, "Connect Dummy") {
		t.Fatalf("authorize = %d, want the discovered enrollment form; body: %.200s", az.StatusCode, page)
	}

	// Submit → the host execs the REAL `dummytool mcp enroll`.
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set("field_token_api_key", "sk-good")
	az, err = client.PostForm(front.URL+oauth.AuthorizePath, form)
	if err != nil {
		t.Fatal(err)
	}
	az.Body.Close()
	if az.StatusCode != http.StatusFound {
		t.Fatalf("enroll submit = %d, want 302", az.StatusCode)
	}

	// The tool's callback ran in its own process and the host namespaced it.
	principals, err := oauth.NewPairing(store).Principals()
	if err != nil {
		t.Fatal(err)
	}
	if principals["alice"]["dummy:workspace"] != "ws-alice" {
		t.Fatalf("persisted binding = %v, want dummy:workspace=ws-alice from the real enroll subprocess", principals["alice"])
	}

	loc, _ := url.Parse(az.Header.Get("Location"))
	tok, err := client.PostForm(front.URL+oauth.TokenPath, url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {redirect}, "client_id": {regOut.ClientID}, "code_verifier": {verifier},
	})
	if err != nil {
		t.Fatal(err)
	}
	var tokOut struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tok.Body).Decode(&tokOut); err != nil {
		t.Fatal(err)
	}
	tok.Body.Close()
	if tokOut.AccessToken == "" {
		t.Fatal("no access token")
	}

	// A real MCP conversation through the reverse proxy into the real server.
	mcpPost := func(body string) map[string]any {
		return mcpCall(t, front, "/dummy/mcp", tokOut.AccessToken, body)
	}

	init := mcpPost(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)
	if init["result"] == nil {
		t.Fatalf("initialize = %v", init)
	}
	list := mcpPost(`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`)
	if !strings.Contains(mustJSON(t, list), "whoami") {
		t.Fatalf("tools/list missing whoami: %v", list)
	}

	// The identity binding crosses into the tool's subprocess: whoami reads
	// the env WithIdentityBinding injected for alice's projected binding.
	call := mcpPost(`{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"whoami","arguments":{}}}`)
	if got := mustJSON(t, call); !strings.Contains(got, "workspace=ws-alice") {
		t.Fatalf("whoami through the proxy = %s, want workspace=ws-alice", got)
	}
}

// mcpCall POSTs one JSON-RPC body to a mount through the front door and
// decodes the (possibly SSE-framed) response.
func mcpCall(t *testing.T, front *httptest.Server, path, token, body string) map[string]any {
	t.Helper()
	req, _ := http.NewRequest(http.MethodPost, front.URL+path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		t.Fatalf("mcp POST %s = %d: %.300s", path, resp.StatusCode, b)
	}
	raw, _ := io.ReadAll(resp.Body)
	// Streamable HTTP may frame the response as an SSE event; take the data
	// line if so.
	payload := string(raw)
	if i := strings.Index(payload, "data:"); i >= 0 {
		payload = strings.TrimSpace(payload[i+len("data:"):])
		if j := strings.Index(payload, "\n\n"); j >= 0 {
			payload = payload[:j]
		}
	}
	var out map[string]any
	if err := json.Unmarshal([]byte(payload), &out); err != nil {
		t.Fatalf("mcp response not JSON: %v\n%.300s", err, raw)
	}
	return out
}

// buildDummyTool compiles internal/dummytool into a temp dir.
func buildDummyTool(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "dummytool")
	cmd := exec.Command("go", "build", "-o", bin, "./internal/dummytool")
	cmd.Dir = "../.." // repo root
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("building dummytool: %v\n%s", err, out)
	}
	return bin
}

func mustJSON(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// integrationHost boots a host over real seams for the given mounts and
// returns it with its front door, ready for traffic.
func integrationHost(t *testing.T, store oauth.SecretStore, mounts ...*Mount) (*Host, *httptest.Server) {
	t.Helper()
	h, err := New(Config{
		PublicURL: hostPublicURL, Addr: "127.0.0.1:0", Store: store,
		Mounts: mounts, Stderr: io.Discard, Stdout: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	handler, cleanup, err := h.handler(ctx)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	t.Cleanup(cleanup)
	if err := h.waitReady(ctx); err != nil {
		t.Fatalf("mounts never became ready: %v", err)
	}
	front := httptest.NewServer(handler)
	t.Cleanup(front.Close)
	return h, front
}

// A rejected credential crosses THREE processes and still lands as the tool's
// own message on the re-rendered form: the real `mcp enroll` subprocess exits
// non-zero with the family's structured JSON error on stderr, the host
// unwraps it, and the browser sees "dummy rejected this API key".
func TestIntegrationEnrollRejection(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test builds and boots a real tool binary")
	}
	bin := buildDummyTool(t)
	store := oauth.NewMemStore()
	_, front := integrationHost(t, store, &Mount{Name: "dummy", Binary: bin})
	code, err := oauth.NewPairing(store).AddPrincipal("bob", nil)
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	clientID := registerIntegrationClient(t, client, front)
	form := integrationAuthForm(clientID, code, hostPublicURL+"/dummy/mcp")
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set("field_token_api_key", "bad")
	resp, err := client.PostForm(front.URL+oauth.AuthorizePath, form)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := readBody(resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("bad-key enroll = %d, want the re-rendered form", resp.StatusCode)
	}
	if !strings.Contains(page, "dummy rejected this API key") {
		t.Errorf("form should carry the tool's own rejection message; body: %.300s", page)
	}
	if strings.Contains(page, "fixable_by") || strings.Contains(page, `"error"`) {
		t.Errorf("raw structured-error JSON leaked into the form; body: %.300s", page)
	}
	// Nothing was persisted for the failed attempt.
	principals, _ := oauth.NewPairing(store).Principals()
	if len(principals["bob"]) != 0 {
		t.Errorf("failed enrollment persisted a binding: %v", principals["bob"])
	}
}

// Two REAL mounts of the same binary: per-mount audiences hold across real
// delegate validators — a dummy token is rejected at dummy2 by the tool's own
// RS, and garbage bearers are challenged.
func TestIntegrationTwoMountsAudienceIsolation(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test builds and boots a real tool binary")
	}
	bin := buildDummyTool(t)
	store := oauth.NewMemStore()
	_, front := integrationHost(t, store,
		&Mount{Name: "dummy", Binary: bin}, &Mount{Name: "dummy2", Binary: bin})
	code, err := oauth.NewPairing(store).AddPrincipal("alice",
		map[string]string{"dummy:workspace": "w1", "dummy2:workspace": "w2"})
	if err != nil {
		t.Fatal(err)
	}

	tok := runOAuthFlow(t, front, code, hostPublicURL+"/dummy/mcp")

	// Accepted at its own mount, with the per-mount projected binding.
	call := mcpCall(t, front, "/dummy/mcp", tok, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}`)
	if got := mustJSON(t, call); !strings.Contains(got, "workspace=w1") {
		t.Errorf("dummy whoami = %s, want workspace=w1", got)
	}

	// Rejected by the OTHER real tool's validator (audience mismatch).
	req, _ := http.NewRequest(http.MethodPost, front.URL+"/dummy2/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("dummy token at dummy2 = %d, want 401 from the real delegate RS", resp.StatusCode)
	}

	// Garbage bearer → challenged by the real RS, not proxied through.
	req, _ = http.NewRequest(http.MethodPost, front.URL+"/dummy/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"ping"}`))
	req.Header.Set("Authorization", "Bearer not-a-token")
	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("garbage token = %d, want 401", resp.StatusCode)
	}
	if resp.Header.Get("WWW-Authenticate") == "" {
		t.Error("401 should carry the WWW-Authenticate discovery challenge")
	}
}

// A REAL attach mount: the test plays operator — launching the tool itself
// with exactly the env mount-env prints — and the host fronts the listener it
// never spawned.
func TestIntegrationAttachRealTool(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test builds and boots a real tool binary")
	}
	bin := buildDummyTool(t)
	store := oauth.NewMemStore()
	h, err := New(Config{
		PublicURL: hostPublicURL, Addr: "127.0.0.1:0", Store: store,
		Mounts: []*Mount{{Name: "dummy", Binary: bin}},
		Stderr: io.Discard, Stdout: io.Discard,
	})
	if err != nil {
		t.Fatal(err)
	}

	// Operator side: launch the tool with the values mount-env would print.
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	addr := fmt.Sprintf("127.0.0.1:%d", port)
	tool := exec.Command(bin, "mcp", "--http", addr, "--oauth", hostPublicURL)
	tool.Env = append(os.Environ(),
		"AGENT_MCP_OAUTH_RESOURCE="+MountResource(hostPublicURL, "dummy"),
		"AGENT_MCP_OAUTH_VERIFY_KEY="+base64.RawURLEncoding.EncodeToString(h.oauth.PublicKey()))
	if err := tool.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = tool.Process.Kill(); _, _ = tool.Process.Wait() })
	h.mounts[0].cfg.Attach = addr

	h.start = func(context.Context, *runningMount, string) error {
		t.Error("an attach mount must never be spawned")
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	handler, cleanup, err := h.handler(ctx)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	t.Cleanup(cleanup)
	if err := h.waitReady(ctx); err != nil {
		t.Fatalf("attached tool never became ready: %v", err)
	}
	front := httptest.NewServer(handler)
	t.Cleanup(front.Close)

	code, err := oauth.NewPairing(store).AddPrincipal("carol", map[string]string{"dummy:workspace": "attached"})
	if err != nil {
		t.Fatal(err)
	}
	tok := runOAuthFlow(t, front, code, hostPublicURL+"/dummy/mcp")
	call := mcpCall(t, front, "/dummy/mcp", tok, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}`)
	if got := mustJSON(t, call); !strings.Contains(got, "workspace=attached") {
		t.Errorf("attached whoami = %s, want workspace=attached", got)
	}
}

// registerIntegrationClient runs DCR and returns the client_id.
func registerIntegrationClient(t *testing.T, client *http.Client, front *httptest.Server) string {
	t.Helper()
	resp, err := client.Post(front.URL+oauth.RegisterPath, "application/json",
		strings.NewReader(`{"redirect_uris":["https://client.example/cb"],"client_name":"integration"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		ClientID string `json:"client_id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out.ClientID
}

// integrationAuthForm is the base authorize POST for a client + code + resource.
func integrationAuthForm(clientID, pairingCode, resource string) url.Values {
	sum := sha256.Sum256([]byte("a-sufficiently-long-pkce-code-verifier-0123456789"))
	return url.Values{
		"client_id": {clientID}, "redirect_uri": {"https://client.example/cb"}, "response_type": {"code"},
		"code_challenge": {base64.RawURLEncoding.EncodeToString(sum[:])}, "code_challenge_method": {"S256"},
		"state": {"s"}, "scope": {"mcp"}, "resource": {resource}, "pairing_code": {pairingCode},
	}
}

// The flagship story, fully real: alice enters her code ONCE at dummy and
// enrolls through the real subprocess; connecting dummy2 rides the session
// cookie (no code) and prompts only for dummy2's own enrollment. Both tools
// then answer with their own projected bindings, and the host's stdout event
// stream records the whole journey without ever leaking a secret.
func TestIntegrationSessionGrowScope(t *testing.T) {
	if testing.Short() {
		t.Skip("integration test builds and boots a real tool binary")
	}
	bin := buildDummyTool(t)
	store := oauth.NewMemStore()
	var events safeBuffer
	h, err := New(Config{
		PublicURL: hostPublicURL, Addr: "127.0.0.1:0", Store: store,
		Mounts: []*Mount{{Name: "dummy", Binary: bin}, {Name: "dummy2", Binary: bin}},
		Stderr: io.Discard, Stdout: &events,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	handler, cleanup, err := h.handler(ctx)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	t.Cleanup(cleanup)
	if err := h.waitReady(ctx); err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(handler)
	t.Cleanup(front.Close)

	aliceCode, err := oauth.NewPairing(store).AddPrincipal("alice", nil)
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	clientID := registerIntegrationClient(t, client, front)

	// Tool 1: code + real enrollment — the honest two-round dance a browser
	// does (initial approval POST renders the form, then the enrollment POST).
	form := integrationAuthForm(clientID, aliceCode, hostPublicURL+"/dummy/mcp")
	first, err := client.PostForm(front.URL+oauth.AuthorizePath, form)
	if err != nil {
		t.Fatal(err)
	}
	firstPage, _ := readBody(first)
	if first.StatusCode != http.StatusOK || !strings.Contains(firstPage, "Connect Dummy") {
		t.Fatalf("tool-1 approval = %d, want the enrollment form", first.StatusCode)
	}
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set("field_token_api_key", "sk-1")
	resp, err := client.PostForm(front.URL+oauth.AuthorizePath, form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("tool-1 enroll = %d, want 302", resp.StatusCode)
	}
	var session string
	for _, c := range resp.Cookies() {
		if strings.HasPrefix(c.Name, "__Host-") {
			session = c.Name + "=" + c.Value
		}
	}
	if session == "" {
		t.Fatal("no session cookie after the code-entered flow")
	}

	// Tool 2: session only — no code. The REAL dummy2 enrollment form appears.
	form2 := integrationAuthForm(clientID, "", hostPublicURL+"/dummy2/mcp")
	req, _ := http.NewRequest(http.MethodPost, front.URL+oauth.AuthorizePath, strings.NewReader(form2.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", session)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := readBody(resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(page, "Connect Dummy") {
		t.Fatalf("tool-2 via session = %d, want the enrollment form; body: %.200s", resp.StatusCode, page)
	}

	form2.Set("enroll", "1")
	form2.Set("enroll_mode", "token")
	form2.Set("field_token_api_key", "sk-2")
	req, _ = http.NewRequest(http.MethodPost, front.URL+oauth.AuthorizePath, strings.NewReader(form2.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Cookie", session)
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("tool-2 enroll via session = %d, want 302", resp.StatusCode)
	}

	// Both tools' namespaced slices coexist on the record.
	principals, _ := oauth.NewPairing(store).Principals()
	if principals["alice"]["dummy:workspace"] != "ws-alice" || principals["alice"]["dummy2:workspace"] != "ws-alice" {
		t.Fatalf("record = %v, want both tools' namespaced bindings", principals["alice"])
	}

	// Tool 2's token works at its mount with its own projected binding.
	loc, _ := url.Parse(resp.Header.Get("Location"))
	tok, err := client.PostForm(front.URL+oauth.TokenPath, url.Values{
		"grant_type": {"authorization_code"}, "code": {loc.Query().Get("code")},
		"redirect_uri": {"https://client.example/cb"}, "client_id": {clientID},
		"code_verifier": {"a-sufficiently-long-pkce-code-verifier-0123456789"},
	})
	if err != nil {
		t.Fatal(err)
	}
	var tokOut struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(tok.Body).Decode(&tokOut); err != nil {
		t.Fatal(err)
	}
	tok.Body.Close()
	call := mcpCall(t, front, "/dummy2/mcp", tokOut.AccessToken, `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"whoami","arguments":{}}}`)
	if got := mustJSON(t, call); !strings.Contains(got, "workspace=ws-alice") {
		t.Errorf("dummy2 whoami = %s", got)
	}

	// The event stream told the whole story — and never a secret.
	stream := events.String()
	for _, want := range []string{
		`"event":"paired","tool":"dummy","principal":"alice"`, // via code
		`"via":"code"`,
		`"event":"enrolled","tool":"dummy","principal":"alice"`,
		`"event":"paired","tool":"dummy2","principal":"alice"`, // via session
		`"via":"session"`,
		`"event":"enrolled","tool":"dummy2","principal":"alice"`,
	} {
		if !strings.Contains(stream, want) {
			t.Errorf("event stream missing %s;\n%s", want, stream)
		}
	}
	for _, secret := range []string{"sk-1", "sk-2", aliceCode} {
		if strings.Contains(stream, secret) {
			t.Errorf("event stream leaked a secret %q", secret)
		}
	}
}
