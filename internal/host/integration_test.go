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
		t.Helper()
		req, _ := http.NewRequest(http.MethodPost, front.URL+"/dummy/mcp", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tokOut.AccessToken)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Accept", "application/json, text/event-stream")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			b, _ := io.ReadAll(resp.Body)
			t.Fatalf("mcp POST = %d: %.300s", resp.StatusCode, b)
		}
		raw, _ := io.ReadAll(resp.Body)
		// Streamable HTTP may frame the response as an SSE event; take the
		// data line if so.
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
