package host

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"

	oauth "github.com/shhac/lib-agent-oauth"
)

// The full host-driven enrollment loop: alice (bound for lin, not slack)
// connects the slack mount, gets slack's discovered form instead of an
// approval, submits her token, the host bridges it to the tool and namespaces
// the returned binding — after which her slack calls carry the projected
// binding and her lin binding is untouched.
func TestHostEnrollmentEndToEnd(t *testing.T) {
	store := oauth.NewMemStore()
	var bridged oauth.EnrollRequest
	var events safeBuffer // stdout: the NDJSON event stream
	_, front := buildTestHostWith(t, store, func(h *Host) {
		h.stdout = &events
		h.discover = func(_ context.Context, m *Mount) (*toolManifest, error) {
			manifest := &toolManifest{Name: m.Name, Version: "test"}
			if m.Name == "slack" {
				manifest.CredentialDescriptor = &oauth.CredentialDescriptor{
					Title: "Connect Slack",
					Modes: []oauth.CredentialMode{{
						Key: "token", Label: "API token",
						Fields: []oauth.CredentialField{{Key: "token", Label: "API token", Secret: true}},
					}},
				}
			}
			return manifest, nil
		}
		h.enrollBridge = func(_ context.Context, m *Mount, req oauth.EnrollRequest) (oauth.EnrollResult, error) {
			bridged = req
			// The tool answers in ITS OWN vocabulary; the host namespaces.
			return oauth.EnrollResult{Binding: map[string]string{"workspace": "acme"}}, nil
		}
	}, "slack", "lin")

	aliceCode, err := oauth.NewPairing(store).AddPrincipal("alice",
		map[string]string{"lin:workspace": "letsdothis"})
	if err != nil {
		t.Fatal(err)
	}

	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	const redirect = "https://client.example/cb"
	const verifier = "a-sufficiently-long-pkce-code-verifier-0123456789"
	sum := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(sum[:])

	reg, err := client.Post(front.URL+oauth.RegisterPath, "application/json",
		strings.NewReader(`{"redirect_uris":["`+redirect+`"],"client_name":"test"}`))
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
		"scope": {"mcp"}, "resource": {hostPublicURL + "/slack/mcp"}, "pairing_code": {aliceCode},
	}

	// Unbound for slack → the enrollment form, rendered from slack's
	// discovered descriptor, not an approval redirect.
	az, err := client.PostForm(front.URL+oauth.AuthorizePath, form)
	if err != nil {
		t.Fatal(err)
	}
	page, _ := readBody(az)
	if az.StatusCode != http.StatusOK || !strings.Contains(page, "Connect Slack") {
		t.Fatalf("authorize = %d, want slack's enrollment form; body: %.200s", az.StatusCode, page)
	}

	// Submit the enrollment.
	form.Set("enroll", "1")
	form.Set("enroll_mode", "token")
	form.Set("field_token_token", "xoxc-sekrit")
	az, err = client.PostForm(front.URL+oauth.AuthorizePath, form)
	if err != nil {
		t.Fatal(err)
	}
	az.Body.Close()
	if az.StatusCode != http.StatusFound {
		t.Fatalf("enroll submit = %d, want 302", az.StatusCode)
	}
	if bridged.Principal != "alice" || bridged.Values["token"] != "xoxc-sekrit" {
		t.Errorf("bridge received %+v", bridged)
	}
	// The host enables AS sessions: completing the code-entered flow sets the
	// login-once cookie, so connecting the next tool skips the code.
	sessionSet := false
	for _, c := range az.Cookies() {
		if strings.HasPrefix(c.Name, "__Host-") && c.HttpOnly && c.Secure {
			sessionSet = true
		}
	}
	if !sessionSet {
		t.Error("no __Host- session cookie after the code-entered enrollment flow")
	}

	// The record merged: slack's namespaced slice landed, lin's survived.
	principals, err := oauth.NewPairing(store).Principals()
	if err != nil {
		t.Fatal(err)
	}
	if principals["alice"]["slack:workspace"] != "acme" || principals["alice"]["lin:workspace"] != "letsdothis" {
		t.Errorf("persisted binding = %v, want slack AND lin keys", principals["alice"])
	}

	// The issued token works at the slack mount with the projected binding.
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
	body := callMount(t, front, "/slack/mcp", tokOut.AccessToken)
	if b, _ := body["binding"].(map[string]any); body["principal"] != "alice" || b["workspace"] != "acme" || b["slack:workspace"] != nil {
		t.Errorf("slack call after enrollment = %v, want projected workspace=acme", body)
	}

	// Stdout is a pure NDJSON event stream: every line parses, the lifecycle
	// moments appear with the mount name (not the audience URL), and no
	// secret ever rides in it.
	stream := events.String()
	seen := map[string]bool{}
	for _, line := range strings.Split(strings.TrimSpace(stream), "\n") {
		var ev map[string]any
		if err := json.Unmarshal([]byte(line), &ev); err != nil {
			t.Fatalf("stdout line is not JSON: %q (%v)", line, err)
		}
		kind, _ := ev["event"].(string)
		seen[kind] = true
		if kind == "enrolled" && (ev["tool"] != "slack" || ev["principal"] != "alice") {
			t.Errorf("enrolled event = %v, want tool=slack principal=alice", ev)
		}
		if kind == "paired" && ev["via"] != "code" {
			t.Errorf("paired event = %v, want via=code", ev)
		}
	}
	for _, want := range []string{"client_registered", "paired", "session_started", "enrolled", "authorized"} {
		if !seen[want] {
			t.Errorf("event stream missing %q; stream:\n%s", want, stream)
		}
	}
	if strings.Contains(stream, "xoxc-sekrit") || strings.Contains(stream, aliceCode) {
		t.Errorf("event stream leaked a secret:\n%s", stream)
	}
}

// safeBuffer is a mutex-guarded bytes.Buffer: events are written from request
// handlers while the test goroutine later reads.
type safeBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *safeBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *safeBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

// A mount without a descriptor has no enrollment: an unbound principal is not
// diverted (the operator pre-binds instead).
func TestHostNoDescriptorNoEnrollment(t *testing.T) {
	store := oauth.NewMemStore()
	_, front := buildTestHost(t, store, "lin")
	code, err := oauth.NewPairing(store).AddPrincipal("bob", nil)
	if err != nil {
		t.Fatal(err)
	}
	// bob is unbound, lin has no descriptor → straight approval, no form.
	tok := runOAuthFlow(t, front, code, hostPublicURL+"/lin/mcp")
	if tok == "" {
		t.Fatal("expected a token without enrollment divert")
	}
}

func readBody(resp *http.Response) (string, error) {
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	return string(b), err
}
