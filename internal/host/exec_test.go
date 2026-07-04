package host

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	oauth "github.com/shhac/lib-agent-oauth"
)

// The real exec seams: discoverExec and enrollExec run this test binary
// re-exec'd as a fake tool, so the actual subprocess + JSON round-trip code
// runs — including the stderr-precedence mapping that turns a tool's
// credential rejection into the message the browser form re-renders with.
// The exec'd argv is fixed (`<binary> mcp schema` / `mcp enroll`), so the
// fake is selected in TestMain via env rather than -test.run.

func TestMain(m *testing.M) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") == "1" {
		helperProcess()
		return
	}
	os.Exit(m.Run())
}

// helperProcess is the fake tool body, selected by GO_HELPER_BEHAVIOR.
func helperProcess() {
	switch os.Getenv("GO_HELPER_BEHAVIOR") {
	case "schema":
		fmt.Println(`{"name":"fake","version":"9.9.9","credential_descriptor":` +
			`{"title":"Connect Fake","modes":[{"key":"token","fields":[{"key":"token","label":"Token","secret":true}]}]}}`)
	case "schema-garbage":
		fmt.Println("this is not json")
	case "enroll-ok":
		// Reflect the mode back as proof the request arrived on stdin.
		var req oauth.EnrollRequest
		if err := json.NewDecoder(os.Stdin).Decode(&req); err != nil {
			fmt.Fprintln(os.Stderr, "bad stdin:", err)
			os.Exit(1)
		}
		fmt.Printf(`{"binding":{"workspace":"acme","mode_seen":%q}}`+"\n", req.Mode)
	case "enroll-reject":
		fmt.Fprintln(os.Stderr, "invalid token: workspace not reachable")
		os.Exit(1)
	case "enroll-reject-structured":
		// The family CLIs' structured-error contract on stderr.
		fmt.Fprintln(os.Stderr, `{"error":"auth.test failed: invalid_auth","fixable_by":"human","hint":"re-copy the token"}`)
		os.Exit(1)
	case "enroll-die-silent":
		os.Exit(3)
	}
}

// helperMount points a mount at this test binary, re-exec'd with behavior.
func helperMount(t *testing.T, behavior string) *Mount {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("GO_WANT_HELPER_PROCESS", "1")
	t.Setenv("GO_HELPER_BEHAVIOR", behavior)
	return &Mount{Name: "fake", Binary: exe}
}

func TestDiscoverExecParsesManifest(t *testing.T) {
	m := helperMount(t, "schema")
	manifest, err := discoverExec(t.Context(), m)
	if err != nil {
		t.Fatal(err)
	}
	if manifest.Name != "fake" || manifest.Version != "9.9.9" {
		t.Errorf("manifest = %+v", manifest)
	}
	if manifest.CredentialDescriptor == nil || manifest.CredentialDescriptor.Modes[0].Key != "token" {
		t.Errorf("descriptor not parsed: %+v", manifest.CredentialDescriptor)
	}
}

func TestDiscoverExecGarbageOutput(t *testing.T) {
	m := helperMount(t, "schema-garbage")
	if _, err := discoverExec(t.Context(), m); err == nil || !strings.Contains(err.Error(), "parsing") {
		t.Errorf("want parse error, got %v", err)
	}
}

func TestEnrollExecRoundTrip(t *testing.T) {
	m := helperMount(t, "enroll-ok")
	res, err := enrollExec(t.Context(), m, oauth.EnrollRequest{Principal: "alice", Mode: "token"})
	if err != nil {
		t.Fatal(err)
	}
	if res.Binding["workspace"] != "acme" || res.Binding["mode_seen"] != "token" {
		t.Errorf("result = %+v (mode_seen proves the request crossed stdin)", res.Binding)
	}
}

// A tool's credential rejection (non-zero exit + stderr) must surface as an
// error whose message IS the trimmed stderr — that text is what the human
// sees on the re-rendered enrollment form.
func TestEnrollExecStderrBecomesFormError(t *testing.T) {
	m := helperMount(t, "enroll-reject")
	_, err := enrollExec(t.Context(), m, oauth.EnrollRequest{Principal: "alice"})
	if err == nil || err.Error() != "invalid token: workspace not reachable" {
		t.Errorf("error = %v, want the tool's exact stderr message", err)
	}
}

// A family CLI's structured JSON error on stderr is unwrapped to its "error"
// field — the human sees "auth.test failed: invalid_auth" on the form, not a
// raw JSON blob.
func TestEnrollExecStructuredStderrUnwrapped(t *testing.T) {
	m := helperMount(t, "enroll-reject-structured")
	_, err := enrollExec(t.Context(), m, oauth.EnrollRequest{Principal: "alice"})
	if err == nil || err.Error() != "auth.test failed: invalid_auth" {
		t.Errorf("error = %v, want the unwrapped structured message", err)
	}
}

func TestEnrollExecSilentDeathWrapsExitError(t *testing.T) {
	m := helperMount(t, "enroll-die-silent")
	_, err := enrollExec(t.Context(), m, oauth.EnrollRequest{Principal: "alice"})
	if err == nil || !strings.Contains(err.Error(), "mcp enroll") {
		t.Errorf("error = %v, want the `mcp enroll: …` wrap when stderr is empty", err)
	}
}

// The boot guard: a discovered descriptor that fails validation must abort
// handler() with the mount named, not bring the host up half-configured.
func TestHandlerRejectsInvalidDescriptor(t *testing.T) {
	h, err := New(Config{
		PublicURL: hostPublicURL, Addr: "127.0.0.1:0", Store: oauth.NewMemStore(),
		Mounts: []*Mount{{Name: "slack", Binary: "unused-in-test"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	h.discover = func(_ context.Context, m *Mount) (*toolManifest, error) {
		return &toolManifest{Name: m.Name, CredentialDescriptor: &oauth.CredentialDescriptor{
			Modes: []oauth.CredentialMode{{Key: "broken"}}, // mode with no fields
		}}, nil
	}
	h.start = func(context.Context, *Mount, string) error {
		t.Error("start must not run after a descriptor failure")
		return nil
	}
	if _, _, err = h.handler(t.Context()); err == nil ||
		!strings.Contains(err.Error(), `mount "slack"`) || !strings.Contains(err.Error(), "invalid credential descriptor") {
		t.Errorf("handler error = %v, want mount name + invalid descriptor", err)
	}
}
