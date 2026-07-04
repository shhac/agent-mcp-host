package cli

import (
	"bytes"
	"strings"
	"testing"
)

// The root builds, carries the family globals, and exposes the serve command.
func TestRootScaffold(t *testing.T) {
	root := newRootCmd("1.2.3")

	if root.Use != "agent-mcp-host" {
		t.Errorf("Use = %q", root.Use)
	}
	if root.Version != "1.2.3" {
		t.Errorf("Version = %q", root.Version)
	}
	if root.PersistentFlags().Lookup("format") == nil {
		t.Error("root missing the shared --format global flag")
	}
	if _, _, err := root.Find([]string{"serve"}); err != nil {
		t.Errorf("serve command not registered: %v", err)
	}
}

// The serve stub returns a structured, human-fixable error (not a bare string),
// honoring the family error contract even while unimplemented.
func TestServeStubIsStructured(t *testing.T) {
	root := newRootCmd("t")
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"serve"})

	// libcli renders the error; we assert the command surfaces one rather than
	// succeeding as a no-op.
	if err := root.Execute(); err == nil {
		t.Fatal("serve stub should return an error until implemented")
	} else if !strings.Contains(err.Error(), "not implemented") {
		t.Errorf("unexpected serve error: %v", err)
	}
}
