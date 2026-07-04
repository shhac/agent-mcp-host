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

// serve requires at least one --mount, and surfaces a structured error (not a
// bare string) when none is given, honoring the family error contract.
func TestServeRequiresMount(t *testing.T) {
	root := newRootCmd("t")
	var out, errBuf bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errBuf)
	root.SetArgs([]string{"serve"})

	if err := root.Execute(); err == nil {
		t.Fatal("serve without --mount should error")
	} else if !strings.Contains(err.Error(), "--mount") {
		t.Errorf("unexpected serve error: %v", err)
	}
}
