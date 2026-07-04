package host

import (
	"slices"
	"testing"
)

func TestMountResources(t *testing.T) {
	const pub = "https://hub.example"

	t.Run("valid mounts yield ordered resources and reverse map", func(t *testing.T) {
		resources, running, byResource, err := mountResources(pub, []*Mount{
			{Name: "slack", Binary: "agent-slack"},
			{Name: "lin", Binary: "lin"},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		want := []string{pub + "/slack/mcp", pub + "/lin/mcp"}
		if !slices.Equal(resources, want) {
			t.Errorf("resources = %v, want %v", resources, want)
		}
		if running[0].cfg.Name != "slack" || running[1].cfg.Name != "lin" {
			t.Errorf("running mounts = %v", running)
		}
		if running[0].resource != want[0] || running[1].resource != want[1] {
			t.Errorf("running mount resources = %q, %q; want %q, %q", running[0].resource, running[1].resource, want[0], want[1])
		}
		if byResource[pub+"/slack/mcp"].cfg.Name != "slack" || byResource[pub+"/lin/mcp"].cfg.Name != "lin" {
			t.Errorf("byResource = %v", byResource)
		}
	})

	errorCases := map[string][]*Mount{
		"missing name":   {{Name: "", Binary: "agent-slack"}},
		"missing binary": {{Name: "slack", Binary: ""}},
		"duplicate name": {{Name: "slack", Binary: "agent-slack"}, {Name: "slack", Binary: "other"}},
	}
	for name, mounts := range errorCases {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := mountResources(pub, mounts); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}
