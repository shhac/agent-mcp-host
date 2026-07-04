package host

import (
	"slices"
	"testing"
)

func TestMountResources(t *testing.T) {
	const pub = "https://hub.example"

	t.Run("valid mounts yield ordered resources and reverse map", func(t *testing.T) {
		resources, byResource, err := mountResources(pub, []*Mount{
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
		if byResource[pub+"/slack/mcp"].Name != "slack" || byResource[pub+"/lin/mcp"].Name != "lin" {
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
			if _, _, err := mountResources(pub, mounts); err == nil {
				t.Errorf("expected error for %s", name)
			}
		})
	}
}
