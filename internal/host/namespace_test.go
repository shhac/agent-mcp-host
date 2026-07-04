package host

import (
	"maps"
	"testing"
)

// stripNamespace projects a principal's namespaced binding down to one mount's
// vocabulary — the security-relevant step that keeps a /slack/mcp token from
// carrying another tool's secrets.
func TestStripNamespace(t *testing.T) {
	cases := map[string]struct {
		binding map[string]string
		mount   string
		want    map[string]string
	}{
		"namespaced key stripped": {
			binding: map[string]string{"slack:workspace": "acme"},
			mount:   "slack",
			want:    map[string]string{"workspace": "acme"},
		},
		"un-namespaced key shared to every mount": {
			binding: map[string]string{"tz": "UTC"},
			mount:   "slack",
			want:    map[string]string{"tz": "UTC"},
		},
		"another tool's key dropped, empty result -> nil": {
			binding: map[string]string{"lin:workspace": "letsdothis"},
			mount:   "slack",
			want:    nil,
		},
		"mix: strip own, keep shared, drop other": {
			binding: map[string]string{"slack:workspace": "acme", "tz": "UTC", "lin:workspace": "x"},
			mount:   "slack",
			want:    map[string]string{"workspace": "acme", "tz": "UTC"},
		},
		"empty binding -> nil": {
			binding: map[string]string{},
			mount:   "slack",
			want:    nil,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got := stripNamespace(tc.binding, tc.mount)
			if !maps.Equal(got, tc.want) {
				t.Errorf("stripNamespace(%v, %q) = %v, want %v", tc.binding, tc.mount, got, tc.want)
			}
		})
	}
}

// namespaceBinding is stripNamespace's inverse: a tool's own-vocabulary binding
// is prefixed with the mount name before it lands on the shared record.
func TestNamespaceBinding(t *testing.T) {
	got := namespaceBinding(map[string]string{"workspace": "acme", "team": "t1"}, "slack")
	if got["slack:workspace"] != "acme" || got["slack:team"] != "t1" || len(got) != 2 {
		t.Errorf("namespaceBinding = %v", got)
	}
	if namespaceBinding(nil, "slack") != nil {
		t.Error("empty binding should stay nil")
	}
}

// stripNamespace and namespaceBinding round-trip: prefixing then projecting for
// the same mount returns the original binding.
func TestNamespaceRoundTrip(t *testing.T) {
	original := map[string]string{"workspace": "acme", "team": "t1"}
	if got := stripNamespace(namespaceBinding(original, "slack"), "slack"); !maps.Equal(got, original) {
		t.Errorf("round-trip = %v, want %v", got, original)
	}
}
