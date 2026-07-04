package host

import (
	"encoding/json"
	"fmt"
	"time"

	oauth "github.com/shhac/lib-agent-oauth"
)

// The host's stdout is an NDJSON event stream (the family's list contract):
// one line per operator-relevant moment — a client registering, a person
// pairing, enrolling, or being authorized for a tool, a mount coming up.
// Human-facing boot info (including the pairing code, which is a secret)
// goes to stderr; events never carry secrets.

// hostEvent is one NDJSON line on stdout.
type hostEvent struct {
	Event     string `json:"event"`
	Tool      string `json:"tool,omitempty"`      // mount name, when the event targets one
	Principal string `json:"principal,omitempty"` // named principal; omitted for the anonymous operator
	Client    string `json:"client,omitempty"`    // MCP client display name
	Via       string `json:"via,omitempty"`       // how identity was proven: code | session
	URL       string `json:"url,omitempty"`       // connector URL, on mount events
	Time      string `json:"time"`
}

// emit writes one event line. Serialized: events arrive from concurrent
// request handlers.
func (h *Host) emit(ev hostEvent) {
	ev.Time = time.Now().UTC().Format(time.RFC3339)
	line, err := json.Marshal(ev)
	if err != nil {
		return // an event is telemetry, never worth failing a flow over
	}
	h.emitMu.Lock()
	defer h.emitMu.Unlock()
	_, _ = fmt.Fprintln(h.stdout, string(line))
}

// oauthEvent adapts the AS's lifecycle events onto the stream, translating
// the audience URL into the mount name people know the tool by.
func (h *Host) oauthEvent(e oauth.Event) {
	ev := hostEvent{
		Event:     e.Type,
		Principal: e.Principal,
		Client:    e.Client,
		Via:       e.Via,
	}
	if m := h.mountByResource[e.Resource]; m != nil {
		ev.Tool = m.cfg.Name
	}
	h.emit(ev)
}
