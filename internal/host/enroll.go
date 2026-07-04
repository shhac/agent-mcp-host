package host

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	oauth "github.com/shhac/lib-agent-oauth"
)

// The enrollment seam between the host and its tools (lib-agent-mcp
// design-docs/host.md): the tool declares WHAT to ask for in its `mcp schema`
// manifest (the credential descriptor), and the hidden `mcp enroll` subcommand
// runs the tool's own enrollment callback on a JSON EnrollRequest from stdin.
// The host renders the form, bridges the submission, and namespaces the
// returned binding under the mount's name before it lands on the shared
// principal record. Secrets cross to the tool once, on stdin, never argv.

// toolManifest is the slice of `mcp schema` output the host consumes.
type toolManifest struct {
	Name                 string                      `json:"name"`
	Version              string                      `json:"version"`
	CredentialDescriptor *oauth.CredentialDescriptor `json:"credential_descriptor"`
}

// discoverExec runs `<binary> mcp schema` and parses the manifest.
func discoverExec(ctx context.Context, m *Mount) (*toolManifest, error) {
	out, err := exec.CommandContext(ctx, m.Binary, "mcp", "schema").Output()
	if err != nil {
		return nil, fmt.Errorf("running %s mcp schema: %w", m.Binary, err)
	}
	var manifest toolManifest
	if err := json.Unmarshal(out, &manifest); err != nil {
		return nil, fmt.Errorf("parsing %s mcp schema output: %w", m.Binary, err)
	}
	return &manifest, nil
}

// enrollExec pipes req to `<binary> mcp enroll` on stdin and parses the
// EnrollResult from stdout. The tool's stderr (its structured error, if the
// callback rejected the credentials) becomes the error message the form
// re-renders with.
func enrollExec(ctx context.Context, m *Mount, req oauth.EnrollRequest) (oauth.EnrollResult, error) {
	payload, err := json.Marshal(req)
	if err != nil {
		return oauth.EnrollResult{}, err
	}
	cmd := exec.CommandContext(ctx, m.Binary, "mcp", "enroll")
	cmd.Stdin = bytes.NewReader(payload)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return oauth.EnrollResult{}, fmt.Errorf("%s", msg)
		}
		return oauth.EnrollResult{}, fmt.Errorf("%s mcp enroll: %w", m.Binary, err)
	}
	var res oauth.EnrollResult
	if err := json.Unmarshal(stdout.Bytes(), &res); err != nil {
		return oauth.EnrollResult{}, fmt.Errorf("parsing %s mcp enroll output: %w", m.Binary, err)
	}
	return res, nil
}

// buildEnrollment constructs a mount's per-resource enrollment from its
// discovered descriptor: the descriptor renders as-is, and the callback
// bridges to the tool, namespacing the returned binding into the mount's
// slice of the shared principal record. A mount without a descriptor gets
// nil — its principals are pre-bound by the operator (`pair add --bind`).
func (h *Host) buildEnrollment(m *Mount) (*oauth.Enrollment, error) {
	if m.descriptor == nil {
		return nil, nil
	}
	e := &oauth.Enrollment{
		Descriptor: *m.descriptor,
		Enroll: func(ctx context.Context, req oauth.EnrollRequest) (oauth.EnrollResult, error) {
			res, err := h.enrollBridge(ctx, m, req)
			if err != nil {
				return oauth.EnrollResult{}, err
			}
			res.Binding = namespaceBinding(res.Binding, m.Name)
			return res, nil
		},
	}
	if err := e.Validate(); err != nil {
		return nil, fmt.Errorf("mount %q: invalid credential descriptor: %w", m.Name, err)
	}
	return e, nil
}

// namespaceBinding is stripNamespace's inverse: the tool answers in its own
// vocabulary (workspace=acme) and the host prefixes every key with the mount
// name (slack:workspace=acme) before it lands on the shared record.
func namespaceBinding(binding map[string]string, mount string) map[string]string {
	if len(binding) == 0 {
		return nil
	}
	out := make(map[string]string, len(binding))
	for k, v := range binding {
		out[mount+":"+k] = v
	}
	return out
}
