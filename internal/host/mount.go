package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"time"

	oauth "github.com/shhac/lib-agent-oauth"
)

// Mount is one family tool served behind a path.
type Mount struct {
	// Name is the URL path segment and the connector's tool label, e.g. "slack"
	// → https://host/slack/mcp.
	Name string
	// Binary is the CLI executable to run, e.g. "agent-slack" (resolved on PATH)
	// or an absolute path. Attach mounts still need it: the host execs it for
	// `mcp schema` (the descriptor) and `mcp enroll` (the credential bridge).
	Binary string
	// Attach, when set (host:port), proxies to an ALREADY-RUNNING delegate
	// listener instead of spawning one — the operator launched the tool
	// themselves (debugger, launchd, …) with the env `mount-env` prints.
	Attach string

	addr string // target host:port the proxy forwards to
	proc *exec.Cmd

	// descriptor is the tool's credential-enrollment form, discovered from
	// `mcp schema` at boot; nil when the tool is not self-serve.
	descriptor *oauth.CredentialDescriptor
	// enrollment is the per-resource enrollment built over descriptor (nil
	// without one), handed to the AS via EnrollmentForResource.
	enrollment *oauth.Enrollment
}

// spawn allocates a loopback port and starts the tool's MCP server in delegate
// mode, injecting its audience and the host's verify key.
func (h *Host) spawn(ctx context.Context, m *Mount, verifyKey string) error {
	port, err := freePort()
	if err != nil {
		return err
	}
	m.addr = fmt.Sprintf("127.0.0.1:%d", port)
	cmd := exec.CommandContext(ctx, m.Binary, "mcp",
		"--http", m.addr,
		"--oauth", h.publicURL)
	cmd.Env = append(os.Environ(),
		"AGENT_MCP_OAUTH_RESOURCE="+h.resource(m),
		"AGENT_MCP_OAUTH_VERIFY_KEY="+verifyKey)
	cmd.Stdout = io.Discard // the tool's stdout is not the protocol channel in HTTP mode
	cmd.Stderr = prefixWriter(h.stderr, m.Name)
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting %s: %w", m.Binary, err)
	}
	m.proc = cmd
	return nil
}

// stop signals the tool to exit.
func (h *Host) stop(m *Mount) {
	if m.proc != nil && m.proc.Process != nil {
		_ = m.proc.Process.Kill()
	}
}

// waitReady polls each tool's /mcp until it answers (a 401 challenge means the
// delegate gate is up), so the first real request doesn't race the spawn.
func (h *Host) waitReady(ctx context.Context) error {
	deadline := time.Now().Add(10 * time.Second)
	for _, m := range h.mounts {
		url := fmt.Sprintf("http://%s/mcp", m.addr)
		if err := waitMountReady(ctx, url, deadline); err != nil {
			return fmt.Errorf("mount %q: %w", m.Name, err)
		}
	}
	return nil
}

// waitMountReady polls url until it answers (any HTTP response means the
// listener is up — a 401 challenge counts), giving up at deadline.
func waitMountReady(ctx context.Context, url string, deadline time.Time) error {
	for {
		req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, strings.NewReader("{}"))
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			_ = resp.Body.Close()
			return nil // any HTTP answer means the listener is up
		}
		if time.Now().After(deadline) {
			return errors.New("did not become ready within 10s")
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
}

// freePort asks the OS for an unused loopback TCP port.
func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}
