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
)

// Mount is one family tool served behind a path.
type Mount struct {
	// Name is the URL path segment and the connector's tool label, e.g. "slack"
	// → https://host/slack/mcp.
	Name string
	// Binary is the CLI executable to run, e.g. "agent-slack" (resolved on PATH)
	// or an absolute path.
	Binary string

	port int      // loopback port the spawned tool listens on
	proc *exec.Cmd
}

// spawn allocates a loopback port and starts the tool's MCP server in delegate
// mode, injecting its audience and the host's verify key.
func (h *Host) spawn(ctx context.Context, m *Mount, verifyKey string) error {
	port, err := freePort()
	if err != nil {
		return err
	}
	m.port = port
	cmd := exec.CommandContext(ctx, m.Binary, "mcp",
		"--http", fmt.Sprintf("127.0.0.1:%d", port),
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
		url := fmt.Sprintf("http://127.0.0.1:%d/mcp", m.port)
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

// stripNamespace projects a principal's namespaced binding down to one mount's
// vocabulary: a "<mount>:<key>" entry becomes "<key>"; an un-namespaced entry
// (no ":") is shared to every mount; another mount's entry is dropped. So a
// token for /slack/mcp carries exactly what agent-slack understands.
func stripNamespace(binding map[string]string, mount string) map[string]string {
	prefix := mount + ":"
	out := map[string]string{}
	for k, v := range binding {
		switch {
		case strings.HasPrefix(k, prefix):
			out[strings.TrimPrefix(k, prefix)] = v
		case !strings.Contains(k, ":"):
			out[k] = v // un-namespaced: applies to every tool
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}
