package cli

import (
	"context"
	"errors"
	"strings"
	"testing"

	oauth "github.com/shhac/lib-agent-oauth"

	"github.com/shhac/agent-mcp-host/internal/host"
)

// fakeServeDeps wires runServe with no tunnel, a MemStore, and a serve func
// that records its config and returns immediately.
func fakeServeDeps(gotCfg *host.Config) serveDeps {
	return serveDeps{
		wire: func(_ context.Context, mode string, _ int, _, publicURL string) (string, func() error, error) {
			return publicURL, nil, nil // no-tailscale passthrough
		},
		openStore: func() (oauth.SecretStore, error) { return oauth.NewMemStore(), nil },
		serve: func(_ context.Context, cfg host.Config) error {
			*gotCfg = cfg
			return nil
		},
	}
}

func TestRunServeRequiresPublicURL(t *testing.T) {
	var cfg host.Config
	err := runServe(t.Context(), &strings.Builder{}, &strings.Builder{},
		serveOpts{addr: "127.0.0.1:8000", mounts: []string{"slack=agent-slack"}}, fakeServeDeps(&cfg))
	if err == nil || !strings.Contains(err.Error(), "--public-url") || !strings.Contains(err.Error(), "--tailscale") {
		t.Errorf("err = %v, want the public-url-or-tailscale guidance", err)
	}
	if cfg.PublicURL != "" {
		t.Error("serve must not run without a public URL")
	}
}

// The tailscale path: the derived URL feeds the host config, the teardown
// runs AFTER serve returns, and the operator messages land on stderr.
func TestRunServeTailscaleDerivesAndTearsDown(t *testing.T) {
	var cfg host.Config
	var order []string
	deps := fakeServeDeps(&cfg)
	deps.wire = func(_ context.Context, mode string, port int, httpAddr, publicURL string) (string, func() error, error) {
		if mode != "funnel" || port != 443 || publicURL != "" {
			t.Errorf("wire args = %q %d %q", mode, port, publicURL)
		}
		return "https://box.tail.ts.net", func() error {
			order = append(order, "teardown")
			return nil
		}, nil
	}
	baseServe := deps.serve
	deps.serve = func(ctx context.Context, c host.Config) error {
		order = append(order, "serve")
		return baseServe(ctx, c)
	}

	var stderr strings.Builder
	err := runServe(t.Context(), &strings.Builder{}, &stderr,
		serveOpts{addr: "127.0.0.1:8000", tailscaleMode: "funnel", tailscalePort: 443, mounts: []string{"slack=agent-slack"}},
		deps)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.PublicURL != "https://box.tail.ts.net" {
		t.Errorf("host config publicURL = %q, want the derived URL", cfg.PublicURL)
	}
	if len(order) != 2 || order[0] != "serve" || order[1] != "teardown" {
		t.Errorf("order = %v, want serve then teardown", order)
	}
	if out := stderr.String(); !strings.Contains(out, "tailscale funnel: https://box.tail.ts.net") ||
		!strings.Contains(out, "tailscale funnel: shut down") {
		t.Errorf("stderr = %q, want bring-up and shut-down messages", out)
	}
}

func TestRunServeTeardownErrorSurfaces(t *testing.T) {
	var cfg host.Config
	deps := fakeServeDeps(&cfg)
	deps.wire = func(context.Context, string, int, string, string) (string, func() error, error) {
		return "https://box.tail.ts.net", func() error { return errors.New("funnel stuck") }, nil
	}
	var stderr strings.Builder
	if err := runServe(t.Context(), &strings.Builder{}, &stderr,
		serveOpts{addr: "127.0.0.1:8000", tailscaleMode: "serve", mounts: []string{"slack=agent-slack"}}, deps); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stderr.String(), "teardown: funnel stuck") {
		t.Errorf("stderr = %q, want the teardown error", stderr.String())
	}
}

func TestRunServeWireErrorPropagates(t *testing.T) {
	var cfg host.Config
	deps := fakeServeDeps(&cfg)
	deps.wire = func(context.Context, string, int, string, string) (string, func() error, error) {
		return "", nil, errors.New("no tailscale CLI")
	}
	err := runServe(t.Context(), &strings.Builder{}, &strings.Builder{},
		serveOpts{tailscaleMode: "funnel", mounts: []string{"slack=agent-slack"}}, deps)
	if err == nil || !strings.Contains(err.Error(), "no tailscale CLI") {
		t.Errorf("err = %v, want the wire error", err)
	}
}
