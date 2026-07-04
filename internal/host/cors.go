package host

import (
	"bufio"
	"fmt"
	"io"
	"net/http"
)

// withCORS lets a browser-based MCP connector reach the host: it answers the
// CORS preflight itself (un-authenticated, so it isn't 401'd) and reflects the
// Origin on every response, exposing WWW-Authenticate so the browser can read
// the OAuth challenge that bootstraps discovery. Access to a resource is gated
// by the bearer token, not the origin. The host is the single source of CORS —
// proxied tool responses have their own CORS headers stripped first.
func withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if origin := r.Header.Get("Origin"); origin != "" {
			h := w.Header()
			h.Set("Access-Control-Allow-Origin", origin)
			h.Set("Vary", "Origin")
			h.Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			h.Set("Access-Control-Allow-Headers", "Authorization, Content-Type, Mcp-Protocol-Version")
			h.Set("Access-Control-Expose-Headers", "WWW-Authenticate, Mcp-Session-Id")
			h.Set("Access-Control-Max-Age", "600")
		}
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// prefixWriter tags each line written to w with "[name] " so several tools'
// stderr streams stay legible when interleaved under the host.
func prefixWriter(w io.Writer, name string) io.Writer {
	pr, pw := io.Pipe()
	go func() {
		sc := bufio.NewScanner(pr)
		sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for sc.Scan() {
			_, _ = fmt.Fprintf(w, "[%s] %s\n", name, sc.Text())
		}
	}()
	return pw
}
