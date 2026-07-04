package host

import "strings"

// The host namespaces a principal's binding by mount so one shared record can
// hold every tool's credentials without collision: keys are stored as
// "<mount>:<key>" and projected down to a tool's own vocabulary when its token
// is minted. stripNamespace and namespaceBinding are the two directions of that
// mapping and are kept together so they can't drift out of inverse.

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
