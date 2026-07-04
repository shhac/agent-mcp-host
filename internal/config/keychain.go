// Package config holds agent-mcp-host's non-secret configuration and the
// reverse-DNS Keychain service names, following the agent-* family convention.
package config

// keychainService is the macOS Keychain service name for agent-mcp-host's own
// secrets, following the family reverse-DNS convention (cf. "app.paulie.lin",
// "app.paulie.agent-slack").
const keychainService = "app.paulie.agent-mcp-host"

// KeychainService returns the host's own credential/config Keychain service.
// The host holds little of its own here; the namespace is reserved for
// symmetry with the family.
func KeychainService() string { return keychainService }

// MCPKeychainService is the Keychain service for the host's OAuth secrets: the
// Ed25519 signing key it mints tokens with, the family-wide pairing/principal
// store, and client registrations. It is the host's service plus a ".mcp"
// namespace — keeping the OAuth trust axis separate from any API credentials,
// within the family reverse-DNS convention (so "app.paulie.agent-mcp-host.mcp").
//
// This is the namespace a delegate-mode tool is pointed at to obtain the host's
// public verify key (see design-docs/architecture.md).
func MCPKeychainService() string { return keychainService + ".mcp" }
