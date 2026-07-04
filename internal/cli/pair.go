package cli

import (
	"fmt"
	"maps"
	"slices"
	"strings"

	oauth "github.com/shhac/lib-agent-oauth"
	agenterrors "github.com/shhac/lib-agent-output"
	"github.com/spf13/cobra"
)

// newPairCmd manages the host's family-wide named principals — the per-person
// pairing codes and their bindings. A person enters their code once (across all
// tools); their binding names the credential set each tool acts with. Bindings
// are namespaced per tool: --bind slack:workspace=acme --bind lin:workspace=xyz.
func newPairCmd() *cobra.Command {
	pair := &cobra.Command{
		Use:   "pair",
		Short: "Manage the host's family-wide pairing codes and named principals",
	}
	pair.AddCommand(pairAddCmd(), pairListCmd(), pairShowCmd(), pairRotateCmd(), pairRemoveCmd())
	return pair
}

// pairing opens the keyring store and wraps it in the pairing layer — the
// shared prologue of every pair subcommand.
func pairing() (*oauth.Pairing, error) {
	store, err := openStore()
	if err != nil {
		return nil, err
	}
	return oauth.NewPairing(store), nil
}

func pairAddCmd() *cobra.Command {
	var binds []string
	cmd := &cobra.Command{
		Use:   "add <name>",
		Short: "Mint a pairing code for a named principal (repeatable --bind <tool>:<key>=<value>)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			binding, err := parseBinds(binds)
			if err != nil {
				return err
			}
			p, err := pairing()
			if err != nil {
				return err
			}
			code, err := p.AddPrincipal(args[0], binding)
			if err != nil {
				return err
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(),
				"pairing code for %s: %s\n⚠ Share it only with %s — whoever completes the OAuth approval "+
					"with this code acts under this principal's binding, across every tool.\n", args[0], code, args[0])
			return err
		},
	}
	cmd.Flags().StringArrayVar(&binds, "bind", nil, "binding as <tool>:<key>=<value> (repeatable), carried in the principal's per-tool tokens")
	return cmd
}

func pairListCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List named principals and their bindings (codes are never shown)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			p, err := pairing()
			if err != nil {
				return err
			}
			principals, err := p.Principals()
			if err != nil {
				return err
			}
			if len(principals) == 0 {
				_, err = fmt.Fprintln(cmd.OutOrStdout(), "no named principals")
				return err
			}
			for _, name := range slices.Sorted(maps.Keys(principals)) {
				line := name
				for _, k := range slices.Sorted(maps.Keys(principals[name])) {
					line += fmt.Sprintf(" %s=%s", k, principals[name][k])
				}
				if _, err := fmt.Fprintln(cmd.OutOrStdout(), line); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

func pairShowCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "show <name>",
		Short: "Print a named principal's stored pairing code (a secret; never in `list`)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := pairing()
			if err != nil {
				return err
			}
			code, ok, err := p.PrincipalCode(args[0])
			if err != nil {
				return err
			}
			if !ok {
				return errNoPrincipal(args[0])
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "pairing code for %s: %s\n", args[0], code)
			return err
		},
	}
}

func pairRotateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "rotate <name>",
		Short: "Issue a fresh pairing code for one principal, preserving their binding",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := pairing()
			if err != nil {
				return err
			}
			code, ok, err := p.RotatePrincipal(args[0])
			if err != nil {
				return err
			}
			if !ok {
				return errNoPrincipal(args[0])
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "new pairing code for %s: %s\n", args[0], code)
			return err
		},
	}
}

func pairRemoveCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "remove <name>",
		Short: "Revoke a named principal (pairing code + refresh tokens)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			p, err := pairing()
			if err != nil {
				return err
			}
			removed, err := p.RemovePrincipal(args[0])
			if err != nil {
				return err
			}
			if !removed {
				return errNoPrincipal(args[0])
			}
			_, err = fmt.Fprintf(cmd.OutOrStdout(), "%s removed: pairing revoked, refresh tokens deleted.\n", args[0])
			return err
		},
	}
}

// errNoPrincipal is the not-found error for commands addressing a principal.
func errNoPrincipal(name string) error {
	return agenterrors.Newf(agenterrors.FixableByAgent, "no principal named %q — mint one with: pair add %s", name, name)
}

// parseBinds turns repeated <tool>:<key>=<value> flags into a binding map. The
// key is stored verbatim (namespace included); the host strips the tool prefix
// when it mints that tool's token.
func parseBinds(pairs []string) (map[string]string, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	m := make(map[string]string, len(pairs))
	for _, kv := range pairs {
		k, v, ok := strings.Cut(kv, "=")
		if !ok || k == "" {
			return nil, agenterrors.Newf(agenterrors.FixableByAgent, "--bind %q is not <key>=<value>", kv)
		}
		m[k] = v
	}
	return m, nil
}
