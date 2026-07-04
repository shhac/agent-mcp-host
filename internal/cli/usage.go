package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

// newUsageCmd is the family-standard `usage` verb: an LLM-optimized reference
// card covering how to run and operate the host.
func newUsageCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "usage",
		Short: "LLM-optimized usage overview",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := fmt.Fprintln(cmd.OutOrStdout(), usageText)
			return err
		},
	}
}
