package cli

import (
	"github.com/spf13/cobra"
)

func newScanCommand(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "scan",
		Short: "List browser profiles found on this device",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profiles, err := a.loadProfiles()
			if err != nil {
				return err
			}
			defer a.flushWarnings()

			if len(profiles) == 0 {
				a.warnf("no browser profiles found")
			}
			return a.output(profilesTable(profiles), profiles, outputName("profiles", a.opts.Format))
		},
	}
}
