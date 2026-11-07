package cli

import (
	"github.com/spf13/cobra"

	"gethisengine/internal/chromium"
	"gethisengine/internal/firefox"
	"gethisengine/internal/model"
)

func newHistoryCommand(a *app) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "history",
		Short: "Extract browsing history",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profiles, err := a.loadProfiles()
			if err != nil {
				return err
			}
			defer a.flushWarnings()

			since, err := parseSince(a.opts.Since)
			if err != nil {
				return err
			}

			entries := make([]model.HistoryEntry, 0)
			for _, profile := range profiles {
				var (
					got      []model.HistoryEntry
					warnings []string
				)
				switch profile.Family {
				case model.FamilyChromium:
					got, warnings = chromium.History(profile, since, a.opts.Limit)
				case model.FamilyFirefox:
					got, warnings = firefox.History(profile, since, a.opts.Limit)
				}
				entries = append(entries, got...)
				a.warnAll(warnings)
			}
			sortHistory(entries)
			if a.opts.Limit > 0 && len(entries) > a.opts.Limit {
				entries = entries[:a.opts.Limit]
			}

			if len(entries) == 0 {
				a.warnf("no history entries found")
			}
			return a.output(historyTable(entries), entries, outputName("history", a.opts.Format))
		},
	}
	cmd.Flags().StringVar(&a.opts.Since, "since", "", "only entries newer than this date (2006-01-02 or RFC3339)")
	cmd.Flags().IntVarP(&a.opts.Limit, "limit", "n", 0, "maximum number of entries (0 = unlimited)")
	return cmd
}
