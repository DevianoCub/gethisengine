package cli

import (
	"github.com/spf13/cobra"

	"gethisengine/internal/chromium"
	"gethisengine/internal/firefox"
	"gethisengine/internal/model"
)

func newPasswordsCommand(a *app) *cobra.Command {
	return &cobra.Command{
		Use:   "passwords",
		Short: "Extract saved logins (hidden unless --reveal)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profiles, err := a.loadProfiles()
			if err != nil {
				return err
			}
			defer a.flushWarnings()

			creds := make([]model.Credential, 0)
			for _, profile := range profiles {
				switch profile.Family {
				case model.FamilyChromium:
					dec, _ := a.chromiumDecryptor(profile)
					got, warnings := chromium.Passwords(profile, dec)
					creds = append(creds, got...)
					a.warnAll(warnings)
				case model.FamilyFirefox:
					key, _ := a.firefoxKey(profile)
					got, warnings := firefox.Passwords(profile, key)
					creds = append(creds, got...)
					a.warnAll(warnings)
				}
			}
			sortCredentials(creds)

			if !a.opts.Reveal && len(creds) > 0 {
				a.warnf("saved passwords are hidden; pass --reveal to decrypt them")
			}
			if len(creds) == 0 {
				a.warnf("no saved logins found")
			}

			return a.output(
				passwordsTable(creds, a.opts.Reveal),
				prepareCredentials(creds, a.opts.Reveal),
				outputName("passwords", a.opts.Format),
			)
		},
	}
}
