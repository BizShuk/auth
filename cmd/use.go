package cmd

import (
	"fmt"

	"github.com/bizshuk/auth/active"
	"github.com/spf13/cobra"
)

// newUseCmd creates the "use" command to switch between multiple credentials.
func newUseCmd(root *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "use <credential-name>",
		Short: "Select the active credential for a provider",
		Long: `When you have multiple credentials for the same provider, this command allows
you to select which one the proxy server should use. The choice is saved to this
application's settings.local.json, so several applications can share one credential
directory and still each pick their own credential.`,
		Example: `  agentsdk use anthropic-dev@example.com_oauth
  agentsdk use openai-apikey`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			store, err := root.store()
			if err != nil {
				return err
			}

			// 1. Verify credential exists
			cred, err := store.Read(name)
			if err != nil {
				return fmt.Errorf("credential %q not found. Run 'agentsdk list' to see available credentials", name)
			}

			// 2. Record the selection in this application's settings file.
			path, err := active.Set(cred.Provider, name)
			if err != nil {
				return err
			}

			fmt.Printf("✅ Active credential for provider %q set to %q\n", cred.Provider, name)
			fmt.Printf("   saved to: %s\n", path)
			return nil
		},
	}
}
