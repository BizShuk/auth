package cmd

import (
	"fmt"

	utils "github.com/bizshuk/auth/utils"
	"github.com/spf13/cobra"
)

// newUseCmd creates the "use" command to switch between multiple credentials.
func newUseCmd(root *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "use <credential-name>",
		Short: "Select the active credential for a provider",
		Long: `When you have multiple credentials for the same provider, this command allows
you to select which one the proxy server should use. The choice is saved to active.json
under the credential directory.`,
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
			cred, err := store.Load(name)
			if err != nil {
				return fmt.Errorf("credential %q not found. Run 'agentsdk list' to see available credentials", name)
			}

			// 2. Record the selection in active.json (temp+rename, 0600)
			if err := utils.SaveActiveName(store.Dir(), cred.Provider, name); err != nil {
				return fmt.Errorf("save active credential selection: %w", err)
			}

			fmt.Printf("✅ Active credential for provider %q set to %q\n", cred.Provider, name)
			return nil
		},
	}
}
