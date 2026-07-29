package cmd

import (
	"fmt"

	"github.com/bizshuk/auth/provider"
	"github.com/spf13/cobra"
)

// newRefreshCmd 換發 access token 並存回磁碟。API key 憑證會回
// ErrRefreshUnsupported — 金鑰不會過期,也沒有東西好換。
func newRefreshCmd(root *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "refresh <name>",
		Short:   "Refresh a stored OAuth / service-account credential",
		Example: `  auth-cli refresh openai-dev@example.com`,
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := root.store()
			if err != nil {
				return err
			}
			cred, err := store.Read(args[0])
			if err != nil {
				return err
			}

			authenticator, err := provider.For(cred)
			if err != nil {
				return err
			}
			refreshed, err := authenticator.Refresh(cmd.Context(), cred)
			if err != nil {
				return err
			}
			if err := store.Write(refreshed.Name(), refreshed); err != nil {
				return err
			}

			fmt.Printf("✅ refreshed: %s\n", refreshed.Name())
			if !refreshed.ExpiresAt.IsZero() {
				fmt.Printf("   expires:   %s\n", refreshed.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
			}
			return nil
		},
	}
}

// newLogoutCmd 刪除一份憑證。
func newLogoutCmd(root *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "logout <name>",
		Short:   "Delete a stored credential",
		Example: `  auth-cli logout anthropic-dev@example.com`,
		Args:    cobra.ExactArgs(1),
		RunE: func(_ *cobra.Command, args []string) error {
			store, err := root.store()
			if err != nil {
				return err
			}
			if err := store.Delete(args[0]); err != nil {
				return err
			}
			fmt.Printf("🗑  deleted: %s\n", args[0])
			return nil
		},
	}
}
