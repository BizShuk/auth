package cmd

import (
	"fmt"
	"os"
	"text/tabwriter"
	"time"

	sdkauth "github.com/bizshuk/auth/model"
	"github.com/spf13/cobra"
)

// newListCmd 列出所有已存的憑證。金鑰與 token 一律不印出,只印末四碼與到期時間。
func newListCmd(root *rootFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List stored credentials",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			store, creds, err := root.credentials()
			if err != nil {
				return err
			}
			if len(creds) == 0 {
				fmt.Printf("no credentials in %s\n", store.Dir())
				fmt.Println("run `auth-cli login --help` to add one")
				return nil
			}

			w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
			fmt.Fprintln(w, "NAME\tPROVIDER\tKIND\tACCOUNT\tSTATUS")
			for _, cred := range creds {
				fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n",
					cred.Name(), cred.Provider, cred.Kind, orDash(cred.Account), status(cred))
			}
			if err := w.Flush(); err != nil {
				return err
			}

			fmt.Printf("\n%d credential(s) in %s\n", len(creds), store.Dir())
			return nil
		},
	}
}

// status 描述憑證的到期狀態。API key 沒有到期概念。
func status(cred *sdkauth.Credential) string {
	if cred.ExpiresAt.IsZero() {
		return "no expiry"
	}
	if cred.Expired(sdkauth.DEFAULT_EXPIRY_SKEW) {
		return "expired (run `auth-cli refresh`)"
	}
	return "valid for " + time.Until(cred.ExpiresAt).Round(time.Minute).String()
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
