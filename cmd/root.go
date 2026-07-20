// Package cmd exposes the credential command set (login / list / verify /
// refresh / logout / use) as reusable cobra commands. Install mounts the
// whole set plus its shared flags onto any cobra root — the aggregated
// auth-cli binary or a standalone one — so the auth module carries its own
// CLI surface.
package cmd

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	sdkauth "github.com/bizshuk/auth/model"
	utils "github.com/bizshuk/auth/utils"
	"github.com/spf13/cobra"
)

// rootFlags 是所有子指令共用的旗標。
type rootFlags struct {
	appName   string
	authDir   string
	noBrowser bool
}

// Install 在 root 上註冊共用旗標並掛載全部憑證子指令。appName 決定預設
// 憑證目錄 ~/.config/<appName>/data/auth（gosdk 目錄慣例，stdlib 實作，
// 不引入 gosdk 依賴）。
func Install(root *cobra.Command, appName string) error {
	if root == nil {
		return fmt.Errorf("auth cmd: root command is required")
	}
	if strings.TrimSpace(appName) == "" {
		return fmt.Errorf("auth cmd: appName must not be empty")
	}
	flags := &rootFlags{appName: appName}

	root.PersistentFlags().StringVar(&flags.authDir, "auth-dir", "",
		"credential directory (default ~/.config/"+appName+"/data/auth)")
	root.PersistentFlags().BoolVar(&flags.noBrowser, "no-browser", false,
		"headless OAuth: print the URL and read the pasted code from stdin")

	root.AddCommand(
		newLoginCmd(flags),
		newListCmd(flags),
		newVerifyCmd(flags),
		newRefreshCmd(flags),
		newLogoutCmd(flags),
		newUseCmd(flags),
	)
	return nil
}

// store 解析出憑證目錄:--auth-dir 優先,否則 ~/.config/<appName>/data/auth。
func (f *rootFlags) store() (*utils.FileStore, error) {
	if f.authDir != "" {
		return utils.NewFileStore(f.authDir)
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return nil, fmt.Errorf("resolve home directory: %w", err)
	}
	return utils.NewFileStore(filepath.Join(home, ".config", f.appName, "data", "auth"))
}

// authOptions 依旗標組出 auth 套件的 options。--no-browser 時切到手動貼碼模式。
func (f *rootFlags) authOptions(extra ...sdkauth.Option) []sdkauth.Option {
	opts := extra
	if f.noBrowser {
		opts = append(opts, sdkauth.WithManualCode(promptForCode))
	} else {
		opts = append(opts, sdkauth.WithBrowserOpener(utils.OpenBrowser))
	}
	return opts
}

// promptForCode 印出授權 URL 並從 stdin 讀回 authorization code。
func promptForCode(authURL string) (string, error) {
	fmt.Println("Open this URL in a browser and authorize:")
	fmt.Println()
	fmt.Println("  " + authURL)
	fmt.Println()
	fmt.Print("Paste the authorization code here: ")

	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(line), nil
}

// saveAndReport 存下憑證並印出結果 — 每個 login 子指令的收尾都一樣。
func saveAndReport(f *rootFlags, cred *sdkauth.Credential) error {
	store, err := f.store()
	if err != nil {
		return err
	}
	if err := store.Save(cred); err != nil {
		return err
	}

	fmt.Printf("✅ logged in: %s (%s / %s)\n", cred.Name(), cred.Provider, cred.Kind)
	if cred.Account != "" {
		fmt.Printf("   account:   %s\n", cred.Account)
	}
	if !cred.ExpiresAt.IsZero() {
		fmt.Printf("   expires:   %s\n", cred.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
	}
	fmt.Printf("   saved to:  %s\n", store.Path(cred.Name()))
	return nil
}
