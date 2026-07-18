package cmd

import (
	"context"
	"fmt"

	sdkauth "github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/provider"
	utils "github.com/bizshuk/auth/utils"
	"github.com/spf13/cobra"
)

// newVerifyCmd 對 provider 發出真實請求,證明存下來的憑證還能用。
//
// 每家的驗證方式不同,VerifyResult.Method 會誠實回報實際做了什麼:
//
//	models_endpoint    api_key       打 provider 的 models 端點 (無副作用)
//	userinfo_endpoint  antigravity   打 Google userinfo (無副作用)
//	token_refresh      其餘 oauth    用 refresh token 換發 (provider 可能輪替 token)
//	sts_exchange       vertex        簽 JWT 向 Google STS 換 access token
//
// 會輪替 token 的那幾條,驗證完會把新憑證存回磁碟。
func newVerifyCmd(root *rootFlags) *cobra.Command {
	var all bool

	cmd := &cobra.Command{
		Use:   "verify [name]",
		Short: "Verify a stored credential against the live provider",
		Example: `  auth-cli verify anthropic-dev@example.com
  auth-cli verify --all`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			store, err := root.store()
			if err != nil {
				return err
			}

			var targets []*sdkauth.Credential
			switch {
			case all:
				targets, err = store.List()
				if err != nil {
					return err
				}
				if len(targets) == 0 {
					return fmt.Errorf("no credentials in %s", store.Dir())
				}
			case len(args) == 1:
				cred, err := store.Load(args[0])
				if err != nil {
					return err
				}
				targets = []*sdkauth.Credential{cred}
			default:
				return fmt.Errorf("pass a credential name or --all (see `auth-cli list`)")
			}

			failed := 0
			for _, cred := range targets {
				if err := verifyOne(cmd.Context(), store, cred); err != nil {
					failed++
					fmt.Printf("❌ %s\n   %v\n", cred.Name(), err)
					continue
				}
			}
			if failed > 0 {
				return fmt.Errorf("%d of %d credential(s) failed verification", failed, len(targets))
			}
			return nil
		},
	}

	cmd.Flags().BoolVar(&all, "all", false, "verify every stored credential")
	return cmd
}

// verifyOne 驗證一份憑證,並在 provider 輪替 token 時把新憑證寫回磁碟。
func verifyOne(ctx context.Context, store *utils.FileStore, cred *sdkauth.Credential) error {
	authenticator, err := provider.For(cred)
	if err != nil {
		return err
	}

	res, err := authenticator.Verify(ctx, cred)
	if err != nil {
		return err
	}

	fmt.Printf("✅ %s (%s / %s)\n", cred.Name(), cred.Provider, cred.Kind)
	fmt.Printf("   method: %s\n", res.Method)
	fmt.Printf("   detail: %s\n", res.Detail)

	// OAuth / service account 的驗證會換到新 token — 不存回去的話,下一次
	// 用的還是舊的 (OpenAI 甚至會讓舊的 refresh token 立刻失效)。
	if res.Credential != nil {
		if err := store.Save(res.Credential); err != nil {
			return fmt.Errorf("verified, but failed to persist the rotated credential: %w", err)
		}
		fmt.Printf("   rotated: credential updated on disk\n")
	}
	return nil
}
