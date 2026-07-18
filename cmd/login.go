package cmd

import (
	"fmt"
	"os"
	"strings"

	sdkauth "github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/provider"
	"github.com/bizshuk/auth/provider/anthropic"
	"github.com/bizshuk/auth/provider/antigravity"
	"github.com/bizshuk/auth/provider/openai"
	"github.com/spf13/cobra"
)

// newLoginCmd 是唯一的登入入口: --provider 就決定了整條認證路徑。
//
//	--provider anthropic                  api key   (ANTHROPIC_API_KEY)
//	--provider anthropic_oauth            oauth2 + pkce,本機收 callback
//	--provider openai                     api key   (OPENAI_API_KEY)
//	--provider openai_oauth               oauth2 + pkce
//	--provider google                     api key   (GOOGLE_API_KEY / GEMINI_API_KEY)
//	--provider xai                        api key   (XAI_API_KEY)
//	--provider xai_oauth                  device code (RFC 8628),不開埠
//	--provider antigravity_oauth          google oauth (client secret,無 PKCE)
//	--provider vertex --sa-file sa.json   service account → Google STS
func newLoginCmd(root *rootFlags) *cobra.Command {
	var (
		id       string
		key      string
		apiBase  string
		saFile   string
		location string
	)

	cmd := &cobra.Command{
		Use:   "login --provider <name>",
		Short: "Log in to a provider (" + strings.Join(provider.IDs(), " | ") + ")",
		Long: strings.TrimSpace(`
Acquire a credential from a provider and save it as a 0600 JSON file.

The credential is verified against the real provider before it is saved, so a
stored credential is one that was proven to work.

  PROVIDER            AUTH METHOD      CREDENTIAL SOURCE
  anthropic           api key          --key or ANTHROPIC_API_KEY
  anthropic_oauth     oauth2 + pkce    browser (claude.ai)
  openai              api key          --key or OPENAI_API_KEY
  openai_oauth        oauth2 + pkce    browser (auth.openai.com)
  google              api key          --key or GOOGLE_API_KEY / GEMINI_API_KEY
  xai                 api key          --key or XAI_API_KEY
  xai_oauth           device code      user code + polling (no local port)
  antigravity_oauth   oauth2           browser (accounts.google.com)
  vertex              service account  --sa-file (RS256 JWT -> Google STS)`),
		Example: `  agentsdk login --provider anthropic
  agentsdk login --provider anthropic_oauth
  agentsdk login --provider xai_oauth
  agentsdk login --provider google --key AIza...
  agentsdk login --provider vertex --sa-file sa.json --location us-central1`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts, err := loginOptions(root, id, saFile, key, apiBase, location)
			if err != nil {
				return err
			}

			// 先解析出 authenticator (順帶驗證 provider id 合法),再宣告接下來
			// 要做的事 — 否則打錯的 provider 會先印出「正在開瀏覽器」才報錯。
			authenticator, err := provider.New(id, opts...)
			if err != nil {
				return err
			}

			announce(root, id, authenticator)
			cred, err := authenticator.Login(cmd.Context())
			if err != nil {
				return err
			}
			return saveAndReport(root, cred)
		},
	}

	cmd.Flags().StringVar(&id, "provider", "",
		"provider to log in to: "+strings.Join(provider.IDs(), " | ")+" (required)")
	cmd.Flags().StringVar(&key, "key", "", "api key providers: the key itself (defaults to the provider's env var)")
	cmd.Flags().StringVar(&apiBase, "api-base", "", "api key providers: override the API root (a gateway or proxy)")
	cmd.Flags().StringVar(&saFile, "sa-file", "", "vertex: path to the Google service account JSON")
	cmd.Flags().StringVar(&location, "location", "us-central1", "vertex: default region")
	_ = cmd.MarkFlagRequired("provider")
	return cmd
}

// loginOptions 把 CLI 旗標翻譯成 auth 套件的 options。--sa-file 在這裡讀進記憶體,
// 讓 auth 套件不必碰檔案系統。
func loginOptions(root *rootFlags, id, saFile, key, apiBase, location string) ([]sdkauth.Option, error) {
	opts := []sdkauth.Option{
		sdkauth.WithAPIKey(key),
		sdkauth.WithAPIBase(apiBase),
		sdkauth.WithLocation(location),
	}

	if saFile != "" {
		raw, err := os.ReadFile(saFile)
		if err != nil {
			return nil, fmt.Errorf("read service account file: %w", err)
		}
		opts = append(opts, sdkauth.WithServiceAccountJSON(raw))
	} else if id == provider.VERTEX {
		return nil, fmt.Errorf("--provider %s requires --sa-file <service account JSON>", provider.VERTEX)
	}

	return root.authOptions(opts...), nil
}

// announce 在動作發生前告訴使用者接下來會做什麼 — OAuth 會開瀏覽器並佔一個
// 本機埠 (device flow 則會顯示一組 user code),那是使用者該預期到的事。
func announce(root *rootFlags, id string, authenticator sdkauth.Authenticator) {
	switch authenticator.Kind() {
	case sdkauth.KIND_OAUTH:
		if redirect := redirectURI(id); redirect != "" {
			if root.noBrowser {
				return // promptForCode 會自己印出 URL 與指示
			}
			fmt.Printf("opening a browser to authorize with %s...\n", authenticator.Provider())
			fmt.Printf("waiting for the callback on %s\n", redirect)
			return
		}
		// device flow: 沒有 redirect,user code 由 PrintDeviceCode 印出。
		fmt.Printf("requesting a device code from %s...\n", authenticator.Provider())
	case sdkauth.KIND_API_KEY:
		fmt.Printf("verifying the %s API key against its models endpoint...\n", authenticator.Provider())
	case sdkauth.KIND_SERVICE_ACCOUNT:
		fmt.Println("signing a JWT assertion and exchanging it at Google STS...")
	}
}

// redirectURI 回傳走 browser 流程的 provider 會監聽的 callback 位址。
// device flow (xai_oauth) 不開埠,回空字串。
func redirectURI(id string) string {
	switch id {
	case provider.ANTHROPIC_OAUTH:
		return anthropic.REDIRECT_URI
	case provider.OPENAI_OAUTH:
		return openai.REDIRECT_URI
	case provider.ANTIGRAVITY:
		return antigravity.REDIRECT_URI
	default:
		return ""
	}
}
