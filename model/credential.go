// Package auth implements the mechanisms behind LLM provider authentication:
// credentials, OAuth2 (authorization-code + PKCE, device-code), API keys,
// and 0600 credential files.
//
// 這一層只有機制,不認識任何一家 provider。每一家 provider 住在
// auth/provider/<name>,由 auth/provider (registry) 統一掛起來:
//
//	cred, err := provider.Login(ctx, "anthropic_oauth")
//
// 三個角色:
//
//	Credential    — 一份可持久化的憑證 (one persisted credential)
//	Authenticator — 取得/更新/驗證憑證的流程 (login / refresh / verify)
//	FileStore     — 憑證的磁碟持久層 (0600 JSON files)
//
// 套件只依賴 stdlib,可與 SDK 其他部分分開發佈。
package model

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Kind 是憑證的取得方式 (how the credential was obtained).
type Kind string

const (
	KIND_API_KEY         Kind = "api_key"
	KIND_OAUTH           Kind = "oauth"
	KIND_SERVICE_ACCOUNT Kind = "service_account"
)

// DEFAULT_EXPIRY_SKEW 是判定過期時預留的緩衝,避免 token 在飛行途中到期。
const DEFAULT_EXPIRY_SKEW = 60 * time.Second

// OAUTH_SUFFIX 是 OAuth 憑證檔名 (與 provider id) 的後綴,見 Credential.Name。
const OAUTH_SUFFIX = "_oauth"

var (
	ErrNotFound           = errors.New("auth: credential not found")
	ErrNoRefreshToken     = errors.New("auth: credential has no refresh token")
	ErrRefreshUnsupported = errors.New("auth: credential kind does not support refresh")
	ErrUnsupported        = errors.New("auth: unsupported provider")
	ErrNoAPIKey           = errors.New("auth: no API key supplied (use --key or set the provider env var)")
	ErrNoServiceAccount   = errors.New("auth: no service account JSON supplied")
	ErrInvalidCredential  = errors.New("auth: invalid credential")
)

// Credential 是一份 provider 憑證。同一個結構承載三種 Kind,未使用的欄位
// 以 omitempty 從 JSON 消失,讓磁碟上的檔案只留下該 Kind 真正需要的內容。
type Credential struct {
	Provider string `json:"provider"`
	Kind     Kind   `json:"kind"`

	// Account 是人類可讀的帳號識別 (email / client_email),同時是檔名的一部分。
	Account string `json:"account,omitempty"`

	// API key 路徑。BaseURL 非空代表這把金鑰是對某個 gateway / proxy 發的,
	// 後續 verify 必須打回同一個地方,而不是 provider 的官方端點。
	APIKey  string `json:"api_key,omitempty"`
	BaseURL string `json:"base_url,omitempty"`

	// OAuth 路徑。
	AccessToken  string   `json:"access_token,omitempty"`
	RefreshToken string   `json:"refresh_token,omitempty"`
	IDToken      string   `json:"id_token,omitempty"`
	AccountID    string   `json:"account_id,omitempty"`
	Scopes       []string `json:"scopes,omitempty"`

	// Service account 路徑 (Vertex AI)。ServiceAccount 是原始 JSON 內容。
	ServiceAccount map[string]any `json:"service_account,omitempty"`
	ProjectID      string         `json:"project_id,omitempty"`
	Location       string         `json:"location,omitempty"`

	ExpiresAt   time.Time `json:"expires_at,omitzero"`
	LastRefresh time.Time `json:"last_refresh,omitzero"`

	// Metadata 承載 provider 特有的附加資訊 (例如 chatgpt_plan_type)。
	Metadata map[string]any `json:"metadata,omitempty"`
}

// Name 是 FileStore 的鍵,也是磁碟檔名 (不含 .json):
//
//	anthropic-dev@example.com_oauth   oauth
//	anthropic_oauth                   oauth,沒有帳號資訊時
//	anthropic-apikey                  api_key
//	vertex-agent@proj.iam...          service_account
//
// OAuth 憑證帶 _oauth 後綴。同一個帳號可以同時擁有 API key 與 OAuth 憑證
// (同一個 email,兩種認證方式),沒有後綴的話兩者會互相覆蓋。
func (c *Credential) Name() string {
	segment := SanitizeSegment(c.Account)

	if c.Kind == KIND_OAUTH {
		if segment == "" {
			return c.Provider + OAUTH_SUFFIX
		}
		return c.Provider + "-" + segment + OAUTH_SUFFIX
	}

	if segment == "" {
		if c.Kind == KIND_API_KEY {
			segment = "apikey"
		} else {
			segment = SanitizeSegment(string(c.Kind))
		}
	}
	return c.Provider + "-" + segment
}

// Expired 回報 access token 是否已過期 (含 skew 緩衝)。沒有到期時間的憑證
// (例如 API key) 永遠不算過期。
func (c *Credential) Expired(skew time.Duration) bool {
	return c.ExpiredAt(time.Now(), skew)
}

// ExpiredAt 是 Expired 的可注入時鐘版本。
func (c *Credential) ExpiredAt(now time.Time, skew time.Duration) bool {
	if c.ExpiresAt.IsZero() {
		return false
	}
	return now.Add(skew).After(c.ExpiresAt)
}

// Validate 檢查該 Kind 的必要欄位是否齊備。
func (c *Credential) Validate() error {
	if c == nil {
		return fmt.Errorf("%w: nil credential", ErrInvalidCredential)
	}
	if strings.TrimSpace(c.Provider) == "" {
		return fmt.Errorf("%w: provider is empty", ErrInvalidCredential)
	}
	switch c.Kind {
	case KIND_API_KEY:
		if strings.TrimSpace(c.APIKey) == "" {
			return fmt.Errorf("%w: api_key credential has no key", ErrInvalidCredential)
		}
	case KIND_OAUTH:
		if strings.TrimSpace(c.AccessToken) == "" {
			return fmt.Errorf("%w: oauth credential has no access token", ErrInvalidCredential)
		}
	case KIND_SERVICE_ACCOUNT:
		if len(c.ServiceAccount) == 0 {
			return fmt.Errorf("%w: service_account credential has no service account JSON", ErrInvalidCredential)
		}
	default:
		return fmt.Errorf("%w: unknown kind %q", ErrInvalidCredential, c.Kind)
	}
	return nil
}

// VerifyResult 是一次線上驗證的結果。Credential 非 nil 時代表驗證過程中
// 憑證被輪替 (OAuth refresh 會換發 token),呼叫端必須把它存回 FileStore。
type VerifyResult struct {
	OK bool

	// Method 說明驗證是怎麼做的,讓 CLI 輸出誠實反映實際發生的網路呼叫:
	//   models_endpoint   — 打 provider 的 models API
	//   userinfo_endpoint — 打 OIDC userinfo
	//   token_refresh     — 用 refresh token 向 token endpoint 換發
	//   sts_exchange      — 用 SA 簽的 JWT 向 Google STS 換 access token
	Method string

	Detail string

	// Credential 非 nil 時,呼叫端應持久化它 (verify 順帶輪替了 token)。
	Credential *Credential
}

// Authenticator 是一個 provider × kind 的認證流程。
type Authenticator interface {
	// Provider 回傳 provider 名稱 (anthropic / openai / xai ...)。
	Provider() string

	// Kind 回傳此流程產生的憑證種類。
	Kind() Kind

	// Login 取得一份新憑證。OAuth 實作會開瀏覽器或顯示 device code。
	Login(ctx context.Context) (*Credential, error)

	// Refresh 換發 access token。API key 憑證回傳 ErrRefreshUnsupported。
	Refresh(ctx context.Context, cred *Credential) (*Credential, error)

	// Verify 對 provider 發出真實請求驗證憑證可用。
	Verify(ctx context.Context, cred *Credential) (*VerifyResult, error)
}

// SanitizeSegment 把任意字串轉成安全的檔名片段。
func SanitizeSegment(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	var b strings.Builder
	for _, r := range value {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
			b.WriteRune(r)
		case r == '@' || r == '.' || r == '_' || r == '-':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	return strings.Trim(b.String(), "-")
}

// SetMetadata 寫入一個 metadata 欄位 (map 為 nil 時建立)。
func (c *Credential) SetMetadata(key string, value any) {
	if c.Metadata == nil {
		c.Metadata = map[string]any{}
	}
	c.Metadata[key] = value
}
