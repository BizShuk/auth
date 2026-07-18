package openai

import (
	"context"
	"net/url"

	auth "github.com/bizshuk/auth/model"
	model "github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
)

// OAuth2 常數 (Codex CLI 的 public client + PKCE)。
const (
	AUTH_URL     = "https://auth.openai.com/oauth/authorize"
	TOKEN_URL    = "https://auth.openai.com/oauth/token"
	CLIENT_ID    = "app_EMoamEEZ73f0CkXaXp7hrann"
	REDIRECT_URI = "http://localhost:1455/auth/callback"
)

// AUTH_CLAIM 是 id_token 裡放 ChatGPT 帳號資訊的 claim 名稱 (一個 URL)。
const AUTH_CLAIM = "https://api.openai.com/auth"

// SCOPES 需要 offline_access 才會拿到 refresh token。
var SCOPES = []string{"openid", "email", "profile", "offline_access"}

// OAuth 是 OpenAI 的 OAuth2 + PKCE 登入流程。
//
// 與 Anthropic 的差異只有三處: token body 編碼 (form 而非 JSON)、額外的 authorize
// 參數、以及帳號資訊來自 id_token 的 claims 而非 token 回應的頂層欄位。
type OAuth struct {
	opts   model.Options
	client *svc.OAuthClient
}

// NewOAuth 建立 OAuth authenticator。
func NewOAuth(opts ...model.Option) *OAuth {
	o := model.NewOptions(opts...)
	cfg := svc.OAuthConfig{
		AuthURL:     model.Pick(o.AuthURL, AUTH_URL),
		TokenURL:    model.Pick(o.TokenURL, TOKEN_URL),
		ClientID:    CLIENT_ID,
		RedirectURI: model.Pick(o.RedirectURI, REDIRECT_URI),
		Scopes:      SCOPES,
		UsePKCE:     true,
		AuthParams: url.Values{
			"prompt":                     {"login"},
			"id_token_add_organizations": {"true"},
			"codex_cli_simplified_flow":  {"true"},
		},
		Encoding: svc.ENCODING_FORM,
	}
	return &OAuth{opts: o, client: svc.NewOAuthClient(cfg, o.HTTPClient, o.Now)}
}

func (a *OAuth) Provider() string { return PROVIDER }
func (a *OAuth) Kind() model.Kind { return model.KIND_OAUTH }

// Login 跑完整的瀏覽器授權流程並回傳憑證。
func (a *OAuth) Login(ctx context.Context) (*model.Credential, error) {
	token, err := svc.RunBrowserLogin(ctx, a.client, a.opts)
	if err != nil {
		return nil, err
	}
	return a.credentialFrom(token, nil), nil
}

// Refresh 換發 access token。OpenAI 會輪替 refresh token,新憑證務必存回去。
func (a *OAuth) Refresh(ctx context.Context, cred *model.Credential) (*model.Credential, error) {
	if cred == nil || cred.RefreshToken == "" {
		return nil, auth.ErrNoRefreshToken
	}
	token, err := a.client.Refresh(ctx, cred.RefreshToken)
	if err != nil {
		return nil, err
	}
	return a.credentialFrom(token, cred), nil
}

// Verify 以 refresh 往返驗證憑證仍然有效。
func (a *OAuth) Verify(ctx context.Context, cred *model.Credential) (*model.VerifyResult, error) {
	return svc.VerifyByRefresh(ctx, a, cred)
}

// credentialFrom 把 token 回應併回憑證,並從 id_token 取出帳號資訊。
func (a *OAuth) credentialFrom(token *svc.TokenResponse, previous *model.Credential) *model.Credential {
	cred := svc.MergeOAuthToken(PROVIDER, token, previous, SCOPES, a.opts.Now())

	// id_token 解不出來不是致命錯誤 — access token 照樣可用,只是憑證檔會少
	// email,檔名退回 openai_oauth.json。
	claims, err := svc.DecodeJWTClaims(cred.IDToken)
	if err != nil {
		return cred
	}
	if email := svc.ClaimString(claims, "email"); email != "" {
		cred.Account = email
	}
	if accountID := svc.ClaimString(claims, AUTH_CLAIM, "chatgpt_account_id"); accountID != "" {
		cred.AccountID = accountID
	}
	if plan := svc.ClaimString(claims, AUTH_CLAIM, "chatgpt_plan_type"); plan != "" {
		cred.SetMetadata("chatgpt_plan_type", plan)
	}
	return cred
}
