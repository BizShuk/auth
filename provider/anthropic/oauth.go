package anthropic

import (
	"context"
	"encoding/json"
	"net/url"

	auth "github.com/bizshuk/auth/model"
	model "github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
)

// OAuth2 常數。ClientID 是 Claude Code CLI 的公開 client id — public client,
// 沒有 client secret,安全性由 PKCE 提供。
const (
	AUTH_URL     = "https://claude.ai/oauth/authorize"
	TOKEN_URL    = "https://api.anthropic.com/v1/oauth/token"
	CLIENT_ID    = "9d1c250a-e61b-44d9-88ed-5944d1962f5e"
	REDIRECT_URI = "http://localhost:54545/callback"
)

// SCOPES 是 Claude Code 使用的 scope 集合。
var SCOPES = []string{"user:profile", "user:inference"}

// OAuth 是 Anthropic 的 OAuth2 + PKCE 登入流程。
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
		// Anthropic 是唯一要求 token exchange 帶 state 的 provider。
		SendState: true,
		// code=true 讓 Anthropic 在授權完成後把 code 顯示出來,支援手動貼回模式。
		AuthParams: url.Values{"code": {"true"}},
		// Anthropic 的 token 端點收 JSON body,不是 form-urlencoded。
		Encoding: svc.ENCODING_JSON,
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

// Refresh 換發 access token。
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

// Verify 以 refresh 往返驗證憑證仍然有效 (見 svc.VerifyByRefresh 的說明)。
func (a *OAuth) Verify(ctx context.Context, cred *model.Credential) (*model.VerifyResult, error) {
	return svc.VerifyByRefresh(ctx, a, cred)
}

// credentialFrom 把 token 回應併回憑證,並補上 Anthropic 的帳號資訊 —
// 它把帳號放在 token 回應的 account / organization 物件裡。
func (a *OAuth) credentialFrom(token *svc.TokenResponse, previous *model.Credential) *model.Credential {
	cred := svc.MergeOAuthToken(PROVIDER, token, previous, SCOPES, a.opts.Now())

	var payload struct {
		Account struct {
			UUID         string `json:"uuid"`
			EmailAddress string `json:"email_address"`
		} `json:"account"`
		Organization struct {
			Name string `json:"name"`
		} `json:"organization"`
	}
	if err := json.Unmarshal(token.Raw, &payload); err != nil {
		return cred
	}
	if payload.Account.EmailAddress != "" {
		cred.Account = payload.Account.EmailAddress
	}
	if payload.Account.UUID != "" {
		cred.AccountID = payload.Account.UUID
	}
	if payload.Organization.Name != "" {
		cred.SetMetadata("organization", payload.Organization.Name)
	}
	return cred
}
