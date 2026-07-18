package xai

import (
	"context"
	"fmt"
	"sync"

	auth "github.com/bizshuk/auth/model"
	model "github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
)

// OAuth2 device flow 常數。端點本身不寫死 — 由 OIDC discovery 取得。
const (
	ISSUER        = "https://auth.x.ai"
	DISCOVERY_URL = ISSUER + "/.well-known/openid-configuration"
	CLIENT_ID     = "b1a00492-073a-47ea-816f-4c329264a828"
)

// SCOPES 需要 offline_access 才會拿到 refresh token。
var SCOPES = []string{"openid", "profile", "email", "offline_access", "grok-cli:access", "api:access"}

// OAuth 是 xAI 的 device-code 登入流程。
type OAuth struct {
	opts model.Options

	// discovery 的結果快取起來: Login 與 Refresh 都需要 token endpoint,
	// 但 discovery 文件在一次程序生命週期內不會變。
	once      sync.Once
	endpoints *svc.OIDCEndpoints
	discErr   error
}

// NewOAuth 建立 device-flow authenticator。
func NewOAuth(opts ...model.Option) *OAuth {
	return &OAuth{opts: model.NewOptions(opts...)}
}

func (a *OAuth) Provider() string { return PROVIDER }
func (a *OAuth) Kind() model.Kind { return model.KIND_OAUTH }

// Login 跑 device-code 流程: 要 code → 顯示給使用者 → 輪詢直到授權完成。
func (a *OAuth) Login(ctx context.Context) (*model.Credential, error) {
	client, endpoints, err := a.oauthClient(ctx)
	if err != nil {
		return nil, err
	}

	token, err := svc.RunDeviceLogin(ctx, client, endpoints.DeviceAuthorizationEndpoint, a.opts)
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
	client, _, err := a.oauthClient(ctx)
	if err != nil {
		return nil, err
	}
	token, err := client.Refresh(ctx, cred.RefreshToken)
	if err != nil {
		return nil, err
	}
	return a.credentialFrom(token, cred), nil
}

// Verify 以 refresh 往返驗證憑證仍然有效。
func (a *OAuth) Verify(ctx context.Context, cred *model.Credential) (*model.VerifyResult, error) {
	return svc.VerifyByRefresh(ctx, a, cred)
}

// oauthClient 解出端點 (OIDC discovery,只做一次) 並建出 OAuthClient。
//
// WithTokenURL / WithAuthURL 兩個覆寫都給了的話就完全跳過 discovery —
// 測試與 gateway 都靠這條路。
func (a *OAuth) oauthClient(ctx context.Context) (*svc.OAuthClient, *svc.OIDCEndpoints, error) {
	endpoints, err := a.discover(ctx)
	if err != nil {
		return nil, nil, err
	}

	cfg := svc.OAuthConfig{
		TokenURL: endpoints.TokenEndpoint,
		ClientID: CLIENT_ID,
		Scopes:   SCOPES,
		UsePKCE:  false, // device flow 不需要 PKCE: 沒有 redirect,也就沒有 code 攔截面
		Encoding: svc.ENCODING_FORM,
	}
	return svc.NewOAuthClient(cfg, a.opts.HTTPClient, a.opts.Now), endpoints, nil
}

func (a *OAuth) discover(ctx context.Context) (*svc.OIDCEndpoints, error) {
	if a.opts.TokenURL != "" && a.opts.AuthURL != "" {
		return &svc.OIDCEndpoints{
			TokenEndpoint:               a.opts.TokenURL,
			DeviceAuthorizationEndpoint: a.opts.AuthURL,
		}, nil
	}

	a.once.Do(func() {
		a.endpoints, a.discErr = svc.DiscoverOIDC(ctx, a.opts.HTTPClient, DISCOVERY_URL)
	})
	if a.discErr != nil {
		return nil, fmt.Errorf("xai: OIDC discovery: %w", a.discErr)
	}
	return a.endpoints, nil
}

// credentialFrom 把 token 回應併回憑證,並從 id_token 取出 email。
func (a *OAuth) credentialFrom(token *svc.TokenResponse, previous *model.Credential) *model.Credential {
	cred := svc.MergeOAuthToken(PROVIDER, token, previous, SCOPES, a.opts.Now())

	claims, err := svc.DecodeJWTClaims(cred.IDToken)
	if err != nil {
		return cred
	}
	if email := svc.ClaimString(claims, "email"); email != "" {
		cred.Account = email
	}
	if sub := svc.ClaimString(claims, "sub"); sub != "" {
		cred.AccountID = sub
	}
	return cred
}
