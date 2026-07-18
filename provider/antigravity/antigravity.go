// Package antigravity implements Antigravity authentication: a Google OAuth2
// installed-app flow against accounts.google.com.
//
// 它與其他 OAuth provider 有兩個結構性差異:
//
//  1. 帶 client_secret,不走 PKCE — Google 的 installed-app client 是這樣設計的,
//     secret 是公開的 (它就寫在每個安裝出去的 client 裡),真正的保護來自
//     redirect_uri 必須指回 localhost。
//  2. token 回應裡沒有帳號資訊,email 要另外打一次 userinfo 端點拿。
package antigravity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	auth "github.com/bizshuk/auth/model"
	model "github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
	"github.com/spf13/viper"
)

// PROVIDER 是憑證裡記的 provider 名稱。
const PROVIDER = "antigravity"

// Antigravity 的 installed-app client 憑證不入庫,從 viper 讀。
//
// 載入路徑 (viper 的標準 precedence):
//  1. shell:`export ANTIGRAVITY_CLIENT_ID=...`
//  2. .env:`ANTIGRAVITY_CLIENT_ID=...`(由 gosdk/config.Default() 透過 EnvConfig 載入
//     到全域 viper;呼叫端應該已經在 wiring 階段跑過 config.Default(...))
//
// viper 在這層已綁定兩個 key 到對應的環境變數(見底下 init())。若呼叫端沒跑
// gosdk/config.Default(),viper 仍然讀得到 shell env — 只剩 .env 那一路失效。
const (
	ENV_CLIENT_ID     = "ANTIGRAVITY_CLIENT_ID"
	ENV_CLIENT_SECRET = "ANTIGRAVITY_CLIENT_SECRET"
)

// Google OAuth2 端點與 Antigravity 的 installed-app redirect URI。
const (
	AUTH_URL     = "https://accounts.google.com/o/oauth2/v2/auth"
	TOKEN_URL    = "https://oauth2.googleapis.com/token"
	USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
	REDIRECT_URI = "http://localhost:51121/oauth-callback"
)

// init 把兩個 client 憑證的 viper key 綁到對應的環境變數。
//
// gosdk/config 把 EnvPrefix 設成 "APP" — 沒有這行 BindEnv,viper.AutomaticEnv
// 只會自動看 APP_* 前綴的環境變數,ANTIGRAVITY_* 不會被掃到。
// BindEnv 強制綁定 key,繞過 prefix 限制,讓 shell env 與 .env 兩條路都通。
func init() {
	_ = viper.BindEnv(ENV_CLIENT_ID, ENV_CLIENT_ID)
	_ = viper.BindEnv(ENV_CLIENT_SECRET, ENV_CLIENT_SECRET)
}

// SCOPES 是 Antigravity 需要的 Google scope 集合。
var SCOPES = []string{
	"https://www.googleapis.com/auth/cloud-platform",
	"https://www.googleapis.com/auth/userinfo.email",
	"https://www.googleapis.com/auth/userinfo.profile",
}

// OAuth 是 Antigravity 的 Google OAuth2 登入流程。
type OAuth struct {
	opts   model.Options
	client *svc.OAuthClient
}

// NewOAuth 建立 authenticator。client_id / client_secret 從 viper 讀;
// .env 載入由 gosdk/config.Default() 負責 (見 package docstring)。
func NewOAuth(opts ...model.Option) *OAuth {
	o := model.NewOptions(opts...)
	cfg := svc.OAuthConfig{
		AuthURL:      model.Pick(o.AuthURL, AUTH_URL),
		TokenURL:     model.Pick(o.TokenURL, TOKEN_URL),
		ClientID:     viper.GetString(ENV_CLIENT_ID),
		ClientSecret: viper.GetString(ENV_CLIENT_SECRET),
		RedirectURI:  model.Pick(o.RedirectURI, REDIRECT_URI),
		Scopes:       SCOPES,
		UsePKCE:      false,
		AuthParams: url.Values{
			// access_type=offline + prompt=consent 是拿到 refresh token 的必要條件;
			// 少了 prompt=consent,Google 對已授權過的帳號不會再發 refresh token。
			"access_type": {"offline"},
			"prompt":      {"consent"},
		},
		Encoding: svc.ENCODING_FORM,
	}
	return &OAuth{opts: o, client: svc.NewOAuthClient(cfg, o.HTTPClient, o.Now)}
}

func (a *OAuth) Provider() string { return PROVIDER }
func (a *OAuth) Kind() model.Kind { return model.KIND_OAUTH }

// Login 跑完整的瀏覽器授權流程,再打 userinfo 補上帳號 email。
func (a *OAuth) Login(ctx context.Context) (*model.Credential, error) {
	if a.client.Config().ClientID == "" || a.client.Config().ClientSecret == "" {
		return nil, fmt.Errorf("antigravity: %s and %s must be set (load from .env or export in shell)",
			ENV_CLIENT_ID, ENV_CLIENT_SECRET)
	}

	token, err := svc.RunBrowserLogin(ctx, a.client, a.opts)
	if err != nil {
		return nil, err
	}

	cred := svc.MergeOAuthToken(PROVIDER, token, nil, SCOPES, a.opts.Now())
	email, err := a.fetchUserEmail(ctx, cred.AccessToken)
	if err != nil {
		// 拿不到 email 不該讓登入失敗 — token 是有效的,只是憑證檔會少個名字。
		return cred, nil
	}
	cred.Account = email
	return cred, nil
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
	return svc.MergeOAuthToken(PROVIDER, token, cred, SCOPES, a.opts.Now()), nil
}

// Verify 打 Google 的 userinfo 端點。
//
// 這裡不用 refresh 往返 (其他 OAuth provider 的做法): Google 有一個免費、
// 無副作用、且會如實對過期 token 回 401 的 userinfo 端點,拿它驗證比輪替
// token 更乾淨 — 驗證不該有副作用。
func (a *OAuth) Verify(ctx context.Context, cred *model.Credential) (*model.VerifyResult, error) {
	if cred == nil || cred.AccessToken == "" {
		return nil, fmt.Errorf("%w: oauth credential has no access token", auth.ErrInvalidCredential)
	}

	email, err := a.fetchUserEmail(ctx, cred.AccessToken)
	if err == nil {
		return &model.VerifyResult{
			OK:     true,
			Method: "userinfo_endpoint",
			Detail: fmt.Sprintf("Google userinfo accepted the access token (%s)", email),
		}, nil
	}

	// access token 過期是正常的 (它只活一小時),此時用 refresh token 換一張新的
	// 再驗一次 — 換得到就代表這份憑證整體仍然有效。
	var httpErr *svc.HTTPError
	if !errors.As(err, &httpErr) || httpErr.Status != http.StatusUnauthorized || cred.RefreshToken == "" {
		return nil, err
	}

	refreshed, refreshErr := a.Refresh(ctx, cred)
	if refreshErr != nil {
		return nil, refreshErr
	}
	email, err = a.fetchUserEmail(ctx, refreshed.AccessToken)
	if err != nil {
		return nil, err
	}
	if refreshed.Account == "" {
		refreshed.Account = email
	}
	return &model.VerifyResult{
		OK:         true,
		Method:     "token_refresh",
		Detail:     fmt.Sprintf("the access token had expired; a refreshed one was accepted by Google userinfo (%s)", email),
		Credential: refreshed,
	}, nil
}

// fetchUserEmail 用 access token 打 userinfo 端點拿 email。
func (a *OAuth) fetchUserEmail(ctx context.Context, accessToken string) (string, error) {
	endpoint := USERINFO_URL
	if a.opts.APIBase != "" {
		endpoint = strings.TrimSuffix(a.opts.APIBase, "/") + "/oauth2/v2/userinfo"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return "", fmt.Errorf("antigravity: create userinfo request: %w", err)
	}
	req.Header.Set("Accept", "application/json")
	svc.BearerAuth(req, accessToken)

	resp, err := a.opts.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("antigravity: userinfo request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("antigravity: read userinfo response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", &svc.HTTPError{
			Op:     "antigravity userinfo",
			Status: resp.StatusCode,
			Body:   strings.TrimSpace(string(raw)),
		}
	}

	var payload struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("antigravity: parse userinfo response: %w", err)
	}
	if payload.Email == "" {
		return "", fmt.Errorf("antigravity: userinfo response has no email")
	}
	return payload.Email, nil
}
