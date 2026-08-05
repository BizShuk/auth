// Package antigravity implements Antigravity authentication: a Google OAuth2
// installed-app flow against accounts.google.com.
//
// 它與其他 OAuth provider 有兩個結構性差異:
//
//  1. 帶 client_secret,不走 PKCE — Google 的 installed-app client 是這樣設計的,
//     secret 是公開的 (它就寫在每個安裝出去的 client 裡),真正的保護來自
//     redirect_uri 必須指回 localhost。
//  2. token 回應裡沒有帳號資訊,email 要另外打一次 userinfo 端點拿,
//     Cloud Code project 要再打一次 loadCodeAssist 拿。
package antigravity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"strings"

	auth "github.com/bizshuk/auth/model"
	model "github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
	"github.com/spf13/viper"
)

// PROVIDER 是憑證裡記的 provider 名稱。
const PROVIDER = "antigravity"

// Antigravity 的 installed-app client 憑證。CLIENT_ID / CLIENT_SECRET 是
// Antigravity 公開發行的 installed-app 憑證 — 與 anthropic / openai / xai 的
// CLIENT_ID 同一性質:它就寫在每個安裝出去的 client 裡,真正的保護來自
// redirect_uri 必須指回 localhost (見 package docstring)。
const (
	CLIENT_ID     = "1071006060591-tmhssin2h21lcre235vtolojh4g403ep.apps.googleusercontent.com"
	CLIENT_SECRET = "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"
)

// 需要換一組 client 時(自建 GCP OAuth client、或憑證被輪替)以環境變數覆寫,
// 空值即沿用上面的預設值。
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
// CALLBACK_PORT 必須與該 client 在 GCP 上登記的 redirect URI 一致。
const (
	AUTH_URL      = "https://accounts.google.com/o/oauth2/v2/auth"
	TOKEN_URL     = "https://oauth2.googleapis.com/token"
	USERINFO_URL  = "https://www.googleapis.com/oauth2/v2/userinfo"
	CALLBACK_PORT = "51121"
	REDIRECT_URI  = "http://localhost:" + CALLBACK_PORT + "/oauth-callback"
)

// Cloud Code 的帳號開通端點。project 是登入的產物而不是推論參數,所以在這裡
// 查:它由 Google 在帳號首次使用時配發,之後對該帳號固定不變,而 Antigravity
// 的每個推論請求都必須把它帶在 body 裡。
const (
	LOAD_CODE_ASSIST_HOST = "https://cloudcode-pa.googleapis.com"
	LOAD_CODE_ASSIST_PATH = "/v1internal:loadCodeAssist"
	LOAD_CODE_ASSIST_URL  = LOAD_CODE_ASSIST_HOST + LOAD_CODE_ASSIST_PATH

	// LOAD_CODE_ASSIST_MODE 選「解析我的 entitlement」而非開通流程。
	LOAD_CODE_ASSIST_MODE = 1
)

// loadCodeAssist 的 client 身分標頭。少了它們 gateway `不會報錯` —— 它照樣回
// 200,但整包只有 tier 清單、沒有 cloudaicompanionProject,等於查不到 project
// 卻沒有任何錯誤訊號。這幾個值必須與 Antigravity IDE 自己送的一致。
const (
	CLIENT_NAME     = "antigravity"
	CLIENT_VERSION  = "2.0.1"
	GOOG_API_CLIENT = "gl-node/18.18.2 fire/0.8.6 grpc/1.10.x"
)

// gateway 以`數字`讀這些 enum;名稱形式只存在於 IDE 的 protobuf descriptor。
const (
	IDE_TYPE_ANTIGRAVITY = 9
	PLUGIN_TYPE_GEMINI   = 2

	PLATFORM_UNSPECIFIED   = 0
	PLATFORM_DARWIN_AMD64  = 1
	PLATFORM_DARWIN_ARM64  = 2
	PLATFORM_LINUX_AMD64   = 3
	PLATFORM_LINUX_ARM64   = 4
	PLATFORM_WINDOWS_AMD64 = 5
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

// NewOAuth 建立 authenticator。client_id / client_secret 預設用內建的
// installed-app 憑證,環境變數有值時覆寫;.env 載入由 gosdk/config.Default()
// 負責 (見 package docstring)。
func NewOAuth(opts ...model.Option) *OAuth {
	o := model.NewOptions(opts...)
	cfg := svc.OAuthConfig{
		AuthURL:      model.Pick(o.AuthURL, AUTH_URL),
		TokenURL:     model.Pick(o.TokenURL, TOKEN_URL),
		ClientID:     model.Pick(viper.GetString(ENV_CLIENT_ID), CLIENT_ID),
		ClientSecret: model.Pick(viper.GetString(ENV_CLIENT_SECRET), CLIENT_SECRET),
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

// Login 跑完整的瀏覽器授權流程,再打 userinfo 補上帳號 email、
// 打 loadCodeAssist 補上 Cloud Code project。
func (a *OAuth) Login(ctx context.Context) (*model.Credential, error) {
	token, err := svc.RunBrowserLogin(ctx, a.client, a.opts)
	if err != nil {
		return nil, err
	}

	cred := svc.MergeOAuthToken(PROVIDER, token, nil, SCOPES, a.opts.Now())
	if email, err := a.fetchUserEmail(ctx, cred.AccessToken); err == nil {
		cred.Account = email
	}
	// 拿不到 email 或 project 都不該讓登入失敗 — token 是有效的,只是憑證檔
	// 會少個名字或少個 project。
	if project, err := a.fetchProjectID(ctx, cred.AccessToken); err == nil {
		cred.ProjectID = project
	}
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

// fetchProjectID 用 access token 打 loadCodeAssist 拿 Cloud Code project。
//
// project 是`帳號開通`的產物,不是推論參數:它由 Google 在帳號首次使用時配發,
// 之後對該帳號固定不變。Antigravity 的每個推論請求都必須把它帶在 body 裡,
// 所以在登入時查一次寫進憑證,呼叫端就不必在每次請求前自己解析。
func (a *OAuth) fetchProjectID(ctx context.Context, accessToken string) (string, error) {
	endpoint := LOAD_CODE_ASSIST_URL
	if a.opts.APIBase != "" {
		endpoint = strings.TrimSuffix(a.opts.APIBase, "/") + LOAD_CODE_ASSIST_PATH
	}

	// gateway 以數字讀這幾個 enum;IDE 的 protobuf descriptor 才有名稱形式。
	body, err := json.Marshal(map[string]any{
		"metadata": map[string]any{
			"ideType":    IDE_TYPE_ANTIGRAVITY,
			"platform":   platformEnum(),
			"pluginType": PLUGIN_TYPE_GEMINI,
		},
		"mode": LOAD_CODE_ASSIST_MODE,
	})
	if err != nil {
		return "", fmt.Errorf("antigravity: encode loadCodeAssist request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("antigravity: create loadCodeAssist request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", clientUserAgent())
	req.Header.Set("X-Client-Name", CLIENT_NAME)
	req.Header.Set("X-Client-Version", CLIENT_VERSION)
	req.Header.Set("x-goog-api-client", GOOG_API_CLIENT)
	svc.BearerAuth(req, accessToken)

	resp, err := a.opts.HTTPClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("antigravity: loadCodeAssist request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("antigravity: read loadCodeAssist response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", &svc.HTTPError{
			Op:     "antigravity loadCodeAssist",
			Status: resp.StatusCode,
			Body:   strings.TrimSpace(string(raw)),
		}
	}

	var payload struct {
		Project json.RawMessage `json:"cloudaicompanionProject"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return "", fmt.Errorf("antigravity: parse loadCodeAssist response: %w", err)
	}
	project := decodeProject(payload.Project)
	if project == "" {
		// 帳號還沒開通 project 是正常的首次狀態,不是傳輸錯誤。
		return "", fmt.Errorf("antigravity: loadCodeAssist response has no project")
	}
	return project, nil
}

// decodeProject 解 cloudaicompanionProject 的兩種形狀:開通完成是字串,
// 開通中則是帶 id 的物件。
func decodeProject(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	var asString string
	if err := json.Unmarshal(raw, &asString); err == nil {
		return strings.TrimSpace(asString)
	}
	var asObject struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(raw, &asObject); err == nil {
		return strings.TrimSpace(asObject.ID)
	}
	return ""
}

// clientUserAgent 組出 gateway 認得的 IDE 身分字串。Node 把 amd64 叫 x64,
// gateway 從每個真實 client 看到的都是 Node 的拼法,所以這裡跟著它。
func clientUserAgent() string {
	arch := runtime.GOARCH
	if arch == "amd64" {
		arch = "x64"
	}
	return fmt.Sprintf("%s/%s %s/%s", CLIENT_NAME, CLIENT_VERSION, runtime.GOOS, arch)
}

// platformEnum 把執行平台對應到 gateway 的 platform enum。
func platformEnum() int {
	arm := runtime.GOARCH == "arm64"
	switch runtime.GOOS {
	case "darwin":
		if arm {
			return PLATFORM_DARWIN_ARM64
		}
		return PLATFORM_DARWIN_AMD64
	case "linux":
		if arm {
			return PLATFORM_LINUX_ARM64
		}
		return PLATFORM_LINUX_AMD64
	case "windows":
		return PLATFORM_WINDOWS_AMD64
	}
	return PLATFORM_UNSPECIFIED
}
