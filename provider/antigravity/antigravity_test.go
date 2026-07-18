package antigravity_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/bizshuk/auth/authtest"
	"github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/provider/antigravity"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// googleServer 假扮 Google: /token 換 token,/oauth2/v2/userinfo 用 bearer 換 email。
// 只有 validToken 這個 access token 會被 userinfo 接受。
type googleServer struct {
	server     *httptest.Server
	validToken string

	tokenRequests []url.Values
	userinfoCalls int
}

// 測試 fixture:模擬 Antigravity 的 installed-app client 憑證。NewOAuth
// 從 ANTIGRAVITY_CLIENT_ID / ANTIGRAVITY_CLIENT_SECRET 環境變數讀,測試要
// 看到的是「送進 token 端點的值」,所以這裡直接 hard-code 一對 fixture。
const (
	testClientID     = "test-antigravity-client-id.apps.googleusercontent.com"
	testClientSecret = "test-antigravity-client-secret"
)

func newGoogleServer(t *testing.T, validToken string) *googleServer {
	t.Helper()
	t.Setenv(antigravity.ENV_CLIENT_ID, testClientID)
	t.Setenv(antigravity.ENV_CLIENT_SECRET, testClientSecret)
	g := &googleServer{validToken: validToken}

	mux := http.NewServeMux()
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		g.tokenRequests = append(g.tokenRequests, r.PostForm)

		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token":  g.validToken,
			"refresh_token": "google-refresh",
			"expires_in":    3600,
		})
	})
	mux.HandleFunc("/oauth2/v2/userinfo", func(w http.ResponseWriter, r *http.Request) {
		g.userinfoCalls++
		if r.Header.Get("Authorization") != "Bearer "+g.validToken {
			authtest.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
			return
		}
		authtest.WriteJSON(w, http.StatusOK, map[string]any{"email": "dev@example.com"})
	})

	g.server = httptest.NewServer(mux)
	t.Cleanup(g.server.Close)
	return g
}

func (g *googleServer) options(t *testing.T, extra ...model.Option) []model.Option {
	t.Helper()
	opts := []model.Option{
		model.WithTokenURL(g.server.URL + "/token"),
		model.WithAuthURL(g.server.URL + "/authorize"),
		model.WithAPIBase(g.server.URL),
		model.WithRedirectURI(authtest.RedirectURI(t)),
		model.WithHTTPClient(g.server.Client()),
		model.WithClock(authtest.FixedClock),
		model.WithLoginTimeout(5 * time.Second),
	}
	return append(opts, extra...)
}

// Antigravity 走 Google 的 installed-app 流程: 帶 client_secret,不帶 PKCE,
// 而且 email 要另外打 userinfo 才拿得到。
func TestLogin(t *testing.T) {
	google := newGoogleServer(t, "google-access")

	a := antigravity.NewOAuth(google.options(t,
		model.WithBrowserOpener(authtest.FollowRedirect(t, "code-1", nil)))...)

	cred, err := a.Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, antigravity.PROVIDER, cred.Provider)
	assert.Equal(t, model.KIND_OAUTH, cred.Kind)
	assert.Equal(t, "google-access", cred.AccessToken)
	assert.Equal(t, "google-refresh", cred.RefreshToken)
	assert.Equal(t, "dev@example.com", cred.Account, "the email comes from the userinfo endpoint")
	assert.Equal(t, authtest.FIXED_NOW.Add(time.Hour), cred.ExpiresAt)
	assert.Equal(t, "antigravity-dev@example.com_oauth", cred.Name())

	require.Len(t, google.tokenRequests, 1)
	sent := google.tokenRequests[0]
	assert.Equal(t, "authorization_code", sent.Get("grant_type"))
	assert.Equal(t, testClientSecret, sent.Get("client_secret"), "an installed-app client authenticates with its secret")
	assert.Empty(t, sent.Get("code_verifier"), "this flow does not use PKCE")
}

// 沒有 access_type=offline + prompt=consent,Google 不會發 refresh token。
func TestAuthURLAsksForOfflineAccess(t *testing.T) {
	google := newGoogleServer(t, "google-access")

	var authURL string
	a := antigravity.NewOAuth(google.options(t,
		model.WithManualCode(func(u string) (string, error) {
			authURL = u
			return "code-1", nil
		}))...)

	_, err := a.Login(context.Background())
	require.NoError(t, err)

	parsed, err := url.Parse(authURL)
	require.NoError(t, err)
	query := parsed.Query()

	assert.Equal(t, "offline", query.Get("access_type"))
	assert.Equal(t, "consent", query.Get("prompt"))
	assert.Empty(t, query.Get("code_challenge"))
	assert.NotContains(t, authURL, testClientSecret, "the secret must never appear in a browser URL")
}

// userinfo 掛掉不該讓登入失敗 — token 是好的,只是憑證少個 email。
func TestLoginSurvivesUserinfoFailure(t *testing.T) {
	google := newGoogleServer(t, "google-access")

	a := antigravity.NewOAuth(google.options(t,
		// 換出來的 token 與 userinfo 認的不同 → userinfo 會回 401。
		model.WithBrowserOpener(authtest.FollowRedirect(t, "code-1", nil)))...)
	google.validToken = "google-access" // token 端點發這個
	google.userinfoCalls = 0

	cred, err := a.Login(context.Background())
	require.NoError(t, err)
	assert.NotEmpty(t, cred.AccessToken)
}

// Verify 打 userinfo — 這是免費、無副作用的檢查,不需要輪替 token。
func TestVerifyUsesUserinfo(t *testing.T) {
	google := newGoogleServer(t, "google-access")
	a := antigravity.NewOAuth(google.options(t)...)

	res, err := a.Verify(context.Background(), &model.Credential{
		Provider: antigravity.PROVIDER, Kind: model.KIND_OAUTH,
		AccessToken: "google-access", RefreshToken: "google-refresh",
	})
	require.NoError(t, err)

	assert.True(t, res.OK)
	assert.Equal(t, "userinfo_endpoint", res.Method)
	assert.Contains(t, res.Detail, "dev@example.com")
	assert.Nil(t, res.Credential, "a live access token needs no rotation")
	assert.Empty(t, google.tokenRequests, "verify must not touch the token endpoint when the access token still works")
}

// access token 過期 (userinfo 回 401) 時,verify 用 refresh token 換一張新的再驗,
// 並把輪替後的憑證交回給呼叫端存檔。
func TestVerifyRefreshesExpiredAccessToken(t *testing.T) {
	google := newGoogleServer(t, "google-access")
	a := antigravity.NewOAuth(google.options(t)...)

	res, err := a.Verify(context.Background(), &model.Credential{
		Provider: antigravity.PROVIDER, Kind: model.KIND_OAUTH,
		AccessToken: "stale-token", RefreshToken: "google-refresh",
	})
	require.NoError(t, err)

	assert.True(t, res.OK)
	assert.Equal(t, "token_refresh", res.Method)
	require.NotNil(t, res.Credential, "the rotated credential must come back for persisting")
	assert.Equal(t, "google-access", res.Credential.AccessToken)
	assert.Equal(t, "dev@example.com", res.Credential.Account)
	require.Len(t, google.tokenRequests, 1)
	assert.Equal(t, "refresh_token", google.tokenRequests[0].Get("grant_type"))
}

// 沒有 refresh token 又過期的憑證,verify 必須誠實地失敗。
func TestVerifyFailsWithoutRefreshToken(t *testing.T) {
	google := newGoogleServer(t, "google-access")
	a := antigravity.NewOAuth(google.options(t)...)

	_, err := a.Verify(context.Background(), &model.Credential{
		Provider: antigravity.PROVIDER, Kind: model.KIND_OAUTH,
		AccessToken: "stale-token",
	})
	require.Error(t, err)
	assert.Empty(t, google.tokenRequests)
}

// Client 憑證是從 .env / shell 來的;Login 必須在憑證缺失時早一步失敗,
// 而不是默默送出一個沒有 client_id 的請求給 Google。
func TestLoginFailsWithoutClientCredentials(t *testing.T) {
	t.Setenv(antigravity.ENV_CLIENT_ID, "")
	t.Setenv(antigravity.ENV_CLIENT_SECRET, "")

	a := antigravity.NewOAuth(model.WithLoginTimeout(time.Second))
	_, err := a.Login(context.Background())
	require.Error(t, err)
	assert.Contains(t, err.Error(), antigravity.ENV_CLIENT_ID)
	assert.Contains(t, err.Error(), antigravity.ENV_CLIENT_SECRET)
}
