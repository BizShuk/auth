package antigravity_test

import (
	"context"
	"encoding/json"
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

	// project 是 loadCodeAssist 要回的值;空字串模擬尚未開通的帳號。
	project        any
	projectCalls   int
	projectHeaders http.Header
	projectRequest int
	projectMode    int
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
	g := &googleServer{validToken: validToken, project: "projects/demo"}

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

	mux.HandleFunc(antigravity.LOAD_CODE_ASSIST_PATH, func(w http.ResponseWriter, r *http.Request) {
		g.projectCalls++
		if r.Header.Get("Authorization") != "Bearer "+g.validToken {
			authtest.WriteJSON(w, http.StatusUnauthorized, map[string]any{"error": "invalid_token"})
			return
		}
		g.projectHeaders = r.Header.Clone()
		// 真實 gateway 少了 client 身分標頭時`不會報錯` — 它照樣回 200,
		// 只是整包不含 cloudaicompanionProject。fake 必須複製這個行為,
		// 否則測試會在真實環境失敗的情況下通過。
		if r.Header.Get("X-Client-Name") == "" || r.Header.Get("x-goog-api-client") == "" {
			authtest.WriteJSON(w, http.StatusOK, map[string]any{
				"allowedTiers": []any{map[string]any{"id": "standard-tier"}},
			})
			return
		}
		var body struct {
			Metadata struct {
				IDEType int `json:"ideType"`
			} `json:"metadata"`
			Mode int `json:"mode"`
		}
		require.NoError(t, json.NewDecoder(r.Body).Decode(&body))
		g.projectRequest = body.Metadata.IDEType
		g.projectMode = body.Mode
		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"cloudaicompanionProject": g.project,
		})
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

// 環境變數是覆寫,不是唯一來源:沒設時要用內建的 installed-app 憑證登入,
// 而不是送出一個沒有 client_id 的請求給 Google。
func TestLoginUsesBuiltInClientCredentials(t *testing.T) {
	google := newGoogleServer(t, "google-access")
	t.Setenv(antigravity.ENV_CLIENT_ID, "")
	t.Setenv(antigravity.ENV_CLIENT_SECRET, "")

	a := antigravity.NewOAuth(google.options(t,
		model.WithBrowserOpener(authtest.FollowRedirect(t, "code-1", nil)))...)

	_, err := a.Login(context.Background())
	require.NoError(t, err)

	require.Len(t, google.tokenRequests, 1)
	sent := google.tokenRequests[0]
	assert.Equal(t, antigravity.CLIENT_ID, sent.Get("client_id"))
	assert.Equal(t, antigravity.CLIENT_SECRET, sent.Get("client_secret"))
}

// 內建的 redirect URI 必須指回登記的 callback port。
func TestRedirectURIUsesCallbackPort(t *testing.T) {
	assert.Equal(t, "51121", antigravity.CALLBACK_PORT)
	assert.Equal(t, "http://localhost:51121/oauth-callback", antigravity.REDIRECT_URI)
}

// project 是帳號開通的產物而不是推論參數,所以在登入時查一次寫進憑證 —
// 呼叫端因此不必在每次推論請求前自己解析。
func TestLoginFetchesCloudCodeProject(t *testing.T) {
	google := newGoogleServer(t, "google-access")

	a := antigravity.NewOAuth(google.options(t,
		model.WithBrowserOpener(authtest.FollowRedirect(t, "code-1", nil)))...)

	cred, err := a.Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "projects/demo", cred.ProjectID)
	assert.Equal(t, 1, google.projectCalls, "登入查一次就夠,之後該值固定不變")
	assert.Equal(t, antigravity.IDE_TYPE_ANTIGRAVITY, google.projectRequest,
		"gateway 以數字讀 ideType,送名稱會被拒")
	assert.Equal(t, antigravity.LOAD_CODE_ASSIST_MODE, google.projectMode)
}

// 開通中的帳號會用帶 id 的物件回這個欄位,而不是字串。
func TestLoginAcceptsObjectShapedProject(t *testing.T) {
	google := newGoogleServer(t, "google-access")
	google.project = map[string]any{"id": "projects/nested"}

	a := antigravity.NewOAuth(google.options(t,
		model.WithBrowserOpener(authtest.FollowRedirect(t, "code-1", nil)))...)

	cred, err := a.Login(context.Background())
	require.NoError(t, err)
	assert.Equal(t, "projects/nested", cred.ProjectID)
}

// 帳號還沒開通 project 是正常的首次狀態 — token 是有效的,登入不該失敗。
func TestLoginSurvivesMissingProject(t *testing.T) {
	google := newGoogleServer(t, "google-access")
	google.project = ""

	a := antigravity.NewOAuth(google.options(t,
		model.WithBrowserOpener(authtest.FollowRedirect(t, "code-1", nil)))...)

	cred, err := a.Login(context.Background())
	require.NoError(t, err)

	assert.Empty(t, cred.ProjectID)
	assert.Equal(t, "google-access", cred.AccessToken, "拿不到 project 不影響 token")
	assert.Equal(t, "dev@example.com", cred.Account)
}

// 少了 client 身分標頭,gateway 回的 200 裡就沒有 cloudaicompanionProject —
// 沒有任何錯誤訊號,project 只是靜靜地拿不到。這是實測踩到的失敗形式,
// 所以標頭必須被釘住。
func TestLoginSendsClientIdentityHeadersToLoadCodeAssist(t *testing.T) {
	google := newGoogleServer(t, "google-access")

	a := antigravity.NewOAuth(google.options(t,
		model.WithBrowserOpener(authtest.FollowRedirect(t, "code-1", nil)))...)

	cred, err := a.Login(context.Background())
	require.NoError(t, err)
	require.Equal(t, "projects/demo", cred.ProjectID, "標頭齊全時才拿得到 project")

	h := google.projectHeaders
	assert.Equal(t, antigravity.CLIENT_NAME, h.Get("X-Client-Name"))
	assert.Equal(t, antigravity.CLIENT_VERSION, h.Get("X-Client-Version"))
	assert.Equal(t, antigravity.GOOG_API_CLIENT, h.Get("x-goog-api-client"))
	assert.Contains(t, h.Get("User-Agent"), antigravity.CLIENT_NAME+"/"+antigravity.CLIENT_VERSION)
}
