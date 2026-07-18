package xai_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/bizshuk/auth/authtest"
	model "github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/provider/xai"
	svc "github.com/bizshuk/auth/svc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// xaiServer 假扮 xAI 的 device-flow 端點。
type xaiServer struct {
	server  *httptest.Server
	idToken string

	deviceCalls   int
	tokenRequests []url.Values

	// pending 是「使用者還沒按同意」要重複幾次。
	pending int
	polls   int
}

func newXAIServer(t *testing.T, pending int) *xaiServer {
	t.Helper()
	s := &xaiServer{pending: pending}
	s.idToken = authtest.MakeIDToken(t, map[string]any{
		"email": "dev@example.com",
		"sub":   "user-1",
	})

	mux := http.NewServeMux()
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		s.deviceCalls++

		assert.Equal(t, xai.CLIENT_ID, r.PostForm.Get("client_id"))
		assert.Contains(t, r.PostForm.Get("scope"), "offline_access")

		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"device_code":               "device-1",
			"user_code":                 "WXYZ-1234",
			"verification_uri":          "https://auth.x.ai/device",
			"verification_uri_complete": "https://auth.x.ai/device?code=WXYZ-1234",
			"expires_in":                600,
			"interval":                  1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		s.tokenRequests = append(s.tokenRequests, r.PostForm)

		if r.PostForm.Get("grant_type") == svc.DEVICE_CODE_GRANT {
			s.polls++
			if s.polls <= s.pending {
				authtest.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "authorization_pending"})
				return
			}
		}
		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token":  "xai-access",
			"refresh_token": "xai-refresh",
			"id_token":      s.idToken,
			"expires_in":    3600,
		})
	})

	s.server = httptest.NewServer(mux)
	t.Cleanup(s.server.Close)
	return s
}

// options 同時給 TokenURL 與 AuthURL,讓 authenticator 跳過 OIDC discovery。
func (s *xaiServer) options(extra ...model.Option) []model.Option {
	opts := []model.Option{
		model.WithTokenURL(s.server.URL + "/token"),
		model.WithAuthURL(s.server.URL + "/device"),
		model.WithHTTPClient(s.server.Client()),
		model.WithClock(authtest.FixedClock),
		model.WithLoginTimeout(30 * time.Second),
	}
	return append(opts, extra...)
}

func TestAPIKeyLogin(t *testing.T) {
	var got *http.Request
	srv := authtest.ModelsServer(t, http.StatusOK, authtest.OKModels(), &got)

	cred, err := xai.NewAPIKey(
		model.WithAPIKey("xai-key-1"),
		model.WithAPIBase(srv.URL),
		model.WithHTTPClient(srv.Client()),
	).Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, xai.PROVIDER, cred.Provider)
	assert.Equal(t, model.KIND_API_KEY, cred.Kind)
	assert.Equal(t, "xai-apikey", cred.Name())

	require.NotNil(t, got)
	assert.Equal(t, "Bearer xai-key-1", got.Header.Get("Authorization"))
	assert.Equal(t, "/v1/models", got.URL.Path)
}

// device flow: 要 code → 顯示 user code → 輪詢到使用者同意。沒有本機 callback 埠。
func TestOAuthDeviceLogin(t *testing.T) {
	const PENDING = 2
	server := newXAIServer(t, PENDING)

	var shown *svc.DeviceCode
	a := xai.NewOAuth(server.options(
		model.WithDeviceCodePrompt(func(d any) { shown = d.(*svc.DeviceCode) }),
		model.WithBrowserOpener(func(string) error { return nil }),
	)...)

	cred, err := a.Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, xai.PROVIDER, cred.Provider)
	assert.Equal(t, model.KIND_OAUTH, cred.Kind)
	assert.Equal(t, "xai-access", cred.AccessToken)
	assert.Equal(t, "xai-refresh", cred.RefreshToken)
	assert.Equal(t, "dev@example.com", cred.Account, "the email is decoded from the id_token")
	assert.Equal(t, "user-1", cred.AccountID)
	assert.Equal(t, "xai-dev@example.com_oauth", cred.Name())

	require.NotNil(t, shown, "the user code must be shown — it is the only way to approve")
	assert.Equal(t, "WXYZ-1234", shown.UserCode)
	assert.Equal(t, PENDING+1, server.polls, "it polled through the pending rounds")
	assert.Equal(t, 1, server.deviceCalls)
}

func TestOAuthRefresh(t *testing.T) {
	server := newXAIServer(t, 0)
	a := xai.NewOAuth(server.options()...)

	refreshed, err := a.Refresh(context.Background(), &model.Credential{
		Provider: xai.PROVIDER, Kind: model.KIND_OAUTH,
		Account: "dev@example.com", AccessToken: "old", RefreshToken: "xai-refresh-1",
	})
	require.NoError(t, err)

	assert.Equal(t, "xai-access", refreshed.AccessToken)
	assert.Equal(t, "dev@example.com", refreshed.Account)

	require.Len(t, server.tokenRequests, 1)
	assert.Equal(t, "refresh_token", server.tokenRequests[0].Get("grant_type"))
	assert.Equal(t, "xai-refresh-1", server.tokenRequests[0].Get("refresh_token"))
}

func TestOAuthRefreshWithoutToken(t *testing.T) {
	_, err := xai.NewOAuth().Refresh(context.Background(), &model.Credential{
		Provider: xai.PROVIDER, Kind: model.KIND_OAUTH,
	})
	require.ErrorIs(t, err, model.ErrNoRefreshToken)
}

func TestOAuthVerify(t *testing.T) {
	server := newXAIServer(t, 0)
	a := xai.NewOAuth(server.options()...)

	res, err := a.Verify(context.Background(), &model.Credential{
		Provider: xai.PROVIDER, Kind: model.KIND_OAUTH,
		AccessToken: "old", RefreshToken: "xai-refresh-1",
	})
	require.NoError(t, err)

	assert.True(t, res.OK)
	assert.Equal(t, "token_refresh", res.Method)
	require.NotNil(t, res.Credential)
	assert.Equal(t, "xai-access", res.Credential.AccessToken)
}

// 沒有端點覆寫時要走 OIDC discovery。discovery 拿不到端點就必須失敗,
// 而不是安靜地退回某個猜測的位址。
func TestOAuthDiscoveryFailureSurfaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	// 只覆寫 HTTP client,不覆寫端點 → 會去打真的 discovery URL,但這個 client
	// 的 transport 指向掛掉的 server。
	a := xai.NewOAuth(
		model.WithHTTPClient(&http.Client{
			Transport: rewriteTransport{target: srv.URL},
			Timeout:   5 * time.Second,
		}),
		model.WithClock(authtest.FixedClock),
	)

	_, err := a.Login(context.Background())
	require.ErrorContains(t, err, "OIDC discovery")
}

// rewriteTransport 把所有請求導向 target,用來假裝 discovery 端點掛了。
type rewriteTransport struct{ target string }

func (rt rewriteTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	target, err := url.Parse(rt.target)
	if err != nil {
		return nil, err
	}
	req.URL.Scheme = target.Scheme
	req.URL.Host = target.Host
	return http.DefaultTransport.RoundTrip(req)
}
