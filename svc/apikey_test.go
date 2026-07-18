package svc_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/bizshuk/auth/authtest"
	"github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testSpec 是一個假 provider 的 API key spec,用來測機制本身 (真實 provider
// 的 spec 由各自的 auth/provider/<name> 套件測)。
func testSpec(base string) svc.APIKeySpec {
	return svc.APIKeySpec{
		Provider:    "testprovider",
		EnvVars:     []string{"TESTPROVIDER_API_KEY", "TESTPROVIDER_FALLBACK_KEY"},
		DefaultBase: base,
		ModelsURL:   func(base string) string { return base + "/v1/models" },
		Authorize:   svc.BearerAuth,
	}
}

func TestAPIKeyLoginFromEnv(t *testing.T) {
	var got *http.Request
	srv := authtest.ModelsServer(t, http.StatusOK, authtest.OKModels(), &got)
	t.Setenv("TESTPROVIDER_API_KEY", "sk-from-env")

	a := svc.NewAPIKey(testSpec(srv.URL), model.WithHTTPClient(srv.Client()), model.WithClock(authtest.FixedClock))
	cred, err := a.Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "testprovider", cred.Provider)
	assert.Equal(t, model.KIND_API_KEY, cred.Kind)
	assert.Equal(t, "sk-from-env", cred.APIKey)
	assert.Equal(t, "TESTPROVIDER_API_KEY", cred.Metadata["key_source"], "the env var it came from is recorded")
	assert.Equal(t, "...-env", cred.Metadata["key_suffix"])

	require.NotNil(t, got)
	assert.Equal(t, "Bearer sk-from-env", got.Header.Get("Authorization"))
	assert.Equal(t, "/v1/models", got.URL.Path)
}

// 明確給的金鑰要蓋過環境變數。
func TestAPIKeyLoginFlagBeatsEnv(t *testing.T) {
	srv := authtest.ModelsServer(t, http.StatusOK, authtest.OKModels(), nil)
	t.Setenv("TESTPROVIDER_API_KEY", "sk-from-env")

	a := svc.NewAPIKey(testSpec(srv.URL), model.WithAPIKey("sk-from-flag"), model.WithHTTPClient(srv.Client()))
	cred, err := a.Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "sk-from-flag", cred.APIKey)
	assert.Equal(t, "flag", cred.Metadata["key_source"])
}

// 環境變數依 spec 的順序查找。
func TestAPIKeyLoginEnvFallback(t *testing.T) {
	srv := authtest.ModelsServer(t, http.StatusOK, authtest.OKModels(), nil)
	t.Setenv("TESTPROVIDER_API_KEY", "")
	t.Setenv("TESTPROVIDER_FALLBACK_KEY", "sk-fallback")

	a := svc.NewAPIKey(testSpec(srv.URL), model.WithHTTPClient(srv.Client()))
	cred, err := a.Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "sk-fallback", cred.APIKey)
	assert.Equal(t, "TESTPROVIDER_FALLBACK_KEY", cred.Metadata["key_source"])
}

func TestAPIKeyLoginWithoutKey(t *testing.T) {
	t.Setenv("TESTPROVIDER_API_KEY", "")
	t.Setenv("TESTPROVIDER_FALLBACK_KEY", "")

	a := svc.NewAPIKey(testSpec("https://unused.example.com"))
	_, err := a.Login(context.Background())

	require.ErrorIs(t, err, model.ErrNoAPIKey)
	assert.Contains(t, err.Error(), "TESTPROVIDER_API_KEY", "the error names the env vars it looked in")
}

// 打不通的金鑰不該被存下來 — Login 內建驗證就是為了讓失敗發生在此刻。
func TestAPIKeyLoginRejectsBadKey(t *testing.T) {
	srv := authtest.ModelsServer(t, http.StatusUnauthorized, map[string]any{"error": "invalid key"}, nil)

	a := svc.NewAPIKey(testSpec(srv.URL), model.WithAPIKey("sk-bad"), model.WithHTTPClient(srv.Client()))
	_, err := a.Login(context.Background())
	require.Error(t, err)

	var httpErr *svc.HTTPError
	require.True(t, errors.As(err, &httpErr))
	assert.Equal(t, http.StatusUnauthorized, httpErr.Status)
	assert.False(t, httpErr.Retryable(), "a rejected key is not worth retrying")
}

func TestAPIKeyVerify(t *testing.T) {
	srv := authtest.ModelsServer(t, http.StatusOK, authtest.OKModels(), nil)

	a := svc.NewAPIKey(testSpec(srv.URL), model.WithHTTPClient(srv.Client()))
	res, err := a.Verify(context.Background(), &model.Credential{
		Provider: "testprovider", Kind: model.KIND_API_KEY, APIKey: "sk-1",
	})
	require.NoError(t, err)

	assert.True(t, res.OK)
	assert.Equal(t, "models_endpoint", res.Method)
	assert.Contains(t, res.Detail, "2 model(s)")
	assert.Nil(t, res.Credential, "verifying an API key does not rotate anything")
}

// 對 gateway 發的金鑰,verify 必須打回同一個 gateway,而不是 provider 官方端點。
func TestAPIKeyVerifyHonoursStoredBaseURL(t *testing.T) {
	var got *http.Request
	srv := authtest.ModelsServer(t, http.StatusOK, authtest.OKModels(), &got)

	// 先對 gateway 登入,base URL 會被存進憑證。
	login := svc.NewAPIKey(testSpec("https://official.example.com"),
		model.WithAPIKey("sk-1"), model.WithAPIBase(srv.URL), model.WithHTTPClient(srv.Client()))
	cred, err := login.Login(context.Background())
	require.NoError(t, err)
	require.Equal(t, srv.URL, cred.BaseURL)

	// 之後用一個「不知道 gateway 在哪」的 authenticator (就像 verify 指令那樣,
	// 它只從磁碟讀憑證) 也要打到同一台。
	got = nil
	verifier := svc.NewAPIKey(testSpec("https://official.example.com"), model.WithHTTPClient(srv.Client()))
	res, err := verifier.Verify(context.Background(), cred)
	require.NoError(t, err)

	assert.True(t, res.OK)
	require.NotNil(t, got)
	assert.Equal(t, srv.Listener.Addr().String(), got.Host, "verify must reach the gateway the key was issued against")
}

func TestAPIKeyRefreshUnsupported(t *testing.T) {
	a := svc.NewAPIKey(testSpec("https://unused.example.com"), model.WithAPIKey("sk-1"))

	_, err := a.Refresh(context.Background(), &model.Credential{
		Provider: "testprovider", Kind: model.KIND_API_KEY, APIKey: "sk-1",
	})
	require.ErrorIs(t, err, model.ErrRefreshUnsupported)
}
