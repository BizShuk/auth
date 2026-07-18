package openai_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/bizshuk/auth/authtest"
	"github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/provider/openai"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyLogin(t *testing.T) {
	var got *http.Request
	srv := authtest.ModelsServer(t, http.StatusOK, authtest.OKModels(), &got)

	cred, err := openai.NewAPIKey(
		model.WithAPIKey("sk-openai-test"),
		model.WithAPIBase(srv.URL),
		model.WithHTTPClient(srv.Client()),
	).Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, openai.PROVIDER, cred.Provider)
	assert.Equal(t, "openai-apikey", cred.Name())

	require.NotNil(t, got)
	assert.Equal(t, "Bearer sk-openai-test", got.Header.Get("Authorization"))
	assert.Equal(t, "/v1/models", got.URL.Path)
}

// OpenAI 的帳號資訊藏在 id_token 的 claims 裡,而不是 token 回應的頂層。
func TestOAuthLogin(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	idToken := authtest.MakeIDToken(t, map[string]any{
		"email": "dev@example.com",
		openai.AUTH_CLAIM: map[string]any{
			"chatgpt_account_id": "acct-9",
			"chatgpt_plan_type":  "plus",
		},
	})
	endpoint.Handler = func(w http.ResponseWriter, _ map[string]string) {
		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token":  "openai-access",
			"refresh_token": "openai-refresh",
			"id_token":      idToken,
			"expires_in":    3600,
		})
	}

	a := openai.NewOAuth(
		model.WithTokenURL(endpoint.URL()),
		model.WithAuthURL(endpoint.URL()+"/authorize"),
		model.WithRedirectURI(authtest.RedirectURI(t)),
		model.WithHTTPClient(endpoint.Client()),
		model.WithBrowserOpener(authtest.FollowRedirect(t, "code-1", nil)),
		model.WithClock(authtest.FixedClock),
		model.WithLoginTimeout(5*time.Second),
	)
	cred, err := a.Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, openai.PROVIDER, cred.Provider)
	assert.Equal(t, "openai-access", cred.AccessToken)
	assert.Equal(t, "dev@example.com", cred.Account, "email is decoded from the id_token")
	assert.Equal(t, "acct-9", cred.AccountID)
	assert.Equal(t, "plus", cred.Metadata["chatgpt_plan_type"])
	assert.Equal(t, "openai-dev@example.com_oauth", cred.Name())

	sent := endpoint.LastRequest()
	assert.Equal(t, openai.CLIENT_ID, sent["client_id"])
	assert.NotEmpty(t, sent["code_verifier"])
	// 真實的 OpenAI token 端點對多出來的 state 會回 400 unknown_parameter。
	assert.NotContains(t, sent, "state", "OpenAI rejects a state parameter in the token exchange")
}

// id_token 壞掉不該讓登入失敗 — access token 照樣可用,只是少了 email。
func TestOAuthLoginWithUnparseableIDToken(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	endpoint.Handler = func(w http.ResponseWriter, _ map[string]string) {
		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token": "openai-access",
			"id_token":     "not-a-jwt",
			"expires_in":   3600,
		})
	}

	a := openai.NewOAuth(
		model.WithTokenURL(endpoint.URL()),
		model.WithRedirectURI(authtest.RedirectURI(t)),
		model.WithHTTPClient(endpoint.Client()),
		model.WithBrowserOpener(authtest.FollowRedirect(t, "code-1", nil)),
		model.WithClock(authtest.FixedClock),
		model.WithLoginTimeout(5*time.Second),
	)
	cred, err := a.Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "openai-access", cred.AccessToken)
	assert.Empty(t, cred.Account)
	assert.Equal(t, "openai_oauth", cred.Name(), "no account: the filename is just the provider id")
}

// OpenAI 每次 refresh 都會輪替 refresh token。
func TestOAuthRefreshRotatesToken(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	endpoint.Handler = func(w http.ResponseWriter, _ map[string]string) {
		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token":  "openai-access-2",
			"refresh_token": "openai-refresh-2",
			"expires_in":    3600,
		})
	}

	a := openai.NewOAuth(
		model.WithTokenURL(endpoint.URL()),
		model.WithHTTPClient(endpoint.Client()),
		model.WithClock(authtest.FixedClock),
	)
	refreshed, err := a.Refresh(context.Background(), &model.Credential{
		Provider: openai.PROVIDER, Kind: model.KIND_OAUTH, Account: "dev@example.com",
		AccessToken: "openai-access-1", RefreshToken: "openai-refresh-1",
	})
	require.NoError(t, err)

	assert.Equal(t, "openai-access-2", refreshed.AccessToken)
	assert.Equal(t, "openai-refresh-2", refreshed.RefreshToken)
	assert.Equal(t, "dev@example.com", refreshed.Account, "the account survives a refresh with no id_token")
}
