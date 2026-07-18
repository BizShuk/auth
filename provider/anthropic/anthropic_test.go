package anthropic_test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/bizshuk/auth/authtest"
	model "github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/provider/anthropic"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// oauthOptions 把 authenticator 指向假 token 端點,並用「假瀏覽器」直接打回
// 本機 callback server。
func oauthOptions(t *testing.T, endpoint *authtest.TokenEndpoint, opener func(string) error) []model.Option {
	t.Helper()
	return []model.Option{
		model.WithTokenURL(endpoint.URL()),
		model.WithAuthURL(endpoint.URL() + "/authorize"),
		model.WithRedirectURI(authtest.RedirectURI(t)),
		model.WithHTTPClient(endpoint.Client()),
		model.WithBrowserOpener(opener),
		model.WithClock(authtest.FixedClock),
		model.WithLoginTimeout(5 * time.Second),
	}
}

func TestAPIKeyLogin(t *testing.T) {
	var got *http.Request
	srv := authtest.ModelsServer(t, http.StatusOK, authtest.OKModels(), &got)

	cred, err := anthropic.NewAPIKey(
		model.WithAPIKey("sk-ant-test"),
		model.WithAPIBase(srv.URL),
		model.WithHTTPClient(srv.Client()),
	).Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, anthropic.PROVIDER, cred.Provider)
	assert.Equal(t, model.KIND_API_KEY, cred.Kind)
	assert.Equal(t, "anthropic-apikey", cred.Name())

	// Anthropic 用 x-api-key,不是 bearer;而且要求版本標頭。
	require.NotNil(t, got)
	assert.Equal(t, "sk-ant-test", got.Header.Get("x-api-key"))
	assert.Equal(t, anthropic.ANTHROPIC_VERSION, got.Header.Get("anthropic-version"))
	assert.Empty(t, got.Header.Get("Authorization"))
	assert.Equal(t, "/v1/models", got.URL.Path)
}

// 完整登入: 開「瀏覽器」→ callback → 用 PKCE verifier 換 token。
func TestOAuthLogin(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	endpoint.Handler = func(w http.ResponseWriter, _ map[string]string) {
		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token":  "anthropic-access",
			"refresh_token": "anthropic-refresh",
			"expires_in":    3600,
			"account":       map[string]any{"uuid": "acct-1", "email_address": "dev@example.com"},
			"organization":  map[string]any{"uuid": "org-1", "name": "Acme"},
		})
	}

	a := anthropic.NewOAuth(oauthOptions(t, endpoint, authtest.FollowRedirect(t, "code-1", nil))...)
	cred, err := a.Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, anthropic.PROVIDER, cred.Provider)
	assert.Equal(t, model.KIND_OAUTH, cred.Kind)
	assert.Equal(t, "anthropic-access", cred.AccessToken)
	assert.Equal(t, "anthropic-refresh", cred.RefreshToken)
	assert.Equal(t, "dev@example.com", cred.Account, "the account email comes from the token response")
	assert.Equal(t, "acct-1", cred.AccountID)
	assert.Equal(t, "Acme", cred.Metadata["organization"])
	assert.Equal(t, authtest.FIXED_NOW.Add(time.Hour), cred.ExpiresAt)
	assert.Equal(t, "anthropic-dev@example.com_oauth", cred.Name())

	sent := endpoint.LastRequest()
	assert.Equal(t, "authorization_code", sent["grant_type"])
	assert.Equal(t, "code-1", sent["code"])
	assert.Equal(t, anthropic.CLIENT_ID, sent["client_id"])
	assert.NotEmpty(t, sent["code_verifier"], "public client must prove it started the flow")
	assert.NotEmpty(t, sent["state"], "Anthropic is the one provider that wants state in the exchange")
}

// state 對不上就必須丟掉 code — 否則我們可能替攻擊者換了一份憑證。
func TestOAuthLoginRejectsStateMismatch(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	tamper := func(string) string { return "attacker-state" }

	a := anthropic.NewOAuth(oauthOptions(t, endpoint, authtest.FollowRedirect(t, "code-1", tamper))...)
	_, err := a.Login(context.Background())

	require.ErrorContains(t, err, "state mismatch")
	assert.Equal(t, int32(0), endpoint.Calls(), "the code must never reach the token endpoint")
}

// 無頭模式: 不開埠,使用者把 code#state 貼回來。
func TestOAuthLoginManualCode(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	endpoint.Handler = func(w http.ResponseWriter, _ map[string]string) {
		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token": "anthropic-access",
			"expires_in":   3600,
			"account":      map[string]any{"email_address": "dev@example.com"},
		})
	}

	var shownURL string
	a := anthropic.NewOAuth(
		model.WithTokenURL(endpoint.URL()),
		model.WithHTTPClient(endpoint.Client()),
		model.WithClock(authtest.FixedClock),
		model.WithManualCode(func(authURL string) (string, error) {
			shownURL = authURL
			return "code-1#pasted-state", nil
		}),
	)

	cred, err := a.Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "anthropic-access", cred.AccessToken)
	assert.Contains(t, shownURL, "code_challenge=", "the URL shown to the user must carry the PKCE challenge")

	sent := endpoint.LastRequest()
	assert.Equal(t, "code-1", sent["code"], "the #state fragment is stripped from the code")
	assert.Equal(t, "pasted-state", sent["state"])
}

// refresh 回應沒帶 refresh_token 時,舊的必須留著,帳號資訊也不能被清空。
func TestOAuthRefreshPreservesPreviousFields(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	endpoint.Handler = func(w http.ResponseWriter, _ map[string]string) {
		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token": "anthropic-access-2",
			"expires_in":   3600,
		})
	}

	a := anthropic.NewOAuth(
		model.WithTokenURL(endpoint.URL()),
		model.WithHTTPClient(endpoint.Client()),
		model.WithClock(authtest.FixedClock),
	)
	refreshed, err := a.Refresh(context.Background(), &model.Credential{
		Provider:     anthropic.PROVIDER,
		Kind:         model.KIND_OAUTH,
		Account:      "dev@example.com",
		AccountID:    "acct-1",
		AccessToken:  "anthropic-access-1",
		RefreshToken: "anthropic-refresh-1",
	})
	require.NoError(t, err)

	assert.Equal(t, "anthropic-access-2", refreshed.AccessToken)
	assert.Equal(t, "anthropic-refresh-1", refreshed.RefreshToken, "the old refresh token must survive")
	assert.Equal(t, "dev@example.com", refreshed.Account)
	assert.Equal(t, "acct-1", refreshed.AccountID)
	assert.Equal(t, authtest.FIXED_NOW, refreshed.LastRefresh)
}

func TestOAuthRefreshWithoutToken(t *testing.T) {
	_, err := anthropic.NewOAuth().Refresh(context.Background(), &model.Credential{
		Provider: anthropic.PROVIDER, Kind: model.KIND_OAUTH,
	})
	require.ErrorIs(t, err, model.ErrNoRefreshToken)
}

// Verify 走 refresh 往返,並把輪替後的憑證交回給呼叫端存檔。
func TestOAuthVerify(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	endpoint.Handler = func(w http.ResponseWriter, _ map[string]string) {
		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token":  "anthropic-access-2",
			"refresh_token": "anthropic-refresh-2",
			"expires_in":    3600,
		})
	}

	a := anthropic.NewOAuth(
		model.WithTokenURL(endpoint.URL()),
		model.WithHTTPClient(endpoint.Client()),
		model.WithClock(authtest.FixedClock),
	)
	res, err := a.Verify(context.Background(), &model.Credential{
		Provider: anthropic.PROVIDER, Kind: model.KIND_OAUTH,
		AccessToken: "anthropic-access-1", RefreshToken: "anthropic-refresh-1",
	})
	require.NoError(t, err)

	assert.True(t, res.OK)
	assert.Equal(t, "token_refresh", res.Method)
	require.NotNil(t, res.Credential, "verify rotated the token; the caller must persist it")
	assert.Equal(t, "anthropic-refresh-2", res.Credential.RefreshToken)
}

func TestOAuthVerifyRejectsDeadCredential(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	endpoint.Handler = func(w http.ResponseWriter, _ map[string]string) {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
	}

	a := anthropic.NewOAuth(
		model.WithTokenURL(endpoint.URL()),
		model.WithHTTPClient(endpoint.Client()),
		model.WithClock(authtest.FixedClock),
	)
	_, err := a.Verify(context.Background(), &model.Credential{
		Provider: anthropic.PROVIDER, Kind: model.KIND_OAUTH,
		AccessToken: "at", RefreshToken: "revoked",
	})
	require.ErrorContains(t, err, "invalid_grant")
}
