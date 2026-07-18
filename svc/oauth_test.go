package svc_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/bizshuk/auth/authtest"
	auth "github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
	utils "github.com/bizshuk/auth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestOAuthClientAuthCodeURL(t *testing.T) {
	pkce, err := utils.GeneratePKCE()
	require.NoError(t, err)

	t.Run("public client sends the PKCE challenge", func(t *testing.T) {
		client := svc.NewOAuthClient(svc.OAuthConfig{
			AuthURL:     "https://auth.example.com/authorize",
			ClientID:    "client-1",
			RedirectURI: "http://localhost:9999/callback",
			Scopes:      []string{"openid", "email"},
			AuthParams:  url.Values{"prompt": {"login"}},
			UsePKCE:     true,
		}, nil, authtest.FixedClock)

		raw, err := client.AuthCodeURL("state-1", pkce)
		require.NoError(t, err)

		u, err := url.Parse(raw)
		require.NoError(t, err)
		q := u.Query()

		assert.Equal(t, "client-1", q.Get("client_id"))
		assert.Equal(t, "code", q.Get("response_type"))
		assert.Equal(t, "http://localhost:9999/callback", q.Get("redirect_uri"))
		assert.Equal(t, "state-1", q.Get("state"))
		assert.Equal(t, "openid email", q.Get("scope"))
		assert.Equal(t, "login", q.Get("prompt"), "static auth params must survive")
		assert.Equal(t, "S256", q.Get("code_challenge_method"))
		assert.Equal(t, pkce.CodeChallenge, q.Get("code_challenge"))
		assert.NotContains(t, raw, pkce.CodeVerifier, "the verifier must never leave the machine")
	})

	// Google 的 installed-app client (Antigravity) 帶 client_secret,不走 PKCE。
	t.Run("client without PKCE sends no challenge", func(t *testing.T) {
		client := svc.NewOAuthClient(svc.OAuthConfig{
			AuthURL:      "https://accounts.google.com/o/oauth2/v2/auth",
			ClientID:     "client-1",
			ClientSecret: "secret-1",
			RedirectURI:  "http://localhost:9999/callback",
			UsePKCE:      false,
		}, nil, authtest.FixedClock)

		raw, err := client.AuthCodeURL("state-1", nil)
		require.NoError(t, err)

		u, err := url.Parse(raw)
		require.NoError(t, err)
		assert.Empty(t, u.Query().Get("code_challenge"))
		assert.NotContains(t, raw, "secret-1", "the client secret must never appear in a browser URL")
	})

	t.Run("a PKCE client without codes is a programming error", func(t *testing.T) {
		client := svc.NewOAuthClient(svc.OAuthConfig{AuthURL: "https://auth.example.com", UsePKCE: true}, nil, authtest.FixedClock)
		_, err := client.AuthCodeURL("state-1", nil)
		require.ErrorContains(t, err, "PKCE codes are required")
	})
}

func TestOAuthClientExchange(t *testing.T) {
	tests := []struct {
		name     string
		encoding svc.Encoding
	}{
		{name: "form encoded token endpoint", encoding: svc.ENCODING_FORM},
		{name: "json body token endpoint", encoding: svc.ENCODING_JSON},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := authtest.NewTokenEndpoint(t)
			client := svc.NewOAuthClient(svc.OAuthConfig{
				TokenURL:    endpoint.URL(),
				ClientID:    "client-1",
				RedirectURI: "http://localhost:9999/callback",
				Encoding:    tc.encoding,
				UsePKCE:     true,
			}, endpoint.Client(), authtest.FixedClock)

			pkce := &utils.PKCECodes{CodeVerifier: "verifier-1", CodeChallenge: utils.S256Challenge("verifier-1")}
			token, err := client.Exchange(context.Background(), "code-1", "state-1", pkce)
			require.NoError(t, err)

			assert.Equal(t, "access-1", token.AccessToken)
			assert.Equal(t, "refresh-1", token.RefreshToken)

			sent := endpoint.LastRequest()
			assert.Equal(t, "authorization_code", sent["grant_type"])
			assert.Equal(t, "code-1", sent["code"])
			assert.Equal(t, "verifier-1", sent["code_verifier"], "PKCE verifier proves we started the flow")
			assert.Equal(t, "client-1", sent["client_id"])
		})
	}
}

// state 預設不進 token exchange 的 body。CSRF 比對在 callback 收回來時就做完了,
// 而 OpenAI 對多出來的 state 會直接回 400 unknown_parameter。只有 Anthropic 要它。
func TestOAuthClientExchangeSendState(t *testing.T) {
	tests := []struct {
		name      string
		sendState bool
		wantState string
	}{
		{name: "state is omitted by default", sendState: false, wantState: ""},
		{name: "state is sent when the provider requires it", sendState: true, wantState: "state-1"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := authtest.NewTokenEndpoint(t)
			client := svc.NewOAuthClient(svc.OAuthConfig{
				TokenURL:  endpoint.URL(),
				ClientID:  "client-1",
				Encoding:  svc.ENCODING_FORM,
				UsePKCE:   true,
				SendState: tc.sendState,
			}, endpoint.Client(), authtest.FixedClock)

			pkce, err := utils.GeneratePKCE()
			require.NoError(t, err)

			_, err = client.Exchange(context.Background(), "code-1", "state-1", pkce)
			require.NoError(t, err)

			assert.Equal(t, tc.wantState, endpoint.LastRequest()["state"])
		})
	}
}

// 帶 client_secret 的 client 必須在 token 請求 (不是 authorize URL) 裡送出 secret。
func TestOAuthClientExchangeWithClientSecret(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	client := svc.NewOAuthClient(svc.OAuthConfig{
		TokenURL:     endpoint.URL(),
		ClientID:     "client-1",
		ClientSecret: "secret-1",
		Encoding:     svc.ENCODING_FORM,
		UsePKCE:      false,
	}, endpoint.Client(), authtest.FixedClock)

	_, err := client.Exchange(context.Background(), "code-1", "", nil)
	require.NoError(t, err)

	sent := endpoint.LastRequest()
	assert.Equal(t, "secret-1", sent["client_secret"])
	assert.NotContains(t, sent, "code_verifier", "a non-PKCE client must not send a verifier")
}

func TestOAuthClientRefresh(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	client := svc.NewOAuthClient(svc.OAuthConfig{
		TokenURL: endpoint.URL(),
		ClientID: "client-1",
		Encoding: svc.ENCODING_FORM,
	}, endpoint.Client(), authtest.FixedClock)

	token, err := client.Refresh(context.Background(), "refresh-0")
	require.NoError(t, err)
	assert.Equal(t, "access-1", token.AccessToken)

	sent := endpoint.LastRequest()
	assert.Equal(t, "refresh_token", sent["grant_type"])
	assert.Equal(t, "refresh-0", sent["refresh_token"])
}

func TestOAuthClientRefreshEmptyToken(t *testing.T) {
	client := svc.NewOAuthClient(svc.OAuthConfig{TokenURL: "https://unused.example.com"}, nil, authtest.FixedClock)
	_, err := client.Refresh(context.Background(), "  ")
	require.ErrorIs(t, err, auth.ErrNoRefreshToken)
}

// 併發 refresh 必須合併成一次網路呼叫: OpenAI 會輪替 refresh token,
// 兩次併發換發會讓其中一次拿到的 token 立刻作廢。
func TestOAuthClientRefreshSingleFlight(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	release := make(chan struct{})
	endpoint.Handler = func(w http.ResponseWriter, _ map[string]string) {
		<-release // 卡住第一個請求,讓其餘的 goroutine 有機會併進來
		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token":  "access-1",
			"refresh_token": "refresh-1",
			"expires_in":    3600,
		})
	}
	client := svc.NewOAuthClient(svc.OAuthConfig{
		TokenURL: endpoint.URL(),
		Encoding: svc.ENCODING_FORM,
	}, endpoint.Client(), authtest.FixedClock)

	const CALLERS = 8
	var wg sync.WaitGroup
	results := make([]*svc.TokenResponse, CALLERS)
	errs := make([]error, CALLERS)
	for i := range CALLERS {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = client.Refresh(context.Background(), "refresh-0")
		}()
	}

	// 給 goroutine 一點時間全部抵達 single-flight 閘門,再放行。
	time.Sleep(50 * time.Millisecond)
	close(release)
	wg.Wait()

	for i := range CALLERS {
		require.NoError(t, errs[i])
		require.NotNil(t, results[i])
		assert.Equal(t, "access-1", results[i].AccessToken)
	}
	assert.Equal(t, int32(1), endpoint.Calls(), "8 concurrent refreshes must collapse into 1 request")
}

func TestOAuthClientHTTPErrors(t *testing.T) {
	tests := []struct {
		name          string
		status        int
		retryAfter    string
		wantRetryable bool
		wantBackoff   time.Duration
	}{
		{
			name:          "500 is retryable",
			status:        http.StatusInternalServerError,
			wantRetryable: true,
			wantBackoff:   svc.REFRESH_MIN_BACKOFF,
		},
		{
			name:          "400 is not retryable",
			status:        http.StatusBadRequest,
			wantRetryable: false,
			wantBackoff:   svc.REFRESH_MIN_BACKOFF,
		},
		{
			name:          "429 honours Retry-After",
			status:        http.StatusTooManyRequests,
			retryAfter:    "30",
			wantRetryable: false,
			wantBackoff:   30 * time.Second,
		},
		{
			name:          "429 clamps an absurd Retry-After to the max backoff",
			status:        http.StatusTooManyRequests,
			retryAfter:    "86400",
			wantRetryable: false,
			wantBackoff:   svc.REFRESH_MAX_BACKOFF,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			endpoint := authtest.NewTokenEndpoint(t)
			endpoint.Handler = func(w http.ResponseWriter, _ map[string]string) {
				if tc.retryAfter != "" {
					w.Header().Set("Retry-After", tc.retryAfter)
				}
				http.Error(w, "nope", tc.status)
			}
			client := svc.NewOAuthClient(svc.OAuthConfig{
				TokenURL: endpoint.URL(),
				Encoding: svc.ENCODING_FORM,
			}, endpoint.Client(), authtest.FixedClock)

			_, err := client.Refresh(context.Background(), "refresh-0")
			require.Error(t, err)

			var httpErr *svc.HTTPError
			require.True(t, errors.As(err, &httpErr))
			assert.Equal(t, tc.status, httpErr.Status)
			assert.Equal(t, tc.wantRetryable, httpErr.Retryable())
			assert.Equal(t, tc.wantBackoff, httpErr.RetryAfter)
		})
	}
}

// 收到 429 後,退避期內的 refresh 直接在本機被擋掉,不再打 provider。
func TestOAuthClientRefreshBackoffBlocksProvider(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	endpoint.Handler = func(w http.ResponseWriter, _ map[string]string) {
		w.Header().Set("Retry-After", "60")
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}
	client := svc.NewOAuthClient(svc.OAuthConfig{
		TokenURL: endpoint.URL(),
		Encoding: svc.ENCODING_FORM,
	}, endpoint.Client(), authtest.FixedClock)

	_, err := client.Refresh(context.Background(), "refresh-0")
	require.Error(t, err)
	require.Equal(t, int32(1), endpoint.Calls())

	_, err = client.Refresh(context.Background(), "refresh-0")
	require.Error(t, err)
	assert.Equal(t, int32(1), endpoint.Calls(), "second refresh must be blocked locally")

	var httpErr *svc.HTTPError
	require.True(t, errors.As(err, &httpErr))
	assert.Contains(t, httpErr.Body, "refresh blocked until")

	// 另一個 refresh token 不受影響 — 封鎖是 per-token 的。
	_, _ = client.Refresh(context.Background(), "refresh-other")
	assert.Equal(t, int32(2), endpoint.Calls())
}

func TestOAuthClientRejectsResponseWithoutAccessToken(t *testing.T) {
	endpoint := authtest.NewTokenEndpoint(t)
	endpoint.Handler = func(w http.ResponseWriter, _ map[string]string) {
		authtest.WriteJSON(w, http.StatusOK, map[string]any{"token_type": "Bearer"})
	}
	client := svc.NewOAuthClient(svc.OAuthConfig{TokenURL: endpoint.URL()}, endpoint.Client(), authtest.FixedClock)

	_, err := client.Refresh(context.Background(), "refresh-0")
	require.ErrorContains(t, err, "no access_token")
}
