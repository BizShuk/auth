package svc_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/bizshuk/auth/authtest"
	"github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// deviceServer 是一個假的 device-flow provider: /device 發 code,/token 在被
// 輪詢 pendingRounds 次之後才發 token (模擬使用者還沒按下同意)。
func deviceServer(t *testing.T, pendingRounds int32) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var polls atomic.Int32

	mux := http.NewServeMux()
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, "client-1", r.PostForm.Get("client_id"))
		assert.Contains(t, r.PostForm.Get("scope"), "offline_access")

		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"device_code":               "device-1",
			"user_code":                 "ABCD-EFGH",
			"verification_uri":          "https://auth.example.com/device",
			"verification_uri_complete": "https://auth.example.com/device?code=ABCD-EFGH",
			"expires_in":                600,
			"interval":                  1,
		})
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())
		assert.Equal(t, svc.DEVICE_CODE_GRANT, r.PostForm.Get("grant_type"))
		assert.Equal(t, "device-1", r.PostForm.Get("device_code"))

		if polls.Add(1) <= pendingRounds {
			// RFC 8628 §3.5: 這不是錯誤,是「使用者還沒按同意」。
			authtest.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": "authorization_pending"})
			return
		}
		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token":  "device-access",
			"refresh_token": "device-refresh",
			"expires_in":    3600,
		})
	})

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv, &polls
}

func deviceClient(srv *httptest.Server) *svc.OAuthClient {
	return svc.NewOAuthClient(svc.OAuthConfig{
		TokenURL: srv.URL + "/token",
		ClientID: "client-1",
		Scopes:   []string{"openid", "offline_access"},
		Encoding: svc.ENCODING_FORM,
	}, srv.Client(), authtest.FixedClock)
}

func TestRequestDeviceCode(t *testing.T) {
	srv, _ := deviceServer(t, 0)

	device, err := deviceClient(srv).RequestDeviceCode(context.Background(), srv.URL+"/device")
	require.NoError(t, err)

	assert.Equal(t, "device-1", device.DeviceCode)
	assert.Equal(t, "ABCD-EFGH", device.UserCode)
	assert.Equal(t, time.Second, device.PollInterval())
	assert.Equal(t, "https://auth.example.com/device?code=ABCD-EFGH", device.VerificationURL(),
		"the complete URL spares the user from typing the code")
}

func TestDeviceCodePollInterval(t *testing.T) {
	assert.Equal(t, svc.DEVICE_DEFAULT_INTERVAL, (&svc.DeviceCode{}).PollInterval(), "no interval means use the default")
	assert.Equal(t, 3*time.Second, (&svc.DeviceCode{Interval: 3}).PollInterval())
}

// authorization_pending 是流程狀態,不是失敗 — 必須繼續輪詢直到使用者同意。
func TestPollDeviceTokenWaitsForApproval(t *testing.T) {
	const PENDING_ROUNDS = 2
	srv, polls := deviceServer(t, PENDING_ROUNDS)
	client := deviceClient(srv)

	device, err := client.RequestDeviceCode(context.Background(), srv.URL+"/device")
	require.NoError(t, err)

	token, err := client.PollDeviceToken(context.Background(), device, 30*time.Second)
	require.NoError(t, err)

	assert.Equal(t, "device-access", token.AccessToken)
	assert.Equal(t, "device-refresh", token.RefreshToken)
	assert.Equal(t, int32(PENDING_ROUNDS+1), polls.Load(), "it kept polling through the pending rounds")
}

func TestPollDeviceTokenTerminalErrors(t *testing.T) {
	tests := []struct {
		name      string
		errorCode string
		wantErr   string
	}{
		{name: "user denied", errorCode: "access_denied", wantErr: "denied"},
		{name: "code expired", errorCode: "expired_token", wantErr: "expired"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				authtest.WriteJSON(w, http.StatusBadRequest, map[string]any{"error": tc.errorCode})
			}))
			t.Cleanup(srv.Close)

			client := svc.NewOAuthClient(svc.OAuthConfig{
				TokenURL: srv.URL, ClientID: "client-1", Encoding: svc.ENCODING_FORM,
			}, srv.Client(), authtest.FixedClock)

			_, err := client.PollDeviceToken(context.Background(),
				&svc.DeviceCode{DeviceCode: "device-1", Interval: 1, ExpiresIn: 600}, 10*time.Second)

			require.ErrorContains(t, err, tc.wantErr)
		})
	}
}

func TestRunDeviceLoginShowsTheUserCode(t *testing.T) {
	srv, _ := deviceServer(t, 1)

	var shown *svc.DeviceCode
	var browsed string
	opts := model.NewOptions(
		model.WithHTTPClient(srv.Client()),
		model.WithClock(authtest.FixedClock),
		model.WithDeviceCodePrompt(func(d any) { shown = d.(*svc.DeviceCode) }),
		model.WithBrowserOpener(func(u string) error { browsed = u; return nil }),
		model.WithLoginTimeout(30*time.Second),
	)

	token, err := svc.RunDeviceLogin(context.Background(), deviceClient(srv), srv.URL+"/device", opts)
	require.NoError(t, err)

	assert.Equal(t, "device-access", token.AccessToken)
	require.NotNil(t, shown, "the user code must be shown — it is the only way the user can approve")
	assert.Equal(t, "ABCD-EFGH", shown.UserCode)
	assert.Equal(t, "https://auth.example.com/device?code=ABCD-EFGH", browsed)
}

func TestDiscoverOIDC(t *testing.T) {
	tests := []struct {
		name     string
		payload  map[string]any
		wantErr  string
		wantEndp string
	}{
		{
			name: "valid discovery document",
			payload: map[string]any{
				"device_authorization_endpoint": "https://auth.example.com/device",
				"token_endpoint":                "https://auth.example.com/token",
			},
			wantEndp: "https://auth.example.com/device",
		},
		{
			name:    "missing device endpoint",
			payload: map[string]any{"token_endpoint": "https://auth.example.com/token"},
			wantErr: "no device_authorization_endpoint",
		},
		{
			name: "plaintext endpoint is rejected",
			payload: map[string]any{
				"device_authorization_endpoint": "http://auth.example.com/device",
				"token_endpoint":                "https://auth.example.com/token",
			},
			wantErr: "must use https",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				authtest.WriteJSON(w, http.StatusOK, tc.payload)
			}))
			t.Cleanup(srv.Close)

			endpoints, err := svc.DiscoverOIDC(context.Background(), srv.Client(), srv.URL)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantEndp, endpoints.DeviceAuthorizationEndpoint)
		})
	}
}
