// Package authtest provides fake providers and helpers for testing the auth
// package and every auth/provider/<name> package.
//
// 它存在的理由: provider 套件住在各自的包裡,沒辦法共用 auth 的 _test.go
// 檔案。與其在六個地方各抄一份假 token server,不如把它們放在一個真正的
// (但只給測試用的) 套件裡。
package authtest

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// FIXED_NOW 讓到期時間的斷言可以精確比對。
var FIXED_NOW = time.Date(2026, 7, 15, 12, 0, 0, 0, time.UTC)

// FixedClock 是釘死的時鐘,配 auth.WithClock 使用。
func FixedClock() time.Time { return FIXED_NOW }

// FreePort 借一個空閒埠再還回去。OAuth redirect URI 必須是完整的 host:port,
// 沒辦法用 :0 讓核心挑,所以測試只能先探再用。
func FreePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := ln.Addr().(*net.TCPAddr).Port
	require.NoError(t, ln.Close())
	return port
}

// RedirectURI 回傳一個指向空閒埠的 redirect URI。
func RedirectURI(t *testing.T) string {
	t.Helper()
	return "http://127.0.0.1:" + strconv.Itoa(FreePort(t)) + "/callback"
}

// FollowRedirect 模擬瀏覽器: 拿到 authorize URL 後,直接以 code + state 打回
// 本機 callback server。回傳的函式可以塞給 auth.WithBrowserOpener。
//
// tamperState 非 nil 時可以竄改 state,用來測 CSRF 防護。
func FollowRedirect(t *testing.T, code string, tamperState func(string) string) func(string) error {
	t.Helper()
	return func(authURL string) error {
		u, err := url.Parse(authURL)
		if err != nil {
			return err
		}
		query := u.Query()

		state := query.Get("state")
		if tamperState != nil {
			state = tamperState(state)
		}

		resp, err := http.Get(query.Get("redirect_uri") + "?code=" + url.QueryEscape(code) + "&state=" + url.QueryEscape(state))
		if err != nil {
			return err
		}
		return resp.Body.Close()
	}
}

// TokenEndpoint 是一個可腳本化的假 token 端點,記錄收到的請求供斷言。
type TokenEndpoint struct {
	Server *httptest.Server

	// Handler 可覆寫回應行為 (預設回一組正常 token)。
	Handler func(w http.ResponseWriter, body map[string]string)

	mu       sync.Mutex
	requests []map[string]string
	calls    atomic.Int32
}

// NewTokenEndpoint 起一個假 token 端點,測試結束時自動關閉。
func NewTokenEndpoint(t *testing.T) *TokenEndpoint {
	t.Helper()
	e := &TokenEndpoint{}
	e.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := DecodeTokenRequest(t, r)
		e.mu.Lock()
		e.requests = append(e.requests, body)
		e.mu.Unlock()
		e.calls.Add(1)

		if e.Handler != nil {
			e.Handler(w, body)
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{
			"access_token":  "access-1",
			"refresh_token": "refresh-1",
			"token_type":    "Bearer",
			"expires_in":    3600,
		})
	}))
	t.Cleanup(e.Server.Close)
	return e
}

// URL 是這個假端點的位址。
func (e *TokenEndpoint) URL() string { return e.Server.URL }

// Client 是能連上這個假端點的 HTTP client。
func (e *TokenEndpoint) Client() *http.Client { return e.Server.Client() }

// Calls 是收到的請求數。
func (e *TokenEndpoint) Calls() int32 { return e.calls.Load() }

// LastRequest 回傳最後一次收到的 token 請求參數。
func (e *TokenEndpoint) LastRequest() map[string]string {
	e.mu.Lock()
	defer e.mu.Unlock()
	if len(e.requests) == 0 {
		return nil
	}
	return e.requests[len(e.requests)-1]
}

// DecodeTokenRequest 同時支援 form 與 JSON body,讓同一個假 server 能服務
// Anthropic (JSON) 與其餘 provider (form)。
func DecodeTokenRequest(t *testing.T, r *http.Request) map[string]string {
	t.Helper()
	raw, err := io.ReadAll(r.Body)
	require.NoError(t, err)

	if strings.HasPrefix(r.Header.Get("Content-Type"), "application/json") {
		var body map[string]string
		require.NoError(t, json.Unmarshal(raw, &body))
		return body
	}
	values, err := url.ParseQuery(string(raw))
	require.NoError(t, err)

	body := make(map[string]string, len(values))
	for k := range values {
		body[k] = values.Get(k)
	}
	return body
}

// ModelsServer 是一個假的 models 端點,回傳 payload 與指定狀態碼,並把收到的
// 請求存進 got (供標頭斷言)。
func ModelsServer(t *testing.T, status int, payload any, got **http.Request) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got != nil {
			*got = r.Clone(r.Context())
		}
		WriteJSON(w, status, payload)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// OKModels 是一組「兩個模型」的正常 models 回應。
func OKModels() map[string]any {
	return map[string]any{"data": []any{
		map[string]any{"id": "model-1"},
		map[string]any{"id": "model-2"},
	}}
}

// MakeIDToken 組一個 payload 正確、簽章是假的 JWT。這樣就夠了 — id_token 是
// token 端點透過 TLS 直接給我們的,我們只解 claims,不驗簽。
func MakeIDToken(t *testing.T, claims map[string]any) string {
	t.Helper()
	payload, err := json.Marshal(claims)
	require.NoError(t, err)

	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","typ":"JWT"}`))
	return header + "." + base64.RawURLEncoding.EncodeToString(payload) + ".fake-signature"
}

// WriteJSON 寫出一個 JSON 回應。
func WriteJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}
