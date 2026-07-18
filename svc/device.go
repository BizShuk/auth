package svc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Device Authorization Grant (RFC 8628) 常數。
const (
	DEVICE_CODE_GRANT = "urn:ietf:params:oauth:grant-type:device_code"

	// DEVICE_DEFAULT_INTERVAL 是端點沒給 interval 時的輪詢間隔。
	DEVICE_DEFAULT_INTERVAL = 5 * time.Second

	// DEVICE_SLOW_DOWN_STEP 是收到 slow_down 時要增加的間隔 (RFC 8628 §3.5)。
	DEVICE_SLOW_DOWN_STEP = 5 * time.Second
)

// DeviceCode 是 device authorization 端點的回應。
//
// 這條流程不需要本機 callback server: 使用者在另一台裝置 (或同一台的瀏覽器)
// 輸入 UserCode 完成授權,我們則對 token 端點輪詢直到它換出 token。
// 無頭機器 (SSH / container) 天然適用。
type DeviceCode struct {
	DeviceCode              string `json:"device_code"`
	UserCode                string `json:"user_code"`
	VerificationURI         string `json:"verification_uri"`
	VerificationURIComplete string `json:"verification_uri_complete"`
	ExpiresIn               int    `json:"expires_in"`
	Interval                int    `json:"interval"`
}

// PollInterval 是兩次輪詢之間該等多久。
func (d *DeviceCode) PollInterval() time.Duration {
	if d.Interval <= 0 {
		return DEVICE_DEFAULT_INTERVAL
	}
	return time.Duration(d.Interval) * time.Second
}

// VerificationURL 是要拿給使用者 (或丟給瀏覽器) 的網址。有 complete 版本時
// 優先用它 — 那個版本已經把 user code 帶在 query 裡,使用者不必手動輸入。
func (d *DeviceCode) VerificationURL() string {
	if d.VerificationURIComplete != "" {
		return d.VerificationURIComplete
	}
	return d.VerificationURI
}

// OIDCEndpoints 是 OIDC discovery (.well-known/openid-configuration) 的結果。
type OIDCEndpoints struct {
	DeviceAuthorizationEndpoint string `json:"device_authorization_endpoint"`
	TokenEndpoint               string `json:"token_endpoint"`
	AuthorizationEndpoint       string `json:"authorization_endpoint"`
	UserinfoEndpoint            string `json:"userinfo_endpoint"`
}

// DiscoverOIDC 讀 provider 的 OIDC discovery 文件解出端點。
//
// 端點是 provider 動態告訴我們的,所以每一個都必須驗證過才用 — 一個被竄改的
// discovery 回應可以把我們的 device code 導去攻擊者的 token 端點。
func DiscoverOIDC(ctx context.Context, httpClient *http.Client, discoveryURL string) (*OIDCEndpoints, error) {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, fmt.Errorf("auth: create discovery request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: discovery request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("auth: read discovery response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{
			Op:        "oidc discovery",
			Status:    resp.StatusCode,
			Body:      strings.TrimSpace(string(raw)),
			retryable: resp.StatusCode >= http.StatusInternalServerError,
		}
	}

	var endpoints OIDCEndpoints
	if err := json.Unmarshal(raw, &endpoints); err != nil {
		return nil, fmt.Errorf("auth: parse discovery response: %w", err)
	}
	for field, value := range map[string]string{
		"device_authorization_endpoint": endpoints.DeviceAuthorizationEndpoint,
		"token_endpoint":                endpoints.TokenEndpoint,
	} {
		if err := validateDiscoveredEndpoint(field, value); err != nil {
			return nil, err
		}
	}
	return &endpoints, nil
}

// validateDiscoveredEndpoint 要求端點存在且是 https —— 明文 http 端點會把
// device code 與 token 暴露在網路上。
func validateDiscoveredEndpoint(field, rawURL string) error {
	rawURL = strings.TrimSpace(rawURL)
	if rawURL == "" {
		return fmt.Errorf("auth: discovery response has no %s", field)
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return fmt.Errorf("auth: discovery %s is not a valid URL: %w", field, err)
	}
	if parsed.Scheme != "https" {
		return fmt.Errorf("auth: discovery %s must use https, got %q", field, rawURL)
	}
	return nil
}

// RequestDeviceCode 向 device authorization 端點要一組 device / user code。
func (c *OAuthClient) RequestDeviceCode(ctx context.Context, deviceAuthURL string) (*DeviceCode, error) {
	form := url.Values{"client_id": {c.cfg.ClientID}}
	if len(c.cfg.Scopes) > 0 {
		form.Set("scope", strings.Join(c.cfg.Scopes, " "))
	}
	if c.cfg.ClientSecret != "" {
		form.Set("client_secret", c.cfg.ClientSecret)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, deviceAuthURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("auth: create device code request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: device code request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("auth: read device code response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &HTTPError{
			Op:        "device authorization",
			Status:    resp.StatusCode,
			Body:      strings.TrimSpace(string(raw)),
			retryable: resp.StatusCode >= http.StatusInternalServerError,
		}
	}

	var code DeviceCode
	if err := json.Unmarshal(raw, &code); err != nil {
		return nil, fmt.Errorf("auth: parse device code response: %w", err)
	}
	if code.DeviceCode == "" || code.UserCode == "" {
		return nil, fmt.Errorf("auth: device authorization response is missing device_code or user_code")
	}
	return &code, nil
}

// PollDeviceToken 輪詢 token 端點直到使用者完成授權。
//
// RFC 8628 §3.5 的錯誤碼不是真的錯誤,而是流程狀態:
//
//	authorization_pending — 使用者還沒按下同意,繼續等
//	slow_down             — 輪太快了,把間隔加大
//	access_denied         — 使用者拒絕,結束
//	expired_token         — device code 過期,結束
func (c *OAuthClient) PollDeviceToken(ctx context.Context, device *DeviceCode, timeout time.Duration) (*TokenResponse, error) {
	deadline := c.now().Add(timeout)
	if device.ExpiresIn > 0 {
		if codeExpiry := c.now().Add(time.Duration(device.ExpiresIn) * time.Second); codeExpiry.Before(deadline) {
			deadline = codeExpiry
		}
	}
	interval := device.PollInterval()

	params := map[string]string{
		"grant_type":  DEVICE_CODE_GRANT,
		"client_id":   c.cfg.ClientID,
		"device_code": device.DeviceCode,
	}
	if c.cfg.ClientSecret != "" {
		params["client_secret"] = c.cfg.ClientSecret
	}

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(interval):
		}

		if c.now().After(deadline) {
			return nil, fmt.Errorf("auth: timed out waiting for the device authorization to be approved")
		}

		raw, err := c.postTokenRaw(ctx, "device token", params)
		if err == nil {
			var token TokenResponse
			if err := json.Unmarshal(raw, &token); err != nil {
				return nil, fmt.Errorf("auth: parse device token response: %w", err)
			}
			if token.AccessToken == "" {
				return nil, fmt.Errorf("auth: device token response has no access_token")
			}
			token.Raw = json.RawMessage(raw)
			return &token, nil
		}

		switch deviceErrorCode(err) {
		case "authorization_pending":
			continue
		case "slow_down":
			interval += DEVICE_SLOW_DOWN_STEP
		case "access_denied":
			return nil, fmt.Errorf("auth: the device authorization was denied")
		case "expired_token":
			return nil, fmt.Errorf("auth: the device code expired before it was approved")
		default:
			return nil, err
		}
	}
}

// deviceErrorCode 從 token 端點的錯誤回應裡取出 OAuth error code。
func deviceErrorCode(err error) string {
	var httpErr *HTTPError
	if !errors.As(err, &httpErr) {
		return ""
	}
	var payload struct {
		Error string `json:"error"`
	}
	if json.Unmarshal([]byte(httpErr.Body), &payload) != nil {
		return ""
	}
	return payload.Error
}
