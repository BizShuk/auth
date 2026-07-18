package svc

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/utils"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Encoding 是 token 端點的請求 body 編碼。Anthropic 收 JSON,其餘幾家收
// form-urlencoded — 這是各家協定上少數的實質差異。
type Encoding string

const (
	ENCODING_FORM Encoding = "form"
	ENCODING_JSON Encoding = "json"
)

// refresh 遇到 429 時的退避範圍。
const (
	REFRESH_MIN_BACKOFF = 5 * time.Second
	REFRESH_MAX_BACKOFF = 5 * time.Minute
)

// OAuthConfig 描述一個 OAuth2 provider。
type OAuthConfig struct {
	AuthURL     string
	TokenURL    string
	ClientID    string
	RedirectURI string
	Scopes      []string

	// ClientSecret 非空時會隨 token 請求送出。CLI 類的 public client (Anthropic /
	// OpenAI / xAI) 沒有 secret,安全性靠 PKCE;Google 的 installed-app client
	// (Antigravity) 則帶一個公開的 secret。
	ClientSecret string

	// UsePKCE 決定是否走 RFC 7636。public client 一定要開;帶 client_secret 的
	// Google installed-app 流程則不送 challenge。
	UsePKCE bool

	// SendState 決定 token exchange 的 body 要不要帶 state。
	//
	// 預設不帶: state 的用途是 CSRF 比對,而那件事在 callback 收回來的當下就
	// 做完了 (見 RunBrowserLogin),token 端點不需要它。OpenAI 甚至會對多出來的
	// state 直接回 400 unknown_parameter。只有 Anthropic 要求 exchange 帶 state。
	SendState bool

	// AuthParams 是 authorize URL 上的額外靜態參數 (例如 access_type=offline)。
	AuthParams url.Values

	// Encoding 是 token 端點的 body 編碼。
	Encoding Encoding
}

// TokenResponse 是 token 端點的回應。Raw 保留原始 JSON,讓 provider 專屬的
// 欄位 (organization / account) 可以在不污染共用結構的情況下被取出。
type TokenResponse struct {
	AccessToken  string          `json:"access_token"`
	RefreshToken string          `json:"refresh_token"`
	IDToken      string          `json:"id_token"`
	TokenType    string          `json:"token_type"`
	ExpiresIn    int             `json:"expires_in"`
	Raw          json.RawMessage `json:"-"`
}

// ExpiresAt 換算絕對到期時間。ExpiresIn 為 0 時回傳零值 (代表未知)。
func (t *TokenResponse) ExpiresAt(now time.Time) time.Time {
	if t.ExpiresIn <= 0 {
		return time.Time{}
	}
	return now.Add(time.Duration(t.ExpiresIn) * time.Second)
}

// HTTPError 是 token 端點回非 2xx 時的錯誤。Retryable 讓它可以直接被
// middleware/harness 的 retry 認出來 (該處認 interface{ Retryable() bool })。
type HTTPError struct {
	Op     string
	Status int
	Body   string

	// RetryAfter 是 provider 要求的退避時間 (429 才有意義)。
	RetryAfter time.Duration

	retryable bool
}

func (e *HTTPError) Error() string {
	return fmt.Sprintf("auth: %s failed with status %d: %s", e.Op, e.Status, e.Body)
}

// Retryable 只對 5xx 回 true。4xx 是憑證/請求本身的問題,重試沒有意義;
// 429 另外走退避封鎖 (見 OAuthClient.Refresh)。
func (e *HTTPError) Retryable() bool { return e != nil && e.retryable }

// OAuthClient 執行 OAuth2 流程 (authorization-code + PKCE,以及 device-code)。
//
// Refresh 帶兩層保護:
//   - single-flight: 同一個 refresh token 的併發呼叫合併成一次網路請求,
//     避免會輪替 refresh token 的 provider (OpenAI) 因為競態而自我失效。
//   - 429 退避: 收到 Retry-After 後在期限內直接拒絕,不再打 provider。
type OAuthClient struct {
	cfg  OAuthConfig
	http *http.Client
	now  func() time.Time

	mu       sync.Mutex
	inflight map[string]*refreshCall
	blocked  map[string]time.Time
}

type refreshCall struct {
	done chan struct{}
	res  *TokenResponse
	err  error
}

// NewOAuthClient 建立 client。httpClient 為 nil 時使用預設 client。
func NewOAuthClient(cfg OAuthConfig, httpClient *http.Client, now func() time.Time) *OAuthClient {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: 30 * time.Second}
	}
	if now == nil {
		now = time.Now
	}
	if cfg.Encoding == "" {
		cfg.Encoding = ENCODING_FORM
	}
	return &OAuthClient{
		cfg:      cfg,
		http:     httpClient,
		now:      now,
		inflight: make(map[string]*refreshCall),
		blocked:  make(map[string]time.Time),
	}
}

// Config 回傳此 client 的設定 (login 流程需要 RedirectURI / UsePKCE)。
func (c *OAuthClient) Config() OAuthConfig { return c.cfg }

// AuthCodeURL 組出授權 URL。pkce 為 nil 時 (UsePKCE=false) 不送 challenge。
func (c *OAuthClient) AuthCodeURL(state string, pkce *utils.PKCECodes) (string, error) {
	if c.cfg.UsePKCE && pkce == nil {
		return "", fmt.Errorf("auth: PKCE codes are required for %s", c.cfg.AuthURL)
	}

	params := url.Values{}
	for k, vs := range c.cfg.AuthParams {
		for _, v := range vs {
			params.Add(k, v)
		}
	}
	params.Set("client_id", c.cfg.ClientID)
	params.Set("response_type", "code")
	params.Set("redirect_uri", c.cfg.RedirectURI)
	params.Set("state", state)
	if len(c.cfg.Scopes) > 0 {
		params.Set("scope", strings.Join(c.cfg.Scopes, " "))
	}
	if pkce != nil {
		params.Set("code_challenge", pkce.CodeChallenge)
		params.Set("code_challenge_method", "S256")
	}
	return c.cfg.AuthURL + "?" + params.Encode(), nil
}

// Exchange 用 authorization code 換 token。
func (c *OAuthClient) Exchange(ctx context.Context, code, state string, pkce *utils.PKCECodes) (*TokenResponse, error) {
	if c.cfg.UsePKCE && pkce == nil {
		return nil, fmt.Errorf("auth: PKCE codes are required for token exchange")
	}

	params := map[string]string{
		"grant_type":   "authorization_code",
		"client_id":    c.cfg.ClientID,
		"code":         code,
		"redirect_uri": c.cfg.RedirectURI,
	}
	if pkce != nil {
		params["code_verifier"] = pkce.CodeVerifier
	}
	if c.cfg.ClientSecret != "" {
		params["client_secret"] = c.cfg.ClientSecret
	}
	if c.cfg.SendState && state != "" {
		params["state"] = state
	}
	return c.PostToken(ctx, "token exchange", params)
}

// Refresh 用 refresh token 換新的 access token。
func (c *OAuthClient) Refresh(ctx context.Context, refreshToken string) (*TokenResponse, error) {
	if strings.TrimSpace(refreshToken) == "" {
		return nil, model.ErrNoRefreshToken
	}
	if until, blocked := c.blockedUntil(refreshToken); blocked {
		return nil, &HTTPError{
			Op:     "token refresh",
			Status: http.StatusTooManyRequests,
			Body:   fmt.Sprintf("refresh blocked until %s", until.Format(time.RFC3339)),
		}
	}

	call, leader := c.joinRefresh(refreshToken)
	if !leader {
		select {
		case <-call.done:
			return call.res, call.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	params := map[string]string{
		"grant_type":    "refresh_token",
		"client_id":     c.cfg.ClientID,
		"refresh_token": refreshToken,
	}
	if c.cfg.ClientSecret != "" {
		params["client_secret"] = c.cfg.ClientSecret
	}

	// Leader 用 WithoutCancel: 跟隨者的 ctx 取消不該中斷已經在飛的換發,
	// 否則 provider 端可能已經輪替了 refresh token 而我們沒收到新的。
	res, err := c.PostToken(context.WithoutCancel(ctx), "token refresh", params)
	c.finishRefresh(refreshToken, call, res, err)

	var httpErr *HTTPError
	if errors.As(err, &httpErr) && httpErr.Status == http.StatusTooManyRequests {
		c.block(refreshToken, c.now().Add(httpErr.RetryAfter))
	}
	return res, err
}

// PostToken 送出 token 端點請求並解析回應。導出給 provider 套件使用 —
// Vertex 的 JWT-bearer 與 xAI 的 device-code 都是「非標準 grant 的 token 請求」,
// 它們共用這條路徑上的錯誤處理與 Retry-After 解析。
func (c *OAuthClient) PostToken(ctx context.Context, op string, params map[string]string) (*TokenResponse, error) {
	raw, err := c.postTokenRaw(ctx, op, params)
	if err != nil {
		return nil, err
	}

	var token TokenResponse
	if err = json.Unmarshal(raw, &token); err != nil {
		return nil, fmt.Errorf("auth: parse %s response: %w", op, err)
	}
	token.Raw = json.RawMessage(raw)
	if token.AccessToken == "" {
		return nil, fmt.Errorf("auth: %s response has no access_token", op)
	}
	return &token, nil
}

// postTokenRaw 是 PostToken 的底層,回傳未解析的 body。device flow 的輪詢需要
// 它 — 那裡的「錯誤」回應 (authorization_pending) 其實是正常流程的一部分。
func (c *OAuthClient) postTokenRaw(ctx context.Context, op string, params map[string]string) ([]byte, error) {
	var (
		body        io.Reader
		contentType string
	)
	switch c.cfg.Encoding {
	case ENCODING_JSON:
		payload, err := json.Marshal(params)
		if err != nil {
			return nil, fmt.Errorf("auth: marshal %s request: %w", op, err)
		}
		body = strings.NewReader(string(payload))
		contentType = "application/json"
	default:
		form := url.Values{}
		for k, v := range params {
			form.Set(k, v)
		}
		body = strings.NewReader(form.Encode())
		contentType = "application/x-www-form-urlencoded"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.cfg.TokenURL, body)
	if err != nil {
		return nil, fmt.Errorf("auth: create %s request: %w", op, err)
	}
	req.Header.Set("Content-Type", contentType)
	req.Header.Set("Accept", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: %s request failed: %w", op, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("auth: read %s response: %w", op, err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &HTTPError{
			Op:         op,
			Status:     resp.StatusCode,
			Body:       strings.TrimSpace(string(raw)),
			RetryAfter: parseRetryAfter(resp, c.now()),
			retryable:  resp.StatusCode >= http.StatusInternalServerError,
		}
	}
	return raw, nil
}

// parseRetryAfter 讀 Retry-After / Retry-After-Ms,夾在 [MIN, MAX] 之間。
// 缺標頭時回傳 REFRESH_MIN_BACKOFF。
func parseRetryAfter(resp *http.Response, now time.Time) time.Duration {
	if resp == nil {
		return REFRESH_MIN_BACKOFF
	}
	if raw := strings.TrimSpace(resp.Header.Get("Retry-After")); raw != "" {
		if seconds, err := strconv.Atoi(raw); err == nil {
			return clampBackoff(time.Duration(seconds) * time.Second)
		}
		if when, err := http.ParseTime(raw); err == nil {
			return clampBackoff(when.Sub(now))
		}
	}
	if raw := strings.TrimSpace(resp.Header.Get("Retry-After-Ms")); raw != "" {
		if ms, err := strconv.Atoi(raw); err == nil {
			return clampBackoff(time.Duration(ms) * time.Millisecond)
		}
	}
	return REFRESH_MIN_BACKOFF
}

func clampBackoff(d time.Duration) time.Duration {
	if d < REFRESH_MIN_BACKOFF {
		return REFRESH_MIN_BACKOFF
	}
	if d > REFRESH_MAX_BACKOFF {
		return REFRESH_MAX_BACKOFF
	}
	return d
}

// joinRefresh 回傳該 refresh token 的 in-flight 呼叫。leader 為 true 時,
// 呼叫端負責實際發網路請求並在完成後呼叫 finishRefresh。
func (c *OAuthClient) joinRefresh(key string) (*refreshCall, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if call, ok := c.inflight[key]; ok {
		return call, false
	}
	call := &refreshCall{done: make(chan struct{})}
	c.inflight[key] = call
	return call, true
}

func (c *OAuthClient) finishRefresh(key string, call *refreshCall, res *TokenResponse, err error) {
	c.mu.Lock()
	delete(c.inflight, key)
	c.mu.Unlock()
	call.res, call.err = res, err
	close(call.done)
}

func (c *OAuthClient) blockedUntil(key string) (time.Time, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	until, ok := c.blocked[key]
	if !ok {
		return time.Time{}, false
	}
	if c.now().After(until) {
		delete(c.blocked, key)
		return time.Time{}, false
	}
	return until, true
}

func (c *OAuthClient) block(key string, until time.Time) {
	if key == "" {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.blocked[key] = until
}
