package model

import (
	"net/http"
	"time"
)

// DEFAULT_LOGIN_TIMEOUT 是等待使用者完成授權 (瀏覽器或 device code) 的上限。
const DEFAULT_LOGIN_TIMEOUT = 5 * time.Minute

// Options 是所有 Authenticator 共用的可調參數。
//
// 它是導出的,因為 auth/provider/<name> 的實作住在別的套件,必須讀得到這些欄位。
// 端點覆寫 (AuthURL / TokenURL / APIBase) 存在的理由是測試與 gateway:
// httptest server 或公司 proxy 都可以完全取代真實 provider。
type Options struct {
	HTTPClient *http.Client

	// 端點覆寫。空字串代表使用該 provider 的正式端點。
	AuthURL     string
	TokenURL    string
	APIBase     string
	RedirectURI string

	// API key 路徑。
	APIKey string

	// Service account 路徑。
	ServiceAccountJSON []byte
	Location           string

	// 使用者互動。OpenBrowser / ShowDeviceCode 由 caller 注入
	// (auth provider 或 CLI 組合根) — model 不預設,以保持單向依賴
	// (model 不反向依賴 svc.DeviceCode 或 utils 函式)。簽名用 any
	// 是同樣理由;caller 端做 type assertion。
	OpenBrowser func(url string) error
	ManualCode  func(authURL string) (code string, err error)

	// ShowDeviceCode 接收 svc.DeviceCode 由 caller type assertion 處理;
	// model 端刻意不引用 svc 型別以維持單向依賴。
	ShowDeviceCode func(any)

	LoginTimeout time.Duration
	Now          func() time.Time
}

// NewOptions 套用 opts 到一份預設 Options 上。OpenBrowser / ShowDeviceCode
// 預設為 nil;由 caller (auth provider / CLI) 在組裝時注入 utils 或 svc 內
// 對應實作 — model 層刻意不帶任何 ui 實作以保持單向依賴。
func NewOptions(opts ...Option) Options {
	o := Options{
		HTTPClient:   &http.Client{Timeout: 30 * time.Second},
		LoginTimeout: DEFAULT_LOGIN_TIMEOUT,
		Now:          time.Now,
	}
	for _, opt := range opts {
		opt(&o)
	}
	return o
}

// Option 調整 Authenticator 的行為。
type Option func(*Options)

// WithHTTPClient 覆寫 HTTP client (proxy / timeout / httptest transport)。
func WithHTTPClient(c *http.Client) Option {
	return func(o *Options) {
		if c != nil {
			o.HTTPClient = c
		}
	}
}

// WithAuthURL 覆寫 OAuth authorize (或 device authorization) 端點。
func WithAuthURL(u string) Option { return func(o *Options) { o.AuthURL = u } }

// WithTokenURL 覆寫 OAuth token 端點 (Vertex 為 STS 端點)。
func WithTokenURL(u string) Option { return func(o *Options) { o.TokenURL = u } }

// WithAPIBase 覆寫驗證用的 API 根位址 (例如 https://api.anthropic.com)。
func WithAPIBase(u string) Option { return func(o *Options) { o.APIBase = u } }

// WithRedirectURI 覆寫 OAuth redirect URI。本機 callback server 會依它決定
// 監聽的 host:port 與 path,因此改這個等同改監聽埠。
func WithRedirectURI(u string) Option { return func(o *Options) { o.RedirectURI = u } }

// WithAPIKey 直接給定 API key,略過環境變數查找。
func WithAPIKey(k string) Option { return func(o *Options) { o.APIKey = k } }

// WithServiceAccountJSON 直接給定 service account JSON 內容。
func WithServiceAccountJSON(raw []byte) Option {
	return func(o *Options) { o.ServiceAccountJSON = raw }
}

// WithLocation 設定 Vertex 的預設區域 (例如 us-central1)。
func WithLocation(l string) Option { return func(o *Options) { o.Location = l } }

// WithBrowserOpener 覆寫開瀏覽器的方式。測試以此把 authorize URL 直接餵給
// 假的 OAuth server,不需要真的瀏覽器。
func WithBrowserOpener(f func(url string) error) Option {
	return func(o *Options) {
		if f != nil {
			o.OpenBrowser = f
		}
	}
}

// WithManualCode 進入無瀏覽器模式: 印出 authorize URL,由 f 取得使用者貼回的
// authorization code,不啟動本機 callback server。
func WithManualCode(f func(authURL string) (string, error)) Option {
	return func(o *Options) { o.ManualCode = f }
}

// WithDeviceCodePrompt 覆寫 device flow 顯示 user code 的方式。簽名為
// func(any): 傳入的 any 實際為 svc.DeviceCode,由 caller 做 type assertion;
// model 不依賴 svc 型別。
func WithDeviceCodePrompt(f func(any)) Option {
	return func(o *Options) {
		if f != nil {
			o.ShowDeviceCode = f
		}
	}
}

// WithLoginTimeout 設定等待使用者授權的上限。
func WithLoginTimeout(d time.Duration) Option {
	return func(o *Options) {
		if d > 0 {
			o.LoginTimeout = d
		}
	}
}

// WithClock 注入時鐘 (測試用)。
func WithClock(f func() time.Time) Option {
	return func(o *Options) {
		if f != nil {
			o.Now = f
		}
	}
}

// Pick 回傳覆寫值,若為空則回傳預設值。provider 套件用它決定端點。
func Pick(override, fallback string) string {
	if override != "" {
		return override
	}
	return fallback
}
