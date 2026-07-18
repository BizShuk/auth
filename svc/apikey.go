package svc

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/bizshuk/auth/model"
	"io"
	"net/http"
	"os"
	"strings"
)

// APIKeySpec 描述一家 provider 的 API key 認證細節。
//
// 各家的差別只有三件事: 金鑰放在哪個環境變數、models 端點長什麼樣、金鑰要
// 塞進哪個標頭。把這三件事抽成 spec,API key 的流程本身就能共用。
type APIKeySpec struct {
	// Provider 是憑證裡記的 provider 名稱。
	Provider string

	// EnvVars 是金鑰的環境變數查找順序 (第一個非空的勝出)。
	EnvVars []string

	// DefaultBase 是 provider 的官方 API 根位址。
	DefaultBase string

	// ModelsURL 依 base 組出「列出模型」的 URL。這是驗證金鑰用的端點:
	// 免費、無副作用、回 200 就代表金鑰有效。
	ModelsURL func(base string) string

	// Authorize 把金鑰塞進請求 (x-api-key / Bearer / x-goog-api-key ...)。
	Authorize func(req *http.Request, key string)
}

// APIKeyAuth 是 API key 認證。Login 不需要瀏覽器 — 它從 option 或環境變數
// 取得金鑰,並立刻打一次 models 端點確認金鑰真的能用。
type APIKeyAuth struct {
	spec APIKeySpec
	opts model.Options
}

// NewAPIKey 依 spec 建立 API key authenticator。
func NewAPIKey(spec APIKeySpec, opts ...model.Option) *APIKeyAuth {
	return &APIKeyAuth{spec: spec, opts: model.NewOptions(opts...)}
}

func (a *APIKeyAuth) Provider() string { return a.spec.Provider }
func (a *APIKeyAuth) Kind() model.Kind { return model.KIND_API_KEY }

// Login 解析金鑰 (option > 環境變數) 並線上驗證。
func (a *APIKeyAuth) Login(ctx context.Context) (*model.Credential, error) {
	key := strings.TrimSpace(a.opts.APIKey)
	source := "flag"
	if key == "" {
		key, source = a.keyFromEnv()
	}
	if key == "" {
		return nil, fmt.Errorf("%w: tried %s", model.ErrNoAPIKey, strings.Join(a.spec.EnvVars, ", "))
	}

	cred := &model.Credential{
		Provider:    a.spec.Provider,
		Kind:        model.KIND_API_KEY,
		APIKey:      key,
		BaseURL:     a.opts.APIBase,
		LastRefresh: a.opts.Now(),
		Metadata: map[string]any{
			"key_source": source,
			"key_suffix": keySuffix(key),
		},
	}

	// 立刻驗證: 存下一把打不通的金鑰只會把失敗延後到第一次推論才爆。
	if _, err := a.Verify(ctx, cred); err != nil {
		return nil, err
	}
	return cred, nil
}

// Refresh 對 API key 沒有意義 — 金鑰不會過期,也沒有 refresh token。
func (a *APIKeyAuth) Refresh(_ context.Context, _ *model.Credential) (*model.Credential, error) {
	return nil, fmt.Errorf("%w: api_key", model.ErrRefreshUnsupported)
}

// Verify 打該 provider 的 models 端點。回 200 即代表金鑰有效。
//
// 端點優先序: 明確的 model.WithAPIBase > 憑證裡存的 BaseURL > provider 官方端點。
// 對 gateway 發的金鑰必須驗回同一個 gateway。
func (a *APIKeyAuth) Verify(ctx context.Context, cred *model.Credential) (*model.VerifyResult, error) {
	if cred == nil || strings.TrimSpace(cred.APIKey) == "" {
		return nil, fmt.Errorf("%w: api_key credential has no key", model.ErrInvalidCredential)
	}

	base := model.Pick(a.opts.APIBase, model.Pick(cred.BaseURL, a.spec.DefaultBase))
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, a.spec.ModelsURL(base), nil)
	if err != nil {
		return nil, fmt.Errorf("auth: create %s models request: %w", a.spec.Provider, err)
	}
	req.Header.Set("Accept", "application/json")
	a.spec.Authorize(req, cred.APIKey)

	resp, err := a.opts.HTTPClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("auth: %s models request failed: %w", a.spec.Provider, err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("auth: read %s models response: %w", a.spec.Provider, err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, &HTTPError{
			Op:        fmt.Sprintf("%s api key verification", a.spec.Provider),
			Status:    resp.StatusCode,
			Body:      strings.TrimSpace(string(raw)),
			retryable: resp.StatusCode >= http.StatusInternalServerError,
		}
	}

	return &model.VerifyResult{
		OK:     true,
		Method: "models_endpoint",
		Detail: fmt.Sprintf("HTTP 200 from %s, %d model(s) visible", req.URL.Host, countModels(raw)),
	}, nil
}

func (a *APIKeyAuth) keyFromEnv() (key, source string) {
	for _, name := range a.spec.EnvVars {
		if v := strings.TrimSpace(os.Getenv(name)); v != "" {
			return v, name
		}
	}
	return "", ""
}

// BearerAuth 是最常見的金鑰標頭 (OpenAI / xAI)。
func BearerAuth(req *http.Request, key string) {
	req.Header.Set("Authorization", "Bearer "+key)
}

// countModels 盡力數出回應裡的 model 筆數。各家的 JSON 形狀不同 (data / models),
// 數不出來時回 0 — 這只是給人看的細節,不影響驗證結果。
func countModels(raw []byte) int {
	var payload struct {
		Data   []json.RawMessage `json:"data"`
		Models []json.RawMessage `json:"models"`
	}
	if err := json.Unmarshal(raw, &payload); err != nil {
		return 0
	}
	if len(payload.Data) > 0 {
		return len(payload.Data)
	}
	return len(payload.Models)
}

// keySuffix 取金鑰末四碼,讓 list 指令能辨識金鑰而不外洩它。
func keySuffix(key string) string {
	if len(key) <= 4 {
		return "****"
	}
	return "..." + key[len(key)-4:]
}
