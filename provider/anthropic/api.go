// Package anthropic implements Anthropic (Claude) authentication:
// an API key path and an OAuth2 + PKCE path against claude.ai.
package anthropic

import (
	"net/http"

	"github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
)

// PROVIDER 是憑證裡記的 provider 名稱。
const PROVIDER = "anthropic"

// API key 路徑。
const (
	API_BASE          = "https://api.anthropic.com"
	ANTHROPIC_VERSION = "2023-06-01"
)

// APIKeySpec 描述 Anthropic 的 API key 認證。
func APIKeySpec() svc.APIKeySpec {
	return svc.APIKeySpec{
		Provider:    PROVIDER,
		EnvVars:     []string{"ANTHROPIC_API_KEY"},
		DefaultBase: API_BASE,
		ModelsURL:   func(base string) string { return base + "/v1/models?limit=1" },
		Authorize: func(req *http.Request, key string) {
			req.Header.Set("x-api-key", key)
			req.Header.Set("anthropic-version", ANTHROPIC_VERSION)
		},
	}
}

// NewAPIKey 建立 API key authenticator。
func NewAPIKey(opts ...model.Option) *svc.APIKeyAuth {
	return svc.NewAPIKey(APIKeySpec(), opts...)
}
