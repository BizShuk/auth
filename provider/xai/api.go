// Package xai implements xAI (Grok) authentication: an API key path and an
// OAuth2 device-code path (RFC 8628) against auth.x.ai.
//
// Device flow 與其他 OAuth provider 的差別: 不開本機 callback 埠,也不需要
// 瀏覽器導回。我們跟 provider 要一組 user code,把它顯示給使用者,然後輪詢
// token 端點直到對方在任何一台裝置上完成授權。無頭機器天然適用。
package xai

import (
	model "github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
)

// PROVIDER 是憑證裡記的 provider 名稱。
const PROVIDER = "xai"

// API key 路徑。xAI 的 REST API 與 OpenAI 相容。
const API_BASE = "https://api.x.ai"

// APIKeySpec 描述 xAI 的 API key 認證。
func APIKeySpec() svc.APIKeySpec {
	return svc.APIKeySpec{
		Provider:    PROVIDER,
		EnvVars:     []string{"XAI_API_KEY"},
		DefaultBase: API_BASE,
		ModelsURL:   func(base string) string { return base + "/v1/models" },
		Authorize:   svc.BearerAuth,
	}
}

// NewAPIKey 建立 API key authenticator。
func NewAPIKey(opts ...model.Option) *svc.APIKeyAuth {
	return svc.NewAPIKey(APIKeySpec(), opts...)
}
