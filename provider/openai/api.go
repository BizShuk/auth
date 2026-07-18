// Package openai implements OpenAI authentication: an API key path and an
// OAuth2 + PKCE path against auth.openai.com (the Codex CLI client).
package openai

import (
	model "github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
)

// PROVIDER 是憑證裡記的 provider 名稱。
const PROVIDER = "openai"

// API key 路徑。
const API_BASE = "https://api.openai.com"

// APIKeySpec 描述 OpenAI 的 API key 認證。
func APIKeySpec() svc.APIKeySpec {
	return svc.APIKeySpec{
		Provider:    PROVIDER,
		EnvVars:     []string{"OPENAI_API_KEY"},
		DefaultBase: API_BASE,
		ModelsURL:   func(base string) string { return base + "/v1/models" },
		Authorize:   svc.BearerAuth,
	}
}

// NewAPIKey 建立 API key authenticator。
func NewAPIKey(opts ...model.Option) *svc.APIKeyAuth {
	return svc.NewAPIKey(APIKeySpec(), opts...)
}
