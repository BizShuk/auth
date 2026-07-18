// Package google implements Google Gemini API key authentication.
//
// Google 的 OAuth 路徑不在這裡: 以 service account 存取 Vertex AI 走
// auth/provider/vertex,以 Google 帳號登入 Antigravity 走
// auth/provider/antigravity。
package google

import (
	"net/http"

	"github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
)

// PROVIDER 是憑證裡記的 provider 名稱。
const PROVIDER = "google"

// API_BASE 是 Gemini 的官方 API 根位址。
const API_BASE = "https://generativelanguage.googleapis.com"

// APIKeySpec 描述 Google 的 API key 認證。
func APIKeySpec() svc.APIKeySpec {
	return svc.APIKeySpec{
		Provider:    PROVIDER,
		EnvVars:     []string{"GOOGLE_API_KEY", "GEMINI_API_KEY"},
		DefaultBase: API_BASE,
		ModelsURL:   func(base string) string { return base + "/v1beta/models?pageSize=1" },
		Authorize: func(req *http.Request, key string) {
			req.Header.Set("x-goog-api-key", key)
		},
	}
}

// NewAPIKey 建立 API key authenticator。
func NewAPIKey(opts ...model.Option) *svc.APIKeyAuth {
	return svc.NewAPIKey(APIKeySpec(), opts...)
}
