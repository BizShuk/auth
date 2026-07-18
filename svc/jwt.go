package svc

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// DecodeJWTClaims 解出 JWT 的 payload,不驗簽章。
//
// 這是刻意的: id_token 是 token 端點透過 TLS 直接給我們的,來源已經可信,
// 我們只是要讀出 email / account id 這類 claim 來命名憑證檔。任何需要
// 「信任第三方遞來的 token」的場景都不可以用這個函式。
func DecodeJWTClaims(token string) (map[string]any, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("auth: invalid JWT: expected 3 parts, got %d", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(strings.TrimRight(parts[1], "="))
	if err != nil {
		return nil, fmt.Errorf("auth: decode JWT payload: %w", err)
	}
	var claims map[string]any
	if err := json.Unmarshal(payload, &claims); err != nil {
		return nil, fmt.Errorf("auth: parse JWT claims: %w", err)
	}
	return claims, nil
}

// ClaimString 取出巢狀的字串 claim。path 逐層下探,任一層缺失即回空字串。
//
//	ClaimString(claims, "https://api.openai.com/auth", "chatgpt_account_id")
func ClaimString(claims map[string]any, path ...string) string {
	var current any = claims
	for _, key := range path {
		m, ok := current.(map[string]any)
		if !ok {
			return ""
		}
		current, ok = m[key]
		if !ok {
			return ""
		}
	}
	s, _ := current.(string)
	return s
}
