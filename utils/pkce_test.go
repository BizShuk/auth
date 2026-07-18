package utils_test

import (
	"crypto/sha256"
	"encoding/base64"
	"testing"

	svc "github.com/bizshuk/auth/svc"
	utils "github.com/bizshuk/auth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGeneratePKCE(t *testing.T) {
	pkce, err := utils.GeneratePKCE()
	require.NoError(t, err)

	// RFC 7636: verifier 長度 43–128 字元。
	assert.GreaterOrEqual(t, len(pkce.CodeVerifier), 43)
	assert.LessOrEqual(t, len(pkce.CodeVerifier), 128)
	assert.NotContains(t, pkce.CodeVerifier, "=", "base64url must be unpadded")

	// challenge 必須是 verifier 的 SHA-256 (base64url, 無 padding)。
	sum := sha256.Sum256([]byte(pkce.CodeVerifier))
	assert.Equal(t, base64.RawURLEncoding.EncodeToString(sum[:]), pkce.CodeChallenge)
}

func TestGeneratePKCEIsRandom(t *testing.T) {
	seen := make(map[string]struct{}, 100)
	for range 100 {
		pkce, err := utils.GeneratePKCE()
		require.NoError(t, err)
		_, duplicate := seen[pkce.CodeVerifier]
		require.False(t, duplicate, "code verifier repeated")
		seen[pkce.CodeVerifier] = struct{}{}
	}
}

func TestS256Challenge(t *testing.T) {
	// RFC 7636 Appendix B 的官方測試向量。
	const (
		VERIFIER  = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
		CHALLENGE = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"
	)
	assert.Equal(t, CHALLENGE, utils.S256Challenge(VERIFIER))
}

func TestGenerateState(t *testing.T) {
	state, err := utils.GenerateState()
	require.NoError(t, err)
	assert.NotEmpty(t, state)

	other, err := utils.GenerateState()
	require.NoError(t, err)
	assert.NotEqual(t, state, other)
}

func TestDecodeJWTClaims(t *testing.T) {
	tests := []struct {
		name    string
		token   string
		wantErr bool
	}{
		{
			// {"email":"dev@example.com"}
			name:  "valid payload",
			token: "aGVhZGVy.eyJlbWFpbCI6ImRldkBleGFtcGxlLmNvbSJ9.c2ln",
		},
		{name: "not a JWT", token: "not-a-jwt", wantErr: true},
		{name: "empty", token: "", wantErr: true},
		{name: "payload is not JSON", token: "aGVhZGVy.bm90LWpzb24.c2ln", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			claims, err := svc.DecodeJWTClaims(tc.token)
			if tc.wantErr {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, "dev@example.com", svc.ClaimString(claims, "email"))
		})
	}
}

func TestClaimString(t *testing.T) {
	claims := map[string]any{
		"email": "dev@example.com",
		"https://api.openai.com/auth": map[string]any{
			"chatgpt_account_id": "acct-1",
		},
	}

	assert.Equal(t, "dev@example.com", svc.ClaimString(claims, "email"))
	assert.Equal(t, "acct-1", svc.ClaimString(claims, "https://api.openai.com/auth", "chatgpt_account_id"))
	assert.Empty(t, svc.ClaimString(claims, "missing"))
	assert.Empty(t, svc.ClaimString(claims, "https://api.openai.com/auth", "missing"))
	assert.Empty(t, svc.ClaimString(claims, "email", "nested-into-a-string"))
}
