package utils

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
)

// PKCE_VERIFIER_BYTES 是 code verifier 的隨機位元組數。96 bytes 經 base64url
// 無 padding 編碼後正好 128 字元,是 RFC 7636 允許的上限。
const PKCE_VERIFIER_BYTES = 96

// STATE_BYTES 是 OAuth state (CSRF token) 的隨機位元組數。
const STATE_BYTES = 32

// PKCECodes 是一組 RFC 7636 的 code verifier / challenge。verifier 只留在本機,
// challenge 才送出去,因此攔截到 authorization code 的人無法自行換 token。
type PKCECodes struct {
	CodeVerifier  string
	CodeChallenge string
}

// GeneratePKCE 產生一組 S256 PKCE codes。
func GeneratePKCE() (*PKCECodes, error) {
	verifier, err := randomBase64(PKCE_VERIFIER_BYTES)
	if err != nil {
		return nil, fmt.Errorf("auth: generate code verifier: %w", err)
	}
	return &PKCECodes{
		CodeVerifier:  verifier,
		CodeChallenge: S256Challenge(verifier),
	}, nil
}

// S256Challenge 以 SHA-256 雜湊 verifier 並做 base64url (無 padding) 編碼。
func S256Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// GenerateState 產生 OAuth state 參數。
func GenerateState() (string, error) {
	state, err := randomBase64(STATE_BYTES)
	if err != nil {
		return "", fmt.Errorf("auth: generate state: %w", err)
	}
	return state, nil
}

func randomBase64(n int) (string, error) {
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(buf), nil
}
