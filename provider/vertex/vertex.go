// Package vertex implements Google Vertex AI service-account authentication:
// sign an RS256 JWT assertion with the service account key, exchange it at
// Google STS for a one-hour access token.
package vertex

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	auth "github.com/bizshuk/auth/model"
	model "github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
)

// PROVIDER 是憑證裡記的 provider 名稱。
const PROVIDER = "vertex"

// Google service account 的 STS 常數。
const (
	TOKEN_URL        = "https://oauth2.googleapis.com/token"
	CLOUD_SCOPE      = "https://www.googleapis.com/auth/cloud-platform"
	JWT_BEARER_GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer"

	// JWT_LIFETIME 是 assertion 的有效期。Google 允許最長 1 小時。
	JWT_LIFETIME = time.Hour
)

// Auth 是 Vertex AI 的 service-account 認證。
//
// 這裡沒有瀏覽器、沒有 refresh token: 我們拿 service account 的私鑰簽一張
// RS256 JWT assertion,再拿它去 Google STS 換一小時的 access token。所以
// Login / Refresh / Verify 底層是同一件事 — 簽一張 JWT 去換 token,換得到就
// 代表這份 SA 憑證是活的。
type Auth struct {
	opts model.Options
}

// New 建立 authenticator。service account JSON 由 model.WithServiceAccountJSON 提供。
func New(opts ...model.Option) *Auth {
	return &Auth{opts: model.NewOptions(opts...)}
}

func (a *Auth) Provider() string { return PROVIDER }
func (a *Auth) Kind() model.Kind { return model.KIND_SERVICE_ACCOUNT }

// Login 載入 service account JSON,驗證私鑰,並立刻換一次 access token 證明它可用。
func (a *Auth) Login(ctx context.Context) (*model.Credential, error) {
	if len(a.opts.ServiceAccountJSON) == 0 {
		return nil, auth.ErrNoServiceAccount
	}
	sa, err := ParseServiceAccount(a.opts.ServiceAccountJSON)
	if err != nil {
		return nil, err
	}

	cred := &model.Credential{
		Provider:       PROVIDER,
		Kind:           model.KIND_SERVICE_ACCOUNT,
		Account:        stringField(sa, "client_email"),
		ServiceAccount: sa,
		ProjectID:      stringField(sa, "project_id"),
		Location:       a.opts.Location,
		Scopes:         []string{CLOUD_SCOPE},
	}
	return a.Refresh(ctx, cred)
}

// Refresh 用私鑰重新簽 JWT 並換一張新的 access token。
func (a *Auth) Refresh(ctx context.Context, cred *model.Credential) (*model.Credential, error) {
	if cred == nil || len(cred.ServiceAccount) == 0 {
		return nil, auth.ErrNoServiceAccount
	}
	token, err := a.mintAccessToken(ctx, cred.ServiceAccount)
	if err != nil {
		return nil, err
	}

	refreshed := *cred
	refreshed.AccessToken = token.AccessToken
	refreshed.ExpiresAt = token.ExpiresAt(a.opts.Now())
	refreshed.LastRefresh = a.opts.Now()
	if refreshed.Location == "" {
		refreshed.Location = a.opts.Location
	}
	return &refreshed, nil
}

// Verify 對 Google STS 換一次 token — 這就是這份憑證能不能用的最終證據。
func (a *Auth) Verify(ctx context.Context, cred *model.Credential) (*model.VerifyResult, error) {
	refreshed, err := a.Refresh(ctx, cred)
	if err != nil {
		return nil, err
	}
	return &model.VerifyResult{
		OK:     true,
		Method: "sts_exchange",
		Detail: fmt.Sprintf("Google STS issued an access token for %s (expires %s)",
			refreshed.Account, refreshed.ExpiresAt.Format("2006-01-02 15:04:05 MST")),
		Credential: refreshed,
	}, nil
}

// mintAccessToken 簽 JWT assertion 並向 STS 換 access token。
func (a *Auth) mintAccessToken(ctx context.Context, sa map[string]any) (*svc.TokenResponse, error) {
	// 覆寫 (測試) > SA 檔裡的 token_uri > Google 正式端點。
	tokenURL := model.Pick(a.opts.TokenURL, model.Pick(stringField(sa, "token_uri"), TOKEN_URL))

	assertion, err := a.signAssertion(sa, tokenURL)
	if err != nil {
		return nil, err
	}

	// STS 只吃 form-urlencoded,且沒有 client_id 概念,所以借用 OAuthClient 的
	// PostToken 而不是它的 Refresh 語意。
	client := svc.NewOAuthClient(
		svc.OAuthConfig{TokenURL: tokenURL, Encoding: svc.ENCODING_FORM},
		a.opts.HTTPClient, a.opts.Now,
	)
	return client.PostToken(ctx, "vertex sts exchange", map[string]string{
		"grant_type": JWT_BEARER_GRANT,
		"assertion":  assertion,
	})
}

// signAssertion 以 service account 私鑰簽出 RS256 JWT。
func (a *Auth) signAssertion(sa map[string]any, audience string) (string, error) {
	clientEmail := stringField(sa, "client_email")
	if clientEmail == "" {
		return "", fmt.Errorf("%w: service account has no client_email", auth.ErrInvalidCredential)
	}
	key, err := parsePrivateKey(stringField(sa, "private_key"))
	if err != nil {
		return "", err
	}

	now := a.opts.Now()
	header := map[string]any{"alg": "RS256", "typ": "JWT"}
	if kid := stringField(sa, "private_key_id"); kid != "" {
		header["kid"] = kid
	}
	claims := map[string]any{
		"iss":   clientEmail,
		"scope": CLOUD_SCOPE,
		"aud":   audience,
		"iat":   now.Unix(),
		"exp":   now.Add(JWT_LIFETIME).Unix(),
	}

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("vertex: marshal JWT header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("vertex: marshal JWT claims: %w", err)
	}

	signingInput := base64.RawURLEncoding.EncodeToString(headerJSON) + "." +
		base64.RawURLEncoding.EncodeToString(claimsJSON)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		return "", fmt.Errorf("vertex: sign JWT assertion: %w", err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature), nil
}

// ParseServiceAccount 解析 service account JSON 並驗證必要欄位與私鑰格式。
// 私鑰在這裡就會被解過一次 — 壞掉的 SA 檔要在 login 當下失敗,而不是等到
// 半年後第一次 refresh 才炸。
func ParseServiceAccount(raw []byte) (map[string]any, error) {
	var sa map[string]any
	if err := json.Unmarshal(raw, &sa); err != nil {
		return nil, fmt.Errorf("vertex: parse service account JSON: %w", err)
	}
	for _, field := range []string{"client_email", "private_key"} {
		if stringField(sa, field) == "" {
			return nil, fmt.Errorf("%w: service account missing %s", auth.ErrInvalidCredential, field)
		}
	}
	if saType := stringField(sa, "type"); saType != "" && saType != "service_account" {
		return nil, fmt.Errorf("%w: expected a service_account JSON, got type=%q", auth.ErrInvalidCredential, saType)
	}
	if _, err := parsePrivateKey(stringField(sa, "private_key")); err != nil {
		return nil, err
	}
	return sa, nil
}

// parsePrivateKey 解出 RSA 私鑰。接受 PKCS#1 ("RSA PRIVATE KEY") 與 PKCS#8
// ("PRIVATE KEY") 兩種 PEM — Google 發的是 PKCS#8,但手工搬運過的檔案兩種都有。
func parsePrivateKey(raw string) (*rsa.PrivateKey, error) {
	normalized := strings.ReplaceAll(strings.TrimSpace(raw), "\r\n", "\n")
	block, _ := pem.Decode([]byte(normalized))
	if block == nil {
		return nil, fmt.Errorf("%w: private_key is not valid PEM", auth.ErrInvalidCredential)
	}

	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		return key, nil
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: private_key is neither PKCS#1 nor PKCS#8: %v", auth.ErrInvalidCredential, err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("%w: private_key is not an RSA key", auth.ErrInvalidCredential)
	}
	return key, nil
}

func stringField(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return strings.TrimSpace(s)
}
