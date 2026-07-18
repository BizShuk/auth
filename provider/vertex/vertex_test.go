package vertex_test

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
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/bizshuk/auth/authtest"
	model "github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/provider/vertex"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const CLIENT_EMAIL = "agent@test-project.iam.gserviceaccount.com"

// serviceAccountJSON 用給定的私鑰組出 service account JSON。
func serviceAccountJSON(t *testing.T, key *rsa.PrivateKey, tokenURL string) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	sa := map[string]any{
		"type":           "service_account",
		"project_id":     "test-project",
		"private_key_id": "key-1",
		"private_key":    string(keyPEM),
		"client_email":   CLIENT_EMAIL,
	}
	if tokenURL != "" {
		sa["token_uri"] = tokenURL
	}
	raw, err := json.Marshal(sa)
	require.NoError(t, err)
	return raw
}

func newKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return key
}

// stsServer 模擬 Google 的 token 端點: 真的驗 assertion 的 RS256 簽章與 claims,
// 過了才發 access token。這樣測試才真的證明我們簽對了 JWT,而不是只證明我們
// 送出了某個字串。
func stsServer(t *testing.T, pub *rsa.PublicKey) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.NoError(t, r.ParseForm())

		if grant := r.PostForm.Get("grant_type"); grant != vertex.JWT_BEARER_GRANT {
			http.Error(w, "unexpected grant_type "+grant, http.StatusBadRequest)
			return
		}
		claims, err := verifyAssertion(r.PostForm.Get("assertion"), pub)
		if err != nil {
			http.Error(w, "bad assertion: "+err.Error(), http.StatusUnauthorized)
			return
		}
		if claims["scope"] != vertex.CLOUD_SCOPE || claims["iss"] != CLIENT_EMAIL {
			http.Error(w, "bad claims", http.StatusUnauthorized)
			return
		}
		authtest.WriteJSON(w, http.StatusOK, map[string]any{
			"access_token": "ya29.vertex-token",
			"token_type":   "Bearer",
			"expires_in":   3600,
		})
	}))
	t.Cleanup(srv.Close)
	return srv
}

// verifyAssertion 驗 JWT 簽章並回傳 claims。
func verifyAssertion(assertion string, pub *rsa.PublicKey) (map[string]any, error) {
	parts := strings.Split(assertion, ".")
	if len(parts) != 3 {
		return nil, errors.New("malformed JWT assertion")
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))
	if err := rsa.VerifyPKCS1v15(pub, crypto.SHA256, digest[:], signature); err != nil {
		return nil, err
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return nil, err
	}
	var claims map[string]any
	return claims, json.Unmarshal(payload, &claims)
}

func TestLogin(t *testing.T) {
	key := newKey(t)
	srv := stsServer(t, &key.PublicKey)

	cred, err := vertex.New(
		model.WithServiceAccountJSON(serviceAccountJSON(t, key, "")),
		model.WithTokenURL(srv.URL),
		model.WithHTTPClient(srv.Client()),
		model.WithLocation("us-central1"),
		model.WithClock(authtest.FixedClock),
	).Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, vertex.PROVIDER, cred.Provider)
	assert.Equal(t, model.KIND_SERVICE_ACCOUNT, cred.Kind)
	assert.Equal(t, CLIENT_EMAIL, cred.Account)
	assert.Equal(t, "test-project", cred.ProjectID)
	assert.Equal(t, "us-central1", cred.Location)
	assert.Equal(t, "ya29.vertex-token", cred.AccessToken, "login mints a real access token")
	assert.Equal(t, authtest.FIXED_NOW.Add(time.Hour), cred.ExpiresAt)
	assert.Equal(t, "vertex-"+CLIENT_EMAIL, cred.Name())
}

// SA 檔自帶的 token_uri 要被用上 (沒有 WithTokenURL 覆寫時)。
func TestUsesTokenURIFromServiceAccount(t *testing.T) {
	key := newKey(t)
	srv := stsServer(t, &key.PublicKey)

	cred, err := vertex.New(
		model.WithServiceAccountJSON(serviceAccountJSON(t, key, srv.URL)),
		model.WithHTTPClient(srv.Client()),
		model.WithClock(authtest.FixedClock),
	).Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, "ya29.vertex-token", cred.AccessToken)
}

func TestRefreshMintsNewToken(t *testing.T) {
	key := newKey(t)
	srv := stsServer(t, &key.PublicKey)
	a := vertex.New(
		model.WithServiceAccountJSON(serviceAccountJSON(t, key, "")),
		model.WithTokenURL(srv.URL),
		model.WithHTTPClient(srv.Client()),
		model.WithClock(authtest.FixedClock),
	)

	cred, err := a.Login(context.Background())
	require.NoError(t, err)

	// 模擬憑證放到過期,再 refresh。
	cred.AccessToken = "stale"
	cred.ExpiresAt = authtest.FIXED_NOW.Add(-time.Hour)

	refreshed, err := a.Refresh(context.Background(), cred)
	require.NoError(t, err)

	assert.Equal(t, "ya29.vertex-token", refreshed.AccessToken)
	assert.Equal(t, authtest.FIXED_NOW.Add(time.Hour), refreshed.ExpiresAt)
	assert.False(t, refreshed.ExpiredAt(authtest.FIXED_NOW, model.DEFAULT_EXPIRY_SKEW))
}

func TestVerify(t *testing.T) {
	key := newKey(t)
	srv := stsServer(t, &key.PublicKey)
	a := vertex.New(
		model.WithServiceAccountJSON(serviceAccountJSON(t, key, "")),
		model.WithTokenURL(srv.URL),
		model.WithHTTPClient(srv.Client()),
		model.WithClock(authtest.FixedClock),
	)

	cred, err := a.Login(context.Background())
	require.NoError(t, err)

	res, err := a.Verify(context.Background(), cred)
	require.NoError(t, err)

	assert.True(t, res.OK)
	assert.Equal(t, "sts_exchange", res.Method)
	assert.Contains(t, res.Detail, CLIENT_EMAIL)
	require.NotNil(t, res.Credential)
}

// 私鑰對不上 SA 帳號時,STS 會拒絕 — 驗證必須誠實地失敗。
func TestVerifyRejectsWrongKey(t *testing.T) {
	keyA, keyB := newKey(t), newKey(t)
	srv := stsServer(t, &keyB.PublicKey) // server 認的是 B 的公鑰

	_, err := vertex.New(
		model.WithServiceAccountJSON(serviceAccountJSON(t, keyA, "")),
		model.WithTokenURL(srv.URL),
		model.WithHTTPClient(srv.Client()),
		model.WithClock(authtest.FixedClock),
	).Login(context.Background())

	require.Error(t, err)
	require.ErrorContains(t, err, "401")
}

func TestLoginWithoutServiceAccount(t *testing.T) {
	_, err := vertex.New().Login(context.Background())
	require.ErrorIs(t, err, model.ErrNoServiceAccount)
}

func TestParseServiceAccount(t *testing.T) {
	valid := serviceAccountJSON(t, newKey(t), "https://oauth2.googleapis.com/token")

	tests := []struct {
		name    string
		raw     []byte
		wantErr string
	}{
		{name: "valid PKCS#8 service account", raw: valid},
		{name: "not JSON", raw: []byte("{nope"), wantErr: "parse service account JSON"},
		{
			name:    "missing client_email",
			raw:     []byte(`{"type":"service_account","private_key":"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"}`),
			wantErr: "missing client_email",
		},
		{
			name:    "missing private_key",
			raw:     []byte(`{"type":"service_account","client_email":"a@b.iam.gserviceaccount.com"}`),
			wantErr: "missing private_key",
		},
		{
			name:    "an OAuth client secret is not a service account",
			raw:     []byte(`{"type":"authorized_user","client_email":"a@b.com","private_key":"x"}`),
			wantErr: "expected a service_account",
		},
		{
			name:    "private key is not valid PEM",
			raw:     []byte(`{"type":"service_account","client_email":"a@b.iam.gserviceaccount.com","private_key":"not-a-pem"}`),
			wantErr: "not valid PEM",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sa, err := vertex.ParseServiceAccount(tc.raw)
			if tc.wantErr != "" {
				require.ErrorContains(t, err, tc.wantErr)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, CLIENT_EMAIL, sa["client_email"])
		})
	}
}
