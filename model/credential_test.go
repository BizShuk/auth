package model_test

import (
	"testing"
	"time"

	"github.com/bizshuk/auth/authtest"
	"github.com/bizshuk/auth/model"
	svc "github.com/bizshuk/auth/svc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialName(t *testing.T) {
	tests := []struct {
		name string
		cred model.Credential
		want string
	}{
		{
			name: "oauth credential is named after the account email, with an _oauth suffix",
			cred: model.Credential{Provider: "anthropic", Kind: model.KIND_OAUTH, Account: "dev@example.com"},
			want: "anthropic-dev@example.com_oauth",
		},
		{
			name: "api key keeps the bare account name",
			cred: model.Credential{Provider: "anthropic", Kind: model.KIND_API_KEY, Account: "dev@example.com"},
			want: "anthropic-dev@example.com",
		},
		{
			name: "api key without an account falls back to apikey",
			cred: model.Credential{Provider: "openai", Kind: model.KIND_API_KEY},
			want: "openai-apikey",
		},
		{
			name: "oauth without an account is just provider_oauth",
			cred: model.Credential{Provider: "openai", Kind: model.KIND_OAUTH},
			want: "openai_oauth",
		},
		{
			name: "service account",
			cred: model.Credential{Provider: "vertex", Kind: model.KIND_SERVICE_ACCOUNT, Account: "sa@proj.iam.gserviceaccount.com"},
			want: "vertex-sa@proj.iam.gserviceaccount.com",
		},
		{
			name: "path separators are sanitized out of the filename",
			cred: model.Credential{Provider: "vertex", Kind: model.KIND_SERVICE_ACCOUNT, Account: "../../etc/passwd"},
			want: "vertex-..-..-etc-passwd",
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			name := tc.cred.Name()
			assert.Equal(t, tc.want, name)
			// 真正要守住的不變式: 檔名不含路徑分隔符,所以無論帳號欄位被塞了
			// 什麼,憑證檔都只會落在 store 目錄裡。
			assert.NotContains(t, name, "/")
			assert.NotContains(t, name, `\`)
		})
	}
}

func TestCredentialExpiredAt(t *testing.T) {
	now := authtest.FIXED_NOW

	tests := []struct {
		name string
		cred model.Credential
		want bool
	}{
		{
			name: "no expiry means never expired (an API key does not age)",
			cred: model.Credential{},
			want: false,
		},
		{
			name: "expiry in the past",
			cred: model.Credential{ExpiresAt: now.Add(-time.Minute)},
			want: true,
		},
		{
			name: "expiry inside the skew window counts as expired",
			cred: model.Credential{ExpiresAt: now.Add(30 * time.Second)},
			want: true,
		},
		{
			name: "expiry beyond the skew window is still valid",
			cred: model.Credential{ExpiresAt: now.Add(10 * time.Minute)},
			want: false,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, tc.cred.ExpiredAt(now, model.DEFAULT_EXPIRY_SKEW))
		})
	}
}

func TestCredentialValidate(t *testing.T) {
	tests := []struct {
		name    string
		cred    model.Credential
		wantErr bool
	}{
		{
			name: "valid api key",
			cred: model.Credential{Provider: "openai", Kind: model.KIND_API_KEY, APIKey: "sk-test"},
		},
		{
			name: "valid oauth",
			cred: model.Credential{Provider: "anthropic", Kind: model.KIND_OAUTH, AccessToken: "at"},
		},
		{
			name: "valid service account",
			cred: model.Credential{Provider: "vertex", Kind: model.KIND_SERVICE_ACCOUNT, ServiceAccount: map[string]any{"a": 1}},
		},
		{
			name:    "api key without a key",
			cred:    model.Credential{Provider: "openai", Kind: model.KIND_API_KEY},
			wantErr: true,
		},
		{
			name:    "oauth without an access token",
			cred:    model.Credential{Provider: "anthropic", Kind: model.KIND_OAUTH},
			wantErr: true,
		},
		{
			name:    "empty provider",
			cred:    model.Credential{Kind: model.KIND_API_KEY, APIKey: "sk-test"},
			wantErr: true,
		},
		{
			name:    "unknown kind",
			cred:    model.Credential{Provider: "openai", Kind: "magic"},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cred.Validate()
			if tc.wantErr {
				require.ErrorIs(t, err, model.ErrInvalidCredential)
				return
			}
			require.NoError(t, err)
		})
	}
}

// MergeOAuthToken 是所有 OAuth provider 共用的合併邏輯: refresh 回應常常不重發
// refresh token / id_token / 帳號資訊,這些舊欄位必須留著。
func TestMergeOAuthToken(t *testing.T) {
	now := authtest.FIXED_NOW
	scopes := []string{"openid"}

	t.Run("fresh login", func(t *testing.T) {
		token := &svc.TokenResponse{AccessToken: "at-1", RefreshToken: "rt-1", IDToken: "id-1", ExpiresIn: 3600}

		cred := svc.MergeOAuthToken("openai", token, nil, scopes, now)

		assert.Equal(t, "openai", cred.Provider)
		assert.Equal(t, model.KIND_OAUTH, cred.Kind)
		assert.Equal(t, "at-1", cred.AccessToken)
		assert.Equal(t, "rt-1", cred.RefreshToken)
		assert.Equal(t, now.Add(time.Hour), cred.ExpiresAt)
		assert.Equal(t, now, cred.LastRefresh)
	})

	t.Run("refresh keeps what the response omits", func(t *testing.T) {
		previous := &model.Credential{
			Provider: "openai", Kind: model.KIND_OAUTH,
			Account: "dev@example.com", AccountID: "acct-1",
			AccessToken: "at-1", RefreshToken: "rt-1", IDToken: "id-1",
			Metadata: map[string]any{"chatgpt_plan_type": "plus"},
		}
		token := &svc.TokenResponse{AccessToken: "at-2", ExpiresIn: 3600}

		cred := svc.MergeOAuthToken("openai", token, previous, scopes, now)

		assert.Equal(t, "at-2", cred.AccessToken)
		assert.Equal(t, "rt-1", cred.RefreshToken, "the old refresh token must survive")
		assert.Equal(t, "id-1", cred.IDToken)
		assert.Equal(t, "dev@example.com", cred.Account)
		assert.Equal(t, "acct-1", cred.AccountID)
		assert.Equal(t, "plus", cred.Metadata["chatgpt_plan_type"])
	})

	t.Run("a rotated refresh token wins over the old one", func(t *testing.T) {
		previous := &model.Credential{RefreshToken: "rt-1"}
		token := &svc.TokenResponse{AccessToken: "at-2", RefreshToken: "rt-2", ExpiresIn: 3600}

		cred := svc.MergeOAuthToken("openai", token, previous, scopes, now)

		assert.Equal(t, "rt-2", cred.RefreshToken)
	})
}

func TestTokenResponseExpiresAt(t *testing.T) {
	now := authtest.FIXED_NOW

	withExpiry := &svc.TokenResponse{ExpiresIn: 3600}
	assert.Equal(t, now.Add(time.Hour), withExpiry.ExpiresAt(now))

	noExpiry := &svc.TokenResponse{}
	assert.True(t, noExpiry.ExpiresAt(now).IsZero(), "an absent expires_in means unknown, not now")
}
