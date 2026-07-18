package provider_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/bizshuk/auth/authtest"
	model "github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/provider"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name         string
		id           string
		wantProvider string
		wantKind     model.Kind
		wantErr      bool
	}{
		{name: "anthropic api key", id: provider.ANTHROPIC, wantProvider: "anthropic", wantKind: model.KIND_API_KEY},
		{name: "anthropic oauth", id: provider.ANTHROPIC_OAUTH, wantProvider: "anthropic", wantKind: model.KIND_OAUTH},
		{name: "openai api key", id: provider.OPENAI, wantProvider: "openai", wantKind: model.KIND_API_KEY},
		{name: "openai oauth", id: provider.OPENAI_OAUTH, wantProvider: "openai", wantKind: model.KIND_OAUTH},
		{name: "google api key", id: provider.GOOGLE, wantProvider: "google", wantKind: model.KIND_API_KEY},
		{name: "vertex service account", id: provider.VERTEX, wantProvider: "vertex", wantKind: model.KIND_SERVICE_ACCOUNT},
		{name: "xai api key", id: provider.XAI, wantProvider: "xai", wantKind: model.KIND_API_KEY},
		{name: "xai device oauth", id: provider.XAI_OAUTH, wantProvider: "xai", wantKind: model.KIND_OAUTH},
		{name: "antigravity oauth", id: provider.ANTIGRAVITY, wantProvider: "antigravity", wantKind: model.KIND_OAUTH},
		{name: "google has no oauth flow here", id: "google_oauth", wantErr: true},
		{name: "unknown provider", id: "mistral", wantErr: true},
		{name: "empty id", id: "", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := provider.New(tc.id)
			if tc.wantErr {
				require.ErrorIs(t, err, model.ErrUnsupported)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantProvider, a.Provider())
			assert.Equal(t, tc.wantKind, a.Kind())
		})
	}
}

func TestNewUnknownProviderListsTheOptions(t *testing.T) {
	_, err := provider.New("mistral")
	require.ErrorIs(t, err, model.ErrUnsupported)

	for _, id := range provider.IDs() {
		assert.Contains(t, err.Error(), id, "the error must list every id the CLI accepts")
	}
}

// For 依存下來的憑證 (provider + kind) 解析,而不是 CLI 的 provider id。
func TestFor(t *testing.T) {
	tests := []struct {
		name     string
		cred     model.Credential
		wantKind model.Kind
		wantErr  bool
	}{
		{
			name:     "an anthropic api key credential",
			cred:     model.Credential{Provider: "anthropic", Kind: model.KIND_API_KEY},
			wantKind: model.KIND_API_KEY,
		},
		{
			name:     "an anthropic oauth credential resolves to the browser flow",
			cred:     model.Credential{Provider: "anthropic", Kind: model.KIND_OAUTH},
			wantKind: model.KIND_OAUTH,
		},
		{
			name:     "an xai oauth credential resolves to the device flow",
			cred:     model.Credential{Provider: "xai", Kind: model.KIND_OAUTH},
			wantKind: model.KIND_OAUTH,
		},
		{
			name:     "a vertex credential",
			cred:     model.Credential{Provider: "vertex", Kind: model.KIND_SERVICE_ACCOUNT},
			wantKind: model.KIND_SERVICE_ACCOUNT,
		},
		{
			name:    "no authenticator for this combination",
			cred:    model.Credential{Provider: "vertex", Kind: model.KIND_API_KEY},
			wantErr: true,
		},
		{
			name:    "unknown provider",
			cred:    model.Credential{Provider: "mistral", Kind: model.KIND_API_KEY},
			wantErr: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, err := provider.For(&tc.cred)
			if tc.wantErr {
				require.ErrorIs(t, err, model.ErrUnsupported)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.cred.Provider, a.Provider())
			assert.Equal(t, tc.wantKind, a.Kind())
		})
	}
}

func TestForNilCredential(t *testing.T) {
	_, err := provider.For(nil)
	require.ErrorIs(t, err, model.ErrInvalidCredential)
}

// facade 的 Login 必須真的跑完該 provider 的流程 (這裡是 api key → models 端點)。
func TestLogin(t *testing.T) {
	srv := authtest.ModelsServer(t, http.StatusOK, authtest.OKModels(), nil)

	cred, err := provider.Login(context.Background(), provider.OPENAI,
		model.WithAPIKey("sk-1"), model.WithAPIBase(srv.URL), model.WithHTTPClient(srv.Client()))
	require.NoError(t, err)

	assert.Equal(t, "openai", cred.Provider)
	assert.Equal(t, model.KIND_API_KEY, cred.Kind)
	assert.Equal(t, "sk-1", cred.APIKey)
}

// ROUTES 是 CLI 與 New 共用的真相來源 — 表格列出的 id,New 就必須建得出來,
// 而且建出來的 authenticator 要與表格宣稱的 (provider, kind) 一致。
func TestEveryRouteHasAnAuthenticator(t *testing.T) {
	require.NotEmpty(t, provider.IDs())

	for _, id := range provider.IDs() {
		t.Run(id, func(t *testing.T) {
			a, err := provider.New(id)
			require.NoError(t, err)

			// 每個 id 都要能反向解析回自己 (以憑證的 provider+kind 為鍵)。
			back, err := provider.For(&model.Credential{Provider: a.Provider(), Kind: a.Kind()})
			require.NoError(t, err)
			assert.Equal(t, a.Provider(), back.Provider())
			assert.Equal(t, a.Kind(), back.Kind())
		})
	}
}

// OAuth 的 provider id 後綴與憑證檔名的後綴必須一致 — 使用者用
// `--provider anthropic_oauth` 登入,就該在磁碟上看到 ..._oauth.json。
func TestOAuthIDsMatchCredentialFilenames(t *testing.T) {
	for _, id := range provider.IDs() {
		a, err := provider.New(id)
		require.NoError(t, err)

		cred := &model.Credential{Provider: a.Provider(), Kind: a.Kind()}
		if a.Kind() == model.KIND_OAUTH {
			assert.Equal(t, id, cred.Name(), "an OAuth id must equal the accountless credential filename")
			assert.Contains(t, id, model.OAUTH_SUFFIX)
			continue
		}
		assert.NotContains(t, id, model.OAUTH_SUFFIX, "only OAuth ids carry the suffix")
	}
}
