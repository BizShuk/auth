package svc

import (
	"context"
	"errors"
	"github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/utils"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type resolverStoreStub struct {
	dir     string
	creds   map[string]*model.Credential
	saved   []*model.Credential
	saveErr error
}

func newResolverStoreStub(t *testing.T, creds ...*model.Credential) *resolverStoreStub {
	t.Helper()
	stub := &resolverStoreStub{dir: t.TempDir(), creds: map[string]*model.Credential{}}
	for _, cred := range creds {
		stub.creds[cred.Name()] = cred
	}
	return stub
}

func (s *resolverStoreStub) Dir() string { return s.dir }

func (s *resolverStoreStub) Load(name string) (*model.Credential, error) {
	cred, ok := s.creds[name]
	if !ok {
		return nil, errors.New("not found: " + name)
	}
	return cred, nil
}

func (s *resolverStoreStub) List() ([]*model.Credential, error) {
	out := make([]*model.Credential, 0, len(s.creds))
	for _, cred := range s.creds {
		out = append(out, cred)
	}
	return out, nil
}

func (s *resolverStoreStub) Save(cred *model.Credential) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.saved = append(s.saved, cred)
	s.creds[cred.Name()] = cred
	return nil
}

type refreshStub struct {
	refreshed *model.Credential
	err       error
	gotCtx    context.Context
}

func (a *refreshStub) Provider() string { return "openai" }

func (a *refreshStub) Kind() model.Kind { return model.KIND_OAUTH }

func (a *refreshStub) Login(ctx context.Context) (*model.Credential, error) {
	return nil, errors.New("login not supported")
}

func (a *refreshStub) Verify(ctx context.Context, cred *model.Credential) (*model.VerifyResult, error) {
	return nil, errors.New("verify not supported")
}

func (a *refreshStub) Refresh(ctx context.Context, cred *model.Credential) (*model.Credential, error) {
	a.gotCtx = ctx
	return a.refreshed, a.err
}

func TestResolverSelectionOrder(t *testing.T) {
	valid := &model.Credential{Provider: "openai", Kind: model.KIND_API_KEY, APIKey: "stored"}

	tests := []struct {
		name       string
		store      *resolverStoreStub
		active     string
		env        map[string]string
		provider   string
		wantAPIKey string
		wantErr    string
	}{
		{
			name:       "active selection wins over alphabetic",
			store:      newResolverStoreStub(t, valid, &model.Credential{Provider: "openai", Kind: model.KIND_API_KEY, APIKey: "aaa", Account: "aaa"}),
			active:     `{"openai":"` + valid.Name() + `"}`,
			provider:   "openai",
			wantAPIKey: "stored",
		},
		{
			name:       "environment fallback when store empty",
			store:      newResolverStoreStub(t),
			env:        map[string]string{"OPENAI_API_KEY": "from-env"},
			provider:   "openai",
			wantAPIKey: "from-env",
		},
		{
			name:       "ollama environment fallback",
			store:      newResolverStoreStub(t),
			env:        map[string]string{"OLLAMA_API_KEY": "ollama-key"},
			provider:   "ollama",
			wantAPIKey: "ollama-key",
		},
		{
			name:       "llmbox environment fallback",
			store:      newResolverStoreStub(t),
			env:        map[string]string{"LLMBOX_API_KEY": "llmbox-key"},
			provider:   "llmbox",
			wantAPIKey: "llmbox-key",
		},
		{
			name:     "no credential anywhere",
			store:    newResolverStoreStub(t),
			provider: "openai",
			wantErr:  `no credential available for provider "openai"`,
		},
		{
			name:     "blank provider",
			store:    newResolverStoreStub(t),
			provider: "  ",
			wantErr:  "credential provider is blank",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if tc.active != "" {
				require.NoError(t, os.WriteFile(filepath.Join(tc.store.Dir(), utils.ACTIVE_FILE_NAME), []byte(tc.active), 0o600))
			}
			lookup := func(key string) (string, bool) {
				value, ok := tc.env[key]
				return value, ok
			}
			resolver := NewResolver(tc.store, nil, lookup)

			cred, err := resolver.Resolve(context.Background(), tc.provider)
			if tc.wantErr != "" {
				var unavailableErr *UnavailableError
				require.ErrorAs(t, err, &unavailableErr)
				assert.Equal(t, tc.wantErr, unavailableErr.Message)
				return
			}
			require.NoError(t, err)
			assert.Equal(t, tc.wantAPIKey, cred.APIKey)
		})
	}
}

func TestResolverRefreshesExpiredAndPersists(t *testing.T) {
	expired := &model.Credential{
		Provider: "openai", Kind: model.KIND_OAUTH,
		AccessToken: "old", RefreshToken: "refresh",
		ExpiresAt: time.Now().Add(-time.Minute),
	}
	rotated := &model.Credential{
		Provider: "openai", Kind: model.KIND_OAUTH,
		AccessToken: "new", RefreshToken: "refresh",
		ExpiresAt: time.Now().Add(time.Hour),
	}
	store := newResolverStoreStub(t, expired)
	authenticator := &refreshStub{refreshed: rotated}
	resolver := NewResolver(store, func(*model.Credential) (model.Authenticator, error) {
		return authenticator, nil
	}, nil)

	type ctxKey struct{}
	ctx := context.WithValue(context.Background(), ctxKey{}, "request")
	cred, err := resolver.Resolve(ctx, "openai")
	require.NoError(t, err)
	assert.Equal(t, "new", cred.AccessToken, "rotated credential must be returned")
	require.Len(t, store.saved, 1, "rotated credential must be persisted")
	assert.Equal(t, "new", store.saved[0].AccessToken)
	assert.Equal(t, "request", authenticator.gotCtx.Value(ctxKey{}), "request ctx must reach Refresh")
}

func TestResolverNilGuards(t *testing.T) {
	var nilResolver *Resolver
	_, err := nilResolver.Resolve(context.Background(), "openai")
	var unavailableErr *UnavailableError
	require.ErrorAs(t, err, &unavailableErr)
	assert.Equal(t, "credential store is unavailable", unavailableErr.Message)
}

func TestActiveNamesRoundTrip(t *testing.T) {
	dir := t.TempDir()

	names, err := utils.LoadActiveNames(dir)
	require.NoError(t, err)
	assert.Empty(t, names, "missing file must read as empty selection")

	require.NoError(t, utils.SaveActiveName(dir, "openai", "openai-work"))
	require.NoError(t, utils.SaveActiveName(dir, "anthropic", "anthropic-personal"))

	names, err = utils.LoadActiveNames(dir)
	require.NoError(t, err)
	assert.Equal(t, map[string]string{
		"openai":    "openai-work",
		"anthropic": "anthropic-personal",
	}, names)

	info, err := os.Stat(filepath.Join(dir, utils.ACTIVE_FILE_NAME))
	require.NoError(t, err)
	assert.Equal(t, utils.AUTH_FILE_PERM, info.Mode().Perm(), "active.json must keep 0600")

	require.NoError(t, os.WriteFile(filepath.Join(dir, utils.ACTIVE_FILE_NAME), []byte(`{"broken":`), 0o600))
	_, err = utils.LoadActiveNames(dir)
	assert.ErrorContains(t, err, "parse active credential selection")
	assert.ErrorContains(t, utils.SaveActiveName(dir, "openai", "x"), "parse active credential selection",
		"corrupt selection must surface instead of being silently replaced")
}
