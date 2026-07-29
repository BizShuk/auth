package svc

import (
	"context"
	"errors"
	"github.com/bizshuk/auth/model"
	"sort"
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

func (s *resolverStoreStub) Read(name string) (*model.Credential, error) {
	cred, ok := s.creds[name]
	if !ok {
		return nil, errors.New("not found: " + name)
	}
	return cred, nil
}

// List mirrors gosdk/file.Store: sorted names, not credentials. The sort is
// load-bearing — Resolver takes the first provider match as the alphabetic
// winner instead of re-sorting.
func (s *resolverStoreStub) List() ([]string, error) {
	out := make([]string, 0, len(s.creds))
	for name := range s.creds {
		out = append(out, name)
	}
	sort.Strings(out)
	return out, nil
}

func (s *resolverStoreStub) Write(name string, cred *model.Credential) error {
	if s.saveErr != nil {
		return s.saveErr
	}
	s.saved = append(s.saved, cred)
	s.creds[name] = cred
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
		active     map[string]string
		env        map[string]string
		provider   string
		wantAPIKey string
		wantErr    string
	}{
		{
			name:       "active selection wins over alphabetic",
			store:      newResolverStoreStub(t, valid, &model.Credential{Provider: "openai", Kind: model.KIND_API_KEY, APIKey: "aaa", Account: "aaa"}),
			active:     map[string]string{"openai": valid.Name()},
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
			lookup := func(key string) (string, bool) {
				value, ok := tc.env[key]
				return value, ok
			}
			active := func(family string) (string, bool) {
				name, ok := tc.active[family]
				return name, ok
			}
			resolver := NewResolver(tc.store, nil, lookup, active)

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
	}, nil, nil)

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
