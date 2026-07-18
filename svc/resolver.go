package svc

import (
	"context"
	"fmt"
	"github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/utils"
	"slices"
	"strings"
)

// ResolverStore is the credential persistence surface Resolver needs;
// *utils.FileStore satisfies it.
type ResolverStore interface {
	Dir() string
	Load(string) (*model.Credential, error)
	List() ([]*model.Credential, error)
	Save(*model.Credential) error
}

// AuthenticatorFor returns the model.Authenticator able to refresh cred, typically
// auth/provider.For. It is a func type so the mechanism layer stays free of
// the provider registry.
type AuthenticatorFor func(*model.Credential) (model.Authenticator, error)

// EnvLookup abstracts os.LookupEnv so callers and tests control the
// environment API-key fallback.
type EnvLookup func(string) (string, bool)

// UnavailableError reports why no usable credential could be produced for a
// provider. Callers map it onto their own error surface (e.g. the proxy's
// credential_unavailable error).
type UnavailableError struct {
	Message string
	Cause   error
}

func (e *UnavailableError) Error() string {
	if e.Cause != nil {
		return e.Message + ": " + e.Cause.Error()
	}
	return e.Message
}

func (e *UnavailableError) Unwrap() error { return e.Cause }

func unavailable(message string, cause error) error {
	return &UnavailableError{Message: message, Cause: cause}
}

// DefaultEnvironmentNames maps a provider family to the API-key environment
// variable consulted when no stored credential matches. Returned fresh so
// callers may customise their copy without affecting others.
func DefaultEnvironmentNames() map[string]string {
	return map[string]string{
		"anthropic": "ANTHROPIC_API_KEY",
		"openai":    "OPENAI_API_KEY",
		"xai":       "XAI_API_KEY",
		"minimax":   "MINIMAX_API_KEY",
		"ollama":    "OLLAMA_API_KEY",
		"llmbox":    "LLMBOX_API_KEY",
	}
}

// Resolver selects, refreshes, and persists provider credentials: active.json
// selection first, then alphabetic fallback, then environment API keys, with
// expiry-triggered refresh persisted back through the store. It is the shared
// mechanism behind the proxy request path and the runtime ModelProvider path.
type Resolver struct {
	store            ResolverStore
	authenticatorFor AuthenticatorFor
	lookupEnv        EnvLookup
	environmentNames map[string]string
}

// NewResolver builds a Resolver over store. authenticatorFor enables expiry
// refresh; lookupEnv enables the environment fallback. Either may be nil to
// disable that behaviour.
func NewResolver(store ResolverStore, authenticatorFor AuthenticatorFor, lookupEnv EnvLookup) *Resolver {
	return &Resolver{
		store:            store,
		authenticatorFor: authenticatorFor,
		lookupEnv:        lookupEnv,
		environmentNames: DefaultEnvironmentNames(),
	}
}

// Resolve selects a credential for providerFamily and refreshes it when
// expired. Failures are *UnavailableError.
func (r *Resolver) Resolve(ctx context.Context, providerFamily string) (*model.Credential, error) {
	providerFamily = strings.ToLower(strings.TrimSpace(providerFamily))
	if providerFamily == "" {
		return nil, unavailable("credential provider is blank", nil)
	}
	if r == nil || r.store == nil {
		return nil, unavailable("credential store is unavailable", nil)
	}

	cred, err := r.resolveStored(providerFamily)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		cred = r.resolveEnvironment(providerFamily)
	}
	if cred == nil {
		return nil, unavailable(fmt.Sprintf("no credential available for provider %q", providerFamily), nil)
	}
	if err := cred.Validate(); err != nil {
		return nil, unavailable(fmt.Sprintf("invalid credential for provider %q", providerFamily), err)
	}
	if !strings.EqualFold(cred.Provider, providerFamily) {
		return nil, unavailable(fmt.Sprintf("credential provider %q does not match %q", cred.Provider, providerFamily), nil)
	}
	if !cred.Expired(model.DEFAULT_EXPIRY_SKEW) {
		return cred, nil
	}
	return r.refresh(ctx, providerFamily, cred)
}

func (r *Resolver) resolveStored(providerFamily string) (*model.Credential, error) {
	active, err := utils.LoadActiveNames(r.store.Dir())
	if err != nil {
		return nil, unavailable("load active credential selection", err)
	}
	if name, ok := active[providerFamily]; ok {
		cred, err := r.store.Load(name)
		if err != nil {
			return nil, unavailable(fmt.Sprintf("load active credential for provider %q", providerFamily), err)
		}
		if !strings.EqualFold(cred.Provider, providerFamily) {
			return nil, unavailable(fmt.Sprintf("active credential provider %q does not match %q", cred.Provider, providerFamily), nil)
		}
		return cred, nil
	}

	creds, err := r.store.List()
	if err != nil {
		return nil, unavailable(fmt.Sprintf("list credentials for provider %q", providerFamily), err)
	}
	matching := make([]*model.Credential, 0, len(creds))
	for _, cred := range creds {
		if cred != nil && strings.EqualFold(cred.Provider, providerFamily) {
			matching = append(matching, cred)
		}
	}
	slices.SortFunc(matching, func(left, right *model.Credential) int {
		return strings.Compare(left.Name(), right.Name())
	})
	if len(matching) == 0 {
		return nil, nil
	}
	return matching[0], nil
}

func (r *Resolver) resolveEnvironment(providerFamily string) *model.Credential {
	if r.lookupEnv == nil {
		return nil
	}
	name, ok := r.environmentNames[providerFamily]
	if !ok {
		return nil
	}
	value, ok := r.lookupEnv(name)
	if !ok || strings.TrimSpace(value) == "" {
		return nil
	}
	return &model.Credential{
		Provider: providerFamily,
		Kind:     model.KIND_API_KEY,
		APIKey:   value,
	}
}

func (r *Resolver) refresh(ctx context.Context, providerFamily string, cred *model.Credential) (*model.Credential, error) {
	if r.authenticatorFor == nil {
		return nil, unavailable(fmt.Sprintf("refresh credential for provider %q", providerFamily), nil)
	}
	authenticator, err := r.authenticatorFor(cred)
	if err != nil {
		return nil, unavailable(fmt.Sprintf("resolve authenticator for provider %q", providerFamily), err)
	}
	refreshed, err := authenticator.Refresh(ctx, cred)
	if err != nil {
		return nil, unavailable(fmt.Sprintf("refresh credential for provider %q", providerFamily), err)
	}
	if refreshed == nil {
		return nil, unavailable(fmt.Sprintf("refresh credential for provider %q returned nil", providerFamily), nil)
	}
	if err := refreshed.Validate(); err != nil {
		return nil, unavailable(fmt.Sprintf("refresh credential for provider %q returned invalid credential", providerFamily), err)
	}
	if !strings.EqualFold(refreshed.Provider, providerFamily) {
		return nil, unavailable(fmt.Sprintf("refreshed credential provider %q does not match %q", refreshed.Provider, providerFamily), nil)
	}
	if err := r.store.Save(refreshed); err != nil {
		return nil, unavailable(fmt.Sprintf("save refreshed credential for provider %q", providerFamily), err)
	}
	return refreshed, nil
}
