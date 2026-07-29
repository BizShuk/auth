package svc

import (
	"context"
	"fmt"
	"github.com/bizshuk/auth/model"
	"strings"
)

// ResolverStore is the credential persistence surface Resolver needs. It is
// deliberately shaped like gosdk/file.Store[*model.Credential], which
// satisfies it as-is — the interface exists so this package keeps its
// stdlib-only dependency set and tests can inject a stub, not to abstract
// over a storage choice.
//
// List returns names, not credentials: a single unparseable file must not
// break the whole listing, so the caller decides what to do per entry.
// Names come back sorted, and a credential's file name is its Name(), so
// that order is already the selection order.
type ResolverStore interface {
	Read(name string) (*model.Credential, error)
	List() ([]string, error)
	Write(name string, cred *model.Credential) error
}

// ActiveLookup reports the credential name an application has selected for a
// provider family, or false when it has selected none. auth/active.Lookup is
// the settings-backed implementation.
//
// It is a func type for the same reason AuthenticatorFor and EnvLookup are:
// the selection lives in the application's settings file, and reading that
// means viper — a dependency this package does not take. The composition
// root injects it.
type ActiveLookup func(providerFamily string) (string, bool)

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

// Resolver selects, refreshes, and persists provider credentials. Precedence
// is the application's explicit selection first (ActiveLookup, backed by its
// own settings file), then alphabetic fallback, then environment API keys,
// with expiry-triggered refresh persisted back through the store. It is the
// shared mechanism behind the proxy request path and the runtime
// ModelProvider path.
type Resolver struct {
	store            ResolverStore
	authenticatorFor AuthenticatorFor
	lookupEnv        EnvLookup
	lookupActive     ActiveLookup
	environmentNames map[string]string
}

// NewResolver builds a Resolver over store. authenticatorFor enables expiry
// refresh; lookupEnv enables the environment fallback; lookupActive enables
// the application's explicit selection. Any of them may be nil to disable
// that behaviour — a nil lookupActive means selection falls straight to the
// alphabetic scan, so a composition root that forgets it silently loses the
// user's `auth use` choice.
func NewResolver(store ResolverStore, authenticatorFor AuthenticatorFor, lookupEnv EnvLookup, lookupActive ActiveLookup) *Resolver {
	return &Resolver{
		store:            store,
		authenticatorFor: authenticatorFor,
		lookupEnv:        lookupEnv,
		lookupActive:     lookupActive,
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

// activeName reports the application's explicit selection for providerFamily.
func (r *Resolver) activeName(providerFamily string) (string, bool) {
	if r.lookupActive == nil {
		return "", false
	}
	return r.lookupActive(providerFamily)
}

func (r *Resolver) resolveStored(providerFamily string) (*model.Credential, error) {
	if name, ok := r.activeName(providerFamily); ok {
		cred, err := r.store.Read(name)
		if err != nil {
			return nil, unavailable(fmt.Sprintf("load active credential for provider %q", providerFamily), err)
		}
		if !strings.EqualFold(cred.Provider, providerFamily) {
			return nil, unavailable(fmt.Sprintf("active credential provider %q does not match %q", cred.Provider, providerFamily), nil)
		}
		return cred, nil
	}

	names, err := r.store.List()
	if err != nil {
		return nil, unavailable(fmt.Sprintf("list credentials for provider %q", providerFamily), err)
	}
	// Names arrive sorted and a credential's file name is its Name(), so the
	// first provider match is the alphabetic winner — no re-sort needed.
	for _, name := range names {
		cred, err := r.store.Read(name)
		if err != nil {
			continue // one unreadable file must not hide the rest
		}
		if cred != nil && strings.EqualFold(cred.Provider, providerFamily) {
			return cred, nil
		}
	}
	return nil, nil
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
	if err := r.store.Write(refreshed.Name(), refreshed); err != nil {
		return nil, unavailable(fmt.Sprintf("save refreshed credential for provider %q", providerFamily), err)
	}
	return refreshed, nil
}
