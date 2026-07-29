// Package active records and resolves which stored credential a provider
// should use.
//
// The selection lives in the application's own settings file, not beside the
// credentials. That placement is the point: gosdk resolves settings under
// ~/.config/<appName>/, so every application gets its own selection while
// they can all share one credential directory. Two services on the same
// machine, run by the same person, then differ only in which credential they
// pick — which is the only distinction that actually matters here.
//
// Reads go through viper, so config.Default() must have run first; if it has
// not, Lookup simply reports no selection and the caller falls back to its
// own precedence. Writes go through gosdk's config layer, which owns
// settings.local.json — this package never opens the file itself.
package active

import (
	"fmt"
	"strings"

	gosdkconfig "github.com/bizshuk/gosdk/cmd/config"
	"github.com/spf13/viper"
)

// KEY_PREFIX namespaces the selection inside the settings document, so the
// on-disk shape is:
//
//	{"auth": {"active": {"anthropic": "anthropic-dev@example.com_oauth"}}}
const KEY_PREFIX = "auth.active"

// Key is the settings key holding the active credential for one provider
// family. Families are lower-cased so the key matches however the caller
// spelled the provider.
func Key(providerFamily string) string {
	return KEY_PREFIX + "." + strings.ToLower(strings.TrimSpace(providerFamily))
}

// Lookup reports the credential name selected for providerFamily. The second
// result is false when nothing is selected, which is not an error — it means
// the caller should apply its own fallback.
//
// The signature matches svc.ActiveLookup so it can be injected directly.
func Lookup(providerFamily string) (string, bool) {
	name := strings.TrimSpace(viper.GetString(Key(providerFamily)))
	if name == "" {
		return "", false
	}
	return name, true
}

// All returns every provider→credential selection currently configured.
func All() map[string]string {
	return viper.GetStringMapString(KEY_PREFIX)
}

// Set records name as the active credential for providerFamily and returns
// the settings file it was written to.
//
// An empty WriteOptions targets settings.local.json under the app config
// dir — the last layer before APP_ environment variables, so the selection
// wins over settings.json and config.yaml but can still be overridden per
// invocation by APP_AUTH_ACTIVE_<PROVIDER>.
func Set(providerFamily, name string) (string, error) {
	if strings.TrimSpace(providerFamily) == "" {
		return "", fmt.Errorf("active: provider family must not be empty")
	}
	if strings.TrimSpace(name) == "" {
		return "", fmt.Errorf("active: credential name must not be empty")
	}

	report, err := gosdkconfig.Update(
		[]string{Key(providerFamily) + "=" + name},
		gosdkconfig.WriteOptions{},
	)
	if err != nil {
		return "", fmt.Errorf("active: record selection for %q: %w", providerFamily, err)
	}
	return report.Path, nil
}
