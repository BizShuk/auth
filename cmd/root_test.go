package cmd

import (
	"path/filepath"
	"testing"

	"github.com/spf13/cobra"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestInstallMountsCredentialCommandsAndFlags(t *testing.T) {
	root := &cobra.Command{Use: "any-root"}
	require.NoError(t, Install(root, "agentsdk"))

	names := map[string]bool{}
	for _, child := range root.Commands() {
		names[child.Name()] = true
	}
	for _, want := range []string{"login", "list", "verify", "refresh", "logout", "use"} {
		assert.True(t, names[want], "command %q must be mounted", want)
	}
	assert.NotNil(t, root.PersistentFlags().Lookup("auth-dir"))
	assert.NotNil(t, root.PersistentFlags().Lookup("no-browser"))
}

func TestInstallRejectsBadArguments(t *testing.T) {
	assert.Error(t, Install(nil, "agentsdk"))
	assert.Error(t, Install(&cobra.Command{}, "  "))
}

func TestStoreResolvesOverrideAndDefault(t *testing.T) {
	override := t.TempDir()
	flags := &rootFlags{appName: "agentsdk", authDir: override}
	store, err := flags.store()
	require.NoError(t, err)
	assert.Equal(t, override, store.Dir())

	home := t.TempDir()
	t.Setenv("HOME", home)
	flags = &rootFlags{appName: "test-auth-cmd"}
	store, err = flags.store()
	require.NoError(t, err)
	assert.Equal(t, filepath.Join(home, ".config", "test-auth-cmd", "data", "auth"), store.Dir())
}
