package utils_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bizshuk/auth/authtest"
	"github.com/bizshuk/auth/model"
	utils "github.com/bizshuk/auth/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFileStoreRoundTrip(t *testing.T) {
	store, err := utils.NewFileStore(t.TempDir())
	require.NoError(t, err)

	cred := &model.Credential{
		Provider:     "anthropic",
		Kind:         model.KIND_OAUTH,
		Account:      "dev@example.com",
		AccessToken:  "access-1",
		RefreshToken: "refresh-1",
		Scopes:       []string{"user:inference"},
		ExpiresAt:    authtest.FIXED_NOW.Add(time.Hour),
		LastRefresh:  authtest.FIXED_NOW,
		Metadata:     map[string]any{"organization": "Acme"},
	}
	require.NoError(t, store.Save(cred))

	loaded, err := store.Load(cred.Name())
	require.NoError(t, err)
	assert.Equal(t, cred.Provider, loaded.Provider)
	assert.Equal(t, cred.Kind, loaded.Kind)
	assert.Equal(t, cred.Account, loaded.Account)
	assert.Equal(t, cred.AccessToken, loaded.AccessToken)
	assert.Equal(t, cred.RefreshToken, loaded.RefreshToken)
	assert.Equal(t, cred.Scopes, loaded.Scopes)
	assert.True(t, cred.ExpiresAt.Equal(loaded.ExpiresAt))
	assert.Equal(t, "Acme", loaded.Metadata["organization"])
}

// 憑證檔含長期 secret,權限必須是 owner-only。
func TestFileStorePermissions(t *testing.T) {
	store, err := utils.NewFileStore(filepath.Join(t.TempDir(), "auth"))
	require.NoError(t, err)

	cred := &model.Credential{Provider: "openai", Kind: model.KIND_API_KEY, APIKey: "sk-secret"}
	require.NoError(t, store.Save(cred))

	fileInfo, err := os.Stat(store.Path(cred.Name()))
	require.NoError(t, err)
	assert.Equal(t, utils.AUTH_FILE_PERM, fileInfo.Mode().Perm())

	dirInfo, err := os.Stat(store.Dir())
	require.NoError(t, err)
	assert.Equal(t, utils.AUTH_DIR_PERM, dirInfo.Mode().Perm())
}

// Save 用 temp+rename,不該留下任何暫存檔。
func TestFileStoreLeavesNoTempFiles(t *testing.T) {
	store, err := utils.NewFileStore(t.TempDir())
	require.NoError(t, err)
	require.NoError(t, store.Save(&model.Credential{Provider: "openai", Kind: model.KIND_API_KEY, APIKey: "sk-1"}))

	entries, err := os.ReadDir(store.Dir())
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "openai-apikey.json", entries[0].Name())
}

func TestFileStoreSaveRejectsInvalidCredential(t *testing.T) {
	store, err := utils.NewFileStore(t.TempDir())
	require.NoError(t, err)

	err = store.Save(&model.Credential{Provider: "openai", Kind: model.KIND_API_KEY})
	require.ErrorIs(t, err, model.ErrInvalidCredential)

	entries, err := os.ReadDir(store.Dir())
	require.NoError(t, err)
	assert.Empty(t, entries, "an invalid credential must not touch the disk")
}

func TestFileStoreList(t *testing.T) {
	store, err := utils.NewFileStore(t.TempDir())
	require.NoError(t, err)

	require.NoError(t, store.Save(&model.Credential{Provider: "openai", Kind: model.KIND_API_KEY, APIKey: "sk-1"}))
	require.NoError(t, store.Save(&model.Credential{Provider: "anthropic", Kind: model.KIND_OAUTH, Account: "dev@example.com", AccessToken: "at"}))
	require.NoError(t, store.Save(&model.Credential{Provider: "google", Kind: model.KIND_API_KEY, APIKey: "gk-1"}))

	// 一個壞掉的檔案不該讓整個列表爆掉。
	require.NoError(t, os.WriteFile(filepath.Join(store.Dir(), "broken.json"), []byte("{not json"), utils.AUTH_FILE_PERM))

	creds, err := store.List()
	require.NoError(t, err)
	require.Len(t, creds, 3)

	names := make([]string, len(creds))
	for i, c := range creds {
		names[i] = c.Name()
	}
	assert.Equal(t, []string{"anthropic-dev@example.com_oauth", "google-apikey", "openai-apikey"}, names, "list is sorted by name")
}

// 同一個帳號可以同時有 API key 與 OAuth 憑證。_oauth 後綴就是為了讓這兩份
// 憑證落在不同檔案上,不會互相覆蓋。
func TestFileStoreAPIKeyAndOAuthCoexistForSameAccount(t *testing.T) {
	store, err := utils.NewFileStore(t.TempDir())
	require.NoError(t, err)

	apiKey := &model.Credential{
		Provider: "anthropic", Kind: model.KIND_API_KEY,
		Account: "dev@example.com", APIKey: "sk-ant-1",
	}
	oauth := &model.Credential{
		Provider: "anthropic", Kind: model.KIND_OAUTH,
		Account: "dev@example.com", AccessToken: "at-1", RefreshToken: "rt-1",
	}
	require.NotEqual(t, apiKey.Name(), oauth.Name())
	require.NoError(t, store.Save(apiKey))
	require.NoError(t, store.Save(oauth))

	creds, err := store.List()
	require.NoError(t, err)
	require.Len(t, creds, 2, "the OAuth credential must not have overwritten the API key")

	loadedKey, err := store.Load("anthropic-dev@example.com")
	require.NoError(t, err)
	assert.Equal(t, "sk-ant-1", loadedKey.APIKey)

	loadedOAuth, err := store.Load("anthropic-dev@example.com_oauth")
	require.NoError(t, err)
	assert.Equal(t, "at-1", loadedOAuth.AccessToken)
}

func TestFileStoreListEmptyDir(t *testing.T) {
	store, err := utils.NewFileStore(t.TempDir())
	require.NoError(t, err)

	creds, err := store.List()
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestFileStoreLoadMissing(t *testing.T) {
	store, err := utils.NewFileStore(t.TempDir())
	require.NoError(t, err)

	_, err = store.Load("openai-apikey")
	require.ErrorIs(t, err, model.ErrNotFound)
}

func TestFileStoreDelete(t *testing.T) {
	store, err := utils.NewFileStore(t.TempDir())
	require.NoError(t, err)

	cred := &model.Credential{Provider: "openai", Kind: model.KIND_API_KEY, APIKey: "sk-1"}
	require.NoError(t, store.Save(cred))
	require.NoError(t, store.Delete(cred.Name()))

	_, err = store.Load(cred.Name())
	require.ErrorIs(t, err, model.ErrNotFound)

	require.ErrorIs(t, store.Delete(cred.Name()), model.ErrNotFound)
}

// 帳號欄位就算被塞了路徑,憑證檔仍然只會落在 store 目錄裡。
func TestFileStorePathStaysInsideDir(t *testing.T) {
	dir := t.TempDir()
	store, err := utils.NewFileStore(dir)
	require.NoError(t, err)

	cred := &model.Credential{
		Provider:       "vertex",
		Kind:           model.KIND_SERVICE_ACCOUNT,
		Account:        "../../../../tmp/pwned",
		ServiceAccount: map[string]any{"client_email": "x"},
	}
	require.NoError(t, store.Save(cred))

	path, err := filepath.Abs(store.Path(cred.Name()))
	require.NoError(t, err)
	assert.True(t, strings.HasPrefix(path, dir+string(os.PathSeparator)), "path %s escaped %s", path, dir)
}
