package google_test

import (
	"context"
	"net/http"
	"testing"

	"github.com/bizshuk/auth/authtest"
	"github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/provider/google"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAPIKeyLogin(t *testing.T) {
	var got *http.Request
	srv := authtest.ModelsServer(t, http.StatusOK, map[string]any{"models": []any{map[string]any{"name": "gemini"}}}, &got)

	cred, err := google.NewAPIKey(
		model.WithAPIKey("AIza-test"),
		model.WithAPIBase(srv.URL),
		model.WithHTTPClient(srv.Client()),
	).Login(context.Background())
	require.NoError(t, err)

	assert.Equal(t, google.PROVIDER, cred.Provider)
	assert.Equal(t, model.KIND_API_KEY, cred.Kind)
	assert.Equal(t, "google-apikey", cred.Name())

	// Google 用 x-goog-api-key,而且 models 端點在 /v1beta 底下。
	require.NotNil(t, got)
	assert.Equal(t, "AIza-test", got.Header.Get("x-goog-api-key"))
	assert.Equal(t, "/v1beta/models", got.URL.Path)
}

// GOOGLE_API_KEY 優先於 GEMINI_API_KEY。
func TestAPIKeyEnvOrder(t *testing.T) {
	srv := authtest.ModelsServer(t, http.StatusOK, map[string]any{"models": []any{}}, nil)

	t.Run("GOOGLE_API_KEY wins", func(t *testing.T) {
		t.Setenv("GOOGLE_API_KEY", "from-google")
		t.Setenv("GEMINI_API_KEY", "from-gemini")

		cred, err := google.NewAPIKey(model.WithAPIBase(srv.URL), model.WithHTTPClient(srv.Client())).
			Login(context.Background())
		require.NoError(t, err)

		assert.Equal(t, "from-google", cred.APIKey)
		assert.Equal(t, "GOOGLE_API_KEY", cred.Metadata["key_source"])
	})

	t.Run("GEMINI_API_KEY is the fallback", func(t *testing.T) {
		t.Setenv("GOOGLE_API_KEY", "")
		t.Setenv("GEMINI_API_KEY", "from-gemini")

		cred, err := google.NewAPIKey(model.WithAPIBase(srv.URL), model.WithHTTPClient(srv.Client())).
			Login(context.Background())
		require.NoError(t, err)

		assert.Equal(t, "from-gemini", cred.APIKey)
		assert.Equal(t, "GEMINI_API_KEY", cred.Metadata["key_source"])
	})
}
