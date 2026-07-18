package svc_test

import (
	"context"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/bizshuk/auth/authtest"
	svc "github.com/bizshuk/auth/svc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func startCallbackServer(t *testing.T) *svc.CallbackServer {
	t.Helper()
	server, err := svc.NewCallbackServer(authtest.RedirectURI(t))
	require.NoError(t, err)
	require.NoError(t, server.Start())
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	return server
}

func TestCallbackServerReceivesCode(t *testing.T) {
	server := startCallbackServer(t)

	go func() {
		resp, err := http.Get(fmt.Sprintf("http://%s/callback?code=code-1&state=state-1", server.Addr()))
		if err == nil {
			_ = resp.Body.Close()
		}
	}()

	res, err := server.Wait(context.Background(), 5*time.Second)
	require.NoError(t, err)
	assert.Equal(t, "code-1", res.Code)
	assert.Equal(t, "state-1", res.State)
}

func TestCallbackServerSurfacesProviderError(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  string
	}{
		{name: "explicit error param", query: "error=access_denied", want: "access_denied"},
		{name: "missing code", query: "state=state-1", want: "no_code"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			server := startCallbackServer(t)

			go func() {
				resp, err := http.Get(fmt.Sprintf("http://%s/callback?%s", server.Addr(), tc.query))
				if err == nil {
					_ = resp.Body.Close()
				}
			}()

			res, err := server.Wait(context.Background(), 5*time.Second)
			require.Error(t, err)
			assert.Equal(t, tc.want, res.Error)
		})
	}
}

func TestCallbackServerTimeout(t *testing.T) {
	server := startCallbackServer(t)

	_, err := server.Wait(context.Background(), 50*time.Millisecond)
	require.ErrorContains(t, err, "timed out")
}

func TestCallbackServerContextCancel(t *testing.T) {
	server := startCallbackServer(t)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := server.Wait(ctx, 5*time.Second)
	require.ErrorIs(t, err, context.Canceled)
}

// 埠被佔住時要明確報錯,而不是安靜地永遠等不到 callback。
func TestCallbackServerPortInUse(t *testing.T) {
	first := startCallbackServer(t)

	second, err := svc.NewCallbackServer("http://" + first.Addr() + "/callback")
	require.NoError(t, err)
	require.ErrorContains(t, second.Start(), "is another login running?")
}

func TestCallbackServerCloseIsIdempotent(t *testing.T) {
	server := startCallbackServer(t)
	require.NoError(t, server.Close(context.Background()))
	require.NoError(t, server.Close(context.Background()))
}
