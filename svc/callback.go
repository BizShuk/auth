package svc

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// CallbackResult 是 OAuth provider 導回本機時帶的參數。
type CallbackResult struct {
	Code  string
	State string
	Error string
}

// CallbackServer 是接收 OAuth redirect 的本機 HTTP server。
//
// 監聽位址與路徑都從 redirect URI 推導,因為 provider 端註冊的 redirect URI
// 是固定的 (例如 http://localhost:54545/callback),server 必須完全對上它。
type CallbackServer struct {
	redirectURI string
	path        string

	srv *http.Server
	ln  net.Listener
	ch  chan CallbackResult

	closeOnce sync.Once
}

// NewCallbackServer 依 redirect URI 建立 server (尚未監聽)。
func NewCallbackServer(redirectURI string) (*CallbackServer, error) {
	u, err := url.Parse(redirectURI)
	if err != nil {
		return nil, fmt.Errorf("auth: parse redirect URI %q: %w", redirectURI, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("auth: redirect URI %q has no host", redirectURI)
	}
	path := u.Path
	if path == "" {
		path = "/"
	}
	return &CallbackServer{
		redirectURI: redirectURI,
		path:        path,
		ch:          make(chan CallbackResult, 1),
	}, nil
}

// Start 開始監聽。埠被佔用時直接回錯 — 這通常代表另一個 login 流程還在跑,
// 或本機有服務佔住了 provider 註冊的固定埠。
func (s *CallbackServer) Start() error {
	u, err := url.Parse(s.redirectURI)
	if err != nil {
		return fmt.Errorf("auth: parse redirect URI: %w", err)
	}
	host := u.Host
	if u.Port() == "" {
		host = net.JoinHostPort(u.Hostname(), "80")
	}

	ln, err := net.Listen("tcp", host)
	if err != nil {
		return fmt.Errorf("auth: listen on %s (is another login running?): %w", host, err)
	}
	s.ln = ln

	mux := http.NewServeMux()
	mux.HandleFunc(s.path, s.handleCallback)
	s.srv = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      10 * time.Second,
	}

	go func() {
		if err := s.srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			s.send(CallbackResult{Error: fmt.Sprintf("callback server: %v", err)})
		}
	}()
	return nil
}

// Addr 回傳實際監聽位址 (測試用 :0 時才知道最終埠)。
func (s *CallbackServer) Addr() string {
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

// Wait 等待 provider 導回。逾時或 ctx 取消時回錯。
func (s *CallbackServer) Wait(ctx context.Context, timeout time.Duration) (CallbackResult, error) {
	timer := time.NewTimer(timeout)
	defer timer.Stop()

	select {
	case res := <-s.ch:
		if res.Error != "" {
			return res, fmt.Errorf("auth: OAuth callback returned error: %s", res.Error)
		}
		return res, nil
	case <-timer.C:
		return CallbackResult{}, fmt.Errorf("auth: timed out after %s waiting for OAuth callback", timeout)
	case <-ctx.Done():
		return CallbackResult{}, ctx.Err()
	}
}

// Close 關閉 server。
func (s *CallbackServer) Close(ctx context.Context) error {
	var err error
	s.closeOnce.Do(func() {
		if s.srv == nil {
			return
		}
		shutdownCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		err = s.srv.Shutdown(shutdownCtx)
	})
	return err
}

func (s *CallbackServer) handleCallback(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	query := r.URL.Query()
	res := CallbackResult{
		Code:  query.Get("code"),
		State: query.Get("state"),
		Error: query.Get("error"),
	}
	if res.Error == "" && res.Code == "" {
		res.Error = "no_code"
	}

	s.send(res)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if res.Error != "" {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = fmt.Fprintf(w, CALLBACK_FAILURE_HTML, res.Error)
		return
	}
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte(CALLBACK_SUCCESS_HTML))
}

// send 非阻塞地送出結果 — channel 有 buffer 1,重複的 callback 會被丟棄。
func (s *CallbackServer) send(res CallbackResult) {
	select {
	case s.ch <- res:
	default:
	}
}

const CALLBACK_SUCCESS_HTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>Login complete</title></head>
<body style="font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div style="text-align:center">
<h1 style="font-size:1.5rem">✅ Login complete</h1>
<p style="color:#666">You can close this tab and return to the terminal.</p>
</div></body></html>`

const CALLBACK_FAILURE_HTML = `<!doctype html>
<html><head><meta charset="utf-8"><title>Login failed</title></head>
<body style="font-family:system-ui;display:flex;align-items:center;justify-content:center;height:100vh;margin:0">
<div style="text-align:center">
<h1 style="font-size:1.5rem">❌ Login failed</h1>
<p style="color:#666">%s</p>
</div></body></html>`
