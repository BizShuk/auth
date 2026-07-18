// Package provider is the registry that hangs every auth provider together.
//
// 分層 (layering):
//
//	auth/                    機制 — Credential / OAuthClient / device flow / FileStore
//	auth/provider/<name>/    一家 provider 一包,只 import auth
//	auth/provider            本包 — registry,import 上面所有子包
//
// 依賴方向是單向的,所以沒有循環。呼叫端只需要這一包:
//
//	cred, err := provider.Login(ctx, "anthropic_oauth")
//	auth, err := provider.For(storedCredential)   // refresh / verify 用
package provider

import (
	"context"
	"fmt"
	"sort"
	"strings"

	auth "github.com/bizshuk/auth/model"
	model "github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/provider/anthropic"
	"github.com/bizshuk/auth/provider/antigravity"
	"github.com/bizshuk/auth/provider/google"
	"github.com/bizshuk/auth/provider/openai"
	"github.com/bizshuk/auth/provider/vertex"
	"github.com/bizshuk/auth/provider/xai"
)

// Provider id: 認證方式直接編碼在 id 裡,而不是另一個 kind 參數。一個 id 就是
// 一條完整的認證路徑,呼叫端不必再處理「這個 provider 支不支援這種 kind」。
//
// OAuth 的 id 帶 _oauth 後綴,與憑證檔名的後綴一致 (見 model.Credential.Name):
// `--provider anthropic_oauth` 登入,磁碟上就會看到 anthropic-<email>_oauth.json。
const (
	ANTHROPIC       = anthropic.PROVIDER
	ANTHROPIC_OAUTH = anthropic.PROVIDER + auth.OAUTH_SUFFIX
	OPENAI          = openai.PROVIDER
	OPENAI_OAUTH    = openai.PROVIDER + auth.OAUTH_SUFFIX
	GOOGLE          = google.PROVIDER
	VERTEX          = vertex.PROVIDER
	XAI             = xai.PROVIDER
	XAI_OAUTH       = xai.PROVIDER + auth.OAUTH_SUFFIX
	ANTIGRAVITY     = antigravity.PROVIDER + auth.OAUTH_SUFFIX
)

// route 是一個 provider id 背後的認證流程。
type route struct {
	provider string
	kind     model.Kind
	build    func(...model.Option) model.Authenticator
}

// ROUTES 是 provider id → 認證流程的唯一真相來源。New / For / Login / IDs 與
// CLI 的旗標說明全部從這裡推導;新增一家 provider 只要加一列。
var ROUTES = map[string]route{
	ANTHROPIC: {anthropic.PROVIDER, model.KIND_API_KEY, func(o ...model.Option) model.Authenticator {
		return anthropic.NewAPIKey(o...)
	}},
	ANTHROPIC_OAUTH: {anthropic.PROVIDER, model.KIND_OAUTH, func(o ...model.Option) model.Authenticator {
		return anthropic.NewOAuth(o...)
	}},
	OPENAI: {openai.PROVIDER, model.KIND_API_KEY, func(o ...model.Option) model.Authenticator {
		return openai.NewAPIKey(o...)
	}},
	OPENAI_OAUTH: {openai.PROVIDER, model.KIND_OAUTH, func(o ...model.Option) model.Authenticator {
		return openai.NewOAuth(o...)
	}},
	GOOGLE: {google.PROVIDER, model.KIND_API_KEY, func(o ...model.Option) model.Authenticator {
		return google.NewAPIKey(o...)
	}},
	VERTEX: {vertex.PROVIDER, model.KIND_SERVICE_ACCOUNT, func(o ...model.Option) model.Authenticator {
		return vertex.New(o...)
	}},
	XAI: {xai.PROVIDER, model.KIND_API_KEY, func(o ...model.Option) model.Authenticator {
		return xai.NewAPIKey(o...)
	}},
	XAI_OAUTH: {xai.PROVIDER, model.KIND_OAUTH, func(o ...model.Option) model.Authenticator {
		return xai.NewOAuth(o...)
	}},
	ANTIGRAVITY: {antigravity.PROVIDER, model.KIND_OAUTH, func(o ...model.Option) model.Authenticator {
		return antigravity.NewOAuth(o...)
	}},
}

// IDs 回傳所有可登入的 provider id (排序過,給 CLI 說明文字用)。
func IDs() []string {
	ids := make([]string, 0, len(ROUTES))
	for id := range ROUTES {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

// New 依 provider id 建出 Authenticator。
func New(id string, opts ...model.Option) (model.Authenticator, error) {
	r, ok := ROUTES[id]
	if !ok {
		return nil, fmt.Errorf("%w: unknown provider %q (want %s)",
			auth.ErrUnsupported, id, strings.Join(IDs(), " | "))
	}
	return r.build(opts...), nil
}

// Login 是單一入口: 選 provider id,拿到一份已驗證過的憑證。
//
// 所有流程都會在回傳前對 provider 驗證一次,因此拿到的憑證是「證明過能用」的。
func Login(ctx context.Context, id string, opts ...model.Option) (*model.Credential, error) {
	authenticator, err := New(id, opts...)
	if err != nil {
		return nil, err
	}
	return authenticator.Login(ctx)
}

// For 依存下來的憑證解析出對應的 Authenticator,讓 refresh / verify 能一視同仁
// 處理任何憑證。
//
// 憑證存的是 (provider, kind) 而不是 provider id — 磁碟上的憑證要記錄的是
// 「它是什麼」,而不是「當初用哪個 CLI 名字取得它」。
func For(cred *model.Credential, opts ...model.Option) (model.Authenticator, error) {
	if cred == nil {
		return nil, fmt.Errorf("%w: nil credential", auth.ErrInvalidCredential)
	}
	for _, r := range ROUTES {
		if r.provider == cred.Provider && r.kind == cred.Kind {
			return r.build(opts...), nil
		}
	}
	return nil, fmt.Errorf("%w: no authenticator for %s/%s", auth.ErrUnsupported, cred.Provider, cred.Kind)
}
