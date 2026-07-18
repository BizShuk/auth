package svc

import (
	"context"
	"fmt"
	"github.com/bizshuk/auth/model"
	"github.com/bizshuk/auth/utils"
	"strings"
	"time"
)

// 這個檔案是三條 login 流程的驅動器,provider 套件把自己的 OAuthClient 交給它:
//
//	RunBrowserLogin — authorization code (瀏覽器 + 本機 callback,或手動貼碼)
//	RunDeviceLogin  — device code (RFC 8628,顯示 user code + 輪詢)
//	VerifyByRefresh — 用 refresh 往返當作線上驗證

// RunBrowserLogin 跑 authorization-code 流程,回傳 token 回應。
//
// 兩種模式:
//
//	瀏覽器模式 (預設) — 啟動本機 callback server,開瀏覽器,等 provider 導回。
//	手動模式 (model.WithManualCode) — 印出 URL,由使用者把 code 貼回來,不開埠。
//	  無頭機器 (SSH / container) 只能走這條。
func RunBrowserLogin(ctx context.Context, client *OAuthClient, o model.Options) (*TokenResponse, error) {
	var (
		pkce *utils.PKCECodes
		err  error
	)
	if client.Config().UsePKCE {
		if pkce, err = utils.GeneratePKCE(); err != nil {
			return nil, err
		}
	}

	state, err := utils.GenerateState()
	if err != nil {
		return nil, err
	}
	authURL, err := client.AuthCodeURL(state, pkce)
	if err != nil {
		return nil, err
	}

	if o.ManualCode != nil {
		raw, err := o.ManualCode(authURL)
		if err != nil {
			return nil, fmt.Errorf("auth: read authorization code: %w", err)
		}
		code, pastedState := splitCodeFragment(strings.TrimSpace(raw))
		if code == "" {
			return nil, fmt.Errorf("auth: empty authorization code")
		}
		// 貼回來的 code 可能帶 #state 尾巴 (Anthropic 的手動流程就是如此),
		// 有的話以它為準,因為那是 provider 真正簽發的 state。
		if pastedState != "" {
			state = pastedState
		}
		return client.Exchange(ctx, code, state, pkce)
	}

	server, err := NewCallbackServer(client.Config().RedirectURI)
	if err != nil {
		return nil, err
	}
	if err := server.Start(); err != nil {
		return nil, err
	}
	defer func() { _ = server.Close(context.WithoutCancel(ctx)) }()

	if err := o.OpenBrowser(authURL); err != nil {
		// 開瀏覽器失敗不該讓整個流程死掉 — 使用者仍可自己貼上 URL。
		fmt.Printf("could not open a browser automatically (%v)\nopen this URL manually:\n\n%s\n\n", err, authURL)
	}

	res, err := server.Wait(ctx, o.LoginTimeout)
	if err != nil {
		return nil, err
	}
	// CSRF: provider 導回的 state 必須與我們簽發的一致,否則這個 code 不是
	// 我們發起的流程換來的。
	if res.State != state {
		return nil, fmt.Errorf("auth: OAuth state mismatch (possible CSRF); discarded the authorization code")
	}
	return client.Exchange(ctx, res.Code, state, pkce)
}

// RunDeviceLogin 跑 device-code 流程 (RFC 8628): 要一組 code、把 user code 顯示
// 給使用者、然後輪詢 token 端點直到對方在瀏覽器裡按下同意。
//
// deviceAuthURL 通常來自 OIDC discovery (見 DiscoverOIDC)。
func RunDeviceLogin(ctx context.Context, client *OAuthClient, deviceAuthURL string, o model.Options) (*TokenResponse, error) {
	device, err := client.RequestDeviceCode(ctx, deviceAuthURL)
	if err != nil {
		return nil, err
	}

	if o.ShowDeviceCode != nil {
		o.ShowDeviceCode(device)
	}
	// device flow 不需要瀏覽器也能完成 (使用者可以拿手機開),所以開不起來
	// 只是少了個便利,不是錯誤 — user code 已經印在畫面上了。
	if o.OpenBrowser != nil && o.ManualCode == nil {
		_ = o.OpenBrowser(device.VerificationURL())
	}

	return client.PollDeviceToken(ctx, device, o.LoginTimeout)
}

// PrintDeviceCode 是 device flow 的預設顯示方式。
func PrintDeviceCode(device *DeviceCode) {
	fmt.Println()
	fmt.Printf("  open this URL:  %s\n", device.VerificationURI)
	fmt.Printf("  and enter code: %s\n", device.UserCode)
	fmt.Println()
	fmt.Println("waiting for the authorization to be approved...")
}

// VerifyByRefresh 用 refresh token 打一次 token 端點作為線上驗證。
//
// 為什麼 OAuth 憑證用 refresh 而不是打 models 端點: 這些 OAuth token 走的是各家
// CLI 專用的後端,沒有一個穩定、免費、無副作用的端點可以拿來 ping。token 端點
// 回 200 是「這份憑證此刻在 provider 端仍然有效」最直接的證據。代價是 provider
// 可能藉此輪替 token,所以結果會帶回新的 model.Credential,呼叫端必須存回去。
func VerifyByRefresh(ctx context.Context, a model.Authenticator, cred *model.Credential) (*model.VerifyResult, error) {
	refreshed, err := a.Refresh(ctx, cred)
	if err != nil {
		return nil, err
	}
	detail := "token endpoint accepted the refresh token"
	if !refreshed.ExpiresAt.IsZero() {
		detail = fmt.Sprintf("%s; new access token expires %s", detail, refreshed.ExpiresAt.Format("2006-01-02 15:04:05 MST"))
	}
	return &model.VerifyResult{
		OK:         true,
		Method:     "token_refresh",
		Detail:     detail,
		Credential: refreshed,
	}, nil
}

// MergeOAuthToken 把 token 回應併成一份 OAuth 憑證。
//
// previous 非 nil 時保留舊欄位 — refresh 回應常常不重發 refresh token,也不帶
// 帳號資訊,不能讓它們被空值蓋掉。provider 套件拿到結果後再補上自己的帳號欄位。
func MergeOAuthToken(provider string, token *TokenResponse, previous *model.Credential, scopes []string, now time.Time) *model.Credential {
	cred := &model.Credential{
		Provider:     provider,
		Kind:         model.KIND_OAUTH,
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		IDToken:      token.IDToken,
		Scopes:       scopes,
		ExpiresAt:    token.ExpiresAt(now),
		LastRefresh:  now,
	}
	if previous != nil {
		cred.Account = previous.Account
		cred.AccountID = previous.AccountID
		cred.ProjectID = previous.ProjectID
		cred.Metadata = previous.Metadata
		if cred.RefreshToken == "" {
			cred.RefreshToken = previous.RefreshToken
		}
		if cred.IDToken == "" {
			cred.IDToken = previous.IDToken
		}
	}
	return cred
}

// splitCodeFragment 拆開 "code#state" 這種貼回格式。
func splitCodeFragment(raw string) (code, state string) {
	code, state, _ = strings.Cut(raw, "#")
	return strings.TrimSpace(code), strings.TrimSpace(state)
}
