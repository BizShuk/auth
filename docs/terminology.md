# auth — 術語表 (Terminology)

本檔是領域名詞、狀態值與縮寫的單一定義來源。Go SDK、`auth` CLI 與文件使用同一組正名。

## 核心模型 (Core Model)

| 術語 (Term) | 英文 (English) | 定義 (Definition) | 出處 (Source) |
| --- | --- | --- | --- |
| 憑證 | Credential | 一份已持久化的認證資料，含 provider、kind 與該 kind 專屬欄位 | `model.Credential` |
| 憑證種類 | Kind | 憑證的形態，值為 `KIND_API_KEY` / `KIND_OAUTH` / `KIND_SERVICE_ACCOUNT` | `model.Credential.Kind` |
| 認證器 | Authenticator | 對某一組 (provider, kind) 實作登入、更新、驗證三個動作的介面 | `model.Authenticator` |
| 提供者 | Provider | 一家 LLM 服務業者的識別字，例如 `anthropic`、`openai`、`vertex` | `provider.IDs()` |
| 提供者識別字 | Provider ID | 含流程的完整識別字；同一家業者的不同流程是不同 ID，例如 `anthropic` 與 `anthropic_oauth` | `provider.ANTHROPIC_OAUTH` |
| 路由表 | Routes Table | 從 (provider, kind) 對應到 `Authenticator` 的唯一註冊表 | `provider.ROUTES` |
| 檔案儲存 | File Store | 以 `0600` 權限存放 JSON 憑證的磁碟後端 | `model.FileStore`、`utils` |

## 三個動作 (Three Operations)

| 術語 (Term) | 英文 (English) | 定義 (Definition) | 出處 (Source) |
| --- | --- | --- | --- |
| 登入 | Login | 首次取得憑證並寫入磁碟；依 provider 可能開瀏覽器、印裝置碼或讀環境變數 | `provider.Login` |
| 更新 | Refresh | access token 過期時換取新的；輸入與輸出都是憑證 | `Authenticator.Refresh` |
| 驗證 | Verify | 對 provider 發出真實呼叫以確認憑證可用；可能順帶輪替憑證 | `Authenticator.Verify`、`VerifyResult` |
| 憑證輪替 | Credential Rotation | 驗證過程中 provider 回傳了新憑證的情形；呼叫端`必須`把結果寫回磁碟 | `VerifyResult.Credential` |

## 認證流程 (Authentication Flows)

| 術語 (Term) | 英文 (English) | 定義 (Definition) | 出處 (Source) |
| --- | --- | --- | --- |
| API 金鑰 | API Key | 從環境變數讀取的靜態金鑰；無瀏覽器、無更新流程 | `provider.OPENAI` 等 |
| 瀏覽器回呼流程 | Browser Callback Flow | 開瀏覽器授權、由本機 callback server 接回授權碼的 OAuth 流程 | `svc` callback、`utils` browser |
| 手動貼碼模式 | Manual Code Mode | 無瀏覽器環境下改由使用者把授權碼貼回終端機 | `auth login --no-browser` |
| 裝置碼流程 | Device Code Flow | RFC 8628 流程；印出使用者碼與驗證網址後輪詢取得 token | `svc` device、`provider.XAI_OAUTH` |
| 服務帳戶流程 | Service Account Flow | 以 service account JSON 經 STS 交換取得 token | `provider.VERTEX` |
| PKCE | PKCE | OAuth 授權碼流程的證明金鑰交換機制；`antigravity` 因公開 secret 而停用 | `utils` PKCE |
| 單飛 | Single-flight | 對會在每次更新輪替 refresh token 的 provider（如 `openai_oauth`）必須避免併發更新的約束 | `README.md` 提供者表 |

## 帳號管理 (Account Management)

| 術語 (Term) | 英文 (English) | 定義 (Definition) | 出處 (Source) |
| --- | --- | --- | --- |
| 帳號 | Account | 同一 provider 下的一份具名憑證，對應磁碟上一個 JSON 檔 | `~/.config/agentsdk/data/auth/<name>.json` |
| 使用中選擇 | Active Selection | 每個 provider 目前被選為預設的帳號 | `active.json`、`auth use` |
| 憑證目錄 | Credential Directory | `~/.config/agentsdk/data/auth/`；與 `auth-cli` 聚合 binary 共用，憑證可互通 | `README.md` |

## 分層約束 (Layering Constraints)

以下是硬性規則，違反即為分層錯誤，詳見 `CLAUDE.md`：

- `model` 不 import `svc` 或 `provider`。
- `svc` 不 import `provider` 或任何 `provider/<name>`。
- `provider/<name>` 之間不互相 import。
- `cmd` 與 `main` 是唯一的組裝根 (composition root)。
