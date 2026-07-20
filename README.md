# auth

LLM provider authentication for the bizshuk/agentsdk family. One module covers
the three things every consumer needs:

1. **Log in** to a provider (API key paste, OAuth browser flow, OAuth device
   code, Google service account).
2. **Refresh** the stored credential when its access token expires.
3. **Verify** a stored credential against the provider before you trust it.

The same code drives the standalone `auth` CLI and the in-process Go SDK that
other agentsdk services link against.

---

## Quick start (Go SDK)

```go
import (
    "context"
    "github.com/bizshuk/auth/provider"
)

// 1. Log in once — opens a browser (or prints a device code) and writes
//    ~/.config/agentsdk/data/auth/<name>.json with mode 0600.
cred, err := provider.Login(ctx, provider.ANTHROPIC_OAUTH)

// 2. Use the stored credential later. provider.For looks up the right
//    Authenticator from cred.(Provider, Kind) — you do not import any
//    provider/<name> subpackage.
auth, err := provider.For(cred)
refreshed, err := auth.Refresh(ctx, cred)         // 401 → new access token
result,   err := auth.Verify(ctx, refreshed)      // real provider call
if result.Credential != nil {                     // verify may rotate
    // caller MUST persist result.Credential back to disk
}
```

API-key providers work the same way — `provider.Login(ctx, provider.OPENAI)`
reads from the env var (`OPENAI_API_KEY`) and returns a `KIND_API_KEY`
credential. No browser, no refresh.

---

## Quick start (CLI)

```bash
# one-shot login (interactive)
auth login --provider anthropic_oauth

# headless machine — no browser, paste the code back
auth login --provider anthropic_oauth --no-browser

# refresh an existing credential in place
auth refresh --provider anthropic_oauth

# verify a credential against the live provider
auth verify --provider anthropic_oauth

# switch which account is "active" for a provider family
auth use anthropic-oauth --name dev@example.com_oauth
auth list
```

Credentials live in `~/.config/agentsdk/data/auth/`:

```
active.json                                 # active selection per provider
anthropic-dev@example.com_oauth.json        # one file per account, mode 0600
openai-apikey.json
vertex-agent@proj.iam.gserviceaccount.com.json
```

The same directory is shared with the `auth-cli` aggregate binary, so
credentials created by either are interchangeable.

---

## Supported providers

| ID | Kind | Flow | Notes |
|---|---|---|---|
| `anthropic` | api_key | env `ANTHROPIC_API_KEY` | |
| `anthropic_oauth` | oauth | browser + local callback (PKCE) | manual-code mode available |
| `openai` | api_key | env `OPENAI_API_KEY` | |
| `openai_oauth` | oauth | browser + local callback (PKCE) | rotates refresh token on every refresh — use single-flight |
| `xai` | api_key | env `XAI_API_KEY` | |
| `xai_oauth` | oauth | device code (RFC 8628) | |
| `google` | api_key | env `GOOGLE_API_KEY` | |
| `vertex` | service_account | SA JSON + STS exchange | location configurable |
| `antigravity` | oauth | Google installed-app + browser (PKCE disabled — public secret) | |

To get the list programmatically:

```go
for _, id := range provider.IDs() { /* ... */ }
```

To add a provider: drop a new `auth/provider/<name>/` package that returns
`model.Authenticator`, then add one row to the `ROUTES` table in
`auth/provider/provider.go`. No other file needs to know.

---

## Three roles, one model

```
model.Credential        — one persisted credential (api_key / oauth / service_account)
model.Authenticator     — Login / Refresh / Verify for one (provider, kind)
model.FileStore         — 0600 JSON files on disk
```

`Authenticator` is the only thing the SDK exposes. Everything else
(`svc.OAuthClient`, `svc.CallbackServer`, `utils.PKCE`, `utils.FileStore`,
`provider.ROUTES`) is implementation detail reachable only through
`provider.Login` / `provider.For`.

---

## What you get back

`*model.Credential` after `Login` or `Refresh` is **already validated
end-to-end** by the authenticator (it makes a real provider call, or for OAuth
without a cheap probe, it does a refresh against the token endpoint). You
can hand the token to your LLM client immediately.

`Verify` returns `model.VerifyResult`. The `Method` field tells you which
kind of live probe was used (`models_endpoint`, `userinfo_endpoint`,
`token_refresh`, `sts_exchange`) so log lines and CLI output stay honest
about what actually happened. If `Result.Credential` is non-nil, the probe
rotated the token — **persist it** before continuing, or the next call
will see the old (possibly revoked) token.

---

## Building & testing

```bash
go build ./...
go test ./...           # full suite
go vet ./...
```

The test suite covers every provider, every flow, the file store, PKCE, the
single-flight refresh, and 429 backoff. The CLI is exercised via
`cmd/root_test.go`; provider behaviour via `authtest.FollowRedirect`.

---

## License

Internal to bizshuk/agentsdk. Not for redistribution.
