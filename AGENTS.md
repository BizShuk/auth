# auth — technical context

Go module `github.com/bizshuk/auth` (Go 1.26). Source of truth for
**how the code is organised and the rules every contributor must keep** when
touching it. If you change architecture, update this file in the same commit.

## Layering

```
┌──────────────────────────────────────────────────────────────┐
│  provider/<name>/*        one package per LLM provider       │  ↓ imports
├──────────────────────────────────────────────────────────────┤
│  provider                 registry, ROUTES table              │  ↓ imports
├──────────────────────────────────────────────────────────────┤
│  svc                      mechanisms: OAuth, callback,       │  ↓ imports
│                           device, resolver, FileStore        │
├──────────────────────────────────────────────────────────────┤
│  model                    Credential, Authenticator, Options │  ← leaf
├──────────────────────────────────────────────────────────────┤
│  utils                    PKCE, FileStore, browser, active   │  ← leaf
└──────────────────────────────────────────────────────────────┘
                         ↑
                    cmd (CLI) and main
```

**Hard rules:**

1. `model` does not import `svc` or `provider`. If you need a type from
   `svc` in `model`, you have a layering bug — push the type down or use
   `any` and assert at the boundary (see `Options.ShowDeviceCode`).
2. `svc` does not import `provider` or any `provider/<name>`. The registry
   is the only place that knows every provider.
3. `provider/<name>` does not import any other `provider/<other>`. They
   only import `auth/model` and `auth/utils`.
4. `cmd` and `main` are the composition root. They are the only place that
   wires `utils.OpenBrowser`, `svc.PrintDeviceCode`, etc. into
   `model.Options`. Do not move that wiring into a library.

The model layer is the leaf. New abstractions get added there; new flows
get added in `svc`; new providers get added in `provider/<name>` plus one
row in the `ROUTES` table.

## The `Authenticator` interface (the contract)

```go
// model/credential.go:174
type Authenticator interface {
    Provider() string
    Kind() Kind
    Login(ctx context.Context) (*Credential, error)
    Refresh(ctx context.Context, cred *Credential) (*Credential, error)
    Verify(ctx context.Context, cred *Credential) (*VerifyResult, error)
}
```

- `Login` returns a credential that has **already been validated** against
  the provider. The implementation is responsible for proving the token
  works, not just that it was issued.
- `Refresh` returns `ErrRefreshUnsupported` for kinds that cannot rotate
  (api_key, service_account in non-Vertex form). Callers must check.
- `Verify` may rotate the credential. When `VerifyResult.Credential` is
  non-nil, the caller must persist it via `FileStore.Save` before trusting
  any token returned here.

## `OAuthClient` guarantees (the hard parts)

`svc/oauth.go` is the only place that talks to OAuth token endpoints.
Three invariants:

- **Single-flight refresh.** Concurrent calls with the same refresh token
  share one network request (`OAuthClient.joinRefresh`). This prevents
  OpenAI's rotating-refresh-token semantics from invalidating the token
  through a race.
- **429 backoff.** When the provider returns `Retry-After`, the token is
  blocked locally for that duration (`OAuthClient.block`). Subsequent
  refresh calls fail fast with `*HTTPError{Status: 429}` rather than
  hammering the endpoint.
- **Leader-ctx is `context.WithoutCancel`.** A cancelled follower's context
  does not abort an in-flight refresh; the leader runs to completion so
  the rotated refresh token is received.

`HTTPError.Retryable()` returns `true` only for 5xx. 4xx is never retried
— it is a credential or request-shape problem.

## File store invariants

`utils.FileStore` writes are **atomic**: `CreateTemp` + `Rename`. Half-
written credential files are not possible. Both the directory and the
files are `0o700` / `0o600` — secrets on a multi-user box stay private.
The store refuses to write an unvalidated credential (`cred.Validate()` is
called first).

## OAuth flow choices

| Provider | Flow | PKCE | Notes |
|---|---|---|---|
| `anthropic_oauth` | authorization_code | yes | state required on token exchange |
| `openai_oauth` | authorization_code | yes | rotates refresh token; no state on exchange |
| `xai_oauth` | device_code | n/a | RFC 8628, no browser required |
| `antigravity` | authorization_code | no | Google installed-app; has a public client_secret |

The driver functions (`svc.RunBrowserLogin`, `svc.RunDeviceLogin`) take a
`*OAuthClient`, not a provider, so flows are reused across providers.
`svc/oauth.go` `OAuthConfig` covers every divergence (PKCE on/off, state
on/off, JSON vs form encoding, `AuthParams`).

## CLI composition

`main.go` builds the cobra root, then `cmd.Install(root, APP_NAME)` wires
all subcommands. Each subcommand (`cmd/login.go`, `cmd/refresh.go`,
`cmd/verify.go`, `cmd/use.go`, `cmd/list.go`) calls into `provider.Login`
or `provider.For`. No business logic lives in `cmd/`.

`APP_NAME = "agentsdk"` is shared with the aggregated `auth-cli` binary
so the two share `~/.config/agentsdk/data/auth/`.

`cmd/rootFlags.authOptions()` is the composition root for the
`OpenBrowser` / `ManualCode` / `ShowDeviceCode` callbacks — those are nil
in `model.NewOptions` by design and must be injected here or the OAuth
flow will nil-panic (regression test in `cmd/root_test.go`).

## Conventions

- **No default commit.** Design / refactor work stops before `git commit`.
  The user commits. If you accidentally committed, `git reset --soft` and
  keep the changes staged.
- **Verify before claiming complete.** Run `go test ./...`, `go vet ./...`,
  and `git diff --check` before saying anything passes.
- **Layered, not lazy.** A function that needs three things from three
  layers composes them at the call site, not by importing upward.
- **Tests use `authtest.FollowRedirect`.** The composition root in
  `cmd/root.go` is the only production code that injects
  `utils.OpenBrowser`; tests inject their own via `WithBrowserOpener`.
- **Slog with structured attrs.** Negative log lines must carry
  ≥3 attrs (request_id, provider, op). See `model.ErrNoRefreshToken` and
  the 429 path for the shape.

## What lives where (file index)

```
main.go                    cobra entry; APP_NAME = "agentsdk"
cmd/                       CLI subcommands — composition root
  root.go                  root flags, authOptions() wiring
  root_test.go             regression: OpenBrowser injection
  login.go / refresh.go /  one file per subcommand, thin wrapper
   verify.go / use.go /
   list.go
model/
  credential.go            Credential, Kind, Authenticator, errors
  options.go               Options + functional Option setters
provider/
  provider.go              ROUTES table; Login / For / New / IDs
  anthropic/ openai/ xai/  one subpackage per provider
   google/ vertex/
   antigravity/
svc/
  oauth.go                 OAuthClient, single-flight, 429 backoff
  login.go                 RunBrowserLogin, RunDeviceLogin, VerifyByRefresh
  callback.go              local callback server (PKCE flow)
  device.go                RFC 8628 device code struct + poll
  resolver.go              Resolver: store + active + env + auto-refresh
  apikey.go                api_key path (env fallback)
  jwt.go                   JWT bearer for Vertex / xAI
utils/
  store.go                 FileStore (0600, atomic write)
  active.go                active.json read/write
  pkce.go                  PKCE codes (RFC 7636)
  browser.go               OpenBrowser implementation
authtest/                  shared test helpers (FollowRedirect, etc.)
```
