# auth — business value

## What this module exists to do

`auth` is the **single credential authority** for the bizshuk/agentsdk
family. Before it existed, every service (proxy, m-agent, agentSDK, …)
re-implemented its own OAuth dance, its own refresh loop, and its own
0600-file format. That meant:

- N copies of the same browser-callback server, each with its own bugs.
- N copies of "where do I put the token," each answering differently.
- Every service that needed an LLM token had to know about every provider.

`auth` collapses all of that to one module with one registry and one CLI.
The cost of adding a new provider goes from "edit every consumer" to
"add one row to `ROUTES`."

## Upstream / downstream

```
                    ┌────────────────────────────┐
                    │  anthropic / openai / xai / │
                    │  google / vertex /         │  ← external
                    │  antigravity provider APIs │
                    └─────────────┬──────────────┘
                                  │ token endpoints
                                  ▼
┌─────────────────────────────────────────────────────────────┐
│                         auth (this module)                  │
│   - provider registry, single-flight refresh, 429 backoff   │
│   - FileStore (0600 atomic JSON)                            │
│   - CLI: auth login | refresh | verify | use | list         │
└────┬───────────┬───────────┬───────────┬──────────┬─────────┘
     │           │           │           │          │
     ▼           ▼           ▼           ▼          ▼
   proxy     m-agent   agentSDK   conversation_  cc-plugin
                                agent / sessiond
                                  / msgHub
```

**Downstream (consumers):** every other repo under `~/projects/ai/*` that
needs an LLM token. They each call `provider.Login` once and
`provider.For(cred) → auth.Refresh → auth.Verify` thereafter. The list
grows as new services are added; today it is at least six.

**Upstream (dependencies of this module):**
- `spf13/cobra` — CLI framework
- `spf13/viper` — config (only used by `cmd/` for the CLI flag wiring)
- `stretchr/testify` — test assertions
- `golang.org/x/sys`, `golang.org/x/text` — indirect

The module's only runtime imports outside the stdlib are the cobra/viper
stack. The model + svc + provider + utils packages are stdlib-only, which
is what makes them reusable from other Go services without dragging cobra
in.

## Core vs non-core

| Core (do not break) | Why it matters |
|---|---|
| `model.Authenticator` interface | The contract every consumer depends on. Adding methods is a breaking change. |
| `provider.Login` / `provider.For` | The single entry point. Renaming either breaks every caller. |
| `model.Credential` JSON shape | Files on disk. Changing the schema loses existing user credentials. |
| File perm 0o600 / dir perm 0o700 | Leak any credential and the blast radius is "all of the user's LLM accounts." |
| Single-flight refresh | Removing it re-introduces the OpenAI refresh-rotation race that took a real incident to find. |
| 429 backoff | Without it, a stuck token endpoint becomes a credential-store-killing infinite loop. |
| `ROUTES` table | Single source of truth. Adding a provider without a row = the provider does not exist. |

| Non-core (replaceable) | Notes |
|---|---|
| `utils.OpenBrowser` implementation | The function shape is what `model.Options` pins; the implementation (xdg-open, open, etc.) is swappable. |
| `cmd/` CLI subcommands | Pure wrapper around the SDK; can be re-written without touching the library. |
| `authtest` helpers | Test-only; OK to move or reshape freely. |
| `svc/apikey.go` | Tiny adapter; could live in `provider/<name>/` instead. |

## Common operations

### User flow: "log into a new provider"

1. Run `auth login --provider anthropic_oauth`.
2. Browser opens (or device code prints) → user grants → callback
   receives `code` + `state`.
3. CSRF state check, then `POST` to the token endpoint with PKCE verifier.
4. New `Credential` saved to `~/.config/agentsdk/data/auth/<name>.json`
   with mode 0600.
5. `active.json` updated to point at this credential.
6. CLI prints the account identifier; done.

### Service flow: "use a stored credential on every request"

1. Resolver (in `svc/resolver.go`) reads `active.json` → load credential →
   if `Expired(skew)` → call `auth.Refresh(ctx, cred)` → save rotated
   credential back to disk → return fresh.
2. Caller uses `cred.AccessToken` (or `cred.APIKey`) against the provider.

This is the hot path in `proxy/` and `m-agent/`. It must be fast (one disk
read + one refresh-or-noop) and safe under concurrency (Resolver uses the
single-flight path in `OAuthClient.Refresh`).

### Operator flow: "rotate an account"

1. `auth login --provider anthropic_oauth` (creates a *new* file with a
   different `Account`).
2. `auth use anthropic-oauth` (picks which one is active).
3. The old file stays; remove manually if no longer needed.

## Status / flow

```
CLI (cmd/)  ──Login(ctx, id)──▶ provider.Login
                                  │
                                  ▼
                            provider.New(id)
                                  │
                                  ▼
                       provider/<name>.NewOAuth/...
                                  │
                                  ▼
                       svc.RunBrowserLogin / RunDeviceLogin
                                  │
                  ┌───────────────┼───────────────┐
                  ▼               ▼               ▼
            utils.PKCE     svc.CallbackServer   utils.OpenBrowser
                  │               │               │
                  └───────────────┴───────────────┘
                                  │
                                  ▼
                       svc.OAuthClient.Exchange
                                  │
                                  ▼
                       TokenResponse → model.Credential
                                  │
                                  ▼
                       utils.FileStore.Save (atomic 0600)
                                  │
                                  ▼
                       active.json updated
```

Refresh path is the same but starts at `provider.For(cred) → svc.OAuthClient.Refresh`.

## Constraints (hard)

- **No background goroutines owned by the library.** Every flow runs to
  completion in the caller's context. Callers cancel; the library obeys.
  The one exception: the single-flight leader uses
  `context.WithoutCancel` so a cancelled follower does not abort a refresh
  whose rotated token is already on the wire.
- **No mutable global state.** `OAuthClient` holds its inflight / blocked
  maps; `FileStore` holds its dir. Everything else is constructed per
  call.
- **Stdlib only for model / svc / provider / utils.** Pulling in a heavy
  dep (e.g. an OAuth library) would force every downstream service to
  re-vendoring it.
- **Credentials on disk are secrets.** Never log the raw
  `AccessToken` / `RefreshToken` / `APIKey`. The model layer is
  `MarshalJSON`-driven; add `//nolint` only with a written reason.

## Risk register

| Risk | Likelihood | Impact | Mitigation in code today |
|---|---|---|---|
| Refresh-token race (OpenAI rotates on every call) | medium | high — credential self-invalidates | `OAuthClient.joinRefresh` single-flight |
| 429 storm from a stuck endpoint | low | high — credential store hammered | `OAuthClient.block` with `Retry-After` clamp `[5s, 5min]` |
| `auth login` from SSH / container | high (every headless box) | medium — flow just fails | `--no-browser` + `WithManualCode` path |
| Stolen credential file | low | high | `0o700` dir, `0o600` files, no world-readable default |
| `active.json` lost / corrupted | low | medium — user re-runs `auth use` | FileStore atomic write covers the per-credential files; `active.json` lives in `utils/active.go` with same atomic shape |
| New provider missing from `ROUTES` | medium (every new provider PR) | medium — provider silently absent | CI must `go test ./provider/...` and assert `IDs()` length matches the registered subpackages |
| Browser-process hang on `OpenBrowser` | low (macOS) | low — flow deadlocks until timeout | `LoginTimeout` (default 5 min) bounds the wait |
| Refresh blocked too long after a 429 | low | low — user sees stale credentials, must re-login | `clampBackoff` caps at 5 min; provider-driven, not arbitrary |
| Adding a method to `Authenticator` interface | high (refactor pressure) | high — breaks every consumer | Treat as a major version bump. Prefer adding a new interface (`Verifier`, `Refresher`) that consumers opt into. |
| Disabling PKCE on a public-client provider | low | critical — token interception | `OAuthConfig.UsePKCE` is a required opt-in per provider; CI must keep it `true` for `_oauth` IDs |

## What "done" looks like for changes here

- A new provider lands as one `provider/<name>/` package + one `ROUTES`
  row, with tests in both. No other file moves.
- A refresh / login flow change is covered by a single targeted test in
  the affected `svc/*_test.go` plus the full suite green.
- A breaking change to the `Authenticator` interface or the on-disk
  `Credential` JSON shape is a major version bump and a migration note in
  the PR.
- Any commit that touches `cmd/root.go` must keep the
  `OpenBrowser`/`ManualCode` injection green — `cmd/root_test.go` is the
  regression guard.
