# go-oidc-provider

A Go OpenID Provider that ships the parts most reference impls hand-wave: a full **CIBA** (Client-Initiated Backchannel Authentication) flow with passkeys as the authorization credential and Telegram / WhatsApp as the notification channel. Composes with [`go-passkey-auth`](https://github.com/rdaniel1105/go-passkey-auth) — the OP delegates the WebAuthn ceremony to it over HTTP. Two services, one passkey, one architectural story.

For a comprehensive certified OIDC stack in Go, see [`luikyv/go-oidc`](https://github.com/luikyv/go-oidc). This repo is a deployable opinionated reference, not a competitor: it picks one notification channel story (LATAM-friendly: Telegram and WhatsApp), one signing algorithm (ES256), and one authentication factor (passkeys), and ships the experience layer end-to-end instead of cataloguing every spec option.

---

## What this is

- **Full CIBA poll + ping + push.** `POST /oidc/bc-authorize` → notifier delivers the URL → user approves with a passkey → tokens reach the RP via the delivery mode it registered with.
- **Server-rendered approval page** that displays the RP-supplied `binding_message` before the passkey prompt fires. Transaction-signing UX, not "approve whatever".
- **`login_hint` matched server-side.** The op_user resolved at `/bc-authorize` is compared against the op_user the asserted passkey belongs to. A stolen URL cannot be approved with a different passkey.
- **Authorization code with PKCE S256** at `/oidc/authorize` + `/oidc/token`. The login page brokers a discoverable passkey login to `go-passkey-auth`.
- **Refresh-token rotation-on-use with family revoke.** Replaying a previously-rotated token is a confirmed compromise signal; the entire chain is revoked.
- **Pluggable `AuthDeviceNotifier` interface.** Implementations ship for `log` (stdout, zero-config), `telegram` (Bot API + inline-keyboard button), and generic `webhook`. WhatsApp via the Meta Cloud API is interface-ready and the production target for LATAM.
- **ES256 ID + access tokens** signed with a persisted P-256 key; rotated via JWKS. RPs verify everything off `/.well-known/jwks.json`.
- **`acr` and `amr` claims set honestly.** Every issued ID token carries `acr=urn:passkey` and `amr=["webauthn","user"]` because every authentication moment on this OP runs a fresh assertion — no remembered-session path that would justify weaker claims.

## Why CIBA + passkeys

CIBA is the decoupled flow: an RP says "I want to authenticate this user", the user receives a notification on a separate device, approves, and the RP collects tokens. It's the right model for point-of-sale, mobile wallets, voice channels, and step-up authentication where the device receiving the prompt is not the device asking for it.

Most CIBA reference implementations hand-wave the "user approves" half. This repo ships a passkey-as-the-credential answer: there is no "logged into the approval app" state to compromise, every approval requires a fresh assertion, and the channel (Telegram, WhatsApp, webhook) is decoupled from the credential. A stolen phone with an active session of any channel still cannot approve because the passkey is what authorizes, not the channel.

---

## Architecture

```
cmd/
  server/main.go            entrypoint, wires config -> stores -> handlers -> http.Server
internal/
  api/
    handler/
      discovery.go          /.well-known/openid-configuration + jwks.json
      user.go               /users + /users/complete (signup)
      authorize.go          /oidc/authorize + login broker endpoints
      token.go              /oidc/token (auth_code, refresh_token, CIBA grants)
      userinfo.go           /oidc/userinfo (Bearer-protected)
      ciba.go               /oidc/bc-authorize + /ciba/approve + /ciba/deny + push/ping callbacks
      mint.go               shared token-minting helper (auth_code, refresh, CIBA grant + push)
      response.go           writeJSON + writeError (stable codes, no err leak)
      templates/            server-rendered login + approval pages
    middleware/
      logger.go             structured slog per request
    router.go               chi routes
  ciba/
    callback.go             OP -> RP notification HTTP client (ping + push wire shapes)
  oidc/
    config.go               issuer-derived endpoints
    jwks.go                 ES256 key load/generate + JWKS publication
    discovery.go            discovery document builder
    idtoken.go              ID token minting
    access.go               access token minting (at+jwt)
    refresh.go              refresh token generation + hashing
    pkce.go                 S256 verifier check
    client_auth.go          client_secret_basic + _post + none
    authorize.go            /authorize request validation
    bc_authorize.go         /bc-authorize request validation
    verify.go               access token verification for /userinfo
  notifier/
    notifier.go             AuthDeviceNotifier interface
    log.go                  stdout (zero-config default for tests + demos)
    telegram.go             Telegram Bot API + inline-keyboard button
    webhook.go              generic HTTP POST for native-app integrations
    build.go                pick implementation from config.Notifier
  passkey/
    client.go               HTTP wrapper around go-passkey-auth's /api/v1/auth endpoints
  domain/                   Client, OPUser, AuthCode, CIBARequest, RefreshToken + sentinels
  store/
    postgres/               pgx-backed client + op_user + refresh_token stores
      migrations/           embedded golang-migrate SQL files
    redis/                  auth_code, ciba_request, approval_token, auth_session, signup_state
  config/config.go          godotenv + os.Getenv + sentinel errors
```

## CIBA flow

```
1. RP    -> POST /oidc/bc-authorize        (client auth, login_hint, binding_message)
2. OP                                       -> resolves op_user
                                            -> creates CIBARequest in Redis (status: pending)
                                            -> creates approval_token in Redis
                                            -> notifier.Notify({url, binding_message})
3. User  <- Telegram / WhatsApp / webhook   receives approval URL
4. User  -> GET /ciba/approve?t=...         renders the binding message page
5. User  -> POST /ciba/approve/login/begin  page brokers BeginLogin to passkey service
6. User  -> POST /ciba/approve              page submits passkey assertion
   OP                                       -> CompleteLogin -> passkey user_id
                                            -> looks up op_user by passkey_user_id
                                            -> verifies it matches the request's op_user
                                            -> transitions status: approved
                                            -> (ping) POSTs {auth_req_id} to the RP
                                            -> (push) POSTs full token set to the RP
7. RP    -> POST /oidc/token (CIBA grant)   poll until terminal state
   OP                                       -> mints access + id + refresh
                                            -> deletes the CIBARequest (single-use)
                                            -> returns tokens
```

Auth-code (`/oidc/authorize` → browser passkey login → `/oidc/token`) runs alongside, with refresh-token rotation as a separate grant at the same `/oidc/token`.

---

## API reference

Discovery sits at the root; everything else lives under `/oidc` or `/ciba`.

### Discovery + JWKS

| Method | Path                                | Description                                    |
|--------|-------------------------------------|------------------------------------------------|
| `GET`  | `/.well-known/openid-configuration` | OIDC discovery document                        |
| `GET`  | `/.well-known/jwks.json`            | Public JWKS (active + retired signing keys)    |

### OIDC core

| Method | Path                          | Description                                                                                |
|--------|-------------------------------|--------------------------------------------------------------------------------------------|
| `GET`  | `/oidc/authorize`             | Auth-code entry. Validates the request, renders the login page                             |
| `POST` | `/oidc/authorize/login/begin` | Brokered passkey login begin (called by the login page)                                    |
| `POST` | `/oidc/authorize/login/complete` | Login complete; mints the authorization code and returns the RP redirect URL           |
| `POST` | `/oidc/token`                 | Grants: `authorization_code`, `refresh_token`, `urn:openid:params:grant-type:ciba`         |
| `GET`  | `/oidc/userinfo`              | Bearer-protected claims endpoint. Scope-gated: `email`, `profile`, `phone`                 |

### CIBA

| Method | Path                          | Description                                                                                |
|--------|-------------------------------|--------------------------------------------------------------------------------------------|
| `POST` | `/oidc/bc-authorize`          | Backchannel authentication request. Returns `auth_req_id`. Errors per CIBA §13              |
| `GET`  | `/ciba/approve?t=<token>`     | User-facing approval page (rendered HTML, no SPA)                                          |
| `POST` | `/ciba/approve/login/begin`   | Brokered passkey login begin during approval                                               |
| `POST` | `/ciba/approve`               | Submit the assertion, enforce login_hint match, transition request to approved             |
| `POST` | `/ciba/deny`                  | Transition the request to denied                                                            |

### Signup

| Method | Path                | Description                                                                       |
|--------|---------------------|-----------------------------------------------------------------------------------|
| `POST` | `/users`            | Begin signup. Validates email + display_name + optional E.164 phone, brokers BeginRegister to the passkey service, persists signup state |
| `POST` | `/users/complete`   | Submit the passkey attestation; creates the op_user and links it to the passkey-side user_id |

### Health

| Method | Path        | Description |
|--------|-------------|-------------|
| `GET`  | `/health`   | Liveness    |

### Error shape

Every error response follows a single envelope:

```json
{ "error": "<stable_code>", "error_description": "<human-readable detail>" }
```

CIBA-specific codes match the spec: `authorization_pending`, `slow_down`, `access_denied`, `expired_token`, `unknown_user_id`, `invalid_binding_message`, `unauthorized_client`. UserInfo failures return 401 with `WWW-Authenticate: Bearer error="invalid_token"`.

---

## Spec decisions

The calls that distinguish this from a tutorial copy-paste:

**Two services, one passkey.** `RP_ID` is set to the registrable domain shared by `go-passkey-auth` and this OP. In production they're at `passkeys.example.com` and `op.example.com`; in the local demo they share `localhost`, which the browser treats as one RP-ID across ports. A passkey registered once works on both services without a redirect-based delegation.

**Passkey assertion is the CIBA authorization step.** The notification (Telegram, WhatsApp, webhook) is the *channel*; the passkey is the *credential*. Approving a CIBA request requires a fresh assertion every time. There is no remembered-session state that a stolen phone could replay.

**`login_hint` matched server-side, not trusted from the client.** When the user authenticates via passkey on the approval page, the OP looks up which op_user_id that passkey belongs to and compares against the op_user_id the original `/bc-authorize` resolved. Mismatch returns `403 user_mismatch` and never transitions the request — the attacker cannot authorize someone else's request with their own passkey.

**Binding message rendered before the ceremony.** The approval page renders `binding_message` prominently, with an explicit "you are authorizing X" framing, *before* the passkey prompt fires. Capped at 200 runes.

**Single-use approval tokens, short-lived.** The URL-safe token in the notifier message is independent from `auth_req_id`; the underlying id is never visible to the user. A screenshot of the message can't be re-targeted at a different request.

**ID token uses ES256, not RS256.** P-256 ECDSA with COSE alg `-7`. Smaller tokens (~half the size), modern, what passkeys use anyway — no reason to bring two curve families into the codebase.

**`acr` + `amr` set on every ID token.** `acr=urn:passkey`, `amr=["webauthn","user"]`. Every authentication moment runs a fresh assertion, so the claims tell the truth. Most reference implementations ship `acr=0` for everything; that's lazy.

**Refresh-token rotation, not long-lived bearer.** Every `/token` call with `grant_type=refresh_token` revokes the presented token and issues a new pair, with the family id carried across rotations. Replaying an already-revoked token revokes the whole family — an attacker holding a stolen descendant has their chain killed alongside the legitimate holder's.

**Approval URL is opaque server-rendered HTML, not a SPA.** No JavaScript bundles, no API surface beyond the form post. The passkey ceremony is the only client-side JS and it's inline in the template. Smaller attack surface, no client-side routing for an auth-critical page.

**Notifier failure is synchronous at `/bc-authorize`.** If Telegram (or WhatsApp, or the webhook) can't deliver, the RP gets `503 notifier_unavailable` immediately instead of sitting in `authorization_pending` until `expired_token`. RPs know to retry or fall back.

**Push delivery preserves polling as a fallback.** If the OP's POST to the RP's notification endpoint fails after a successful approval, the refresh row is *not* persisted and the CIBARequest is *not* deleted. The RP can poll `/oidc/token` to recover, which mints a fresh, persisted token pair — no orphan credentials.

---

## Running locally

```bash
cp .env.example .env
docker compose up
```

The OP listens on `:8081`. `go-passkey-auth` is expected on `:8080`. Host ports are chosen so both compose stacks run side-by-side without collisions (passkey-auth uses 5432/6379, the OP uses 5433/6380).

A demo client and op_user are not seeded automatically — for now, register a passkey via `go-passkey-auth`'s demo page, then `INSERT` a row into `clients` (with a `bcrypt`-hashed secret) and `op_users` (linking `passkey_user_id` to the registered user). The YAML reconciler that automates this is on the list below.

## What I'd add next

- **Health + request logger polish.** A real `/health/ready` that pings Postgres + Redis (and optionally the passkey service) and tighter request-log fields (RP, scope, grant).
- **testcontainers integration tests** of the full RP ↔ OP ↔ passkey-service flow, using the same software authenticator pattern as `go-passkey-auth/internal/testutil/webauthntest`.
- **Demo RP** — a single HTML page that drives both the auth-code and CIBA flows from a browser, so the repo can be cloned and exercised without writing any RP code.
- **YAML client reconciliation.** A `clients.yaml` reconciled into the `clients` table at startup so first-run setup doesn't need a hand-rolled `INSERT`.
- **WhatsApp notifier.** Meta Cloud API + approved template message, behind `NOTIFIER=whatsapp`. The interface and config are already in place; the implementation is gated on a real WABA registration.
- **Token introspection (RFC 7662) and revocation (RFC 7009).** The refresh-token store already supports revocation; surfacing it as an endpoint is a thin wrapper.
- **OID4VCI issuance.** SD-JWT-VC credentials plus `/.well-known/openid-credential-issuer` — the wallet-issuance follow-on that uses the same signing key, the same client registry, and the same passkey-as-authentication model.

---

## License

MIT — see [LICENSE](LICENSE).
