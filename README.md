# go-oidc-provider

A Go OpenID Provider that ships the parts most reference impls hand-wave: a full **CIBA** (Client-Initiated Backchannel Authentication) flow with passkeys as the authorization credential and WhatsApp / Telegram as the notification channel. Composes with [`go-passkey-auth`](https://github.com/rdaniel1105/go-passkey-auth) — the OP delegates the WebAuthn ceremony to it over HTTP. Two services, one passkey, one architectural story.

> 🚧 Under construction. Each phase below ships as a separate commit on `master`. For a comprehensive certified OIDC stack in Go, see [`luikyv/go-oidc`](https://github.com/luikyv/go-oidc) — this repo is a deployable opinionated reference, not a competitor.

## Status

| Phase | Status |
|---|---|
| 1. Scaffold | ✅ |
| 2. Config package | ✅ |
| 3. Signing keys + JWKS | ✅ |
| 4. Discovery endpoint | ✅ |
| 5. Postgres stores | ✅ |
| 6. Redis stores | ✅ |
| 7. go-passkey-auth HTTP client | ✅ |
| 8. User signup | ✅ |
| 9. Auth code flow | ⏳ |
| 10. Token endpoint | ⏳ |
| 11. UserInfo | ⏳ |
| 12. Refresh token rotation | ⏳ |
| 13. AuthDeviceNotifier interface | ⏳ |
| 14. Telegram + WhatsApp notifiers | ⏳ |
| 15–20. CIBA (bc-authorize, approve, poll/ping/push) | ⏳ |
| 21. Health + request logger | ⏳ |
| 22. testcontainers integration tests | ⏳ |
| 23. Demo RP | ⏳ |
| 24. README (this file, properly) | ⏳ |

## Running locally

```bash
echo "127.0.0.1 op.local" | sudo tee -a /etc/hosts
cp .env.example .env
docker compose up
```

The OP listens on `:8081`. `go-passkey-auth` is expected on `:8080`; both compose stacks run side by side without port collisions.

## License

MIT — see [LICENSE](LICENSE).
