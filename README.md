# user-service

Identity service: credentials, sessions, token issuance/rotation/revocation, and the
gateway's ForwardAuth verifier. NestJS 11 · Node 24 · MikroORM 7 · Redis · Kafka.

## Endpoints

| Route | Auth | Purpose |
|---|---|---|
| `POST /auth/register` | public | Argon2id-hashed signup, emits `identity.user.registered.v1` |
| `POST /auth/login` | public | Sets `__Host-at` (access, 10 min) + `__Secure-rt` (refresh) cookies; returns CSRF token |
| `POST /auth/refresh` | refresh cookie | Single-use rotation; **reuse outside the 10 s grace window revokes the whole family** and emits `identity.user.session_revoked.v1` |
| `POST /auth/mfa/verify` | access cookie | Step-up: fresh `auth_time`, `amr += mfa` |
| `POST /auth/logout` | access + CSRF | jti + session denylisted, family revoked, cookies cleared |
| `GET/DELETE /auth/sessions` | access (+CSRF) | Security center: list / revoke-all-others |
| `GET/HEAD /auth/verify` | — | **Traefik ForwardAuth**: signature+claims → denylist (fail closed) → session → CSRF for mutating methods → `X-User-Id/-Roles/-Session-Id` |
| `GET /.well-known/jwks.json` | public | ES256 verification keys (`kid`-rotatable) |
| `GET /users/me` | gateway | Profile + KYC status |
| `GET /health/live` · `/health/ready` | — | probes |

## Theft-protection model

Access tokens are 10-minute ES256 JWTs carrying `jti` + `sid`; refresh tokens are
opaque 256-bit values stored only as SHA-256 hashes with `family_id`/`generation`.
Every refresh consumes its row atomically (`UPDATE … WHERE consumed_at IS NULL`).
A consumed token presented again outside the grace window is treated as theft:
the family is revoked, the session denylisted (`revoked:sid:*`), and a security
event flows through the outbox. Session records bind a device-fingerprint hash —
rotation from a different context also kills the family. The denylist check
**fails closed** (503) if Redis is unreachable. Cookies are httpOnly/Secure
(`__Host-`/`__Secure-` prefixes); the SPA never sees a token. CSRF is enforced
at the gateway for all mutating methods via double-submit.

## Patterns map

- **Facade** — `AuthService` over keys/sessions/tokens/outbox subsystems
- **Factory** — `TokenFactory` (JWT), `EventEnvelopeFactory`
- **Strategy** — `MfaChannelStrategy` (email mock, TOTP mock)
- **Chain of Responsibility** — `AuthGuard` → `CsrfGuard` on mutating routes
- **Transactional Outbox** — `OutboxEvent` written in the registering UoW tx; `OutboxRelayService` polls with `FOR UPDATE SKIP LOCKED` (Debezium-compatible columns)

## Notes

- MikroORM 7 is decorator-free: entities live in `src/entities/*` via `defineEntity`.
- Unit tests stub the ESM-only packages (`test/stubs/*.cjs`) — they exercise pure
  control flow (rotation, revocation, CSRF), not the ORM.
- Migrations run at boot (transactional, all-or-nothing).
