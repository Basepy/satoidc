# Spec: Nostr Login

## Status

- Status: review
- Owner: Unassigned (proposed by the author of the Nostr login pull request)
- Created: 2026-11-06
- Updated: 2026-11-06
- Related code: `satoidc/satoidc/auth/nostr.py`, `satoidc/satoidc/routes/nostr_auth.py`, `satoidc/satoidc/schemas/nostr.py`, `satoidc/satoidc/models/__init__.py`, `satoidc/satoidc/auth/middleware.py`, `satoidc/migrations/versions/95a7a4cb05e8_add_nostr_login.py`
- Related specs: [Nostr Auth Flow](../../flows/nostr-auth.md), [LNURL-auth Flow](../../flows/lnurl-auth.md), [Login Flow](../../flows/login.md), [Registration Flow](../../flows/registration.md), [Security And Session Contract](../../contracts/security-session.md), [Database Contract](../../contracts/database.md), [Public Route Boundary Hardening](../public-route-boundary/spec.md)

## Intent

Let a user log in to, register with, and link to a SatOIDC account using a Nostr key, with the same single-use challenge discipline as LNURL-auth, and without the server ever handling a private key.

This is the "Evaluate Nostr identity integration" item of the README roadmap. It is delivered as an HTTP API first, so the protocol and security behavior can be reviewed independently from any screen.

## Context

- SatOIDC authenticates with a password or with LNURL-auth (a Lightning wallet signs `k1`). Sessions are Starlette session cookies holding `user_id`.
- A Nostr identity is a secp256k1 x-only public key (BIP-340). A user proves control of the key by signing an event with a browser extension (NIP-07), a remote signer (NIP-46) or another Nostr client.
- NIP-98 defines an HTTP authentication event (kind `27235`) that binds a URL and an HTTP method. This spec adds a `challenge` tag so the event is also bound to a server-issued one-time challenge.
- Unlike LNURL-auth, the signer is not a wallet that calls the server. The client that holds the key signs an event and posts it, so the verification endpoint is called by the user's browser.
- The repository forbids custom JavaScript and `ui.run_javascript` in NiceGUI screens without explicit maintainer authorization (`AGENTS.md`). NIP-07 needs `window.nostr`, so a login button is intentionally out of scope here (see Out of scope).

## Scope

In scope:

- `POST /auth/nostr/challenge` and `POST /auth/nostr/verify`.
- Actions `login`, `register` and `link`.
- `users.nostr_pubkey` (unique, nullable) and the `nostr_auth_challenges` table, with an Alembic migration.
- BIP-340 Schnorr verification and NIP-98 event validation in `auth/nostr.py`.
- Public route prefix `/auth/nostr` in the auth middleware.
- Setting `NOSTR_CHALLENGE_TTL_SECONDS`.
- Tests, including the official BIP-340 test vectors.

Out of scope:

- Any NiceGUI screen or button. A NIP-07 button requires `ui.run_javascript`, which needs explicit maintainer authorization; a JavaScript-free option is NIP-46 (server-side relay client and NIP-44 encryption) and should be its own spec.
- Unlinking or replacing a Nostr key, account recovery, and email verification.
- Using a Nostr key as an OIDC claim. `nostr_pubkey` is not exposed in tokens or UserInfo by this spec.
- Rate limiting and cleanup of expired challenges (see Risks).

## Rules

Protocol and security rules:

- The server never receives, generates or stores a private key.
- A challenge is created with 32 random bytes (`k1`, hex), an action and the exact verification URL to be signed.
- The verification URL is `<OAUTH2_JWT_ISS>/auth/nostr/verify`. It does not depend on `Host`, `X-Forwarded-*` or the request URL, so it is stable behind proxies.
- The signed event must be kind `27235`, have empty `content`, and contain exactly the tags `["u", <verification url>]`, `["method", "POST"]` and `["challenge", <k1>]` (extra tags are allowed).
- `created_at` must be within 60 seconds of the server clock.
- The event `id` must equal the NIP-01 serialization hash and `sig` must be a valid BIP-340 signature of `id` for `pubkey`.
- A challenge is bound to the browser session that requested it (`nostr_k1` in the session). A different session cannot use it.
- A challenge is single use. It is consumed atomically (conditional `UPDATE ... RETURNING`) before the signature is checked, and the consumption is committed immediately, so a failed attempt can never be replayed.
- A challenge expires after `NOSTR_CHALLENGE_TTL_SECONDS` (default 120). An expired or unknown challenge returns the same error.
- `redirect_to` is stored in the session after `safe_redirect` and returned only after a successful login or registration.
- Success opens the same session as the password login: `request.session["user_id"] = user.id.hex`.

Account rules:

- `login`: requires an active user with this `nostr_pubkey`. A key without an account returns `NOT_FOUND` and creates nothing.
- `register`: creates a user whose only identity is `nostr_pubkey` (no email, login, password or LNURL key; the nickname takes the model default). It fails if the key is already linked.
- `link`: requires an authenticated session when the challenge is created and the same user when it is verified. It sets `nostr_pubkey` on that user. It is idempotent for the same key and fails with a conflict if the account already has a different key or the key belongs to another account.
- `nostr_pubkey` is unique. Concurrent creation or linking is resolved by the unique index and reported as a conflict.
- Disabled users (`is_active = false`) cannot log in.

## Flows

### Happy Path

1. The client posts `{"action": "login", "redirect_to": "/profile"}` to `/auth/nostr/challenge` and receives `k1`, `action`, `url` and `expires_in`.
2. The client builds the kind `27235` event for `url` and `k1` and has it signed by the Nostr key holder.
3. The client posts `{"k1": ..., "event": ...}` to `/auth/nostr/verify`.
4. The server consumes the challenge, validates the event, resolves the user and opens the session.
5. The response is `{"status": "OK", "redirect": "/profile"}`.

### Failure Paths

- Unknown, expired, already used or foreign-session challenge: `400` `Invalid or expired challenge`.
- Malformed event, wrong kind, wrong URL or challenge, clock skew, id mismatch or bad signature: `400` with a short reason.
- `login` for a key without an account: `404` with `status: NOT_FOUND`.
- Disabled account: `403`.
- `register` or `link` for a key that is already linked, or `link` on an account that already has another key: `409`.
- `link` without an authenticated session, or with a different session than the one that asked: `401`.

## Contracts

HTTP API (public paths; the challenge is the authentication):

- `POST /auth/nostr/challenge`
  - Body: `{"action": "login" | "register" | "link", "redirect_to": "/path"}` (both optional; default `login` and `/`).
  - `201`: `{"k1": "<64 hex>", "action": "...", "url": "<verification url>", "expires_in": <seconds>}`.
  - `401` for `link` without a session. `422` for an invalid body.
- `POST /auth/nostr/verify`
  - Body: `{"k1": "<64 hex>", "event": { ...signed NIP-98 event... }}`.
  - `200` `{"status": "OK", "redirect": "/path"}` for `login` and `register`; `200` `{"status": "OK"}` for `link`.
  - Errors: `{"status": "ERROR", "reason": "..."}` with `400`, `401`, `403` or `409`; `{"status": "NOT_FOUND", "reason": "..."}` with `404`.

Database:

- `users.nostr_pubkey`: nullable string, unique index. Hex x-only public key.
- `nostr_auth_challenges`: `k1` (primary key), `action`, `url`, `user_id` (nullable foreign key to `users`, set for `link`), `consumed`, `created_at`, `updated_at`. Same shape and replay-defense semantics as `lnurl_auth_challenges`.

Configuration:

- `NOSTR_CHALLENGE_TTL_SECONDS` (default `120`).

Session keys: `nostr_k1`, `nostr_next`, and `user_id` on success.

## Acceptance Criteria

- Given a user linked to a key, when the key signs a valid event for a fresh challenge, then the session is opened and the response redirects to the stored path.
- Given a key without an account, when it logs in, then the response is `404 NOT_FOUND`, no user is created and no session is opened.
- Given a `register` challenge, when a valid event arrives, then a user with only `nostr_pubkey` is created and the session is opened; a second registration with the same key returns `409`.
- Given a challenge that was verified once, successfully or not, when the same `k1` is verified again, then it returns `400`.
- Given a challenge older than `NOSTR_CHALLENGE_TTL_SECONDS`, when it is verified, then it returns `400` and nothing changes.
- Given a challenge requested by browser A, when browser B verifies it, then it returns `400` and the challenge stays unused.
- Given an event with another URL, another challenge, a non-empty content, a kind other than `27235`, a skew above 60 seconds, a tampered id or a signature of another key, when it is verified, then it returns `400`.
- Given an authenticated user without a key, when a `link` event is verified, then `nostr_pubkey` is set; with a different key already set, or a key owned by another account, it returns `409`.
- Given a `link` challenge, when the session user changed before verification, then it returns `401`.
- Given the official BIP-340 test vectors with 32-byte messages, when they are verified, then the results match the expected values.

## Test Plan

- Unit: BIP-340 vectors, test-signer round trip, wrong lengths, event validation (kind, content, URL, method, challenge, skew with `freezegun`, id tampering, foreign signature, malformed shapes).
- Integration: challenge creation and binding, login, register, link, replay, failed-attempt burn, expiry with `freezegun`, foreign browser, public routing and request validation through `app_client`.
- UI/manual: none (no screen).
- Security/regression: sabotaging the session binding, the single-use condition or the expiry condition makes tests fail. Manual end-to-end run against a migrated database and a running app: register, login, replay, foreign browser, unknown key and link conflicts, with the session accepted by `/profile`.

## Implementation Notes

- Verification is implemented in pure Python in `auth/nostr.py` (affine secp256k1 arithmetic, about 100 lines). It uses `hashlib` only and adds no dependency. The cost of one verification is a few milliseconds. If the maintainers prefer an audited library (for example one exposing `secp256k1` Schnorr), only `schnorr_verify` changes; the official vectors in the tests then act as the compatibility check.
- The migration was generated with `alembic revision --autogenerate` against a database at the previous head. The unrelated `permissions.permission_type` enum drift that autogenerate also reports was left out on purpose.
- Add `/auth/nostr` to `PUBLIC_PREFIXES`. If [Public Route Boundary Hardening](../public-route-boundary/spec.md) lands first, the entry must follow its segment-aware matching.
- The challenge endpoint creates one row per call and anonymous callers can call it. Rate limiting and a cleanup job are follow-ups, shared with LNURL challenges.

Risks:

- Pure-Python big-integer arithmetic is not constant time. The verifier only handles public values (public key, message and signature), so timing does not leak secrets.
- Without rate limiting, anonymous clients can create challenge rows and trigger signature verifications. A failed attempt burns a challenge but does not affect other users.
- Nostr keys are not recoverable. Users who lose the key and have no other login method lose the account; `link` is meant to attach a key to an account that also has another method.

Sequencing: this API first; a UI (NIP-07 button or NIP-46 flow) as a separate spec and pull request after a decision about `ui.run_javascript`.

## Traceability

- Code: `satoidc/satoidc/auth/nostr.py`, `satoidc/satoidc/routes/nostr_auth.py`, `satoidc/satoidc/schemas/nostr.py`, `satoidc/satoidc/models/__init__.py` (`User.nostr_pubkey`, `NostrAuthChallenge`), `satoidc/satoidc/auth/middleware.py`, `satoidc/satoidc/settings.py`, `satoidc/migrations/versions/95a7a4cb05e8_add_nostr_login.py`
- Tests: `satoidc/tests/test_nostr_auth.py`
- Docs: [Nostr Auth Flow](../../flows/nostr-auth.md), `README.md`
- Decisions: challenge bound to the browser session; consumption committed before verification; verification URL derived from `OAUTH2_JWT_ISS`; no UI until `ui.run_javascript` is authorized or NIP-46 is specified
