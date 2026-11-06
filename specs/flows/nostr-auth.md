# Nostr Auth Flow

Status: review
Updated: 2026-11-06

See the feature spec: [Nostr Login](../features/nostr-login/spec.md).

## Actors

- User browser (or any HTTP client acting for the user) holding the session cookie.
- Nostr signer: browser extension (NIP-07), remote signer (NIP-46) or another Nostr client holding the private key.
- SatOIDC app.
- Database.

## Challenge Creation

```text
POST /auth/nostr/challenge
{"action": "login" | "register" | "link", "redirect_to": "/path"}
```

The app creates a `NostrAuthChallenge` with a random `k1`, the action and the verification URL (`<OAUTH2_JWT_ISS>/auth/nostr/verify`), stores `k1` and the safe redirect in the session, and returns `k1`, `action`, `url` and `expires_in`. `link` requires an authenticated session and remembers the user.

## Signed Event

The signer builds a NIP-98 event:

```json
{
  "kind": 27235,
  "content": "",
  "created_at": 1767268800,
  "tags": [
    ["u", "<url from the challenge>"],
    ["method", "POST"],
    ["challenge", "<k1>"]
  ]
}
```

and signs it (BIP-340). The private key never leaves the signer.

## Verification

```text
POST /auth/nostr/verify
{"k1": "<hex>", "event": {...}}
```

1. The `k1` must equal the one stored in the caller's session.
2. The challenge is consumed atomically if it is unused and younger than `NOSTR_CHALLENGE_TTL_SECONDS`; the consumption is committed before anything else.
3. The event is validated: kind, empty content, `u`, `method` and `challenge` tags, clock skew of at most 60 seconds, event id and BIP-340 signature.
4. The action runs for the event's public key.

## Action Behavior

- `login`: opens the session of the active user linked to the key; `NOT_FOUND` when no account exists.
- `register`: creates a user with only `nostr_pubkey` and opens its session; conflict when the key is linked.
- `link`: sets `nostr_pubkey` on the authenticated user that asked; conflict when the account already has another key or the key belongs to another account.

## Differences From LNURL-auth

- The caller is the user's browser, not a wallet. The challenge is therefore bound to the browser session.
- There is no `auth` action and no event emitter: success opens the session directly in the response.
- Errors use HTTP status codes instead of the LNURL `status`/`reason` body at status 200.
- A failed attempt consumes the challenge and the consumption is committed, so replay defense does not depend on a later commit.

## Risks To Resolve

- No UI yet; see the feature spec for the NIP-07 and NIP-46 options.
- No rate limiting or expired-challenge cleanup.
