from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.nostr import NostrEventError, check_auth_event
from satoidc.models import NostrAuthChallenge, User
from satoidc.models.database import get_session
from satoidc.schemas.nostr import NostrChallengeIn, NostrVerifyIn
from satoidc.settings import ENV
from satoidc.utils import safe_redirect

router = APIRouter(prefix="/auth/nostr", tags=["Nostr Auth"])

Session = Annotated[AsyncSession, Depends(get_session)]

# The challenge is bound to the browser session that requested it.
SESSION_CHALLENGE = "nostr_k1"
SESSION_REDIRECT = "nostr_next"

INVALID_CHALLENGE = "Invalid or expired challenge"
KEY_TAKEN = "Nostr key already linked to an account"


def _error(reason: str, status: HTTPStatus) -> JSONResponse:
    return JSONResponse(
        {"status": "ERROR", "reason": reason}, status_code=status
    )


def _verify_url() -> str:
    """Absolute URL that clients must sign (NIP-98 ``u`` tag)."""
    return f"{ENV.OAUTH2_JWT_ISS.rstrip('/')}/auth/nostr/verify"


def _session_user_id(request: Request) -> Optional[UUID]:
    value = request.session.get("user_id")
    try:
        return UUID(str(value)) if value else None
    except ValueError:
        return None


def _open_session(request: Request, user: User) -> dict:
    request.session["user_id"] = user.id.hex
    redirect = request.session.pop(SESSION_REDIRECT, "/")
    return {"status": "OK", "redirect": safe_redirect(redirect)}


async def _consume_challenge(
    session: AsyncSession, k1: str
) -> Optional[NostrAuthChallenge]:
    """Atomically mark an unused, unexpired challenge as consumed."""
    cutoff = datetime.now(timezone.utc) - timedelta(
        seconds=ENV.NOSTR_CHALLENGE_TTL_SECONDS
    )
    challenge = await session.scalar(
        update(NostrAuthChallenge)
        .where(
            NostrAuthChallenge.k1 == k1,
            NostrAuthChallenge.consumed.is_(False),
            NostrAuthChallenge.created_at >= cutoff,
        )
        .values(consumed=True)
        .returning(NostrAuthChallenge)
        .execution_options(synchronize_session=False)
    )
    # Commit right away so a failed attempt can never be replayed.
    await session.commit()
    return challenge


async def _login(
    request: Request,
    session: AsyncSession,
    challenge: NostrAuthChallenge,
    pubkey: str,
):
    user = await session.scalar(
        select(User).where(User.nostr_pubkey == pubkey)
    )
    if not user:
        return JSONResponse(
            {"status": "NOT_FOUND", "reason": "No account for this key"},
            status_code=HTTPStatus.NOT_FOUND,
        )
    if not user.is_active:
        return _error("Account is disabled", HTTPStatus.FORBIDDEN)
    return _open_session(request, user)


async def _register(
    request: Request,
    session: AsyncSession,
    challenge: NostrAuthChallenge,
    pubkey: str,
):
    if await session.scalar(select(User).where(User.nostr_pubkey == pubkey)):
        return _error(KEY_TAKEN, HTTPStatus.CONFLICT)
    user = User(
        lnurl_pubkey=None,
        email=None,
        login=None,
        password_hash=None,
        nostr_pubkey=pubkey,
    )
    session.add(user)
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        return _error(KEY_TAKEN, HTTPStatus.CONFLICT)
    return _open_session(request, user)


async def _link(
    request: Request,
    session: AsyncSession,
    challenge: NostrAuthChallenge,
    pubkey: str,
):
    # The authenticated account must still be the one that asked.
    if not challenge.user_id or _session_user_id(request) != challenge.user_id:
        return _error("Authentication required", HTTPStatus.UNAUTHORIZED)
    user = await session.get(User, challenge.user_id)
    if not user or not user.is_active:
        return _error("Account not found", HTTPStatus.FORBIDDEN)
    if user.nostr_pubkey and user.nostr_pubkey != pubkey:
        return _error("Account already has a Nostr key", HTTPStatus.CONFLICT)
    owner = await session.scalar(
        select(User).where(User.nostr_pubkey == pubkey)
    )
    if owner and owner.id != user.id:
        return _error(KEY_TAKEN, HTTPStatus.CONFLICT)

    user.nostr_pubkey = pubkey
    try:
        await session.commit()
    except IntegrityError:
        await session.rollback()
        return _error(KEY_TAKEN, HTTPStatus.CONFLICT)
    request.session.pop(SESSION_REDIRECT, None)
    return {"status": "OK"}


ACTIONS = {"login": _login, "register": _register, "link": _link}


@router.post("/challenge", status_code=HTTPStatus.CREATED)
async def create_challenge(
    body: NostrChallengeIn, request: Request, session: Session
):
    """Create a one-time challenge for the signed Nostr event."""
    user_id = None
    if body.action == "link":
        user_id = _session_user_id(request)
        if not user_id:
            return _error("Authentication required", HTTPStatus.UNAUTHORIZED)

    challenge = NostrAuthChallenge(
        action=body.action, url=_verify_url(), user_id=user_id
    )
    session.add(challenge)
    await session.commit()
    await session.refresh(challenge)

    request.session[SESSION_CHALLENGE] = challenge.k1
    request.session[SESSION_REDIRECT] = safe_redirect(body.redirect_to)
    return {
        "k1": challenge.k1,
        "action": challenge.action,
        "url": challenge.url,
        "expires_in": ENV.NOSTR_CHALLENGE_TTL_SECONDS,
    }


@router.post("/verify")
async def verify(body: NostrVerifyIn, request: Request, session: Session):
    """Verify the signed event and run the action stored in the challenge."""
    if request.session.get(SESSION_CHALLENGE) != body.k1:
        return _error(INVALID_CHALLENGE, HTTPStatus.BAD_REQUEST)
    # One attempt per challenge: it is consumed before the signature check.
    request.session.pop(SESSION_CHALLENGE, None)
    challenge = await _consume_challenge(session, body.k1)
    if not challenge:
        return _error(INVALID_CHALLENGE, HTTPStatus.BAD_REQUEST)

    try:
        pubkey = check_auth_event(
            body.event, url=challenge.url, challenge=challenge.k1
        )
    except NostrEventError as exc:
        return _error(str(exc), HTTPStatus.BAD_REQUEST)

    handler = ACTIONS.get(challenge.action)
    if not handler:
        return _error("Unknown action", HTTPStatus.BAD_REQUEST)
    return await handler(request, session, challenge, pubkey)
