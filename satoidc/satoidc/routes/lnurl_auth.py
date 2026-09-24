from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from typing import Annotated, Literal, Optional

from fastapi import APIRouter, Depends, Query, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.lnurl import url_encode, verify
from satoidc.auth.lnurl_schemas import LnurlAuthCallbackIn
from satoidc.auth.session import current_user
from satoidc.models import LnurlAuthChallenge, User
from satoidc.models.database import get_session
from satoidc.settings import ENV
from satoidc.utils import safe_redirect

router = APIRouter(prefix="/auth/lnurl", tags=["LNURL Auth"])

Session = Annotated[AsyncSession, Depends(get_session)]


class ChallengeIn(BaseModel):
    action: Literal["login", "register", "link"] = "login"
    redirect_to: Optional[str] = "/"


def is_expired(challenge: LnurlAuthChallenge) -> bool:
    created_at = challenge.created_at
    if created_at.tzinfo is None:  # SQLite devolve datas sem timezone (UTC)
        created_at = created_at.replace(tzinfo=timezone.utc)
    ttl = timedelta(seconds=ENV.LNURL_K1_TTL_SECONDS)
    return datetime.now(timezone.utc) - created_at > ttl


@router.post("", status_code=HTTPStatus.CREATED)
async def create_challenge(
    request: Request, session: Session, body: ChallengeIn = ChallengeIn()
):
    """Cria o desafio (k1) que a carteira Lightning vai assinar."""
    owner = None
    if body.action == "link":
        # vincular carteira exige estar logado: o desafio nasce preso à conta
        owner = await current_user(session, request)
        if not owner:
            return JSONResponse(
                {"status": "ERROR", "reason": "login_required"},
                status_code=HTTPStatus.UNAUTHORIZED,
            )
    challenge = LnurlAuthChallenge(
        action=body.action, user_id=owner.id if owner else None
    )
    session.add(challenge)
    await session.commit()
    await session.refresh(challenge)

    # Amarra o desafio ao navegador que o pediu: só ele consegue concluir.
    request.session["lnurl_k1"] = challenge.k1
    request.session["lnurl_next"] = safe_redirect(body.redirect_to)

    base_url = str(request.base_url).rstrip("/")
    callback = f"{base_url}/auth/lnurl/callback?tag=login&k1={challenge.k1}"
    lnurl = url_encode(callback)
    return {
        "k1": challenge.k1,
        "action": challenge.action,
        "lnurl": lnurl,
        "uri": f"lightning:{lnurl}",
        "callback": callback,
        "expires_in": ENV.LNURL_K1_TTL_SECONDS,
    }


@router.get("/callback", status_code=HTTPStatus.OK)
async def lnurl_auth_callback(
    session: Session, query: Annotated[LnurlAuthCallbackIn, Query()]
):
    """Chamado pela carteira (LUD-04) com k1, sig e key."""
    challenge = await session.get(LnurlAuthChallenge, query.k1)
    if (
        not challenge
        or challenge.used
        or challenge.verified
        or is_expired(challenge)
    ):
        return {"status": "ERROR", "reason": "Invalid or expired k1"}

    if not verify(query.k1, query.key, query.sig):
        return {"status": "ERROR", "reason": "Bad signature"}

    user = await session.scalar(
        select(User).where(User.lnurl_pubkey == query.key)
    )

    if challenge.action == "link":
        if not challenge.user_id or (user and user.id != challenge.user_id):
            return {
                "status": "ERROR",
                "reason": "Esta carteira já está vinculada a outra conta",
            }
        owner = await session.get(User, challenge.user_id)
        owner.lnurl_pubkey = query.key
        session.add(owner)
        user = owner
    elif challenge.action == "register":
        if user:
            return {
                "status": "ERROR",
                "reason": "Esta carteira já está vinculada a uma conta",
            }
        user = User(
            lnurl_pubkey=query.key,
            email=None,
            login=None,
            password_hash=None,
        )
        session.add(user)
        await session.flush()
    elif not user:
        return {
            "status": "ERROR",
            "reason": "Nenhuma conta vinculada a esta carteira. Crie uma conta primeiro.",
        }

    challenge.verified = True
    challenge.user_id = user.id
    session.add(challenge)
    await session.commit()
    return {"status": "OK"}


@router.get("/status/{k1}")
async def challenge_status(k1: str, request: Request, session: Session):
    """O navegador consulta até a carteira concluir; aí abre a sessão."""
    if request.session.get("lnurl_k1") != k1:
        return {"status": "ERROR", "reason": "Unknown challenge"}

    challenge = await session.get(LnurlAuthChallenge, k1)
    if not challenge or challenge.used:
        return {"status": "ERROR", "reason": "Unknown challenge"}
    if not challenge.verified or not challenge.user_id:
        if is_expired(challenge):
            return {"status": "EXPIRED"}
        return {"status": "PENDING"}

    if challenge.action == "link":
        # só o dono da sessão que pediu o desafio conclui a vinculação
        if request.session.get("user_id") != challenge.user_id.hex:
            return {"status": "ERROR", "reason": "Unknown challenge"}
        challenge.used = True
        session.add(challenge)
        await session.commit()
        request.session.pop("lnurl_k1", None)
        request.session.pop("lnurl_next", None)
        return {"status": "OK", "redirect": "/account"}

    challenge.used = True
    session.add(challenge)
    await session.commit()

    request.session["user_id"] = challenge.user_id.hex
    request.session.pop("lnurl_k1", None)
    redirect = request.session.pop("lnurl_next", "/")
    return {"status": "OK", "redirect": redirect}
