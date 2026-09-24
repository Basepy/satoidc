import uuid
from typing import Annotated, Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.nostr import NostrKeyError, keys_from_private_key
from satoidc.auth.security import verify_password
from satoidc.models import User
from satoidc.models.database import get_session
from satoidc.utils import safe_redirect
from satoidc.web import templates

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]


# ---------------------------
# Helpers
# ---------------------------


def build_return_to(request: Request) -> str:
    """Constrói /path?query a partir do request atual."""
    path = request.url.path
    if request.url.query:
        return f"{path}?{request.url.query}"
    return path


def redirect_to_login(request: Request) -> RedirectResponse:
    """Redirect para /login com redirect_to URL-encoded."""
    return_to = build_return_to(request)
    return RedirectResponse(
        url=f"/login?redirect_to={quote(return_to, safe='')}",
        status_code=303,
    )


def encode_query_value(value: str) -> str:
    """URL-encode seguro para valores em querystring."""
    return quote(value or "", safe="")


@router.post("/login")
async def login_post(
    session: Session,
    request: Request,
    identifier: Annotated[str, Form()],
    password: Annotated[str, Form()],
    redirect_to: Annotated[Optional[str], Form()] = "/",
    login_nonce: Annotated[Optional[str], Form()] = None,
):
    expected_nonce = request.session.get("login_nonce")
    if (
        not expected_nonce
        or not login_nonce
        or login_nonce != expected_nonce
    ):
        request.session.pop("login_nonce", None)
        return RedirectResponse(url="/login?err=bad_flow", status_code=303)

    request.session.pop("login_nonce", None)
    nxt = safe_redirect(redirect_to)

    user = await session.scalar(
        select(User).where(
            (User.email == identifier)
            | (User.login == identifier)
        )
    )
    if not user or not user.password_hash or not verify_password(
        password, user.password_hash
    ):
        return RedirectResponse(
            url=f"/login?err=invalid&redirect_to={encode_query_value(nxt)}",
            status_code=303,
        )

    request.session["user_id"] = user.id.hex
    return RedirectResponse(url=nxt, status_code=303)


@router.post("/login/nostr")
async def login_nostr_post(
    session: Session,
    request: Request,
    nostr_private_key: Annotated[str, Form()],
    redirect_to: Annotated[Optional[str], Form()] = "/",
):
    nxt = safe_redirect(redirect_to)
    try:
        keys = keys_from_private_key(nostr_private_key)
    except NostrKeyError:
        return RedirectResponse(
            url=f"/login?err=nostr_invalid&redirect_to={encode_query_value(nxt)}",
            status_code=303,
        )

    user = await session.scalar(
        select(User).where(User.nostr_pubkey == keys.public_key_hex)
    )
    if not user:
        return RedirectResponse(
            url=f"/login?err=nostr_not_found&redirect_to={encode_query_value(nxt)}",
            status_code=303,
        )

    request.session["user_id"] = user.id.hex
    return RedirectResponse(url=nxt, status_code=303)


@router.get("/login")
async def login_page(
    request: Request,
    redirect_to: Optional[str] = "/",
    err: Optional[str] = None,
):
    login_nonce = uuid.uuid4().hex
    request.session["login_nonce"] = login_nonce
    safe_next = safe_redirect(redirect_to)
    return templates.TemplateResponse(
        request,
        "login.html",
        {
            "request": request,
            "redirect_to": safe_next,
            "redirect_to_encoded": encode_query_value(safe_next),
            "login_nonce": login_nonce,
            "err": err,
        },
    )


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)
