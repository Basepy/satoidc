import re
from typing import Annotated, Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form
from fastapi.responses import RedirectResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from satoidc.auth.nostr import (
    NostrKeyError,
    generate_keys,
    keys_from_private_key,
)
from satoidc.auth.security import hash_password
from satoidc.models import User
from satoidc.models.database import get_session
from satoidc.utils import safe_redirect
from satoidc.web import templates

router = APIRouter()

LOGIN_RE = re.compile(r"^[a-z0-9]{6,30}$")
MIN_PASSWORD_LENTH = 8


Session = Annotated[AsyncSession, Depends(get_session)]


def register_error_url(err: str, redirect_to: str) -> str:
    return f"/register?err={err}&redirect_to={quote(redirect_to, safe='')}"


async def create_nostr_user(
    session: Session,
    request: Request,
    keys,
    nickname: Optional[str],
    redirect_to: str,
):
    existing = await session.scalar(
        select(User).where(User.nostr_pubkey == keys.public_key_hex)
    )
    if existing:
        return RedirectResponse(
            url=register_error_url("nostr_exists", redirect_to),
            status_code=303,
        )

    user = User(
        lnurl_pubkey=None,
        email=None,
        login=None,
        nickname=(nickname or "").strip() or "Satoshi",
        password_hash=None,
        nostr_pubkey=keys.public_key_hex,
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    request.session["user_id"] = user.id.hex

    return templates.TemplateResponse(
        request,
        "register.html",
        {
            "request": request,
            "redirect_to": redirect_to,
            "redirect_to_encoded": quote(redirect_to, safe=""),
            "err": None,
            "generated_keys": keys,
        },
    )


@router.get("/register")
async def register_page(
    request: Request,
    redirect_to: Optional[str] = None,
    err: Optional[str] = None,
):
    redirect_to = safe_redirect(redirect_to)
    return templates.TemplateResponse(
        request,
        "register.html",
        {
            "request": request,
            "redirect_to": redirect_to,
            "redirect_to_encoded": quote(redirect_to, safe=""),
            "err": err,
            "generated_keys": None,
        },
    )


@router.post("/register")
async def register_post(
    session: Session,
    request: Request,
    login: Annotated[str, Form()],
    email: Annotated[str, Form()],
    password: Annotated[str, Form()],
    confirm: Annotated[str, Form()],
    nickname: Annotated[Optional[str], Form()] = None,
    redirect_to: Annotated[Optional[str], Form()] = "/",
):
    redirect_to = safe_redirect(redirect_to)
    login_value = login.strip()
    email_value = email.strip().lower()

    if not LOGIN_RE.fullmatch(login_value):
        return RedirectResponse(register_error_url("login", redirect_to), 303)
    if not email_value or "@" not in email_value:
        return RedirectResponse(register_error_url("email", redirect_to), 303)
    if len(password) < MIN_PASSWORD_LENTH:
        return RedirectResponse(register_error_url("password", redirect_to), 303)
    if password != confirm:
        return RedirectResponse(register_error_url("confirm", redirect_to), 303)

    existing = await session.scalar(
        select(User).where(User.login == login_value)
    ) or await session.scalar(select(User).where(User.email == email_value))
    if existing:
        return RedirectResponse(register_error_url("exists", redirect_to), 303)

    user = User(
        lnurl_pubkey=None,
        login=login_value,
        email=email_value,
        nickname=(nickname or "").strip() or "Satoshi",
        password_hash=hash_password(password),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    request.session["user_id"] = user.id.hex
    return RedirectResponse(url=redirect_to, status_code=303)


@router.post("/register/nostr/generate")
async def register_nostr_generate(
    session: Session,
    request: Request,
    nickname: Annotated[Optional[str], Form()] = None,
    redirect_to: Annotated[Optional[str], Form()] = "/",
):
    redirect_to = safe_redirect(redirect_to)
    return await create_nostr_user(
        session, request, generate_keys(), nickname, redirect_to
    )


@router.post("/register/nostr")
async def register_nostr_existing(
    session: Session,
    request: Request,
    nostr_private_key: Annotated[str, Form()],
    nickname: Annotated[Optional[str], Form()] = None,
    redirect_to: Annotated[Optional[str], Form()] = "/",
):
    redirect_to = safe_redirect(redirect_to)
    try:
        keys = keys_from_private_key(nostr_private_key)
    except NostrKeyError:
        return RedirectResponse(
            url=register_error_url("nostr_invalid", redirect_to),
            status_code=303,
        )
    return await create_nostr_user(session, request, keys, nickname, redirect_to)
