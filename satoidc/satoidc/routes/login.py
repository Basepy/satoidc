import uuid
from typing import Annotated, Literal, Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.security import hash_password, verify_password
from satoidc.models import User
from satoidc.models.database import get_session
from satoidc.utils import safe_redirect
from satoidc.web import templates

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]

# Hash "fantasma": mantém o tempo de resposta igual quando o login não existe
_DUMMY_HASH = hash_password(uuid.uuid4().hex)

BAD_CREDENTIALS = "E-mail ou senha incorretos. Tente novamente."


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


def base_context(request: Request, redirect_to: Optional[str]) -> dict:
    safe_next = safe_redirect(redirect_to)
    return {
        "request": request,
        "redirect_to": safe_next,
        "redirect_to_encoded": encode_query_value(safe_next),
    }


# ---------------------------
# 1 · identificação
# ---------------------------


@router.get("/login")
async def login_page(
    request: Request,
    redirect_to: Optional[str] = "/",
    err: Optional[str] = None,
):
    request.session.pop("login_identifier", None)
    return templates.TemplateResponse(
        request,
        "auth/identify.html",
        {
            **base_context(request, redirect_to),
            "identifier": "",
            "err": err,
            "err_text": (
                "Informe seu e-mail ou login."
                if err == "empty"
                else "Sua sessão de login expirou. Tente novamente."
            ),
        },
    )


@router.post("/login")
async def login_identify(
    request: Request,
    login: Annotated[str, Form()] = "",
    redirect_to: Annotated[Optional[str], Form()] = "/",
):
    nxt = safe_redirect(redirect_to)
    identifier = login.strip()
    if not identifier:
        return RedirectResponse(
            f"/login?err=empty&redirect_to={encode_query_value(nxt)}", 303
        )
    request.session["login_identifier"] = identifier[:254]
    return RedirectResponse(
        f"/login/password?redirect_to={encode_query_value(nxt)}", 303
    )


# ---------------------------
# 2 · senha
# ---------------------------


@router.get("/login/password")
async def password_page(
    request: Request,
    redirect_to: Optional[str] = "/",
    err: Optional[str] = None,
):
    identifier = request.session.get("login_identifier")
    if not identifier:
        return RedirectResponse(
            f"/login?redirect_to={encode_query_value(safe_redirect(redirect_to))}",
            303,
        )
    login_nonce = uuid.uuid4().hex
    request.session["login_nonce"] = login_nonce
    return templates.TemplateResponse(
        request,
        "auth/password.html",
        {
            **base_context(request, redirect_to),
            "identifier": identifier,
            "login_nonce": login_nonce,
            "err": err,
            "err_text": BAD_CREDENTIALS,
        },
    )


@router.post("/login/password")
async def login_password(
    session: Session,
    request: Request,
    password: Annotated[str, Form()],
    redirect_to: Annotated[Optional[str], Form()] = "/",
    login_nonce: Annotated[Optional[str], Form()] = None,
):
    nxt = safe_redirect(redirect_to)
    expected_nonce = request.session.pop("login_nonce", None)
    identifier = request.session.get("login_identifier")
    if (
        not identifier
        or not expected_nonce
        or not login_nonce
        or login_nonce != expected_nonce
    ):
        return RedirectResponse(
            f"/login?err=bad_flow&redirect_to={encode_query_value(nxt)}", 303
        )

    user = await session.scalar(
        select(User).where(
            (func.lower(User.email) == identifier.lower())
            | (User.login == identifier)
        )
    )
    password_hash = user.password_hash if user and user.password_hash else _DUMMY_HASH
    valid = verify_password(password, password_hash)
    if not user or not user.password_hash or not valid or not user.is_active:
        return RedirectResponse(
            f"/login/password?err=1&redirect_to={encode_query_value(nxt)}",
            303,
        )

    request.session.pop("login_identifier", None)
    request.session["user_id"] = user.id.hex
    return RedirectResponse(url=nxt, status_code=303)


# ---------------------------
# 3 · Lightning
# ---------------------------


@router.get("/login/lightning")
async def login_lightning_page(
    request: Request,
    redirect_to: Optional[str] = "/",
    action: Literal["login", "register"] = "login",
):
    return templates.TemplateResponse(
        request,
        "auth/lightning.html",
        {
            **base_context(request, redirect_to),
            "action": action,
            "domain": request.url.netloc,
        },
    )


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/login", status_code=303)
