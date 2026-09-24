import re
from typing import Annotated, Optional
from urllib.parse import quote

from fastapi import APIRouter, Depends, Form
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from satoidc.auth.security import hash_password
from satoidc.models import User
from satoidc.models.database import get_session
from satoidc.utils import safe_redirect
from satoidc.web import templates

router = APIRouter()

LOGIN_RE = re.compile(r"^[a-z0-9]{6,30}$")
NICKNAME_RE = re.compile(r"^[\w.\-]{2,80}$", re.UNICODE)
EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")
MIN_PASSWORD_LENGTH = 8

Session = Annotated[AsyncSession, Depends(get_session)]

MESSAGES = {
    "login": "Use de 6 a 30 letras minúsculas e números.",
    "login_taken": "Este login já está em uso.",
    "email": "Informe um e-mail válido.",
    "email_taken": "Este e-mail já está cadastrado.",
    "nickname": "Letras, números, ponto, _ ou -, de 2 a 80 caracteres.",
    "password": "A senha precisa ter 8 ou mais caracteres com maiúscula, minúscula, número e símbolo.",
    "confirm": "As senhas não conferem.",
    "terms": "Você precisa aceitar os Termos de Serviço.",
}


def strong_password(password: str) -> bool:
    return (
        len(password) >= MIN_PASSWORD_LENGTH
        and any(c.islower() for c in password)
        and any(c.isupper() for c in password)
        and any(c.isdigit() for c in password)
        and any(not c.isalnum() for c in password)
    )


def render_form(request, redirect_to, values=None, errs=None, status=200):
    return templates.TemplateResponse(
        request,
        "auth/register.html",
        {
            "request": request,
            "redirect_to": redirect_to,
            "redirect_to_encoded": quote(redirect_to, safe=""),
            "values": values or {},
            "errs": {k: MESSAGES[v] for k, v in (errs or {}).items()},
        },
        status_code=status,
    )


@router.get("/register")
async def register_page(
    request: Request,
    redirect_to: Optional[str] = None,
):
    return render_form(request, safe_redirect(redirect_to))


@router.post("/register")
async def register_post(
    session: Session,
    request: Request,
    login: Annotated[str, Form()] = "",
    email: Annotated[str, Form()] = "",
    password: Annotated[str, Form()] = "",
    confirm: Annotated[str, Form()] = "",
    nickname: Annotated[Optional[str], Form()] = None,
    terms: Annotated[Optional[str], Form()] = None,
    redirect_to: Annotated[Optional[str], Form()] = "/",
):
    redirect_to = safe_redirect(redirect_to)
    login_value = login.strip()
    email_value = email.strip().lower()
    nickname_value = (nickname or "").strip()
    errs: dict[str, str] = {}

    if not LOGIN_RE.fullmatch(login_value):
        errs["login"] = "login"
    if not EMAIL_RE.fullmatch(email_value):
        errs["email"] = "email"
    if nickname_value and not NICKNAME_RE.fullmatch(nickname_value):
        errs["nickname"] = "nickname"
    if not strong_password(password):
        errs["password"] = "password"
    elif password != confirm:
        errs["confirm"] = "confirm"
    if not terms:
        errs["terms"] = "terms"

    if "login" not in errs and await session.scalar(
        select(User).where(User.login == login_value)
    ):
        errs["login"] = "login_taken"
    if "email" not in errs and await session.scalar(
        select(User).where(func.lower(User.email) == email_value)
    ):
        errs["email"] = "email_taken"

    if errs:
        return render_form(
            request,
            redirect_to,
            values={
                "login": login_value,
                "email": email.strip(),
                "nickname": nickname_value,
            },
            errs=errs,
            status=422,
        )

    user = User(
        lnurl_pubkey=None,
        login=login_value,
        email=email_value,
        nickname=nickname_value or "Satoshi",
        password_hash=hash_password(password),
    )
    session.add(user)
    await session.commit()
    await session.refresh(user)
    request.session["user_id"] = user.id.hex
    return RedirectResponse(url=redirect_to, status_code=303)
