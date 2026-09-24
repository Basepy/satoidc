"""Guardas das telas logadas: sessão, desenvolvedor e administrador."""

from typing import Optional
from urllib.parse import quote

from fastapi import Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.permissions import is_admin, is_developer
from satoidc.auth.session import current_user
from satoidc.models import User
from satoidc.web import templates


def login_redirect(request: Request) -> RedirectResponse:
    target = request.url.path
    if request.url.query:
        target += f"?{request.url.query}"
    return RedirectResponse(f"/login?redirect_to={quote(target, safe='')}", 303)


def error_page(request: Request, status: int, title: str, message: str):
    return templates.TemplateResponse(
        request,
        "auth/error.html",
        {"request": request, "title": title, "message": message, "code": None},
        status_code=status,
    )


def forbidden(request: Request):
    return error_page(
        request,
        403,
        "Acesso restrito",
        "Você não tem permissão para abrir esta página.",
    )


def not_found(request: Request):
    return error_page(
        request,
        404,
        "Não encontrado",
        "Não encontramos o que você procurou.",
    )


async def need_user(
    session: AsyncSession, request: Request
) -> Optional[User]:
    user = await current_user(session, request)
    if user is None:
        request.session.clear()
    return user


async def need_developer(session: AsyncSession, request: Request):
    """(usuário, resposta). Resposta != None quando o acesso deve ser barrado."""
    user = await need_user(session, request)
    if not user:
        return None, login_redirect(request)
    if await is_developer(session, user) or await is_admin(session, user):
        return user, None
    return user, forbidden(request)


async def need_admin(session: AsyncSession, request: Request):
    user = await need_user(session, request)
    if not user:
        return None, login_redirect(request)
    if await is_admin(session, user):
        return user, None
    return user, forbidden(request)
