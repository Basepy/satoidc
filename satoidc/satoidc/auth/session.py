"""Helpers da sessão de navegador (cookie assinado)."""

from typing import Optional
from uuid import UUID

from sqlalchemy.ext.asyncio import AsyncSession
from starlette.requests import Request

from satoidc.models import User


async def current_user(
    session: AsyncSession, request: Request
) -> Optional[User]:
    """Usuário logado (ou None se a sessão for inválida/inativa)."""
    raw = request.session.get("user_id")
    if not raw:
        return None
    try:
        user = await session.get(User, UUID(raw))
    except (ValueError, TypeError):
        return None
    if not user or not user.is_active:
        return None
    return user
