"""Permissões de usuário (desenvolvedor, administrador)."""

from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.enums import PermissionsEnum
from satoidc.models import Permission, User
from satoidc.settings import ENV


def _bootstrap_admins() -> set[str]:
    return {a.strip().lower() for a in ENV.ADMIN_USERS.split(",") if a.strip()}


def is_bootstrap_admin(user: User) -> bool:
    admins = _bootstrap_admins()
    return bool(
        admins
        and (
            (user.login or "").lower() in admins
            or (user.email or "").lower() in admins
        )
    )


def _is_active(perm: Permission) -> bool:
    if perm.disabled:
        return False
    if perm.expiration_date is None:
        return True
    expiry = perm.expiration_date
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    return expiry > datetime.now(timezone.utc)


async def get_permission(
    session: AsyncSession, user: User, kind: PermissionsEnum
) -> Optional[Permission]:
    return await session.scalar(
        select(Permission).where(
            Permission.user_id == user.id,
            Permission.permission_type == kind,
        )
    )


async def has_permission(
    session: AsyncSession, user: User, kind: PermissionsEnum
) -> bool:
    perm = await get_permission(session, user, kind)
    return bool(perm and _is_active(perm))


async def is_admin(session: AsyncSession, user: User) -> bool:
    return (
        is_bootstrap_admin(user)
        or await has_permission(session, user, PermissionsEnum.ADMIN)
        or await has_permission(session, user, PermissionsEnum.ROOT)
    )


async def is_developer(session: AsyncSession, user: User) -> bool:
    return await has_permission(session, user, PermissionsEnum.DEVELOPER)


async def grant_permission(
    session: AsyncSession,
    user: User,
    kind: PermissionsEnum,
    granted_by: Optional[User] = None,
    reason: Optional[str] = None,
) -> Permission:
    """Concede (ou reativa) uma permissão. Não faz commit."""
    perm = await get_permission(session, user, kind)
    if perm:
        perm.disabled = False
        perm.expiration_date = None
        perm.reason = reason
        perm.granted_by = granted_by.id if granted_by else None
    else:
        perm = Permission(
            user_id=user.id,
            granted_by=granted_by.id if granted_by else None,
            permission_type=kind,
            expiration_date=None,
            reason=reason,
        )
        session.add(perm)
    return perm
