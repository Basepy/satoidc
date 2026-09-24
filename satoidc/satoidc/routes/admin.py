import time
from datetime import datetime, timezone
from typing import Annotated, Optional
from uuid import UUID

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.guards import need_admin, not_found
from satoidc.auth.permissions import (
    get_permission,
    grant_permission,
    is_developer,
)
from satoidc.enums import PermissionsEnum
from satoidc.formatting import fmt_date
from satoidc.models import (
    DevAccessRequest,
    OAuth2Client,
    Permission,
    User,
)
from satoidc.models.database import get_session
from satoidc.web import templates

router = APIRouter(prefix="/admin", tags=["admin"])
Session = Annotated[AsyncSession, Depends(get_session)]

RECENT_LIMIT = 5


def display_name(user: User) -> str:
    return user.login or user.nickname


def parse_id(raw: str) -> Optional[UUID]:
    try:
        return UUID(raw)
    except ValueError:
        return None


async def count(session: AsyncSession, stmt) -> int:
    return (
        await session.scalar(select(func.count()).select_from(stmt.subquery()))
        or 0
    )


async def pending_requests(session: AsyncSession):
    rows = (
        await session.execute(
            select(DevAccessRequest, User)
            .join(User, User.id == DevAccessRequest.user_id)
            .where(DevAccessRequest.status == "pending")
            .order_by(DevAccessRequest.created_at)
        )
    ).all()
    return [
        {
            "id": str(req.id),
            "name": display_name(user),
            "initial": (display_name(user)[:1] or "?").upper(),
            "note": req.reason.strip(),
        }
        for req, user in rows
    ]


async def render_ops(
    session: AsyncSession, request: Request, user: User, dialog=None, req=None
):
    pending = await pending_requests(session)
    week_ago = int(time.time()) - 7 * 24 * 3600
    recent_rows = (
        await session.execute(
            select(DevAccessRequest, User)
            .join(User, User.id == DevAccessRequest.user_id)
            .where(DevAccessRequest.status == "approved")
            .order_by(DevAccessRequest.decided_at.desc())
            .limit(RECENT_LIMIT)
        )
    ).all()
    stats = {
        "pending": len(pending),
        "users": await count(session, select(User.id)),
        "developers": await count(
            session,
            select(Permission.id).where(
                Permission.permission_type == PermissionsEnum.DEVELOPER,
                Permission.disabled.is_(False),
            ),
        ),
        "clients": await count(session, select(OAuth2Client.id)),
        "clients_7d": await count(
            session,
            select(OAuth2Client.id).where(
                OAuth2Client.client_id_issued_at >= week_ago
            ),
        ),
        "inactive": await count(
            session,
            select(Permission.id).where(Permission.disabled.is_(True)),
        ),
    }
    return templates.TemplateResponse(
        request,
        "admin/ops.html",
        {
            "request": request,
            "user": user,
            "stats": stats,
            "pending": pending,
            "recent": [
                {"name": display_name(u), "date": fmt_date(r.decided_at)}
                for r, u in recent_rows
            ],
            "dialog": dialog,
            "req": req,
        },
    )


@router.get("")
async def overview(session: Session, request: Request):
    user, blocked = await need_admin(session, request)
    if blocked:
        return blocked
    return await render_ops(session, request, user)


# ---------------------------------------------------------------------
# Solicitações de acesso
# ---------------------------------------------------------------------


async def pending_request(session: AsyncSession, raw_id: str):
    req_id = parse_id(raw_id)
    if not req_id:
        return None
    req = await session.get(DevAccessRequest, req_id)
    return req if req and req.status == "pending" else None


@router.post("/requests/{req_id}/approve")
async def approve(req_id: str, session: Session, request: Request):
    admin, blocked = await need_admin(session, request)
    if blocked:
        return blocked
    req = await pending_request(session, req_id)
    if not req:
        return not_found(request)
    target = await session.get(User, req.user_id)
    await grant_permission(
        session,
        target,
        PermissionsEnum.DEVELOPER,
        granted_by=admin,
        reason=req.reason,
    )
    req.status = "approved"
    req.decided_by = admin.id
    req.decided_at = datetime.now(timezone.utc)
    await session.commit()
    return RedirectResponse("/admin", 303)


@router.get("/requests/{req_id}/deny")
async def deny_dialog(req_id: str, session: Session, request: Request):
    admin, blocked = await need_admin(session, request)
    if blocked:
        return blocked
    req = await pending_request(session, req_id)
    if not req:
        return not_found(request)
    target = await session.get(User, req.user_id)
    return await render_ops(
        session,
        request,
        admin,
        "deny",
        {"id": str(req.id), "name": display_name(target)},
    )


@router.post("/requests/{req_id}/deny")
async def deny(
    req_id: str,
    session: Session,
    request: Request,
    note: Annotated[str, Form()] = "",
):
    admin, blocked = await need_admin(session, request)
    if blocked:
        return blocked
    req = await pending_request(session, req_id)
    if not req:
        return not_found(request)
    req.status = "denied"
    req.decision_reason = note.strip() or None
    req.decided_by = admin.id
    req.decided_at = datetime.now(timezone.utc)
    await session.commit()
    return RedirectResponse("/admin", 303)


# ---------------------------------------------------------------------
# Usuários
# ---------------------------------------------------------------------


@router.get("/users")
async def users(session: Session, request: Request):
    admin, blocked = await need_admin(session, request)
    if blocked:
        return blocked
    rows = await session.scalars(select(User).order_by(User.created_at))
    items = []
    for u in rows:
        items.append(
            {
                "id": u.id,
                "name": display_name(u),
                "initial": (display_name(u)[:1] or "?").upper(),
                "email": u.email,
                "active": u.is_active,
                "developer": await is_developer(session, u),
                "wallet": bool(u.lnurl_pubkey),
                "created": fmt_date(u.created_at),
                "is_self": u.id == admin.id,
            }
        )
    return templates.TemplateResponse(
        request,
        "admin/users.html",
        {"request": request, "user": admin, "users": items, "dialog": None},
    )


@router.post("/users/{user_id}/developer")
async def set_developer(
    user_id: str,
    session: Session,
    request: Request,
    grant: Annotated[str, Form()] = "0",
):
    admin, blocked = await need_admin(session, request)
    if blocked:
        return blocked
    uid = parse_id(user_id)
    target = await session.get(User, uid) if uid else None
    if not target:
        return not_found(request)
    if grant == "1":
        await grant_permission(
            session, target, PermissionsEnum.DEVELOPER, granted_by=admin
        )
    else:
        perm = await get_permission(session, target, PermissionsEnum.DEVELOPER)
        if perm:
            perm.disabled = True
    await session.commit()
    return RedirectResponse("/admin/users", 303)


@router.post("/users/{user_id}/active")
async def set_active(
    user_id: str,
    session: Session,
    request: Request,
    active: Annotated[str, Form()] = "1",
):
    admin, blocked = await need_admin(session, request)
    if blocked:
        return blocked
    uid = parse_id(user_id)
    target = await session.get(User, uid) if uid else None
    if not target:
        return not_found(request)
    if target.id != admin.id:  # ninguém desativa a própria conta por aqui
        target.is_active = active == "1"
        await session.commit()
    return RedirectResponse("/admin/users", 303)
