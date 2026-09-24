import time
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.guards import login_redirect, need_user
from satoidc.auth.permissions import is_admin, is_developer
from satoidc.auth.security import hash_password, verify_password
from satoidc.formatting import fmt_date, scope_labels, short
from satoidc.models import (
    AuthorizedApp,
    DevAccessRequest,
    OAuth2Client,
    OAuth2Token,
    User,
)
from satoidc.models.database import get_session
from satoidc.routes.register import EMAIL_RE, NICKNAME_RE, strong_password
from satoidc.web import templates

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]

APPS_PREVIEW = 5
MIN_REASON = 10


async def dev_status(session: AsyncSession, user: User) -> str:
    if await is_developer(session, user):
        return "active"
    last = await session.scalar(
        select(DevAccessRequest)
        .where(DevAccessRequest.user_id == user.id)
        .order_by(DevAccessRequest.created_at.desc())
    )
    if last and last.status in ("pending", "denied"):
        return last.status
    return "none"


async def connected_apps(session: AsyncSession, user: User, everything: bool):
    rows = (
        await session.execute(
            select(AuthorizedApp, OAuth2Client)
            .join(
                OAuth2Client,
                OAuth2Client.client_id == AuthorizedApp.client_id,
            )
            .where(AuthorizedApp.user_id == user.id)
            .order_by(AuthorizedApp.updated_at.desc())
        )
    ).all()
    apps = []
    for grant, client in rows:
        name = client.client_name or client.client_id
        apps.append(
            {
                "name": name,
                "initial": (name[:1] or "?").upper(),
                "client_id": client.client_id,
                "scopes": scope_labels(grant.scope),
                "granted": fmt_date(grant.updated_at or grant.created_at),
            }
        )
    return apps if everything else apps[:APPS_PREVIEW], len(apps)


async def render_account(
    session: AsyncSession,
    request: Request,
    user: User,
    dialog: Optional[str] = None,
    errs: Optional[dict] = None,
    values: Optional[dict] = None,
    status: int = 200,
):
    apps, total = await connected_apps(
        session, user, request.query_params.get("apps") == "all"
    )
    defaults = {
        "nick": user.nickname,
        "email": user.email or "",
        "reason": "",
    }
    return templates.TemplateResponse(
        request,
        "account/index.html",
        {
            "request": request,
            "user": user,
            "sub_short": short(user.id.hex, 8, 8),
            "created": fmt_date(user.created_at),
            "has_password": bool(user.password_hash),
            "wallet": short(user.lnurl_pubkey) if user.lnurl_pubkey else None,
            "dev_status": await dev_status(session, user),
            "is_admin": await is_admin(session, user),
            "apps": apps,
            "apps_total": total,
            "dialog": dialog,
            "errs": errs or {},
            "values": {**defaults, **(values or {})},
        },
        status_code=status,
    )


# ---------------------------------------------------------------------
# Página principal
# ---------------------------------------------------------------------


@router.get("/")
async def root():
    return RedirectResponse("/account", 303)


@router.get("/account")
async def account(session: Session, request: Request):
    user = await need_user(session, request)
    if not user:
        return login_redirect(request)
    return await render_account(session, request, user)


# ---------------------------------------------------------------------
# Diálogos (GET mostra a conta com o diálogo por cima; POST aplica)
# ---------------------------------------------------------------------


@router.get("/account/nickname")
async def nickname_dialog(session: Session, request: Request):
    user = await need_user(session, request)
    if not user:
        return login_redirect(request)
    return await render_account(session, request, user, "nickname")


@router.post("/account/nickname")
async def nickname_save(
    session: Session, request: Request, nick: Annotated[str, Form()] = ""
):
    user = await need_user(session, request)
    if not user:
        return login_redirect(request)
    nick = nick.strip()
    if not NICKNAME_RE.fullmatch(nick):
        return await render_account(
            session,
            request,
            user,
            "nickname",
            {"nick": "Use letras, números, ponto, _ ou -, de 2 a 80 caracteres."},
            {"nick": nick},
            422,
        )
    user.nickname = nick
    await session.commit()
    return RedirectResponse("/account", 303)


@router.get("/account/email")
async def email_dialog(session: Session, request: Request):
    user = await need_user(session, request)
    if not user:
        return login_redirect(request)
    return await render_account(session, request, user, "email")


@router.post("/account/email")
async def email_save(
    session: Session,
    request: Request,
    email: Annotated[str, Form()] = "",
    pwd: Annotated[str, Form()] = "",
):
    user = await need_user(session, request)
    if not user:
        return login_redirect(request)
    email = email.strip().lower()
    errs = {}
    if not EMAIL_RE.fullmatch(email):
        errs["email"] = "Informe um e-mail válido."
    elif await session.scalar(
        select(User).where(func.lower(User.email) == email, User.id != user.id)
    ):
        errs["email"] = "Este e-mail já está cadastrado."
    if user.password_hash and not verify_password(pwd, user.password_hash):
        errs["pwd"] = "Senha incorreta."
    if errs:
        return await render_account(
            session, request, user, "email", errs, {"email": email}, 422
        )
    user.email = email
    await session.commit()
    return RedirectResponse("/account", 303)


@router.get("/account/password")
async def password_dialog(session: Session, request: Request):
    user = await need_user(session, request)
    if not user:
        return login_redirect(request)
    return await render_account(session, request, user, "password")


@router.post("/account/password")
async def password_save(
    session: Session,
    request: Request,
    cur: Annotated[str, Form()] = "",
    new: Annotated[str, Form()] = "",
    conf: Annotated[str, Form()] = "",
):
    user = await need_user(session, request)
    if not user:
        return login_redirect(request)
    errs = {}
    if user.password_hash and not verify_password(cur, user.password_hash):
        errs["cur"] = "Senha atual incorreta."
    if not strong_password(new):
        errs["new"] = "8 ou mais caracteres com maiúscula, minúscula, número e símbolo."
    elif new != conf:
        errs["conf"] = "As senhas não conferem."
    if errs:
        return await render_account(
            session, request, user, "password", errs, None, 422
        )
    user.password_hash = hash_password(new)
    await session.commit()
    return RedirectResponse("/account", 303)


@router.get("/account/wallet/link")
async def link_dialog(session: Session, request: Request):
    user = await need_user(session, request)
    if not user:
        return login_redirect(request)
    return await render_account(session, request, user, "relink")


@router.get("/account/wallet/unlink")
async def unlink_dialog(session: Session, request: Request):
    user = await need_user(session, request)
    if not user:
        return login_redirect(request)
    return await render_account(session, request, user, "unlink")


@router.post("/account/wallet/unlink")
async def unlink_save(session: Session, request: Request):
    user = await need_user(session, request)
    if not user:
        return login_redirect(request)
    if not user.password_hash:
        return await render_account(
            session,
            request,
            user,
            "unlink",
            {
                "unlink": "Defina uma senha antes de desvincular. Sem ela, você perde o acesso à conta."
            },
            None,
            422,
        )
    user.lnurl_pubkey = None
    await session.commit()
    return RedirectResponse("/account", 303)


@router.get("/account/developer-access")
async def devrequest_dialog(session: Session, request: Request):
    user = await need_user(session, request)
    if not user:
        return login_redirect(request)
    return await render_account(session, request, user, "devrequest")


@router.post("/account/developer-access")
async def devrequest_save(
    session: Session, request: Request, reason: Annotated[str, Form()] = ""
):
    user = await need_user(session, request)
    if not user:
        return login_redirect(request)
    reason = reason.strip()
    status = await dev_status(session, user)
    if status == "active":
        return RedirectResponse("/account", 303)
    if status == "pending":
        errs = {"reason": "Você já tem uma solicitação em análise."}
    elif len(reason) < MIN_REASON:
        errs = {
            "reason": f"Conte em pelo menos {MIN_REASON} caracteres o que você pretende fazer."
        }
    else:
        errs = {}
    if errs:
        return await render_account(
            session, request, user, "devrequest", errs, {"reason": reason}, 422
        )
    session.add(DevAccessRequest(user_id=user.id, reason=reason))
    await session.commit()
    return RedirectResponse("/account", 303)


# ---------------------------------------------------------------------
# Apps conectados
# ---------------------------------------------------------------------


@router.post("/account/apps/{client_id}/revoke")
async def revoke_app(client_id: str, session: Session, request: Request):
    user = await need_user(session, request)
    if not user:
        return login_redirect(request)
    now = int(time.time())
    await session.execute(
        delete(AuthorizedApp).where(
            AuthorizedApp.user_id == user.id,
            AuthorizedApp.client_id == client_id,
        )
    )
    await session.execute(
        update(OAuth2Token)
        .where(OAuth2Token.user_id == user.id, OAuth2Token.client_id == client_id)
        .values(access_token_revoked_at=now, refresh_token_revoked_at=now)
    )
    await session.commit()
    return RedirectResponse("/account#apps", 303)
