from datetime import datetime
from secrets import token_urlsafe
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy import delete, select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.clients import (
    ClientForm,
    is_active,
    issued_now,
    new_credentials,
)
from satoidc.auth.guards import need_developer, not_found
from satoidc.formatting import fmt_date
from satoidc.models import (
    AuthorizedApp,
    OAuth2AuthorizationCode,
    OAuth2Client,
    OAuth2Token,
    User,
)
from satoidc.models.database import get_session
from satoidc.web import templates

router = APIRouter(prefix="/developer", tags=["developer"])
Session = Annotated[AsyncSession, Depends(get_session)]

NO_STORE = {"Cache-Control": "no-store"}


def client_view(client: OAuth2Client) -> dict:
    meta = client.client_metadata
    name = meta.get("client_name") or client.client_id
    auth_method = meta.get("token_endpoint_auth_method", "client_secret_basic")
    cid = client.client_id
    return {
        "client_id": cid,
        "name": name,
        "initial": (name[:1] or "?").upper(),
        "cid_short": f"{cid[:12]}…",
        "cid_long": f"{cid[:16]}…{cid[-4:]}" if len(cid) > 21 else cid,
        "active": is_active(client),
        "auth_method": auth_method,
        "has_secret": auth_method != "none" and bool(client.client_secret),
        "scopes": (meta.get("scope") or "").split(),
        "grants": meta.get("grant_types", []),
        "responses": meta.get("response_types", []),
        "redirect_uris": meta.get("redirect_uris", []),
        "redirects": len(meta.get("redirect_uris", [])),
        "uri": meta.get("client_uri", ""),
        "created": fmt_date(
            datetime.fromtimestamp(client.client_id_issued_at)
            if client.client_id_issued_at
            else None
        ),
    }


async def owned_client(
    session: AsyncSession, user: User, client_id: str
) -> Optional[OAuth2Client]:
    return await session.scalar(
        select(OAuth2Client).where(
            OAuth2Client.client_id == client_id,
            OAuth2Client.user_id == user.id,
        )
    )


def render_client(
    request: Request,
    user: User,
    client: OAuth2Client,
    dialog: Optional[str] = None,
    secret: Optional[str] = None,
    errs: Optional[dict] = None,
    status: int = 200,
):
    return templates.TemplateResponse(
        request,
        "developer/client.html",
        {
            "request": request,
            "user": user,
            "c": client_view(client),
            "dialog": dialog,
            "secret": secret,
            "errs": errs or {},
        },
        status_code=status,
        headers=NO_STORE if secret else None,
    )


def render_form(
    request: Request,
    user: User,
    form: ClientForm,
    client_id: Optional[str] = None,
    status: int = 200,
):
    editing = client_id is not None
    return templates.TemplateResponse(
        request,
        "developer/form.html",
        {
            "request": request,
            "user": user,
            "form": form,
            "editing": editing,
            "client_id": client_id,
            "action": (
                f"/developer/clients/{client_id}/edit"
                if editing
                else "/developer/clients/new"
            ),
        },
        status_code=status,
    )


# ---------------------------------------------------------------------
# Lista
# ---------------------------------------------------------------------


@router.get("/clients")
async def clients(session: Session, request: Request):
    user, blocked = await need_developer(session, request)
    if blocked:
        return blocked
    rows = await session.scalars(
        select(OAuth2Client)
        .where(OAuth2Client.user_id == user.id)
        .order_by(OAuth2Client.client_id_issued_at.desc())
    )
    return templates.TemplateResponse(
        request,
        "developer/clients.html",
        {
            "request": request,
            "user": user,
            "clients": [client_view(c) for c in rows],
            "dialog": None,
        },
    )


# ---------------------------------------------------------------------
# Criar
# ---------------------------------------------------------------------


@router.get("/clients/new")
async def new_page(session: Session, request: Request):
    user, blocked = await need_developer(session, request)
    if blocked:
        return blocked
    return render_form(request, user, ClientForm())


@router.post("/clients/new")
async def new_save(
    session: Session,
    request: Request,
    cname: Annotated[str, Form()] = "",
    curi: Annotated[str, Form()] = "",
    redirect: Annotated[str, Form()] = "",
    scope: Annotated[list[str], Form()] = [],  # noqa: B006
    grant: Annotated[list[str], Form()] = [],  # noqa: B006
    auth: Annotated[str, Form()] = "client_secret_basic",
):
    user, blocked = await need_developer(session, request)
    if blocked:
        return blocked
    form = ClientForm.from_post(
        cname, curi, redirect, ["openid", *scope], grant, auth, "on"
    )
    if not form.validate():
        return render_form(request, user, form, status=422)

    client_id, secret = new_credentials(form.auth_method)
    client = OAuth2Client(
        user_id=user.id,
        client_id=client_id,
        client_id_issued_at=issued_now(),
        client_secret=secret,
    )
    client.set_client_metadata(form.metadata())
    session.add(client)
    await session.commit()
    if not secret:  # app público: não há secret a mostrar
        return RedirectResponse(f"/developer/clients/{client_id}", 303)
    return render_client(request, user, client, "secret", secret)


# ---------------------------------------------------------------------
# Ver / editar
# ---------------------------------------------------------------------


@router.get("/clients/{client_id}")
async def view(client_id: str, session: Session, request: Request):
    user, blocked = await need_developer(session, request)
    if blocked:
        return blocked
    client = await owned_client(session, user, client_id)
    if not client:
        return not_found(request)
    return render_client(request, user, client)


@router.get("/clients/{client_id}/edit")
async def edit_page(client_id: str, session: Session, request: Request):
    user, blocked = await need_developer(session, request)
    if blocked:
        return blocked
    client = await owned_client(session, user, client_id)
    if not client:
        return not_found(request)
    return render_form(request, user, ClientForm.from_client(client), client_id)


@router.post("/clients/{client_id}/edit")
async def edit_save(
    client_id: str,
    session: Session,
    request: Request,
    cname: Annotated[str, Form()] = "",
    curi: Annotated[str, Form()] = "",
    redirect: Annotated[str, Form()] = "",
    scope: Annotated[list[str], Form()] = [],  # noqa: B006
    grant: Annotated[list[str], Form()] = [],  # noqa: B006
    auth: Annotated[str, Form()] = "client_secret_basic",
):
    user, blocked = await need_developer(session, request)
    if blocked:
        return blocked
    client = await owned_client(session, user, client_id)
    if not client:
        return not_found(request)
    form = ClientForm.from_post(
        cname,
        curi,
        redirect,
        ["openid", *scope],
        grant,
        auth,
        "on" if is_active(client) else None,
    )
    if not form.validate():
        return render_form(request, user, form, client_id, 422)

    previous = client.client_metadata.get("token_endpoint_auth_method")
    client.set_client_metadata(form.metadata())
    if form.auth_method == "none":
        client.client_secret = ""
    elif previous == "none" or not client.client_secret:
        # passou de app público para confidencial: precisa de um secret novo
        secret = token_urlsafe(48)
        client.client_secret = secret
        session.add(client)
        await session.commit()
        return render_client(request, user, client, "secret", secret)
    session.add(client)
    await session.commit()
    return RedirectResponse(f"/developer/clients/{client_id}", 303)


# ---------------------------------------------------------------------
# Ativar/desativar, girar secret, excluir
# ---------------------------------------------------------------------


@router.post("/clients/{client_id}/toggle")
async def toggle(client_id: str, session: Session, request: Request):
    user, blocked = await need_developer(session, request)
    if blocked:
        return blocked
    client = await owned_client(session, user, client_id)
    if not client:
        return not_found(request)
    meta = dict(client.client_metadata)
    meta["disabled"] = is_active(client)
    client.set_client_metadata(meta)
    session.add(client)
    await session.commit()
    return RedirectResponse(f"/developer/clients/{client_id}", 303)


@router.get("/clients/{client_id}/rotate")
async def rotate_dialog(client_id: str, session: Session, request: Request):
    user, blocked = await need_developer(session, request)
    if blocked:
        return blocked
    client = await owned_client(session, user, client_id)
    if not client:
        return not_found(request)
    if not client_view(client)["has_secret"]:
        return RedirectResponse(f"/developer/clients/{client_id}", 303)
    return render_client(request, user, client, "rotate")


@router.post("/clients/{client_id}/rotate")
async def rotate(client_id: str, session: Session, request: Request):
    user, blocked = await need_developer(session, request)
    if blocked:
        return blocked
    client = await owned_client(session, user, client_id)
    if not client:
        return not_found(request)
    if client.client_metadata.get("token_endpoint_auth_method") == "none":
        return RedirectResponse(f"/developer/clients/{client_id}", 303)
    secret = token_urlsafe(48)
    client.client_secret = secret
    session.add(client)
    await session.commit()
    return render_client(request, user, client, "secret", secret)


@router.get("/clients/{client_id}/delete")
async def delete_dialog(client_id: str, session: Session, request: Request):
    user, blocked = await need_developer(session, request)
    if blocked:
        return blocked
    client = await owned_client(session, user, client_id)
    if not client:
        return not_found(request)
    return render_client(request, user, client, "delete")


@router.post("/clients/{client_id}/delete")
async def delete_client(
    client_id: str,
    session: Session,
    request: Request,
    confirm: Annotated[str, Form()] = "",
):
    user, blocked = await need_developer(session, request)
    if blocked:
        return blocked
    client = await owned_client(session, user, client_id)
    if not client:
        return not_found(request)
    name = client_view(client)["name"]
    if confirm.strip() != name:
        return render_client(
            request,
            user,
            client,
            "delete",
            errs={"confirm": f"Digite exatamente “{name}” para confirmar."},
            status=422,
        )
    for model in (OAuth2Token, OAuth2AuthorizationCode):
        await session.execute(
            delete(model).where(model.client_id == client_id)
        )
    await session.execute(
        delete(AuthorizedApp).where(AuthorizedApp.client_id == client_id)
    )
    await session.delete(client)
    await session.commit()
    return RedirectResponse("/developer/clients", 303)
