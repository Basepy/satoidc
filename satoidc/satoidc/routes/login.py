"""
Login + OAuth2 authorize redirect (FastAPI + NiceGUI + Authlib)
- Corrige redirect_to com query (URL-encode)
- Corrige bug do `nxt` não definido
- Evita confusão com OIDC nonce (renomeia para login_nonce)
- Repassa redirect_to com segurança em erros
"""

import uuid
from typing import Annotated, Optional
from urllib.parse import quote

from fastapi import Depends, Form, Request
from fastapi.responses import RedirectResponse
from nicegui import APIRouter, ui
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.nostr import NostrKeyError, keys_from_private_key
from satoidc.auth.security import verify_password
from satoidc.models import User
from satoidc.models.database import get_session

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


# ==========================================================
# LOGIN
# ==========================================================


class LoginSchema(BaseModel):
    identifier: str
    password: str
    redirect_to: Optional[str] = None
    login_nonce: Optional[str] = None


LoginForm = Annotated[LoginSchema, Form()]


@router.post("/login")
async def login_post(
    session: Session,
    request: Request,
    login_form: LoginForm,
):
    # (A) anti-post-direto / anti-replay do login flow
    expected_nonce = request.session.get("login_nonce")
    if (
        not expected_nonce
        or not login_form.login_nonce
        or login_form.login_nonce != expected_nonce
    ):
        request.session.pop("login_nonce", None)
        return RedirectResponse(url="/login?err=bad_flow", status_code=303)

    request.session.pop("login_nonce", None)

    # (B) redirect_to seguro e URL-encoded para querystring em caso de erro
    nxt = login_form.redirect_to

    # (C) autentica
    user = await session.scalar(
        select(User).where(
            (User.email == login_form.identifier)
            | (User.login == login_form.identifier)
        )
    )
    if not user or not verify_password(
        login_form.password, user.password_hash
    ):
        return RedirectResponse(
            url=f"/login?err=invalid&redirect_to={encode_query_value(nxt)}",
            status_code=303,
        )

    # (D) grava sessão e redireciona (redirect_to pode conter query)
    request.session["user_id"] = user.id.hex
    return RedirectResponse(url=nxt, status_code=303)


@router.page("/login")
async def login_page(
    request: Request,
    session: Session,
    redirect_to: Optional[str] = "/",
    err: Optional[str] = None,
):
    # gera nonce do login (não confundir com OIDC nonce)
    login_nonce = uuid.uuid4().hex
    request.session["login_nonce"] = login_nonce

    ui.label("Sign in").classes("text-2xl font-bold mb-2")
    ui.label("Use your account to continue.").classes("text-gray-500 mb-6")

    with ui.card().classes("w-full max-w-md p-6"):
        match err:
            case None:
                pass
            case "invalid":
                ui.label("Invalid credentials.").classes("text-red-500 mb-2")
            case "bad_flow":
                ui.label("Invalid login flow. Please try again.").classes(
                    "text-red-500 mb-2"
                )
            case _:
                ui.label("Unknown error!").classes("text-red-500 mb-2")

        with (
            ui.element("form")
            .props('method="post" action="/login"')
            .classes("flex flex-col gap-3")
        ):
            ui.input("Email or Login").props(
                "name='identifier' autocomplete='username'"
            ).classes("w-full")
            ui.input("Password").props(
                "name='password' type='password'"
                " autocomplete='current-password'"
            ).classes("w-full")

            # hidden redirect_to + login_nonce
            ui.element("input").props(
                f"type='hidden' name='redirect_to' value='{redirect_to}'"
            )
            ui.element("input").props(
                f"type='hidden' name='login_nonce' value='{login_nonce}'"
            )

            ui.separator().classes("my-1")

            ui.button("Login").props("type='submit'").classes("w-full")
            ui.button("Cancel", on_click=lambda: ui.navigate.to("/")).props(
                "outline"
            ).classes("w-full")

        ui.separator().classes("my-5")
        ui.label("Nostr").classes("text-lg font-semibold")
        ui.label(
            "Entre com uma chave privada Nostr existente. A chave nao e armazenada; apenas a chave publica fica vinculada a sua conta."
        ).classes("text-gray-500 text-sm")
        nostr_key = ui.input("nsec ou chave privada hex").props(
            "type='password' autocomplete='off'"
        ).classes("w-full")
        nostr_error = ui.label("").classes("text-red-500 mt-1")

        async def login_with_nostr():
            nostr_error.set_text("")
            try:
                keys = keys_from_private_key(nostr_key.value or "")
            except NostrKeyError as exc:
                nostr_error.set_text(str(exc))
                return

            user = await session.scalar(
                select(User).where(User.nostr_pubkey == keys.public_key_hex)
            )
            if not user:
                nostr_error.set_text(
                    "Nenhuma conta encontrada para esta chave. Crie a conta com Nostr primeiro."
                )
                return

            request.session["user_id"] = user.id.hex
            ui.navigate.to(redirect_to)

        ui.button("Entrar com Nostr", on_click=login_with_nostr).classes(
            "w-full mt-2"
        )

    with ui.row().classes("gap-4 mt-4"):
        ui.link("← Home", "/").classes("text-blue-500 underline")
        ui.link("Register", "/register").classes("text-blue-500 underline")


@router.get("/logout")
def logout(request: Request):
    request.session.clear()
    return RedirectResponse("/", status_code=303)
