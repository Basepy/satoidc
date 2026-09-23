import re
from typing import Annotated, Optional

from fastapi import Depends
from nicegui import APIRouter, ui
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

router = APIRouter()

LOGIN_RE = re.compile(r"^[a-z0-9]{6,30}$")
MIN_PASSWORD_LENTH = 8


Session = Annotated[AsyncSession, Depends(get_session)]


@router.page("/register")
async def register_page(
    request: Request, session: Session, redirect_to: Optional[str] = None
):
    redirect_to = safe_redirect(redirect_to)

    ui.label("Create account").classes("text-2xl font-bold mb-2")
    ui.label("Fill in the details below.").classes("text-gray-500 mb-6")

    with ui.card().classes("w-full max-w-lg p-6"):
        login_field = ui.input("Login (a-z0-9, 6-30)").classes("w-full")
        email = ui.input("Email").props("type=email").classes("w-full")
        nickname = ui.input("Nickname (optional)").classes("w-full")

        password = ui.input(
            "Password", password=True, password_toggle_button=True
        ).classes("w-full")
        confirm = ui.input(
            "Confirm password", password=True, password_toggle_button=True
        ).classes("w-full")

        error = ui.label("").classes("text-red-500 mt-2")
        ok = ui.label("").classes("text-green-600 mt-2")

        def validate_form() -> Optional[str]:
            login_value = (login_field.value or "").strip()
            e = (email.value or "").strip().lower()
            p = password.value or ""
            c = confirm.value or ""

            if not login_value:
                return "Login is required."
            if not LOGIN_RE.fullmatch(login_value):
                return "Login must match ^[a-z0-9]{6,30}$."
            if not e or "@" not in e:
                return "Valid email is required."
            if len(p) < MIN_PASSWORD_LENTH:
                return "Password must be at least 8 characters."
            if p != c:
                return "Passwords do not match."
            return None

        async def submit():
            error.set_text("")
            ok.set_text("")

            msg = validate_form()
            if msg:
                error.set_text(msg)
                return

            login_value = login_field.value.strip()
            e = email.value.strip().lower()
            n = (nickname.value or "").strip() or None
            pw_hash = hash_password(password.value)

            db_user = await session.scalar(
                select(User).where(User.login == login_value)
            ) or await session.scalar(select(User).where(User.email == e))
            if db_user:
                error.set_text("Login or Email already in use.")
                return

            user = User(
                lnurl_pubkey=None,
                login=login_value,
                email=e,
                nickname=n,
                password_hash=pw_hash,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)

            # auto-login
            request.session["user_id"] = user.id.hex

            ok.set_text("Account created! Redirecting...")
            ui.timer(0.8, lambda: ui.navigate.to(redirect_to), once=True)

        with ui.row().classes("gap-3 mt-4"):
            ui.button("Create account", on_click=submit).classes("w-full")
            ui.button("Cancel", on_click=lambda: ui.navigate.to("/")).props(
                "outline"
            ).classes("w-full")

        ui.separator().classes("my-6")
        ui.label("Criar conta com Nostr").classes("text-lg font-semibold")
        ui.label(
            "Gere uma chave Nostr nova ou use uma chave privada existente. Guarde o nsec com cuidado: ele nao sera armazenado."
        ).classes("text-gray-500 text-sm")

        nostr_nickname = ui.input("Nickname (opcional)").classes("w-full")
        nostr_key = ui.input("nsec ou chave privada hex existente").props(
            "type='password' autocomplete='off'"
        ).classes("w-full")
        nostr_error = ui.label("").classes("text-red-500 mt-1")
        nostr_ok = ui.label("").classes("text-green-600 mt-1")
        nostr_result = ui.column().classes("w-full gap-2")

        async def create_nostr_user(keys):
            nostr_error.set_text("")
            nostr_ok.set_text("")
            nostr_result.clear()

            db_user = await session.scalar(
                select(User).where(User.nostr_pubkey == keys.public_key_hex)
            )
            if db_user:
                nostr_error.set_text("Esta chave Nostr ja esta vinculada a uma conta.")
                return

            nickname_value = (nostr_nickname.value or "").strip() or "Satoshi"
            user = User(
                lnurl_pubkey=None,
                email=None,
                login=None,
                nickname=nickname_value,
                password_hash=None,
                nostr_pubkey=keys.public_key_hex,
            )
            session.add(user)
            await session.commit()
            await session.refresh(user)
            request.session["user_id"] = user.id.hex

            nostr_ok.set_text("Conta Nostr criada e autenticada.")
            with nostr_result:
                ui.label("Salve sua chave privada Nostr antes de continuar.").classes(
                    "font-semibold"
                )
                ui.textarea("nsec", value=keys.nsec).props("readonly").classes(
                    "w-full"
                )
                ui.input("npub", value=keys.npub).props("readonly").classes(
                    "w-full"
                )
                ui.button(
                    "Continuar",
                    on_click=lambda: ui.navigate.to(redirect_to),
                ).classes("w-full")

        async def generate_nostr_account():
            await create_nostr_user(generate_keys())

        async def create_with_existing_nostr_key():
            try:
                keys = keys_from_private_key(nostr_key.value or "")
            except NostrKeyError as exc:
                nostr_error.set_text(str(exc))
                return
            await create_nostr_user(keys)

        with ui.row().classes("gap-3 mt-4"):
            ui.button("Gerar conta Nostr", on_click=generate_nostr_account).classes(
                "w-full"
            )
            ui.button(
                "Usar chave existente",
                on_click=create_with_existing_nostr_key,
            ).props("outline").classes("w-full")

    with ui.row().classes("gap-4 mt-4"):
        ui.link(
            "Already have an account? Login",
            f"/login?redirect_to={redirect_to}",
        ).classes("text-blue-500 underline")
        ui.link("← Home", "/").classes("text-blue-500 underline")
