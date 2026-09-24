"""Telas do plano (login em 2 passos, cadastro, conta, desenvolvedor, admin)."""

import re

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.permissions import grant_permission
from satoidc.auth.security import hash_password
from satoidc.enums import PermissionsEnum
from satoidc.models import (
    AuthorizedApp,
    DevAccessRequest,
    OAuth2Client,
    Permission,
    User,
)

from .test_lnurl_auth import Wallet, challenge, engine, new_client, wallet_callback  # noqa: F401

PASSWORD = "Sats!2140"


async def make_user(engine, login="satoshi21", *, developer=False, admin=False, **extra):
    async with AsyncSession(engine, expire_on_commit=False) as session:
        user = User(
            lnurl_pubkey=extra.pop("lnurl_pubkey", None),
            login=login,
            email=extra.pop("email", f"{login}@exemplo.com"),
            password_hash=extra.pop("password_hash", hash_password(PASSWORD)),
            nickname=extra.pop("nickname", login),
        )
        session.add(user)
        await session.flush()
        if developer:
            await grant_permission(session, user, PermissionsEnum.DEVELOPER)
        if admin:
            await grant_permission(session, user, PermissionsEnum.ADMIN)
        await session.commit()
        return user


async def sign_in(browser, login="satoshi21", password=PASSWORD):
    res = await browser.post("/login", data={"login": login})
    assert res.headers["location"].startswith("/login/password")
    page = await browser.get("/login/password")
    nonce = re.search(r'name="login_nonce" value="([^"]+)"', page.text).group(1)
    return await browser.post(
        "/login/password", data={"password": password, "login_nonce": nonce}
    )


# --------------------------------------------------------------------- login


@pytest.mark.asyncio
async def test_login_in_two_steps(engine):
    await make_user(engine)
    async with new_client() as browser:
        res = await sign_in(browser)
        assert res.status_code == 303 and res.headers["location"] == "/"
        assert (await browser.get("/account")).status_code == 200


@pytest.mark.asyncio
async def test_login_by_email_and_wrong_password_message(engine):
    await make_user(engine)
    async with new_client() as browser:
        res = await sign_in(browser, "SATOSHI21@exemplo.com", "errada")
        assert "err=1" in res.headers["location"]
        page = await browser.get(res.headers["location"])
        assert "E-mail ou senha incorretos. Tente novamente." in page.text
        assert (await browser.get("/account")).status_code == 303


@pytest.mark.asyncio
async def test_password_step_requires_the_first_step(engine):
    async with new_client() as browser:
        res = await browser.get("/login/password")
        assert res.status_code == 303 and res.headers["location"].startswith("/login")
        res = await browser.post("/login/password", data={"password": "x", "login_nonce": "y"})
        assert "err=bad_flow" in res.headers["location"]


# ------------------------------------------------------------------ cadastro


@pytest.mark.asyncio
async def test_register_validates_and_signs_in(engine):
    async with new_client() as browser:
        bad = await browser.post(
            "/register",
            data={"login": "AB", "email": "x", "password": "fraca", "confirm": "outra"},
        )
        assert bad.status_code == 422
        assert "Use de 6 a 30 letras minúsculas e números." in bad.text
        assert "As senhas não conferem." in bad.text or "8 ou mais caracteres" in bad.text
        assert "Você precisa aceitar os Termos de Serviço." in bad.text

        ok = await browser.post(
            "/register",
            data={
                "login": "satoshi21",
                "email": "Satoshi@Exemplo.com",
                "nickname": "satoshi",
                "password": PASSWORD,
                "confirm": PASSWORD,
                "terms": "on",
            },
        )
        assert ok.status_code == 303
        assert (await browser.get("/account")).status_code == 200

    async with new_client() as other:
        dup = await other.post(
            "/register",
            data={
                "login": "satoshi21",
                "email": "outro@exemplo.com",
                "password": PASSWORD,
                "confirm": PASSWORD,
                "terms": "on",
            },
        )
        assert dup.status_code == 422 and "Este login já está em uso." in dup.text


# --------------------------------------------------------------------- conta


@pytest.mark.asyncio
async def test_account_page_shows_the_user_and_dialogs(engine):
    await make_user(engine, lnurl_pubkey="02" + "a" * 64, nickname="satoshi")
    async with new_client() as browser:
        await sign_in(browser)
        page = (await browser.get("/account")).text
        assert "Bem-vindo, satoshi" in page
        assert "satoshi21@exemplo.com" in page
        assert "Vinculada" in page and "02aaaa…aaaaaa" in page
        assert "Nenhum app conectado ainda" in page
        assert "Administração" not in page
        for path, title in (
            ("/account/nickname", "Alterar apelido"),
            ("/account/email", "Alterar e-mail"),
            ("/account/password", "Alterar senha"),
            ("/account/wallet/unlink", "Desvincular carteira?"),
            ("/account/wallet/link", "Vincular outra carteira"),
            ("/account/developer-access", "Solicitar acesso de desenvolvedor"),
        ):
            res = await browser.get(path)
            assert res.status_code == 200 and title in res.text, path


@pytest.mark.asyncio
async def test_account_requires_login(engine):
    async with new_client() as browser:
        for path in ("/account", "/developer/clients", "/admin", "/admin/users"):
            res = await browser.get(path)
            assert res.status_code == 303 and res.headers["location"].startswith("/login")


@pytest.mark.asyncio
async def test_change_nickname_email_and_password(engine):
    await make_user(engine)
    async with new_client() as browser:
        await sign_in(browser)

        bad = await browser.post("/account/nickname", data={"nick": "!"})
        assert bad.status_code == 422
        ok = await browser.post("/account/nickname", data={"nick": "novo.apelido"})
        assert ok.status_code == 303
        assert "Bem-vindo, novo.apelido" in (await browser.get("/account")).text

        wrong = await browser.post("/account/email", data={"email": "n@exemplo.com", "pwd": "errada"})
        assert wrong.status_code == 422 and "Senha incorreta." in wrong.text
        ok = await browser.post("/account/email", data={"email": "n@exemplo.com", "pwd": PASSWORD})
        assert ok.status_code == 303

        weak = await browser.post(
            "/account/password", data={"cur": PASSWORD, "new": "fraca", "conf": "fraca"}
        )
        assert weak.status_code == 422
        ok = await browser.post(
            "/account/password", data={"cur": PASSWORD, "new": "Nova!2140x", "conf": "Nova!2140x"}
        )
        assert ok.status_code == 303

    async with new_client() as browser:
        res = await sign_in(browser, "n@exemplo.com", "Nova!2140x")
        assert res.headers["location"] == "/"


@pytest.mark.asyncio
async def test_unlink_wallet_needs_a_password(engine):
    await make_user(engine, "lightonly", lnurl_pubkey="02" + "b" * 64, password_hash=None)
    wallet = Wallet()
    async with new_client() as browser:
        chal = await challenge(browser, "register")
        await wallet_callback(browser, chal, wallet)
        await browser.get(f"/auth/lnurl/status/{chal['k1']}")

        res = await browser.post("/account/wallet/unlink")
        assert res.status_code == 422
        assert "Defina uma senha antes de desvincular" in res.text
        async with AsyncSession(engine) as session:
            user = await session.scalar(select(User).where(User.lnurl_pubkey == wallet.key))
            assert user is not None

        ok = await browser.post(
            "/account/password", data={"new": "Nova!2140x", "conf": "Nova!2140x"}
        )
        assert ok.status_code == 303
        assert (await browser.post("/account/wallet/unlink")).status_code == 303
        async with AsyncSession(engine) as session:
            assert await session.scalar(select(User).where(User.lnurl_pubkey == wallet.key)) is None


@pytest.mark.asyncio
async def test_link_wallet_from_the_account_page(engine):
    await make_user(engine)
    wallet = Wallet()
    async with new_client() as browser:
        await sign_in(browser)
        chal = await challenge(browser, "link")
        assert (await wallet_callback(browser, chal, wallet)) == {"status": "OK"}
        res = await browser.get(f"/auth/lnurl/status/{chal['k1']}")
        assert res.json() == {"status": "OK", "redirect": "/account"}
        assert "Vinculada" in (await browser.get("/account")).text

    async with new_client() as anonymous:  # vincular exige estar logado
        res = await anonymous.post("/auth/lnurl", json={"action": "link"})
        assert res.status_code == 401


@pytest.mark.asyncio
async def test_revoke_connected_app(engine):
    owner = await make_user(engine, "bittle", developer=True)
    user = await make_user(engine)
    async with AsyncSession(engine) as session:
        client = OAuth2Client(user_id=owner.id, client_id="abc", client_id_issued_at=1, client_secret="s")
        client.set_client_metadata({"client_name": "Sats Lottu", "scope": "openid profile"})
        session.add(client)
        session.add(AuthorizedApp(user_id=user.id, client_id="abc", scope="openid profile"))
        await session.commit()
    async with new_client() as browser:
        await sign_in(browser)
        page = (await browser.get("/account")).text
        assert "Sats Lottu" in page and "Perfil" in page
        assert (await browser.post("/account/apps/abc/revoke")).status_code == 303
        assert "Sats Lottu" not in (await browser.get("/account")).text


# ------------------------------------------------- acesso de desenvolvedor


@pytest.mark.asyncio
async def test_developer_request_and_admin_review(engine):
    await make_user(engine)
    await make_user(engine, "admin01", admin=True)

    async with new_client() as dev:
        await sign_in(dev)
        short = await dev.post("/account/developer-access", data={"reason": "oi"})
        assert short.status_code == 422 and "pelo menos 10 caracteres" in short.text
        ok = await dev.post(
            "/account/developer-access", data={"reason": "Quero registrar o app da minha loja."}
        )
        assert ok.status_code == 303
        assert "Sua solicitação está em análise" in (await dev.get("/account")).text
        again = await dev.post(
            "/account/developer-access", data={"reason": "Quero registrar de novo, por favor."}
        )
        assert again.status_code == 422
        assert (await dev.get("/developer/clients")).status_code == 403

        async with new_client() as admin:
            await sign_in(admin, "admin01")
            page = (await admin.get("/admin")).text
            assert "satoshi21" in page and "Quero registrar o app da minha loja." in page
            req_id = re.search(r"/admin/requests/([0-9a-f-]{36})/approve", page).group(1)
            assert "Negar solicitação" in (await admin.get(f"/admin/requests/{req_id}/deny")).text
            assert (await admin.post(f"/admin/requests/{req_id}/approve")).status_code == 303
            assert "Nenhuma solicitação pendente" in (await admin.get("/admin")).text
            users = (await admin.get("/admin/users")).text
            assert "satoshi21" in users and "admin01" in users

        assert (await dev.get("/developer/clients")).status_code == 200
        assert "Ativo" in (await dev.get("/account")).text


@pytest.mark.asyncio
async def test_admin_can_deny_with_a_note_and_the_user_can_ask_again(engine):
    user = await make_user(engine)
    await make_user(engine, "admin01", admin=True)
    async with AsyncSession(engine) as session:
        session.add(DevAccessRequest(user_id=user.id, reason="Quero registrar meu app."))
        await session.commit()
    async with new_client() as admin:
        await sign_in(admin, "admin01")
        page = (await admin.get("/admin")).text
        req_id = re.search(r"/admin/requests/([0-9a-f-]{36})/approve", page).group(1)
        assert (await admin.post(f"/admin/requests/{req_id}/deny", data={"note": "Sem contexto"})).status_code == 303
    async with AsyncSession(engine) as session:
        req = await session.scalar(select(DevAccessRequest))
        assert req.status == "denied" and req.decision_reason == "Sem contexto"
    async with new_client() as browser:
        await sign_in(browser)
        assert "Sua última solicitação foi negada" in (await browser.get("/account")).text


@pytest.mark.asyncio
async def test_admin_area_is_restricted(engine):
    await make_user(engine, developer=True)
    async with new_client() as browser:
        await sign_in(browser)
        for path in ("/admin", "/admin/users"):
            res = await browser.get(path)
            assert res.status_code == 403 and "Acesso restrito" in res.text
        assert (await browser.post("/admin/users/00000000-0000-0000-0000-000000000000/active")).status_code == 403


@pytest.mark.asyncio
async def test_admin_grants_revokes_developer_and_deactivates(engine):
    target = await make_user(engine, "alvo01")
    admin = await make_user(engine, "admin01", admin=True)
    async with new_client() as browser:
        await sign_in(browser, "admin01")
        assert (await browser.post(f"/admin/users/{target.id}/developer", data={"grant": "1"})).status_code == 303
        async with AsyncSession(engine) as session:
            perm = await session.scalar(
                select(Permission).where(Permission.user_id == target.id)
            )
            assert perm and not perm.disabled
        assert (await browser.post(f"/admin/users/{target.id}/developer", data={"grant": "0"})).status_code == 303
        async with AsyncSession(engine) as session:
            perm = await session.scalar(select(Permission).where(Permission.user_id == target.id))
            assert perm.disabled
        await browser.post(f"/admin/users/{target.id}/active", data={"active": "0"})
        await browser.post(f"/admin/users/{admin.id}/active", data={"active": "0"})  # ignorado
        async with AsyncSession(engine) as session:
            assert not (await session.get(User, target.id)).is_active
            assert (await session.get(User, admin.id)).is_active

    async with new_client() as blocked:  # conta desativada não entra
        res = await sign_in(blocked, "alvo01")
        assert "err=1" in res.headers["location"]


# -------------------------------------------------------------- desenvolvedor

FORM = {
    "cname": "argus",
    "curi": "https://argus.example.com",
    "redirect": "https://argus.example.com/auth/satoidc/callback",
    "scope": ["profile", "email"],
    "grant": ["authorization_code"],
    "auth": "client_secret_basic",
}


@pytest.mark.asyncio
async def test_developer_client_lifecycle(engine):
    await make_user(engine, developer=True)
    async with new_client() as browser:
        await sign_in(browser)
        assert "Nenhum cliente ainda" in (await browser.get("/developer/clients")).text
        assert "Novo cliente OAuth2" in (await browser.get("/developer/clients/new")).text

        bad = await browser.post("/developer/clients/new", data=FORM | {"cname": "", "redirect": "http://evil.com/cb"})
        assert bad.status_code == 422
        assert "Informe um nome" in bad.text and "http só vale para localhost" in bad.text

        created = await browser.post("/developer/clients/new", data=FORM)
        assert created.status_code == 200
        assert "Guarde o client secret" in created.text
        assert created.headers["cache-control"] == "no-store"
        async with AsyncSession(engine) as session:
            client = await session.scalar(select(OAuth2Client))
        cid, secret = client.client_id, client.client_secret
        assert secret in created.text and len(secret) >= 48
        assert client.client_metadata["scope"] == "openid profile email"
        assert client.client_metadata["response_types"] == ["code"]

        view = (await browser.get(f"/developer/clients/{cid}")).text
        assert "argus" in view and "Configurado" in view and secret not in view
        assert "Guarde o client secret" not in view

        edited = await browser.post(
            f"/developer/clients/{cid}/edit",
            data=FORM | {"cname": "argus 2", "scope": ["profile"], "auth": "client_secret_post"},
        )
        assert edited.status_code == 303
        assert "argus 2" in (await browser.get("/developer/clients")).text
        edit_page = (await browser.get(f"/developer/clients/{cid}/edit")).text
        assert "Editar cliente" in edit_page and 'value="argus 2"' in edit_page

        assert (await browser.post(f"/developer/clients/{cid}/toggle")).status_code == 303
        assert "Desativado" in (await browser.get("/developer/clients")).text
        assert "Ativar" in (await browser.get(f"/developer/clients/{cid}")).text

        assert "Girar o client secret?" in (await browser.get(f"/developer/clients/{cid}/rotate")).text
        rotated = await browser.post(f"/developer/clients/{cid}/rotate")
        async with AsyncSession(engine) as session:
            new_secret = (await session.scalar(select(OAuth2Client))).client_secret
        assert new_secret != secret and new_secret in rotated.text

        assert "Excluir argus 2?" in (await browser.get(f"/developer/clients/{cid}/delete")).text
        wrong = await browser.post(f"/developer/clients/{cid}/delete", data={"confirm": "outro"})
        assert wrong.status_code == 422
        assert (await browser.post(f"/developer/clients/{cid}/delete", data={"confirm": "argus 2"})).status_code == 303
        async with AsyncSession(engine) as session:
            assert await session.scalar(select(OAuth2Client)) is None


@pytest.mark.asyncio
async def test_public_client_has_no_secret_and_others_cannot_touch_it(engine):
    await make_user(engine, developer=True)
    await make_user(engine, "outro01", developer=True)
    async with new_client() as browser:
        await sign_in(browser)
        res = await browser.post("/developer/clients/new", data=FORM | {"auth": "none"})
        assert res.status_code == 303
        async with AsyncSession(engine) as session:
            client = await session.scalar(select(OAuth2Client))
        assert client.client_secret == ""
        assert "Não usa" in (await browser.get(res.headers["location"])).text

    async with new_client() as other:
        await sign_in(other, "outro01")
        for path in ("", "/edit", "/rotate", "/delete"):
            res = await other.get(f"/developer/clients/{client.client_id}{path}")
            assert res.status_code == 404, path
        assert (await other.post(f"/developer/clients/{client.client_id}/toggle")).status_code == 404


@pytest.mark.asyncio
async def test_disabled_client_is_not_served_by_oidc(engine):
    from satoidc.auth.clients import is_active

    await make_user(engine, developer=True)
    async with new_client() as browser:
        await sign_in(browser)
        await browser.post("/developer/clients/new", data=FORM)
        async with AsyncSession(engine) as session:
            client = await session.scalar(select(OAuth2Client))
        assert is_active(client)
        await browser.post(f"/developer/clients/{client.client_id}/toggle")
        async with AsyncSession(engine) as session:
            client = await session.scalar(select(OAuth2Client))
        assert not is_active(client)
