"""Fluxo de login/cadastro com carteira Lightning (LNURL-auth, LUD-04).

A "carteira" aqui é uma chave secp256k1 que assina o k1 recebido, igual às
carteiras reais fazem depois de escanear o QR code.
"""

from urllib.parse import parse_qs, urlparse

import ecdsa
import pytest
import pytest_asyncio
from bech32 import bech32_decode, convertbits
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.pool import StaticPool

from satoidc import app
from satoidc.auth.lnurl import url_encode, verify
from satoidc.models import table_registry
from satoidc.models.database import get_session
from satoidc.settings import ENV


class Wallet:
    def __init__(self):
        self.sk = ecdsa.SigningKey.generate(curve=ecdsa.SECP256k1)
        self.key = self.sk.verifying_key.to_string("compressed").hex()

    def sign(self, k1: str, compact: bool = False) -> str:
        encode = (
            ecdsa.util.sigencode_string if compact else ecdsa.util.sigencode_der
        )
        return self.sk.sign_digest(bytes.fromhex(k1), sigencode=encode).hex()


@pytest_asyncio.fixture
async def engine():
    engine = create_async_engine(
        "sqlite+aiosqlite://",
        poolclass=StaticPool,
        connect_args={"check_same_thread": False},
    )
    async with engine.begin() as conn:
        await conn.run_sync(table_registry.metadata.create_all)

    async def override():
        async with AsyncSession(engine, expire_on_commit=False) as session:
            yield session

    app.dependency_overrides[get_session] = override
    yield engine
    app.dependency_overrides.clear()
    await engine.dispose()


def new_client() -> AsyncClient:
    return AsyncClient(
        transport=ASGITransport(app=app), base_url="http://testserver"
    )


async def challenge(client: AsyncClient, action: str) -> dict:
    res = await client.post("/auth/lnurl", json={"action": action})
    assert res.status_code == 201
    return res.json()


async def wallet_callback(client, chal, wallet, **overrides):
    params = {
        "tag": "login",
        "k1": chal["k1"],
        "sig": wallet.sign(chal["k1"]),
        "key": wallet.key,
    } | overrides
    res = await client.get("/auth/lnurl/callback", params=params)
    return res.json()


def test_url_encode_roundtrip():
    url = "https://example.com/auth/lnurl/callback?tag=login&k1=" + "ab" * 32
    hrp, data = bech32_decode(url_encode(url).lower())
    assert hrp == "lnurl"
    assert bytes(convertbits(data, 5, 8, False)).decode() == url


def test_verify_accepts_der_and_compact_and_rejects_others():
    wallet, other = Wallet(), Wallet()
    k1 = "cd" * 32
    assert verify(k1, wallet.key, wallet.sign(k1))
    assert verify(k1, wallet.key, wallet.sign(k1, compact=True))
    assert not verify(k1, wallet.key, other.sign(k1))
    assert not verify("ef" * 32, wallet.key, wallet.sign(k1))
    assert not verify(k1, wallet.key, "zz")


@pytest.mark.asyncio
async def test_challenge_payload(engine):
    async with new_client() as client:
        chal = await challenge(client, "login")
    assert len(chal["k1"]) == 64
    assert chal["uri"] == f"lightning:{chal['lnurl']}"
    _, data = bech32_decode(chal["lnurl"].lower())
    decoded = bytes(convertbits(data, 5, 8, False)).decode()
    assert "//auth" not in decoded.replace("http://", "")
    assert parse_qs(urlparse(decoded).query)["k1"] == [chal["k1"]]


@pytest.mark.asyncio
async def test_register_then_login_with_wallet(engine):
    wallet = Wallet()

    async with new_client() as browser:
        chal = await challenge(browser, "register")
        res = await browser.get(f"/auth/lnurl/status/{chal['k1']}")
        assert res.json() == {"status": "PENDING"}

        assert (await wallet_callback(browser, chal, wallet)) == {"status": "OK"}
        res = await browser.get(f"/auth/lnurl/status/{chal['k1']}")
        assert res.json()["status"] == "OK"

        home = await browser.get("/account")  # sessão aberta -> não redireciona
        assert home.status_code == 200

    async with new_client() as browser:  # navegador novo, mesma carteira
        chal = await challenge(browser, "login")
        assert (await wallet_callback(browser, chal, wallet)) == {"status": "OK"}
        res = await browser.get(f"/auth/lnurl/status/{chal['k1']}")
        assert res.json() == {"status": "OK", "redirect": "/"}


@pytest.mark.asyncio
async def test_login_with_unknown_wallet_is_rejected(engine):
    async with new_client() as browser:
        chal = await challenge(browser, "login")
        body = await wallet_callback(browser, chal, Wallet())
        assert body["status"] == "ERROR"
        assert "Nenhuma conta" in body["reason"]
        res = await browser.get(f"/auth/lnurl/status/{chal['k1']}")
        assert res.json()["status"] == "PENDING"


@pytest.mark.asyncio
async def test_bad_signature_and_replay_are_rejected(engine):
    wallet = Wallet()
    async with new_client() as browser:
        chal = await challenge(browser, "register")
        bad = await wallet_callback(
            browser, chal, wallet, sig=Wallet().sign(chal["k1"])
        )
        assert bad == {"status": "ERROR", "reason": "Bad signature"}

        assert (await wallet_callback(browser, chal, wallet))["status"] == "OK"
        replay = await wallet_callback(browser, chal, wallet)
        assert replay["status"] == "ERROR"

        assert (await browser.get(f"/auth/lnurl/status/{chal['k1']}")).json()[
            "status"
        ] == "OK"
        again = await browser.get(f"/auth/lnurl/status/{chal['k1']}")
        assert again.json()["status"] == "ERROR"  # k1 já consumido


@pytest.mark.asyncio
async def test_other_browser_cannot_take_over_the_session(engine):
    wallet = Wallet()
    async with new_client() as victim, new_client() as attacker:
        chal = await challenge(victim, "register")
        await wallet_callback(victim, chal, wallet)
        res = await attacker.get(f"/auth/lnurl/status/{chal['k1']}")
        assert res.json()["status"] == "ERROR"
        assert (await attacker.get("/account")).status_code == 303


@pytest.mark.asyncio
async def test_expired_challenge(engine, monkeypatch):
    monkeypatch.setattr(ENV, "LNURL_K1_TTL_SECONDS", 0)
    async with new_client() as browser:
        chal = await challenge(browser, "register")
        body = await wallet_callback(browser, chal, Wallet())
        assert body["reason"] == "Invalid or expired k1"
        res = await browser.get(f"/auth/lnurl/status/{chal['k1']}")
        assert res.json()["status"] == "EXPIRED"


@pytest.mark.asyncio
async def test_login_links_to_the_lightning_screen_not_nostr(engine):
    async with new_client() as browser:
        page = (await browser.get("/login?redirect_to=%2Fapps")).text
        register = (await browser.get("/register")).text
    assert "Nostr" not in page + register
    assert 'href="/login/lightning?redirect_to=%2Fapps"' in page
    assert "Entrar com carteira Lightning" in page
    assert "/login/lightning?action=register" in register
    assert "/static/img/satoidc-logo.png" in page


@pytest.mark.asyncio
async def test_lightning_screen_follows_the_design_plan(engine):
    async with new_client() as browser:
        page = (await browser.get("/login/lightning")).text
        register = (await browser.get("/login/lightning?action=register")).text
        evil = (await browser.get("/login/lightning?redirect_to=https://evil.test")).text

    assert "Entrar com Lightning" in page
    for step in (
        "Abra uma carteira compatível com LNURL-auth.",
        "Escaneie o código ou toque em “Abrir na carteira”.",
        "Sua carteira assina um desafio único — nenhuma senha é enviada.",
    ):
        assert step in page
    assert "O código expira em" in page and "só pode ser usado uma vez" in page
    assert "Aguardando sua carteira" in page or "Gerando código" in page
    assert "Confira o domínio exibido na carteira: ele deve ser <strong>testserver</strong>" in page
    assert 'aria-label="Copiar LNURL"' in page
    assert "Abrir na carteira" in page and 'href="/login?redirect_to=%2F"' in page
    assert 'data-action="login"' in page

    assert "Criar conta com Lightning" in register
    assert 'data-action="register"' in register
    assert 'href="/register?redirect_to=%2F"' in register

    assert 'data-redirect="/"' in evil  # open-redirect neutralizado
    assert "Nostr" not in page + register
