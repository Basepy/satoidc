import hashlib
import json
import time
from datetime import datetime, timedelta, timezone
from http import HTTPStatus
from types import SimpleNamespace
from uuid import uuid4

import pytest
from freezegun import freeze_time
from sqlalchemy import select

from satoidc.auth.nostr import (
    AUTH_KIND,
    G,
    N,
    NostrEventError,
    check_auth_event,
    event_id,
    point_mul,
    schnorr_verify,
    tagged_hash,
)
from satoidc.models import NostrAuthChallenge, User
from satoidc.routes.nostr_auth import create_challenge, verify
from satoidc.schemas.nostr import NostrChallengeIn, NostrVerifyIn
from satoidc.settings import ENV

VERIFY_URL = "http://localhost:8000/auth/nostr/verify"
K1_LENGTH = 64

# Official BIP-340 vectors (bitcoin/bips, bip-0340/test-vectors.csv) whose
# message is 32 bytes long, like a Nostr event id.
# (index, public key, message, signature, expected result)
BIP340_VECTORS = [
    (
        0,
        "F9308A019258C31049344F85F89D5229B531C845836F99B08601F113BCE036F9",
        "0000000000000000000000000000000000000000000000000000000000000000",
        (
            "E907831F80848D1069A5371B402410364BDF1C5F8307B0084C55F1CE2DCA8215"
            "25F66A4A85EA8B71E482A74F382D2CE5EBEEE8FDB2172F477DF4900D310536C0"
        ),
        True,
    ),
    (
        1,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        (
            "6896BD60EEAE296DB48A229FF71DFE071BDE413E6D43F917DC8DCF8C78DE3341"
            "8906D11AC976ABCCB20B091292BFF4EA897EFCB639EA871CFA95F6DE339E4B0A"
        ),
        True,
    ),
    (
        2,
        "DD308AFEC5777E13121FA72B9CC1B7CC0139715309B086C960E18FD969774EB8",
        "7E2D58D8B3BCDF1ABADEC7829054F90DDA9805AAB56C77333024B9D0A508B75C",
        (
            "5831AAEED7B44BB74E5EAB94BA9D4294C49BCF2A60728D8B4C200F50DD313C1B"
            "AB745879A5AD954A72C45A91C3A51D3C7ADEA98D82F8481E0E1E03674A6F3FB7"
        ),
        True,
    ),
    (
        3,
        "25D1DFF95105F5253C4022F628A996AD3A0D95FBF21D468A1B33F8C160D8F517",
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
        (
            "7EB0509757E246F19449885651611CB965ECC1A187DD51B64FDA1EDC9637D5EC"
            "97582B9CB13DB3933705B32BA982AF5AF25FD78881EBB32771FC5922EFC66EA3"
        ),
        True,
    ),
    (
        4,
        "D69C3509BB99E412E68B0FE8544E72837DFA30746D8BE2AA65975F29D22DC7B9",
        "4DF3C3F68FCC83B27E9D42C90431A72499F17875C81A599B566C9889B9696703",
        (
            "00000000000000000000003B78CE563F89A0ED9414F5AA28AD0D96D6795F9C63"
            "76AFB1548AF603B3EB45C9F8207DEE1060CB71C04E80F593060B07D28308D7F4"
        ),
        True,
    ),
    (
        5,
        "EEFDEA4CDB677750A420FEE807EACF21EB9898AE79B9768766E4FAA04A2D4A34",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        (
            "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
            "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"
        ),
        False,
    ),
    (
        6,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        (
            "FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556"
            "3CC27944640AC607CD107AE10923D9EF7A73C643E166BE5EBEAFA34B1AC553E2"
        ),
        False,
    ),
    (
        7,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        (
            "1FA62E331EDBC21C394792D2AB1100A7B432B013DF3F6FF4F99FCB33E0E1515F"
            "28890B3EDB6E7189B630448B515CE4F8622A954CFE545735AAEA5134FCCDB2BD"
        ),
        False,
    ),
    (
        8,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        (
            "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
            "961764B3AA9B2FFCB6EF947B6887A226E8D7C93E00C5ED0C1834FF0D0C2E6DA6"
        ),
        False,
    ),
    (
        9,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        (
            "0000000000000000000000000000000000000000000000000000000000000000"
            "123DDA8328AF9C23A94C1FEECFD123BA4FB73476F0D594DCB65C6425BD186051"
        ),
        False,
    ),
    (
        10,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        (
            "0000000000000000000000000000000000000000000000000000000000000001"
            "7615FBAF5AE28864013C099742DEADB4DBA87F11AC6754F93780D5A1837CF197"
        ),
        False,
    ),
    (
        11,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        (
            "4A298DACAE57395A15D0795DDBFD1DCB564DA82B0F269BC70A74F8220429BA1D"
            "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"
        ),
        False,
    ),
    (
        12,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        (
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F"
            "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"
        ),
        False,
    ),
    (
        13,
        "DFF1D77F2A671C5F36183726DB2341BE58FEAE1DA2DECED843240F7B502BA659",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        (
            "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
            "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141"
        ),
        False,
    ),
    (
        14,
        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC30",
        "243F6A8885A308D313198A2E03707344A4093822299F31D0082EFA98EC4E6C89",
        (
            "6CFF5C3BA86C69EA4B7376F31A9BCB4F74C1976089B2D9963DA2E5543E177769"
            "69E89B4C5564D00349106B8497785DD7D1D713A8AE82B32FA79D5F7FC407D39B"
        ),
        False,
    ),
]


def _x_only(secret: int) -> bytes:
    return point_mul(secret, G)[0].to_bytes(32, "big")


def _sign(secret: int, message: bytes) -> bytes:
    """BIP-340 signing with a deterministic nonce (tests only)."""
    point = point_mul(secret, G)
    d = secret if point[1] % 2 == 0 else N - secret
    public_key = point[0].to_bytes(32, "big")
    k = int.from_bytes(
        tagged_hash(
            "BIP0340/nonce", d.to_bytes(32, "big") + public_key + message
        ),
        "big",
    )
    k %= N
    r_point = point_mul(k, G)
    if r_point[1] % 2:
        k = N - k
    r = r_point[0].to_bytes(32, "big")
    e = int.from_bytes(
        tagged_hash("BIP0340/challenge", r + public_key + message), "big"
    )
    return r + ((k + e * d) % N).to_bytes(32, "big")


SECRET_A = 0xB7E151628AED2A6ABF7158809CF4F3C762E7160F38B4DA56A784D9045190CFEF
SECRET_B = 0x0B432B2677937381AEF05BB02A66ECD012773062CF3FA2549E44F58ED2401710
PUBKEY_A = _x_only(SECRET_A).hex()
PUBKEY_B = _x_only(SECRET_B).hex()


def _event(secret: int, k1: str, **fields) -> dict:
    """Signed NIP-98 event; ``fields`` override url, kind, content, tags or
    created_at."""
    url = fields.get("url", VERIFY_URL)
    event = {
        "pubkey": _x_only(secret).hex(),
        "created_at": fields.get("created_at", int(time.time())),
        "kind": fields.get("kind", AUTH_KIND),
        "tags": fields.get(
            "tags", [["u", url], ["method", "POST"], ["challenge", k1]]
        ),
        "content": fields.get("content", ""),
    }
    event["id"] = event_id(event)
    event["sig"] = _sign(secret, bytes.fromhex(event["id"])).hex()
    return event


def _request(**session) -> SimpleNamespace:
    return SimpleNamespace(session=dict(session))


def _body(response) -> dict:
    return json.loads(response.body)


async def _new_challenge(db_session, request, action="login", redirect="/"):
    return await create_challenge(
        NostrChallengeIn(action=action, redirect_to=redirect),
        request,
        db_session,
    )


async def _verify(db_session, request, k1, event):
    return await verify(NostrVerifyIn(k1=k1, event=event), request, db_session)


async def _make_user(db_session, **fields) -> User:
    values = {
        "lnurl_pubkey": None,
        "email": f"{uuid4().hex[:8]}@example.com",
        "login": uuid4().hex[:8],
        "password_hash": None,
    }
    values.update(fields)
    user = User(**values)
    db_session.add(user)
    await db_session.commit()
    await db_session.refresh(user)
    return user


# ---------------------------------------------------------------------------
# Signature primitives
# ---------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("index", "public_key", "message", "signature", "expected"),
    BIP340_VECTORS,
    ids=[f"bip340-{vector[0]}" for vector in BIP340_VECTORS],
)
def test_schnorr_verify_matches_official_bip340_vectors(
    index, public_key, message, signature, expected
):
    result = schnorr_verify(
        bytes.fromhex(message),
        bytes.fromhex(public_key),
        bytes.fromhex(signature),
    )

    assert result is expected


def test_test_signer_produces_signatures_the_verifier_accepts():
    message = hashlib.sha256(b"nostr").digest()

    signature = _sign(SECRET_A, message)

    assert schnorr_verify(message, bytes.fromhex(PUBKEY_A), signature)
    assert not schnorr_verify(
        hashlib.sha256(b"other").digest(), bytes.fromhex(PUBKEY_A), signature
    )


@pytest.mark.parametrize("length", [0, 31, 33])
def test_schnorr_verify_rejects_wrong_lengths(length):
    signature = _sign(SECRET_A, bytes(32))

    assert not schnorr_verify(
        bytes(length), bytes.fromhex(PUBKEY_A), signature
    )
    assert not schnorr_verify(bytes(32), bytes(length), signature)
    assert not schnorr_verify(
        bytes(32), bytes.fromhex(PUBKEY_A), signature[:length]
    )


# ---------------------------------------------------------------------------
# NIP-98 event validation
# ---------------------------------------------------------------------------
def test_check_auth_event_returns_the_pubkey_of_a_valid_event():
    event = _event(SECRET_A, "k" * 64)

    assert (
        check_auth_event(event, url=VERIFY_URL, challenge="k" * 64) == PUBKEY_A
    )


@pytest.mark.parametrize(
    ("overrides", "reason"),
    [
        ({"kind": 1}, "Event is not an authentication request"),
        ({"content": "hello"}, "Event is not an authentication request"),
        (
            {"url": "https://evil.example/auth/nostr/verify"},
            "Event was signed for another URL",
        ),
        (
            {"tags": [["u", VERIFY_URL], ["challenge", "k" * 64]]},
            "Event was signed for another URL",
        ),
        (
            {"tags": [["u", VERIFY_URL], ["method", "GET"]]},
            "Event was signed for another URL",
        ),
        (
            {"tags": [["u", VERIFY_URL], ["method", "POST"]]},
            "Event was signed for another challenge",
        ),
    ],
)
def test_check_auth_event_rejects_events_for_something_else(overrides, reason):
    event = _event(SECRET_A, "k" * 64, **overrides)

    with pytest.raises(NostrEventError, match=reason):
        check_auth_event(event, url=VERIFY_URL, challenge="k" * 64)


def test_check_auth_event_rejects_another_challenge():
    event = _event(SECRET_A, "a" * 64)

    with pytest.raises(NostrEventError, match="another challenge"):
        check_auth_event(event, url=VERIFY_URL, challenge="b" * 64)


@pytest.mark.parametrize("offset", [-61, 61])
def test_check_auth_event_rejects_clock_skew_over_a_minute(offset):
    with freeze_time("2026-01-01 12:00:00"):
        now = 1767268800
        event = _event(SECRET_A, "k" * 64, created_at=now + offset)

        with pytest.raises(NostrEventError, match="too old"):
            check_auth_event(event, url=VERIFY_URL, challenge="k" * 64)


def test_check_auth_event_accepts_small_clock_skew():
    with freeze_time("2026-01-01 12:00:00"):
        event = _event(SECRET_A, "k" * 64, created_at=1767268800 - 59)

        assert check_auth_event(event, url=VERIFY_URL, challenge="k" * 64)


def test_check_auth_event_rejects_tampered_content_and_id():
    event = _event(SECRET_A, "k" * 64)
    changed_tags = {**event, "tags": [*event["tags"], ["extra", "tag"]]}
    changed_id = {**event, "id": "0" * 64}

    for tampered in (changed_tags, changed_id):
        with pytest.raises(NostrEventError, match="Event id"):
            check_auth_event(tampered, url=VERIFY_URL, challenge="k" * 64)


def test_check_auth_event_rejects_a_signature_from_another_key():
    event = _event(SECRET_A, "k" * 64)
    forged = {**event, "pubkey": PUBKEY_B}
    forged["id"] = event_id(forged)

    with pytest.raises(NostrEventError, match="Invalid signature"):
        check_auth_event(forged, url=VERIFY_URL, challenge="k" * 64)


@pytest.mark.parametrize(
    "mutation",
    [
        lambda e: "not-an-object",
        lambda e: {**e, "id": e["id"].upper()},
        lambda e: {**e, "sig": e["sig"][:-2]},
        lambda e: {**e, "created_at": True},
        lambda e: {**e, "created_at": "1"},
        lambda e: {**e, "kind": "27235"},
        lambda e: {**e, "content": None},
        lambda e: {**e, "tags": "tags"},
        lambda e: {**e, "tags": [["u", 1]]},
        lambda e: {**e, "tags": ["u"]},
        lambda e: {k: v for k, v in e.items() if k != "pubkey"},
    ],
)
def test_check_auth_event_rejects_malformed_events(mutation):
    event = mutation(_event(SECRET_A, "k" * 64))

    with pytest.raises(NostrEventError, match="Invalid event"):
        check_auth_event(event, url=VERIFY_URL, challenge="k" * 64)


# ---------------------------------------------------------------------------
# Challenge endpoint
# ---------------------------------------------------------------------------
async def test_challenge_is_stored_and_bound_to_the_session(db_session):
    request = _request()

    response = await _new_challenge(db_session, request, redirect="/profile")

    stored = await db_session.scalar(
        select(NostrAuthChallenge).where(
            NostrAuthChallenge.k1 == response["k1"]
        )
    )
    assert response["url"] == VERIFY_URL
    assert response["action"] == "login"
    assert response["expires_in"] == ENV.NOSTR_CHALLENGE_TTL_SECONDS
    assert len(response["k1"]) == K1_LENGTH
    assert stored.consumed is False
    assert stored.url == VERIFY_URL
    assert request.session["nostr_k1"] == response["k1"]
    assert request.session["nostr_next"] == "/profile"


async def test_challenge_url_comes_from_the_configured_issuer(
    db_session, monkeypatch
):
    monkeypatch.setattr(ENV, "OAUTH2_JWT_ISS", "https://id.example.com/")

    response = await _new_challenge(db_session, _request())

    assert response["url"] == "https://id.example.com/auth/nostr/verify"


async def test_challenge_drops_external_redirects(db_session):
    request = _request()

    await _new_challenge(db_session, request, redirect="https://evil.test/")

    assert request.session["nostr_next"] == "/"


async def test_link_challenge_requires_an_authenticated_session(db_session):
    response = await _new_challenge(db_session, _request(), action="link")

    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert _body(response)["reason"] == "Authentication required"


async def test_link_challenge_remembers_the_authenticated_user(db_session):
    user = await _make_user(db_session)
    request = _request(user_id=user.id.hex)

    response = await _new_challenge(db_session, request, action="link")

    stored = await db_session.get(NostrAuthChallenge, response["k1"])
    assert stored.user_id == user.id


def test_challenge_endpoint_is_public_and_validates_the_action(app_client):
    created = app_client.post("/auth/nostr/challenge", json={})
    invalid = app_client.post(
        "/auth/nostr/challenge", json={"action": "delete"}
    )

    assert created.status_code == HTTPStatus.CREATED
    assert created.json()["action"] == "login"
    assert invalid.status_code == HTTPStatus.UNPROCESSABLE_ENTITY


# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------
async def test_login_opens_a_session_for_the_linked_user(db_session):
    user = await _make_user(db_session, nostr_pubkey=PUBKEY_A)
    request = _request()
    challenge = await _new_challenge(db_session, request, redirect="/next")

    response = await _verify(
        db_session, request, challenge["k1"], _event(SECRET_A, challenge["k1"])
    )

    assert response == {"status": "OK", "redirect": "/next"}
    assert request.session["user_id"] == user.id.hex
    assert "nostr_k1" not in request.session
    assert "nostr_next" not in request.session


async def test_login_reports_missing_accounts_without_creating_one(
    db_session,
):
    request = _request()
    challenge = await _new_challenge(db_session, request)

    response = await _verify(
        db_session, request, challenge["k1"], _event(SECRET_A, challenge["k1"])
    )

    users = (await db_session.scalars(select(User))).all()
    assert response.status_code == HTTPStatus.NOT_FOUND
    assert _body(response)["status"] == "NOT_FOUND"
    assert users == []
    assert "user_id" not in request.session


async def test_login_rejects_disabled_accounts(db_session):
    await _make_user(db_session, nostr_pubkey=PUBKEY_A, is_active=False)
    request = _request()
    challenge = await _new_challenge(db_session, request)

    response = await _verify(
        db_session, request, challenge["k1"], _event(SECRET_A, challenge["k1"])
    )

    assert response.status_code == HTTPStatus.FORBIDDEN
    assert "user_id" not in request.session


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------
async def test_register_creates_a_user_with_only_the_nostr_key(db_session):
    request = _request()
    challenge = await _new_challenge(db_session, request, action="register")

    response = await _verify(
        db_session, request, challenge["k1"], _event(SECRET_A, challenge["k1"])
    )

    user = await db_session.scalar(
        select(User).where(User.nostr_pubkey == PUBKEY_A)
    )
    assert response["status"] == "OK"
    assert user.email is None
    assert user.login is None
    assert user.password_hash is None
    assert user.lnurl_pubkey is None
    assert request.session["user_id"] == user.id.hex


async def test_register_rejects_a_key_that_already_has_an_account(db_session):
    await _make_user(db_session, nostr_pubkey=PUBKEY_A)
    request = _request()
    challenge = await _new_challenge(db_session, request, action="register")

    response = await _verify(
        db_session, request, challenge["k1"], _event(SECRET_A, challenge["k1"])
    )

    users = (await db_session.scalars(select(User))).all()
    assert response.status_code == HTTPStatus.CONFLICT
    assert len(users) == 1
    assert "user_id" not in request.session


# ---------------------------------------------------------------------------
# Link
# ---------------------------------------------------------------------------
async def test_link_attaches_the_key_to_the_authenticated_account(db_session):
    user = await _make_user(db_session)
    request = _request(user_id=user.id.hex)
    challenge = await _new_challenge(db_session, request, action="link")

    response = await _verify(
        db_session, request, challenge["k1"], _event(SECRET_A, challenge["k1"])
    )

    await db_session.refresh(user)
    assert response == {"status": "OK"}
    assert user.nostr_pubkey == PUBKEY_A


async def test_link_is_idempotent_for_the_same_key(db_session):
    user = await _make_user(db_session, nostr_pubkey=PUBKEY_A)
    request = _request(user_id=user.id.hex)
    challenge = await _new_challenge(db_session, request, action="link")

    response = await _verify(
        db_session, request, challenge["k1"], _event(SECRET_A, challenge["k1"])
    )

    assert response == {"status": "OK"}


async def test_link_refuses_to_replace_an_existing_key(db_session):
    user = await _make_user(db_session, nostr_pubkey=PUBKEY_A)
    request = _request(user_id=user.id.hex)
    challenge = await _new_challenge(db_session, request, action="link")

    response = await _verify(
        db_session, request, challenge["k1"], _event(SECRET_B, challenge["k1"])
    )

    await db_session.refresh(user)
    assert response.status_code == HTTPStatus.CONFLICT
    assert user.nostr_pubkey == PUBKEY_A


async def test_link_refuses_a_key_owned_by_another_account(db_session):
    await _make_user(db_session, nostr_pubkey=PUBKEY_A)
    user = await _make_user(db_session)
    request = _request(user_id=user.id.hex)
    challenge = await _new_challenge(db_session, request, action="link")

    response = await _verify(
        db_session, request, challenge["k1"], _event(SECRET_A, challenge["k1"])
    )

    await db_session.refresh(user)
    assert response.status_code == HTTPStatus.CONFLICT
    assert user.nostr_pubkey is None


async def test_link_requires_the_same_account_that_asked(db_session):
    asker = await _make_user(db_session)
    other = await _make_user(db_session)
    request = _request(user_id=asker.id.hex)
    challenge = await _new_challenge(db_session, request, action="link")
    request.session["user_id"] = other.id.hex

    response = await _verify(
        db_session, request, challenge["k1"], _event(SECRET_A, challenge["k1"])
    )

    await db_session.refresh(other)
    assert response.status_code == HTTPStatus.UNAUTHORIZED
    assert other.nostr_pubkey is None


# ---------------------------------------------------------------------------
# Challenge lifecycle and replay defense
# ---------------------------------------------------------------------------
async def test_challenge_cannot_be_replayed_after_success(db_session):
    await _make_user(db_session, nostr_pubkey=PUBKEY_A)
    request = _request()
    challenge = await _new_challenge(db_session, request)
    event = _event(SECRET_A, challenge["k1"])
    await _verify(db_session, request, challenge["k1"], event)
    request.session["nostr_k1"] = challenge["k1"]  # attacker re-binds

    response = await _verify(db_session, request, challenge["k1"], event)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert _body(response)["reason"] == "Invalid or expired challenge"


async def test_a_failed_attempt_burns_the_challenge(db_session):
    await _make_user(db_session, nostr_pubkey=PUBKEY_A)
    request = _request()
    challenge = await _new_challenge(db_session, request)
    bad = _event(SECRET_A, challenge["k1"], content="x")

    first = await _verify(db_session, request, challenge["k1"], bad)
    request.session["nostr_k1"] = challenge["k1"]
    second = await _verify(
        db_session, request, challenge["k1"], _event(SECRET_A, challenge["k1"])
    )

    stored = await db_session.get(NostrAuthChallenge, challenge["k1"])
    assert first.status_code == HTTPStatus.BAD_REQUEST
    assert second.status_code == HTTPStatus.BAD_REQUEST
    assert stored.consumed is True


async def test_challenge_from_another_browser_is_rejected(db_session):
    await _make_user(db_session, nostr_pubkey=PUBKEY_A)
    owner = _request()
    challenge = await _new_challenge(db_session, owner)
    attacker = _request()

    response = await _verify(
        db_session,
        attacker,
        challenge["k1"],
        _event(SECRET_A, challenge["k1"]),
    )

    stored = await db_session.get(NostrAuthChallenge, challenge["k1"])
    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert "user_id" not in attacker.session
    assert stored.consumed is False


async def test_expired_challenge_is_rejected(db_session):
    await _make_user(db_session, nostr_pubkey=PUBKEY_A)
    request = _request()
    challenge = await _new_challenge(db_session, request)
    event = _event(SECRET_A, challenge["k1"])

    later = datetime.now(timezone.utc) + timedelta(
        seconds=ENV.NOSTR_CHALLENGE_TTL_SECONDS + 1
    )
    with freeze_time(later):
        response = await _verify(db_session, request, challenge["k1"], event)

    assert response.status_code == HTTPStatus.BAD_REQUEST
    assert _body(response)["reason"] == "Invalid or expired challenge"
    assert "user_id" not in request.session


async def test_unknown_challenge_is_rejected(db_session):
    request = _request(nostr_k1="f" * 64)

    response = await _verify(
        db_session, request, "f" * 64, _event(SECRET_A, "f" * 64)
    )

    assert response.status_code == HTTPStatus.BAD_REQUEST


def test_verify_validates_the_request_body(app_client):
    short_k1 = app_client.post(
        "/auth/nostr/verify", json={"k1": "abc", "event": {}}
    )
    no_event = app_client.post("/auth/nostr/verify", json={"k1": "a" * 64})

    assert short_k1.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
    assert no_event.status_code == HTTPStatus.UNPROCESSABLE_ENTITY
