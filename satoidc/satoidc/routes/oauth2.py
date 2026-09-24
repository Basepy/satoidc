import hmac
from typing import Annotated, Literal
from uuid import UUID

from authlib.oauth2 import OAuth2Error
from authlib.oauth2.rfc6749.errors import UnsupportedResponseTypeError
from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import JSONResponse
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.oauth2 import (
    KEY,
    authorization,
    generate_user_info,
    require_oauth,
)
from satoidc.models import AuthorizedApp, User
from satoidc.models.database import get_session
from satoidc.settings import ENV

router = APIRouter(prefix="/oauth", tags=["OAuth2"])
Session = Annotated[AsyncSession, Depends(get_session)]


@router.post("/authorize")
async def authorize(  # noqa: PLR0911
    session: Session,
    request: Request,
    decision: Annotated[Literal["approve", "deny"], Form()],
    csrf_token: Annotated[str, Form()],
):
    user_id = request.session.get("user_id")
    if not user_id:
        return JSONResponse({"error": "login_required"}, status_code=401)

    csrf_expected = request.session.get("csrf_token")
    if (
        not csrf_expected
        or not csrf_token
        or not hmac.compare_digest(csrf_expected, csrf_token)
    ):
        return JSONResponse({"error": "invalid_csrf"}, status_code=403)

    request.session.pop("csrf_token", None)

    try:
        uid = UUID(user_id)
    except (ValueError, TypeError):
        return JSONResponse({"error": "invalid_session"}, status_code=401)

    user = await session.scalar(select(User).where(User.id == uid))
    if not user:
        return JSONResponse({"error": "invalid_session"}, status_code=401)

    try:
        grant = authorization.validate_consent_request(
            request=request, end_user=user
        )
    except (OAuth2Error, UnsupportedResponseTypeError) as error:
        return JSONResponse(
            dict(error.get_body()), status_code=error.status_code
        )

    if decision == "deny":
        return authorization.create_authorization_response(
            request=request,
            grant_user=None,
        )

    # registra o consentimento para aparecer em "Apps conectados"
    payload = getattr(grant.request, "payload", grant.request)
    scope = getattr(payload, "scope", "") or ""
    known = await session.scalar(
        select(AuthorizedApp).where(
            AuthorizedApp.user_id == user.id,
            AuthorizedApp.client_id == grant.client.client_id,
        )
    )
    if known:
        known.scope = scope
        known.updated_at = func.now()
    else:
        session.add(
            AuthorizedApp(
                user_id=user.id,
                client_id=grant.client.client_id,
                scope=scope,
            )
        )
    await session.commit()

    return authorization.create_authorization_response(
        request=request,
        grant_user=user,
        grant=grant,
    )


@router.post("/token")
async def token(request: Request):
    # garante request._body para seu payload sync
    await request.body()

    # IMPORTANTÍSSIMO: passe o Request do Starlette pro authlib
    # (ele vai chamar create_oauth2_request sync internamente)
    return authorization.create_token_response(request=request)


@router.post("/introspect")
def introspect_token(
    request: Request,
):
    return authorization.create_endpoint_response(
        "introspection", request=request
    )


@router.post("/revoke")
def revoke_token(
    request: Request,
):

    return authorization.create_endpoint_response(
        "revocation", request=request
    )


@router.get("/userinfo")
def userinfo(request: Request):
    """Request user profile information"""
    with require_oauth.acquire(request, ["openid"]) as token:
        return generate_user_info(token.user, token.scope)


@router.get("/.well-known/openid-configuration")
def well_known():

    return {
        "issuer": ENV.OAUTH2_JWT_ISS,
        "authorization_endpoint": f"{ENV.OAUTH2_JWT_ISS}/authorize",
        "token_endpoint": f"{ENV.OAUTH2_JWT_ISS}/oauth/token",
        "userinfo_endpoint": f"{ENV.OAUTH2_JWT_ISS}/oauth/userinfo",
        "jwks_uri": f"{ENV.OAUTH2_JWT_ISS}/oauth/jwks.json",
        # RECOMENDADOS / IMPORTANTES
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email", "wallet"],
        "token_endpoint_auth_methods_supported": [
            "none",
            "client_secret_post",
            "client_secret_basic",
        ],
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "exp",
            "iat",
            "profile",
            "email",
        ],
        # PKCE (importante)
        "code_challenge_methods_supported": ["S256"],
    }


@router.get("/jwks.json")
def jwks():
    # Extrai apenas a chave PÚBLICA para enviar ao cliente
    public_key = KEY.as_dict(add_kid=True)
    public_key.pop("d", None)  # Remove parte privada por segurança
    public_key.pop("p", None)
    public_key.pop("q", None)
    public_key.pop("dp", None)
    public_key.pop("dq", None)
    public_key.pop("qi", None)

    return {"keys": [public_key]}
