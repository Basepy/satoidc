from secrets import token_urlsafe
from typing import Annotated
from urllib.parse import quote, urlparse

from authlib.oauth2 import OAuth2Error
from fastapi import APIRouter, Depends, Request
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.auth.oauth2 import authorization
from satoidc.auth.session import current_user
from satoidc.models.database import get_session
from satoidc.web import templates

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]


def _scopes(grant) -> list[str]:
    req = getattr(grant, "request", None)
    payload = getattr(req, "payload", req)
    raw = getattr(payload, "scope", "") or ""
    return raw.split()


@router.get("/authorize")
async def authorize_get(session: Session, request: Request):
    user = await current_user(session, request)
    try:
        grant = authorization.validate_consent_request(
            request=request, end_user=user
        )
    except OAuth2Error as error:
        body = dict(error.get_body())
        return templates.TemplateResponse(
            request,
            "auth/error.html",
            {
                "request": request,
                "title": "Não foi possível continuar",
                "message": body.get("error_description")
                or "O aplicativo enviou um pedido de acesso inválido.",
                "code": body.get("error"),
            },
            status_code=400,
        )

    csrf = token_urlsafe(32)
    request.session["csrf_token"] = csrf
    action = "/oauth/authorize" + (
        ("?" + request.url.query) if request.url.query else ""
    )
    client = grant.client
    app_name = client.client_name or client.client_id
    payload = getattr(grant.request, "payload", grant.request)
    redirect_uri = getattr(payload, "redirect_uri", None) or (
        client.redirect_uris[0] if client.redirect_uris else ""
    )
    scopes = _scopes(grant)
    label = user.email or user.login or user.nickname

    return templates.TemplateResponse(
        request,
        "auth/consent.html",
        {
            "request": request,
            "action": action,
            "csrf": csrf,
            "app_name": app_name,
            "app_initial": (app_name[:1] or "A").upper(),
            "scopes": scopes,
            "user": user,
            "user_label": label,
            "redirect_host": urlparse(redirect_uri).netloc or redirect_uri,
            "redirect_to_encoded": quote(
                str(request.url.path)
                + (("?" + request.url.query) if request.url.query else ""),
                safe="",
            ),
        },
    )
