from secrets import token_urlsafe

from authlib.oauth2 import OAuth2Error
from fastapi import APIRouter, Request

from satoidc.auth.oauth2 import authorization
from satoidc.web import templates

router = APIRouter()


@router.get("/authorize")
async def authorize_get(request: Request):
    error_body = None
    grant = None
    try:
        grant = authorization.validate_consent_request(request=request)
    except OAuth2Error as error:
        error_body = dict(error.get_body())

    csrf = token_urlsafe(32)
    request.session["csrf_token"] = csrf
    action = "/oauth/authorize" + (
        ("?" + request.url.query) if request.url.query else ""
    )
    return templates.TemplateResponse(
        request,
        "authorize.html",
        {
            "request": request,
            "action": action,
            "csrf": csrf,
            "query_params": list(request.query_params.items()),
            "grant": grant,
            "error_body": error_body,
        },
    )
