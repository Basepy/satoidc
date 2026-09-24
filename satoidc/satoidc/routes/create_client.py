import time
from secrets import token_urlsafe
from typing import Annotated
from uuid import UUID

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.models import OAuth2Client
from satoidc.models.database import get_session
from satoidc.web import templates

router = APIRouter()
Session = Annotated[AsyncSession, Depends(get_session)]


@router.get("/create_client")
async def create_client_page(
    request: Request,
    created: bool = False,
):
    user_id = request.session.get("user_id")
    return templates.TemplateResponse(
        "create_client.html",
        {"request": request, "user_id": user_id, "created": created},
    )


@router.post("/create_client")
async def create_client_post(
    session: Session,
    request: Request,
    client_name: Annotated[str, Form()],
    client_uri: Annotated[str, Form()],
    scope: Annotated[str, Form()],
    redirect_uri: Annotated[str, Form()],
    grant_type: Annotated[str, Form()],
    response_type: Annotated[str, Form()],
    token_endpoint_auth_method: Annotated[str, Form()] = "client_secret_basic",
):
    user_id = request.session.get("user_id")
    client_id = token_urlsafe(32)
    client_id_issued_at = int(time.time())
    secret = (
        token_urlsafe(64) if token_endpoint_auth_method != "none" else ""
    )
    client = OAuth2Client(
        user_id=UUID(user_id),
        client_id=client_id,
        client_id_issued_at=client_id_issued_at,
        client_secret=secret,
    )

    client.set_client_metadata(
        {
            "client_name": client_name,
            "client_uri": client_uri,
            "grant_types": grant_type.splitlines(),
            "redirect_uris": redirect_uri.splitlines(),
            "response_types": response_type.splitlines(),
            "scope": scope,
            "token_endpoint_auth_method": token_endpoint_auth_method,
        }
    )

    session.add(client)
    await session.commit()
    return RedirectResponse(url="/create_client?created=true", status_code=303)
