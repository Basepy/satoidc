from typing import Annotated

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from satoidc.models import OAuth2Client
from satoidc.models.database import get_session
from satoidc.web import templates

router = APIRouter()

Session = Annotated[AsyncSession, Depends(get_session)]


@router.get("/")
async def home(session: Session, request: Request):
    user_id = request.session.get("user_id")
    clients = await session.scalars(
        select(OAuth2Client)  # .where(OAuth2Client.client_id == UUID(user_id))
    )
    return templates.TemplateResponse(
        request,
        "home.html",
        {
            "request": request,
            "user_id": user_id,
            "clients": list(clients),
        },
    )
