from urllib.parse import quote, urlencode

from fastapi import Request
from fastapi.responses import RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

PUBLIC_PREFIXES = (
    "/static",  # assets da UI Jinja
    "/oauth",  # tudo de OIDC
    "/api",  # APIs públicas (token, callbacks, etc.)
)

PUBLIC_EXACT = {
    "/register",
    "/register/nostr",
    "/register/nostr/generate",
    "/login",
    "/login/nostr",
    "/logout",
    "/health",
}


class AuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):  # noqa: PLR6301

        path = request.url.path

        if path in PUBLIC_EXACT:
            return await call_next(request)

        if path.startswith(PUBLIC_PREFIXES):
            return await call_next(request)
        user_id = request.session.get("user_id")
        if not user_id:
            full = path + (
                ("?" + request.url.query) if request.url.query else ""
            )
            qs = urlencode({"redirect_to": full}, quote_via=quote)
            return RedirectResponse(
                url=f"/login?{qs}",
                status_code=303,
            )

        return await call_next(request)
