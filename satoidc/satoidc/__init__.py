from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from satoidc.auth.middleware import AuthMiddleware
from satoidc.auth.oauth2 import config_oauth
from satoidc.routes.account import router as account_page
from satoidc.routes.admin import router as admin_page
from satoidc.routes.authorize import router as authorize_page
from satoidc.routes.developer import router as developer_page
from satoidc.routes.lnurl_auth import router as lnurl_auth_router
from satoidc.routes.login import router as login_page
from satoidc.routes.oauth2 import router
from satoidc.routes.register import router as register_page
from satoidc.settings import ENV
from satoidc.web import PACKAGE_DIR

app = FastAPI(title="Identity Service", version="0.1.0")
app.mount(
    "/static",
    StaticFiles(directory=str(PACKAGE_DIR / "static")),
    name="static",
)
app.add_middleware(AuthMiddleware)
app.add_middleware(
    SessionMiddleware,
    secret_key=ENV.SESSION_MIDDLEWARE_SECRECT_KEY,
    same_site="lax",
    https_only=False,
    session_cookie="client_session",
)


app.config = {
    "OAUTH2_JWT_ISS": ENV.OAUTH2_JWT_ISS,
    "OAUTH2_JWT_KEY": ENV.OAUTH2_JWT_SECRET_KEY,
    "OAUTH2_JWT_ALG": ENV.OAUTH2_JWT_ALG,
    "OAUTH2_TOKEN_EXPIRES_IN": {
        "authorization_code": ENV.OAUTH2_TOKEN_EXPIRES_IN
    },
    "OAUTH2_ERROR_URIS": [
        (
            "invalid_client",
            f"https://developer.{ENV.DOMAIN}/errors#invalid-client",
        ),
    ],
}


config_oauth(app)

app.include_router(router)
app.include_router(router=account_page, tags=["account"])
app.include_router(router=developer_page)
app.include_router(router=admin_page)
app.include_router(router=login_page, tags=["login"])
app.include_router(router=lnurl_auth_router)
app.include_router(router=register_page, tags=["register"])
app.include_router(router=authorize_page, tags=["authorize"])
