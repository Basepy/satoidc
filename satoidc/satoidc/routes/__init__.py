from .authorize import router as authorize_router
from .create_client import router as create_client_router
from .dashboard import router as dashboard_router
from .forbidden import router as forbidden_router
from .home import router as home_router
from .lnurl_auth import router as lnurl_auth_router
from .login import router as login_router
from .nostr_auth import router as nostr_auth_router
from .oauth2 import admin_oidc_keys_router, well_known_router
from .oauth2 import router as oauth_router
from .profile import router as profile_router
from .register import router as register_router

__all__ = [
    "home_router",
    "register_router",
    "login_router",
    "profile_router",
    "dashboard_router",
    "forbidden_router",
    "oauth_router",
    "admin_oidc_keys_router",
    "well_known_router",
    "authorize_router",
    "create_client_router",
    "lnurl_auth_router",
    "nostr_auth_router",
]

routers = [
    home_router,
    register_router,
    login_router,
    dashboard_router,
    forbidden_router,
    well_known_router,
    admin_oidc_keys_router,
    oauth_router,
    authorize_router,
    create_client_router,
    lnurl_auth_router,
    nostr_auth_router,
    profile_router,
]
