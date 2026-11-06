from typing import Any

from pydantic_settings import BaseSettings, SettingsConfigDict

PRODUCTION_ENVIRONMENTS = {"production", "prod"}
PLACEHOLDER_SECRET = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8"
    )
    SERVICE_NAME: str = "SatOIDC"
    DOMAIN: str = ""
    APP_ENV: str = "development"

    # Database settings
    DATABASE_URL: str = "sqlite+aiosqlite:///satoidc.db"
    SYNC_DATABASE_URL: str = "sqlite:///satoidc.db"

    # LNURL-AUTH settings
    LNURL_K1_TTL_SECONDS: int = 60

    # NOSTR-AUTH settings
    NOSTR_CHALLENGE_TTL_SECONDS: int = 120

    # OAUTH2 JWT settings
    OAUTH2_JWT_ISS: str = "http://localhost:8000"
    OAUTH2_JWT_AUDIENCE: str = "SatOIDC-clients"
    OAUTH2_JWT_SECRET_KEY: str = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
    OAUTH2_JWT_ALG: str = "RS256"
    OAUTH2_TOKEN_EXPIRES_IN: int = 300
    OIDC_JWKS_CACHE_TTL_SECONDS: int = 300
    OIDC_KEY_RETENTION_MARGIN_SECONDS: int = 900

    SESSION_MIDDLEWARE_SECRET_KEY: str = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
    SESSION_COOKIE_HTTPS_ONLY: bool | None = None

    @property
    def is_production(self) -> bool:
        return self.APP_ENV.lower() in PRODUCTION_ENVIRONMENTS

    @property
    def session_cookie_https_only(self) -> bool:
        if self.SESSION_COOKIE_HTTPS_ONLY is not None:
            return self.SESSION_COOKIE_HTTPS_ONLY
        return self.is_production

    def model_post_init(self, __context: Any) -> None:
        if not self.is_production:
            return

        if self.SESSION_MIDDLEWARE_SECRET_KEY == PLACEHOLDER_SECRET:
            raise ValueError(
                "SESSION_MIDDLEWARE_SECRET_KEY must be changed in production"
            )
        if self.OAUTH2_JWT_SECRET_KEY == PLACEHOLDER_SECRET:
            raise ValueError(
                "OAUTH2_JWT_SECRET_KEY must be changed in production"
            )
        if not self.session_cookie_https_only:
            raise ValueError(
                "SESSION_COOKIE_HTTPS_ONLY must be enabled in production"
            )


ENV = Settings()
