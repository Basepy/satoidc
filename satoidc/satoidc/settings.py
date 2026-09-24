from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env", env_file_encoding="utf-8"
    )
    SERVICE_NAME: str = "SatOIDC"
    DOMAIN: str = ""

    # Database settings
    DATABASE_URL: str = "sqlite+aiosqlite:///satoidc.db"
    SYNC_DATABASE_URL: str = "sqlite:///satoidc.db"

    # LNURL-AUTH settings
    LNURL_K1_TTL_SECONDS: int = 300

    # OAUTH2 JWT settings
    OAUTH2_JWT_ISS: str = "http://localhost:8000"
    OAUTH2_JWT_AUDIENCE: str = "SatOIDC-clients"
    OAUTH2_JWT_SECRET_KEY: str = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"
    OAUTH2_JWT_ALG: str = "RS256"
    OAUTH2_TOKEN_EXPIRES_IN: int = 300

    SESSION_MIDDLEWARE_SECRECT_KEY: str = "CHANGE_ME_TO_A_LONG_RANDOM_SECRET"

    # Administradores "de bootstrap": logins ou e-mails separados por vírgula.
    # Além deles, quem tiver a permissão ADMIN/ROOT também administra.
    ADMIN_USERS: str = ""


ENV = Settings()
