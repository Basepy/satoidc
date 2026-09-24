from enum import StrEnum, auto


class PermissionsEnum(StrEnum):
    ROOT = auto()
    ADMIN = auto()
    SUPPORT = auto()
    DEVELOPER = auto()


class PKCEMethodEnum(StrEnum):
    PLAIN = "plain"
    S256 = "S256"


class GrantTypeEnum(StrEnum):
    AUTHORIZATION_CODE = "authorization_code"
    REFRESH_TOKEN = "refresh_token"
    CLIENT_CREDENTIALS = "client_credentials"
    DEVICE_CODE = "urn:ietf:params:oauth:grant-type:device_code"  # opcional


class ResponseTypeEnum(StrEnum):
    CODE = "code"
    # Se no futuro quiser implicit/hybrid (OIDC), adicione:
    # ID_TOKEN = "id_token"
    # TOKEN = "token"
    # CODE_ID_TOKEN = "code id_token"
    # CODE_TOKEN = "code token"
    # CODE_ID_TOKEN_TOKEN = "code id_token token"


class TokenEndpointAuthMethodEnum(StrEnum):
    NONE = "none"  # public client (PKCE)
    CLIENT_SECRET_BASIC = "client_secret_basic"
    CLIENT_SECRET_POST = "client_secret_post"
    # Se quiser futuramente:
    # PRIVATE_KEY_JWT = "private_key_jwt"
    # TLS_CLIENT_AUTH = "tls_client_auth"


class JwkAlgEnum(StrEnum):
    # Recomendo RS256 primeiro (simples e compatível). Depois, EdDSA.
    RS256 = "RS256"
    PS256 = "PS256"
    ES256 = "ES256"
    EDDSA = "EdDSA"
