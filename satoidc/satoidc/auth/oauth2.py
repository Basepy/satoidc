"""OIDC server example"""

from secrets import token_urlsafe

from authlib.integrations.sqla_oauth2 import (
    create_bearer_token_validator,
    create_query_client_func,
    create_revocation_endpoint,
    create_save_token_func,
)
from authlib.jose import JsonWebKey
from authlib.oauth2.rfc6749 import grants
from authlib.oauth2.rfc7636 import CodeChallenge
from authlib.oauth2.rfc7662 import (
    IntrospectionEndpoint as _IntrospectionEndpoint,
)
from authlib.oidc.core import UserInfo
from authlib.oidc.core.grants import OpenIDCode as _OpenIDCode
from authlib.oidc.core.grants import (
    OpenIDHybridGrant as _OpenIDHybridGrant,
)
from authlib.oidc.core.grants import (
    OpenIDImplicitGrant as _OpenIDImplicitGrant,
)

from satoidc.fastapi_oauth2 import (
    AuthorizationServer,
    ResourceProtector,
)
from satoidc.models import (
    OAuth2AuthorizationCode,
    OAuth2Client,
    OAuth2Token,
    User,
)
from satoidc.models.database import db
from satoidc.settings import ENV

KEY = JsonWebKey.generate_key("RSA", 2048, is_private=True)

JWT_CONFIG = {
    "key": KEY,
    "alg": ENV.OAUTH2_JWT_ALG,
    "iss": ENV.OAUTH2_JWT_ISS,
    "exp": ENV.OAUTH2_TOKEN_EXPIRES_IN,
}


def exists_nonce(nonce, req):
    """Check nonce existance"""
    exists = (
        db.query(OAuth2AuthorizationCode)
        .filter(
            OAuth2AuthorizationCode.client_id == req.payload.client_id,
            OAuth2AuthorizationCode.nonce == nonce,
        )
        .first()
    )
    return bool(exists)


def generate_user_info(user, scope):
    """Generates the user profile information"""
    user_info = UserInfo(sub=str(user.id))
    if "email" in scope:
        user_info["email"] = user.email
    if "profile" in scope:
        user_info["name"] = user.nickname
        user_info["lnurl_pubkey"] = user.lnurl_pubkey
        user_info["nostr_pubkey"] = user.nostr_pubkey
    return user_info


def create_authorization_code(client, grant_user, request):
    code = token_urlsafe(64)
    nonce = request.data.get("nonce")
    item = OAuth2AuthorizationCode(
        code=code,
        client_id=client.client_id,
        redirect_uri=request.redirect_uri,
        scope=request.scope,
        user_id=grant_user.id,
        nonce=nonce,
    )
    db.add(item)
    db.commit()
    return code


class AuthorizationCodeGrant(grants.AuthorizationCodeGrant):
    """AuthorizationCodeGrant class"""

    TOKEN_ENDPOINT_AUTH_METHODS = [
        "client_secret_basic",
        "client_secret_post",
        "none",
    ]

    def generate_authorization_code(self):  # noqa: PLR6301
        return token_urlsafe(64)

    def save_authorization_code(self, code, request):
        nonce = request.payload.data.get("nonce")
        code_challenge = request.payload.data.get("code_challenge")
        code_challenge_method = request.payload.data.get(
            "code_challenge_method"
        )
        auth_code = OAuth2AuthorizationCode(
            code=code,
            client_id=self.client.client_id,
            redirect_uri=request.payload.redirect_uri,
            scope=request.payload.scope,
            user_id=request.user.id,
            nonce=nonce,
            code_challenge=code_challenge,
            code_challenge_method=code_challenge_method,
        )
        db.add(auth_code)
        db.commit()
        return auth_code

    def query_authorization_code(self, code, client):  # noqa: PLR6301
        """Query the authorization code"""
        item = (
            db.query(OAuth2AuthorizationCode)
            .filter(
                OAuth2AuthorizationCode.code == code,
                OAuth2AuthorizationCode.client_id == client.client_id,
            )
            .first()
        )
        if item and not item.is_expired():
            return item

    def delete_authorization_code(self, authorization_code):  # noqa: PLR6301
        db.delete(authorization_code)
        db.commit()

    def authenticate_user(self, authorization_code):  # noqa: PLR6301
        return (
            db.query(User)
            .filter(User.id == authorization_code.user_id)
            .first()
        )


class RefreshTokenGrant(grants.RefreshTokenGrant):
    """RefreshTokenGrant class"""

    def authenticate_refresh_token(self, refresh_token):  # noqa: PLR6301
        token = (
            db.query(OAuth2Token)
            .filter(OAuth2Token.refresh_token == refresh_token)
            .first()
        )
        if token and token.is_refresh_token_active():
            return token

    def authenticate_user(self, credential):  # noqa: PLR6301
        return db.query(User).filter(User.id == credential.user_id).first()

    def revoke_old_credential(self, credential):  # noqa: PLR6301
        credential.revoked = True
        db.add(credential)
        db.commit()


class IntrospectionEndpoint(_IntrospectionEndpoint):
    """IntrospectionEndpoint class"""

    def query_token(self, token, token_type_hint, client):  # noqa: PLR6301
        if token_type_hint == "access_token":
            tok = (
                db.query(OAuth2Token)
                .filter(OAuth2Token.access_token == token)
                .first()
            )
        elif token_type_hint == "refresh_token":
            tok = (
                db.query(OAuth2Token)
                .filter(OAuth2Token.refresh_token == token)
                .first()
            )
        else:
            tok = (
                db.query(OAuth2Token)
                .filter(OAuth2Token.access_token == token)
                .first()
            )
            if not tok:
                tok = (
                    db.query(OAuth2Token)
                    .filter(OAuth2Token.refresh_token == token)
                    .first()
                )
        if tok:
            if tok.client_id == client.client_id:
                return tok

    def introspect_token(self, token):  # noqa: PLR6301
        return {
            "active": True,
            "client_id": token.client_id,
            "token_type": token.token_type,
            "username": token.user_id,
            "scope": token.get_scope(),
            "sub": token.user.id,
            "aud": token.client_id,
            "iss": JWT_CONFIG.get("iss"),
            "exp": token.expires_in,
            "iat": token.issued_at,
        }


class OpenIDCode(_OpenIDCode):
    """OpenIDCode class"""

    def exists_nonce(self, nonce, request):  # noqa: PLR6301
        return exists_nonce(nonce, request)

    def get_jwt_config(self, grant):  # noqa: PLR6301
        return JWT_CONFIG

    def generate_user_info(self, user, scope):  # noqa: PLR6301
        return generate_user_info(user, scope)


class ImplicitGrant(_OpenIDImplicitGrant):
    def exists_nonce(self, nonce, request):  # noqa: PLR6301
        return exists_nonce(nonce, request)

    def get_jwt_config(self, grant):  # noqa: PLR6301
        return JWT_CONFIG

    def generate_user_info(self, user, scope):  # noqa: PLR6301
        return generate_user_info(user, scope)


class HybridGrant(_OpenIDHybridGrant):
    def create_authorization_code(self, client, grant_user, request):  # noqa: PLR6301
        return create_authorization_code(client, grant_user, request)

    def exists_nonce(self, nonce, request):  # noqa: PLR6301
        return exists_nonce(nonce, request)

    def get_jwt_config(self):  # noqa: PLR6301
        return JWT_CONFIG

    def generate_user_info(self, user, scope):  # noqa: PLR6301
        return generate_user_info(user, scope)


authorization = AuthorizationServer()
require_oauth = ResourceProtector()


def config_oauth(app):
    """Setup the application configuration"""
    query_client = create_query_client_func(db, OAuth2Client)
    save_token = create_save_token_func(db, OAuth2Token)
    authorization.init_app(
        app, query_client=query_client, save_token=save_token
    )

    # support all openid grants
    authorization.register_grant(
        AuthorizationCodeGrant,
        [OpenIDCode(require_nonce=True), CodeChallenge(required=True)],
    )
    authorization.register_grant(ImplicitGrant)
    authorization.register_grant(HybridGrant)
    authorization.register_grant(RefreshTokenGrant)
    authorization.register_endpoint(IntrospectionEndpoint)

    # revocation
    revocation_cls = create_revocation_endpoint(db, OAuth2Token)
    authorization.register_endpoint(revocation_cls)

    # protect resource
    bearer_cls = create_bearer_token_validator(db, OAuth2Token)
    require_oauth.register_token_validator(bearer_cls())
