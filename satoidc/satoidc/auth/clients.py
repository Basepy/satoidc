"""Regras dos clients OAuth2/OIDC gerenciados no painel do desenvolvedor."""

import time
from dataclasses import dataclass, field
from secrets import token_urlsafe
from typing import Optional
from urllib.parse import urlparse

from satoidc.models import OAuth2Client

AUTH_METHODS = ("client_secret_basic", "client_secret_post", "none")
GRANT_TYPES = ("authorization_code", "refresh_token")
SCOPES = ("openid", "profile", "email")
NAME_MAX = 80


def is_active(client: OAuth2Client) -> bool:
    return not client.client_metadata.get("disabled", False)


def new_credentials(auth_method: str) -> tuple[str, str]:
    """(client_id, client_secret). Clients públicos (PKCE) não têm secret."""
    secret = token_urlsafe(48) if auth_method != "none" else ""
    return token_urlsafe(24), secret


def issued_now() -> int:
    return int(time.time())


@dataclass
class ClientForm:
    name: str = ""
    uri: str = ""
    redirect_uris: str = ""
    scopes: list[str] = field(default_factory=lambda: ["openid", "profile"])
    grant_types: list[str] = field(
        default_factory=lambda: ["authorization_code"]
    )
    auth_method: str = "client_secret_basic"
    active: bool = True
    errors: dict[str, str] = field(default_factory=dict)

    @classmethod
    def from_client(cls, client: OAuth2Client) -> "ClientForm":
        meta = client.client_metadata
        return cls(
            name=meta.get("client_name", ""),
            uri=meta.get("client_uri", ""),
            redirect_uris="\n".join(meta.get("redirect_uris", [])),
            scopes=(meta.get("scope") or "").split(),
            grant_types=list(meta.get("grant_types", [])),
            auth_method=meta.get("token_endpoint_auth_method", AUTH_METHODS[0]),
            active=not meta.get("disabled", False),
        )

    @classmethod
    def from_post(
        cls,
        name: str,
        uri: str,
        redirect_uris: str,
        scopes: list[str],
        grant_types: list[str],
        auth_method: str,
        active: Optional[str],
    ) -> "ClientForm":
        return cls(
            name=name.strip(),
            uri=uri.strip(),
            redirect_uris=redirect_uris.strip(),
            scopes=[s for s in scopes if s in SCOPES],
            grant_types=[g for g in grant_types if g in GRANT_TYPES],
            auth_method=auth_method,
            active=bool(active),
        )

    def redirect_list(self) -> list[str]:
        return [u.strip() for u in self.redirect_uris.splitlines() if u.strip()]

    def validate(self) -> bool:
        if not self.name or len(self.name) > NAME_MAX:
            self.errors["name"] = f"Informe um nome de até {NAME_MAX} caracteres."
        if self.uri and urlparse(self.uri).scheme not in ("http", "https"):
            self.errors["uri"] = "Use uma URL completa começando com http:// ou https://."
        uris = self.redirect_list()
        if not uris:
            self.errors["redirect_uris"] = "Informe ao menos uma URI de redirecionamento."
        else:
            for uri in uris:
                parsed = urlparse(uri)
                local = parsed.hostname in ("localhost", "127.0.0.1")
                if parsed.scheme not in ("http", "https") or not parsed.netloc:
                    self.errors["redirect_uris"] = f"URI inválida: {uri}"
                    break
                if parsed.scheme == "http" and not local:
                    self.errors["redirect_uris"] = f"Use https (http só vale para localhost): {uri}"
                    break
                if parsed.fragment:
                    self.errors["redirect_uris"] = f"A URI não pode ter fragmento (#): {uri}"
                    break
        if "openid" not in self.scopes:
            self.errors["scopes"] = "O escopo openid é obrigatório."
        if not self.grant_types:
            self.errors["grant_types"] = "Escolha ao menos um tipo de concessão."
        if self.auth_method not in AUTH_METHODS:
            self.errors["auth_method"] = "Método de autenticação inválido."
        return not self.errors

    def metadata(self) -> dict:
        return {
            "client_name": self.name,
            "client_uri": self.uri,
            "redirect_uris": self.redirect_list(),
            "grant_types": self.grant_types,
            "response_types": ["code"],
            "scope": " ".join(s for s in SCOPES if s in self.scopes),
            "token_endpoint_auth_method": self.auth_method,
            "disabled": not self.active,
        }
