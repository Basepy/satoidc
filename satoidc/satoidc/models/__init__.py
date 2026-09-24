import time
from datetime import datetime
from secrets import token_hex
from typing import Optional
from uuid import UUID, uuid4

from authlib.integrations.sqla_oauth2 import (
    OAuth2AuthorizationCodeMixin,
    OAuth2ClientMixin,
    OAuth2TokenMixin,
)
from sqlalchemy import DateTime, ForeignKey, UniqueConstraint, func
from sqlalchemy.orm import Mapped, mapped_column, registry, relationship

from satoidc.enums import PermissionsEnum

table_registry = registry()


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), init=False, server_default=func.now()
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        init=False,
        server_default=func.now(),
        onupdate=func.now(),
    )


@table_registry.mapped_as_dataclass
class User(TimestampMixin):
    __tablename__ = "users"

    id: Mapped[UUID] = mapped_column(
        init=False, primary_key=True, default_factory=uuid4
    )
    lnurl_pubkey: Mapped[Optional[str]] = mapped_column(
        unique=True, nullable=True, index=True
    )
    email: Mapped[Optional[str]] = mapped_column(unique=True, nullable=True)
    login: Mapped[Optional[str]] = mapped_column(unique=True, nullable=True)
    password_hash: Mapped[Optional[str]] = mapped_column(nullable=True)
    nickname: Mapped[str] = mapped_column(default="Satoshi")
    is_active: Mapped[bool] = mapped_column(default=True)

    # Relationships
    permissions: Mapped[list["Permission"]] = relationship(
        "Permission",
        foreign_keys="Permission.user_id",
        init=False,
        back_populates="user",
        cascade="all, delete-orphan",
    )
    granted_permissions: Mapped[list["Permission"]] = relationship(
        "Permission",
        foreign_keys="Permission.granted_by",
        init=False,
        back_populates="granted_by_user",
    )

    def get_user_id(self):
        """Fetch user identifier"""
        return self.id


@table_registry.mapped_as_dataclass
class Permission:
    __tablename__ = "permissions"
    user_id: Mapped[UUID] = mapped_column(ForeignKey("users.id"), index=True)
    granted_by: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("users.id"),
        nullable=True,
    )

    id: Mapped[int] = mapped_column(init=False, primary_key=True)
    permission_type: Mapped[PermissionsEnum]
    expiration_date: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, index=True
    )
    reason: Mapped[Optional[str]] = mapped_column(nullable=True)
    disabled: Mapped[bool] = mapped_column(default=False, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), init=False, server_default=func.now()
    )

    user: Mapped["User"] = relationship(
        "User",
        foreign_keys=[user_id],
        init=False,
        back_populates="permissions",
    )
    granted_by_user: Mapped[Optional["User"]] = relationship(
        "User",
        foreign_keys=[granted_by],
        back_populates="granted_permissions",
        init=False,
    )

    __table_args__ = (
        UniqueConstraint(
            "user_id", "permission_type", name="uq_permissions_user_type"
        ),
    )


@table_registry.mapped_as_dataclass
class LnurlAuthChallenge(TimestampMixin):
    __tablename__ = "lnurl_auth_challenges"
    user_id: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("users.id"), nullable=True, index=True, default=None
    )

    k1: Mapped[str] = mapped_column(
        primary_key=True, default_factory=lambda: token_hex(32)
    )
    action: Mapped[str] = mapped_column(default="login")
    verified: Mapped[bool] = mapped_column(default=False, index=True)
    used: Mapped[bool] = mapped_column(default=False, index=True)

    user: Mapped[Optional["User"]] = relationship("User", init=False)


@table_registry.mapped
class OAuth2Client(OAuth2ClientMixin):
    __tablename__ = "oauth2_client"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE")
    )
    user: Mapped["User"] = relationship("User")


@table_registry.mapped
class OAuth2AuthorizationCode(OAuth2AuthorizationCodeMixin):
    __tablename__ = "oauth2_code"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE")
    )
    user: Mapped["User"] = relationship("User")

    def is_expired(self):
        return self.auth_time + 300 < time.time()


@table_registry.mapped
class OAuth2Token(OAuth2TokenMixin):
    __tablename__ = "oauth2_token"

    id: Mapped[int] = mapped_column(primary_key=True)
    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE")
    )
    user: Mapped["User"] = relationship("User")

    def is_refresh_token_active(self):
        if self.revoked:
            return False
        expires_at = self.issued_at + self.expires_in * 2
        return expires_at >= time.time()


@table_registry.mapped_as_dataclass
class DevAccessRequest(TimestampMixin):
    """Pedido de acesso de desenvolvedor, analisado por um administrador."""

    __tablename__ = "dev_access_requests"

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    id: Mapped[UUID] = mapped_column(
        init=False, primary_key=True, default_factory=uuid4
    )
    reason: Mapped[str] = mapped_column(default="")
    status: Mapped[str] = mapped_column(default="pending", index=True)
    decision_reason: Mapped[Optional[str]] = mapped_column(default=None)
    decided_by: Mapped[Optional[UUID]] = mapped_column(
        ForeignKey("users.id"), nullable=True, default=None
    )
    decided_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True, default=None
    )

    user: Mapped["User"] = relationship(
        "User", foreign_keys=[user_id], init=False
    )


@table_registry.mapped_as_dataclass
class AuthorizedApp(TimestampMixin):
    """App (client OAuth2) ao qual o usuário deu consentimento."""

    __tablename__ = "authorized_apps"
    __table_args__ = (
        UniqueConstraint("user_id", "client_id", name="uq_authorized_app"),
    )

    user_id: Mapped[UUID] = mapped_column(
        ForeignKey("users.id", ondelete="CASCADE"), index=True
    )
    client_id: Mapped[str] = mapped_column(index=True)
    id: Mapped[int] = mapped_column(init=False, primary_key=True)
    scope: Mapped[str] = mapped_column(default="")
