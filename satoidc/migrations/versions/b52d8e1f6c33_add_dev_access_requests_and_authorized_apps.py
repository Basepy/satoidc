"""add dev_access_requests and authorized_apps

Revision ID: b52d8e1f6c33
Revises: a41c7d0e5b21
Create Date: 2026-09-24 12:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "b52d8e1f6c33"
down_revision: Union[str, Sequence[str], None] = "a41c7d0e5b21"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table(
        "dev_access_requests",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("reason", sa.String(), nullable=False),
        sa.Column("status", sa.String(), nullable=False),
        sa.Column("decision_reason", sa.String(), nullable=True),
        sa.Column("decided_by", sa.Uuid(), nullable=True),
        sa.Column("decided_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["decided_by"], ["users.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index(op.f("ix_dev_access_requests_user_id"), "dev_access_requests", ["user_id"])
    op.create_index(op.f("ix_dev_access_requests_status"), "dev_access_requests", ["status"])
    op.create_table(
        "authorized_apps",
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("client_id", sa.String(), nullable=False),
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("scope", sa.String(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), server_default=sa.func.now(), nullable=False),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("user_id", "client_id", name="uq_authorized_app"),
    )
    op.create_index(op.f("ix_authorized_apps_user_id"), "authorized_apps", ["user_id"])
    op.create_index(op.f("ix_authorized_apps_client_id"), "authorized_apps", ["client_id"])


def downgrade() -> None:
    op.drop_table("authorized_apps")
    op.drop_table("dev_access_requests")
