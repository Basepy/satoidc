"""add used to lnurl_auth_challenges

Revision ID: a41c7d0e5b21
Revises: 32a836ab058b
Create Date: 2026-09-24 03:40:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = "a41c7d0e5b21"
down_revision: Union[str, Sequence[str], None] = "32a836ab058b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    with op.batch_alter_table("lnurl_auth_challenges") as batch:
        batch.add_column(
            sa.Column(
                "used",
                sa.Boolean(),
                nullable=False,
                server_default=sa.false(),
            )
        )
        batch.create_index(
            op.f("ix_lnurl_auth_challenges_used"), ["used"], unique=False
        )


def downgrade() -> None:
    with op.batch_alter_table("lnurl_auth_challenges") as batch:
        batch.drop_index(op.f("ix_lnurl_auth_challenges_used"))
        batch.drop_column("used")
