"""add nostr pubkey to users

Revision ID: 8f6b1c2d9a03
Revises: 32a836ab058b
Create Date: 2026-09-23 00:00:00.000000

"""

from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = "8f6b1c2d9a03"
down_revision: Union[str, Sequence[str], None] = "32a836ab058b"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.add_column(
        "users",
        sa.Column("nostr_pubkey", sa.String(), nullable=True),
    )
    op.create_index(
        op.f("ix_users_nostr_pubkey"),
        "users",
        ["nostr_pubkey"],
        unique=True,
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f("ix_users_nostr_pubkey"), table_name="users")
    op.drop_column("users", "nostr_pubkey")
