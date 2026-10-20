"""add files.version and audit_log.prev_hmac

Revision ID: e3a7b9c1d2f4
Revises: d9f0a8c3e2b1
Create Date: 2026-10-19 12:00:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "e3a7b9c1d2f4"
down_revision: str | Sequence[str] | None = "d9f0a8c3e2b1"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    # batch_alter_table: o SQLite não altera constraints com ALTER TABLE.
    with op.batch_alter_table("files") as batch_op:
        batch_op.add_column(
            sa.Column("version", sa.Integer(), nullable=False, server_default="1")
        )
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.add_column(sa.Column("prev_hmac", sa.String(length=64), nullable=True))
        batch_op.create_unique_constraint("uq_audit_log_prev_hmac", ["prev_hmac"])


def downgrade() -> None:
    """Downgrade schema."""
    with op.batch_alter_table("audit_log") as batch_op:
        batch_op.drop_constraint("uq_audit_log_prev_hmac", type_="unique")
        batch_op.drop_column("prev_hmac")
    with op.batch_alter_table("files") as batch_op:
        batch_op.drop_column("version")
