"""create files and file_permissions tables

Revision ID: d9f0a8c3e2b1
Revises: c8d4f2a1b7e3
Create Date: 2026-10-17 06:12:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = "d9f0a8c3e2b1"
down_revision: str | Sequence[str] | None = "c8d4f2a1b7e3"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table(
        "files",
        sa.Column("file_id", sa.String(length=36), nullable=False),
        sa.Column("owner_id", sa.String(length=36), nullable=False),
        sa.Column("original_name", sa.Text(), nullable=False),
        sa.Column("sha256_hash", sa.String(length=64), nullable=False),
        sa.Column("encrypted_path", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(
            ["owner_id"],
            ["users.user_id"],
        ),
        sa.PrimaryKeyConstraint("file_id"),
    )
    op.create_table(
        "file_permissions",
        sa.Column("file_id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=False),
        sa.Column("permission", sa.String(length=8), nullable=False),
        sa.Column("wrapped_dek", sa.LargeBinary(), nullable=False),
        sa.Column("wrap_alg", sa.String(length=8), nullable=False),
        sa.Column("granted_by", sa.String(length=36), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.CheckConstraint(
            "permission IN ('READ', 'MODIFY')", name="ck_file_permissions_permission"
        ),
        sa.CheckConstraint(
            "wrap_alg IN ('KEK', 'RSA')", name="ck_file_permissions_wrap_alg"
        ),
        sa.ForeignKeyConstraint(
            ["file_id"],
            ["files.file_id"],
        ),
        sa.ForeignKeyConstraint(
            ["user_id"],
            ["users.user_id"],
        ),
        sa.PrimaryKeyConstraint("file_id", "user_id"),
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_table("file_permissions")
    op.drop_table("files")
