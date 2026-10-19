"""create audit_log table

Revision ID: c8d4f2a1b7e3
Revises: 23ecaab85db9
Create Date: 2026-10-17 05:37:44.000000

"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision: str = 'c8d4f2a1b7e3'
down_revision: Union[str, Sequence[str], None] = '23ecaab85db9'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema."""
    op.create_table('audit_log',
    sa.Column('event_id', sa.String(length=36), nullable=False),
    sa.Column('timestamp', sa.DateTime(timezone=True), nullable=False),
    sa.Column('user_id', sa.String(length=36), nullable=True),
    sa.Column('username', sa.String(length=32), nullable=True),
    sa.Column('action_type', sa.String(length=32), nullable=False),
    sa.Column('resource_id', sa.Text(), nullable=True),
    sa.Column('status', sa.String(length=7), nullable=False),
    sa.Column('ip_address', sa.String(length=64), nullable=True),
    sa.Column('hostname', sa.String(length=255), nullable=True),
    sa.Column('details', sa.Text(), nullable=True),
    sa.Column('signature_hmac', sa.String(length=64), nullable=False),
    sa.CheckConstraint("status IN ('SUCCESS', 'FAIL')", name='ck_audit_log_status'),
    sa.PrimaryKeyConstraint('event_id'),
    sa.Index('ix_audit_log_timestamp', 'timestamp')
    )


def downgrade() -> None:
    """Downgrade schema."""
    op.drop_index(op.f('ix_audit_log_timestamp'), table_name='audit_log')
    op.drop_table('audit_log')