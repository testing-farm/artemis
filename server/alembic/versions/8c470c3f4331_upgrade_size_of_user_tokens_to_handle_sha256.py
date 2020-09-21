"""
Upgrade size of user tokens to handle SHA256

Revision ID: 8c470c3f4331
Revises: 85e51f3435b4
Create Date: 2020-09-21 11:02:04.149998
"""

from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8c470c3f4331'
down_revision = '85e51f3435b4'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column(
            'admin_token',
            type_=sa.String(length=64),
            server_default='undefined',
            nullable=False
        )
        batch_op.alter_column(
            'provisioning_token',
            type_=sa.String(length=64),
            server_default='undefined',
            nullable=False
        )


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column(
            'admin_token',
            type_=sa.String(length=32),
            server_default='undefined',
            nullable=False
        )
        batch_op.alter_column(
            'provisioning_token',
            type_=sa.String(length=32),
            server_default='undefined',
            nullable=False
        )
