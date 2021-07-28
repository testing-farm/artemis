"""
Upgrade size of user tokens to handle SHA256

Revision ID: 8c470c3f4331
Revises: 85e51f3435b4
Create Date: 2020-09-21 11:02:04.149998
"""

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = '8c470c3f4331'
down_revision = '85e51f3435b4'
branch_labels = None
depends_on = None


# NOTE: this revision downgrade becomes no-op: after upgrade, there's no way how to gracefully handle downgrade
# if there are existing records. It's not possible to fit 64 chars long tokens into 32 chars, truncating tokens
# would render them unusable. Therefore both upgrade and downgrade work with string columns without any particular
# size, allowing the downgrade to proceed.

def upgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column(
            'admin_token',
            type_=sa.String(),
            server_default='undefined',
            nullable=False
        )
        batch_op.alter_column(
            'provisioning_token',
            type_=sa.String(),
            server_default='undefined',
            nullable=False
        )


def downgrade():
    with op.batch_alter_table('users', schema=None) as batch_op:
        batch_op.alter_column(
            'admin_token',
            type_=sa.String(),
            server_default='undefined',
            nullable=False
        )
        batch_op.alter_column(
            'provisioning_token',
            type_=sa.String(),
            server_default='undefined',
            nullable=False
        )
