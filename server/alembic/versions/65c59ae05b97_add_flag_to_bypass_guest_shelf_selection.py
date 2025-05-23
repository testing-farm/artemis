# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Add flag to bypass guest shelf selection

Revision ID: 65c59ae05b97
Revises: 237cc90c30dc
Create Date: 2023-03-31 12:13:57.259803

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '65c59ae05b97'
down_revision = '237cc90c30dc'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('bypass_shelf_lookup', sa.Boolean(), server_default='false', nullable=False))

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('bypass_shelf_lookup')

    # ### end Alembic commands ###
