# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Add column storing task to be dispatched once guest is ready

Revision ID: 3082955b6723
Revises: 237cc90c30dc
Create Date: 2023-04-03 17:43:07.049679

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = '3082955b6723'
down_revision = '65c59ae05b97'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('_on_ready', sa.JSON()))

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('_on_ready')

    # ### end Alembic commands ###
