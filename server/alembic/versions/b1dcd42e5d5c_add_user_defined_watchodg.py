# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Add user defined watchdog delays

Revision ID: b1dcd42e5d5c
Revises: 3af7c26ec4f3
Create Date: 2023-04-06 15:25:47.811562

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'b1dcd42e5d5c'
down_revision = '3af7c26ec4f3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('watchdog_dispatch_delay', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('watchdog_period_delay', sa.Integer(), nullable=True))

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('watchdog_dispatch_delay')
        batch_op.drop_column('watchdog_period_delay')

    # ### end Alembic commands ###
