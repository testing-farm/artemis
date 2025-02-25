# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Adds guest_requests.state_mtime

Revision ID: cf1a39506196
Revises: 5b43d515411a
Create Date: 2021-05-27 17:37:10.552688

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'cf1a39506196'
down_revision = '5b43d515411a'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('state_mtime', sa.DateTime(), nullable=True))

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('state_mtime')

    # ### end Alembic commands ###
