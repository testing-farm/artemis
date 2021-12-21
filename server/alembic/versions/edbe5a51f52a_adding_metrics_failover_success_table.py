# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Adding metrics_failover_success table

Revision ID: edbe5a51f52a
Revises: e454a81bd5a2
Create Date: 2020-11-03 15:04:02.410404

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = 'edbe5a51f52a'
down_revision = 'e454a81bd5a2'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'metrics_failover_success',
        sa.Column('from_pool', sa.String(length=250)),
        sa.Column('to_pool', sa.String(length=250)),
        sa.Column('count', sa.Integer()),
        sa.Column('updated', sa.DateTime()),
        sa.ForeignKeyConstraint(['from_pool'], ['pools.poolname'], ),
        sa.ForeignKeyConstraint(['to_pool'], ['pools.poolname'], ),
        sa.PrimaryKeyConstraint('from_pool', 'to_pool')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('metrics_failover_success')
    # ### end Alembic commands ###
