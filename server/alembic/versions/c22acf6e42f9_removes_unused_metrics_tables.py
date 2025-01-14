# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Removes unused metrics tables

Revision ID: c22acf6e42f9
Revises: 7adee582ada3
Create Date: 2021-03-01 17:03:20.417063

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'c22acf6e42f9'
down_revision = '7adee582ada3'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('metrics_failover_success')
    op.drop_table('metrics_policy_rulings')
    op.drop_table('metrics_policy_cancellations')
    op.drop_table('metrics_policy_calls')
    op.drop_table('metrics_provisioning_success')
    op.drop_table('metrics_failover')
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'metrics_failover',
        sa.Column('from_pool', sa.VARCHAR(length=250), nullable=False),
        sa.Column('to_pool', sa.VARCHAR(length=250), nullable=False),
        sa.Column('count', sa.INTEGER(), nullable=True),
        sa.Column('updated', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['from_pool'], ['pools.poolname'], ),
        sa.ForeignKeyConstraint(['to_pool'], ['pools.poolname'], ),
        sa.PrimaryKeyConstraint('from_pool', 'to_pool')
    )
    op.create_table(
        'metrics_provisioning_success',
        sa.Column('pool', sa.VARCHAR(), nullable=False),
        sa.Column('count', sa.INTEGER(), nullable=False),
        sa.PrimaryKeyConstraint('pool')
    )
    op.create_table(
        'metrics_policy_calls',
        sa.Column('policy_name', sa.VARCHAR(), nullable=False),
        sa.Column('count', sa.INTEGER(), nullable=True),
        sa.PrimaryKeyConstraint('policy_name')
    )
    op.create_table(
        'metrics_policy_cancellations',
        sa.Column('policy_name', sa.VARCHAR(), nullable=False),
        sa.Column('count', sa.INTEGER(), nullable=True),
        sa.PrimaryKeyConstraint('policy_name')
    )
    op.create_table(
        'metrics_policy_rulings',
        sa.Column('policy_name', sa.VARCHAR(), nullable=False),
        sa.Column('pool_name', sa.VARCHAR(), nullable=False),
        sa.Column('allowed', sa.BOOLEAN(), nullable=False),
        sa.Column('count', sa.INTEGER(), nullable=True),
        sa.PrimaryKeyConstraint('policy_name', 'pool_name', 'allowed')
    )
    op.create_table(
        'metrics_failover_success',
        sa.Column('from_pool', sa.VARCHAR(length=250), nullable=False),
        sa.Column('to_pool', sa.VARCHAR(length=250), nullable=False),
        sa.Column('count', sa.INTEGER(), nullable=True),
        sa.Column('updated', sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(['from_pool'], ['pools.poolname'], ),
        sa.ForeignKeyConstraint(['to_pool'], ['pools.poolname'], ),
        sa.PrimaryKeyConstraint('from_pool', 'to_pool')
    )
    # ### end Alembic commands ###
