# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Adds policy rulings metrics

Revision ID: a31dd2a66069
Revises: 51c5e4b2a7ac
Create Date: 2021-02-09 15:25:23.460167

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'a31dd2a66069'
down_revision = '51c5e4b2a7ac'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'metrics_policy_calls',
        sa.Column('policy_name', sa.String(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('policy_name')
    )
    op.create_table(
        'metrics_policy_cancellations',
        sa.Column('policy_name', sa.String(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('policy_name')
    )
    op.create_table(
        'metrics_policy_rulings',
        sa.Column('policy_name', sa.String(), nullable=False),
        sa.Column('pool_name', sa.String(), nullable=False),
        sa.Column('allowed', sa.Boolean(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=True),
        sa.PrimaryKeyConstraint('policy_name', 'pool_name', 'allowed')
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('metrics_policy_rulings')
    op.drop_table('metrics_policy_cancellations')
    op.drop_table('metrics_policy_calls')
    # ### end Alembic commands ###
