# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Adds knobs table

Revision ID: 1d54a4ff03e8
Revises: 48609a3f5d7a
Create Date: 2020-10-08 18:42:09.724642

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = '1d54a4ff03e8'
down_revision = '48609a3f5d7a'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'knobs',
        sa.Column('knobname', sa.String(), nullable=False),
        sa.Column('value', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('knobname')
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('knobs')
    # ### end Alembic commands ###
