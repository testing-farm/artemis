# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Adds guest_tags table

Revision ID: 7adee582ada3
Revises: a31dd2a66069
Create Date: 2021-02-12 15:05:51.412826

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '7adee582ada3'
down_revision = 'a31dd2a66069'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'guest_tags',
        sa.Column('poolname', sa.String(), nullable=False),
        sa.Column('tag', sa.String(), nullable=False),
        sa.Column('value', sa.String(), nullable=False),
        sa.PrimaryKeyConstraint('poolname', 'tag')
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('guest_tags')
    # ### end Alembic commands ###
