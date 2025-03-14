# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Upgrade to SQLAlchemy 2.0 - guest_events

Revision ID: 56597d9c983a
Revises: e5e1011ec6c2
Create Date: 2024-11-13 11:37:41.404810

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '56597d9c983a_1'
down_revision = 'e5e1011ec6c2'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_events', schema=None) as batch_op:
        batch_op.alter_column(
            'updated',
            existing_type=sa.DATETIME(),
            nullable=False
        )

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_events', schema=None) as batch_op:
        batch_op.alter_column(
            'updated',
            existing_type=sa.DATETIME(),
            nullable=True
        )

    # ### end Alembic commands ###
