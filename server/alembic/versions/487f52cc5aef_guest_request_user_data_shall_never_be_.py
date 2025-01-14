# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Guest request user data shall never be NULL

Revision ID: 487f52cc5aef
Revises: a3c173dfd6f5
Create Date: 2020-09-14 14:51:17.934625

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '487f52cc5aef'
down_revision = 'a3c173dfd6f5'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.alter_column(
            'user_data',
            existing_type=sa.TEXT(),
            nullable=False
        )

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.alter_column(
            'user_data',
            existing_type=sa.TEXT(),
            nullable=True
        )

    # ### end Alembic commands ###
