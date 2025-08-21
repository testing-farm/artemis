# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Add log_types field to guest_request

Revision ID: 28e90f8952e9
Revises: 97d761c531e7
Create Date: 2021-09-07 12:08:17.395710

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '28e90f8952e9'
down_revision = '97d761c531e7'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('_log_types', sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('_log_types')
