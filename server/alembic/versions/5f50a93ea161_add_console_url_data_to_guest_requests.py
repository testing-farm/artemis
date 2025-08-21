# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
create console requests table

Revision ID: 5f50a93ea161
Revises: 4066bcbc54eb
Create Date: 2021-04-21 10:09:29.214793

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '5f50a93ea161'
down_revision = '4066bcbc54eb'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('console_url', sa.String(), nullable=True))
        batch_op.add_column(sa.Column('console_url_expires', sa.DateTime(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('console_url')
        batch_op.drop_column('console_url_expires')
