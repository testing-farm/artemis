# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Post-Python 3.12 update

Revision ID: c7138dc9a462
Revises: d3da2cf5de49
Create Date: 2026-09-09 10:02:28.249347
"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'c7138dc9a462'
down_revision = 'd3da2cf5de49'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('guest_shelves', schema=None) as batch_op:
        batch_op.alter_column(
            'state',
            existing_type=sa.VARCHAR(length=250),
            type_=sa.Enum(
                'ERROR',
                'PENDING',
                'SHELF_LOOKUP',
                'ROUTING',
                'PROVISIONING',
                'PROMISED',
                'PREPARING',
                'READY',
                'CONDEMNED',
                'SHELVED',
                name='gueststate',
            ),
            existing_nullable=False,
            postgresql_using='state::text::gueststate',
        )


def downgrade() -> None:
    with op.batch_alter_table('guest_shelves', schema=None) as batch_op:
        batch_op.alter_column(
            'state',
            existing_type=sa.Enum(
                'ERROR',
                'PENDING',
                'SHELF_LOOKUP',
                'ROUTING',
                'PROVISIONING',
                'PROMISED',
                'PREPARING',
                'READY',
                'CONDEMNED',
                'SHELVED',
                name='gueststate',
            ),
            type_=sa.VARCHAR(length=250),
            existing_nullable=False,
            postgresql_using='state::text',
        )
