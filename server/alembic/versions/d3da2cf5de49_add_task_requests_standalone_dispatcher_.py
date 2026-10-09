# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Add task_requests standalone/in sequence dispatcher indexes

Revision ID: d3da2cf5de49
Revises: c7138dc9a462
Create Date: 2026-10-09 10:47:12.342574

"""

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = 'd3da2cf5de49'
down_revision = '63866e38fe0b'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('task_requests', schema=None) as batch_op:
        batch_op.create_index(
            batch_op.f('ix_task_requests_standalone_id'),
            ['id'],
            unique=False,
            postgresql_where=sa.text('task_sequence_request_id IS NULL'),
            sqlite_where=sa.text('task_sequence_request_id IS NULL'),
        )

        batch_op.create_index(
            batch_op.f('ix_task_requests_in_sequence_id'),
            ['id'],
            unique=False,
            postgresql_where=sa.text('task_sequence_request_id IS NOT NULL'),
            sqlite_where=sa.text('task_sequence_request_id IS NOT NULL'),
        )


def downgrade() -> None:
    with op.batch_alter_table('task_requests', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_task_requests_standalone_id'))
        batch_op.drop_index(batch_op.f('ix_task_requests_in_sequence_id'))
