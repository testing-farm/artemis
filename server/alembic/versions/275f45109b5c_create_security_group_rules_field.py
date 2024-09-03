# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
create security_group_rules field

Revision ID: 275f45109b5c
Revises: 43204dc08933
Create Date: 2024-07-29 14:25:16.967283

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = '275f45109b5c'
down_revision = '43204dc08933'
branch_labels = None
depends_on = None


def upgrade() -> None:
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('_security_group_rules_ingress', sa.JSON(), nullable=True))
        batch_op.add_column(sa.Column('_security_group_rules_egress', sa.JSON(), nullable=True))


def downgrade() -> None:
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('_security_group_rules_ingress')
        batch_op.drop_column('_security_group_rules_egress')
