# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Add skip-prepare-verify-ssh to guest request

Revision ID: 0404338f093a
Revises: 5529d49203b8
Create Date: 2021-08-24 09:51:41.729054

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = '0404338f093a'
down_revision = '5529d49203b8'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('skip_prepare_verify_ssh', sa.Boolean(), server_default='false', nullable=False))

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('skip_prepare_verify_ssh')

    # ### end Alembic commands ###
