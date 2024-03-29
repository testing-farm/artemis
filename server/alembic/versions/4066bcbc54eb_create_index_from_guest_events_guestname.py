# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Create index from guest events guestname

Revision ID: 4066bcbc54eb
Revises: 17445bd3cd8d
Create Date: 2021-03-24 14:16:04.358895

"""
from alembic import op

# revision identifiers, used by Alembic.
revision = '4066bcbc54eb'
down_revision = '17445bd3cd8d'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_events', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_guest_events_guestname'), ['guestname'], unique=False)

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_events', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_guest_events_guestname'))

    # ### end Alembic commands ###
