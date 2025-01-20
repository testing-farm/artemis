# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Add guest logs

Revision ID: 9844f8f59644
Revises: 5f50a93ea161
Create Date: 2021-06-15 15:28:19.688751

"""
import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision = '9844f8f59644'
down_revision = '5f50a93ea161'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'guest_logs',
        sa.Column('guestname', sa.String(), nullable=False),
        sa.Column('logname', sa.String(), nullable=False),
        sa.Column('contenttype', sa.Enum('URL', 'BLOB', name='guestlogcontenttype'), nullable=False),
        sa.Column(
            'state',
            sa.Enum('PENDING', 'IN_PROGRESS', 'COMPLETE', 'ERROR', name='guestlogstate'),
            nullable=False
        ),
        sa.Column('url', sa.String(), nullable=True),
        sa.Column('blob', sa.String(), nullable=True),
        sa.Column('updated', sa.DateTime(), nullable=True),
        sa.Column('expires', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('guestname', 'logname', 'contenttype')
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('guest_logs')

    if op.get_bind().dialect.name == 'postgresql':
        op.execute("DROP TYPE guestlogcontenttype;")
        op.execute("DROP TYPE guestlogstate;")

    # ### end Alembic commands ###
