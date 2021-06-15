"""
guest logs table

Revision ID: 3fdd1a194d2c
Revises: 5f50a93ea161
Create Date: 2021-05-26 14:37:45.750543

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = '3fdd1a194d2c'
down_revision = '5f50a93ea161'
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'guest_logs',
        sa.Column('guestname', sa.String(), nullable=False),
        sa.Column('logname', sa.String(), nullable=False),
        sa.Column('contenttype', sa.String(), nullable=False),
        sa.Column('url', sa.String(), nullable=True),
        sa.Column('blob', sa.String(), nullable=True),
        sa.Column('updated', sa.DateTime(), nullable=True),
        sa.Column('state', sa.String(), nullable=False),
        sa.Column('expires', sa.DateTime(), nullable=True),

        sa.PrimaryKeyConstraint('guestname', 'logname', 'contenttype')
    )


def downgrade():
    op.drop_table('guest_logs')
