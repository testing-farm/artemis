# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Introduce guest shelf table

Revision ID: 3af7c26ec4f3
Revises: cbb792480f16
Create Date: 2023-01-19 10:56:12.546863

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = '3af7c26ec4f3'
down_revision = 'cbb792480f16'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'guest_shelves',
        sa.Column('shelfname', sa.String(length=250), nullable=False),
        sa.Column('ownername', sa.String(length=250), nullable=False),
        sa.Column('state', sa.String(length=250), nullable=False),
        sa.ForeignKeyConstraint(['ownername'], ['users.username'], ),
        sa.PrimaryKeyConstraint('shelfname')
    )
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('shelfname', sa.String(length=250), nullable=True))
        batch_op.create_foreign_key(
            'fk_guest_requests_shelfname_guest_shelves',
            'guest_shelves',
            ['shelfname'],
            ['shelfname']
        )

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_constraint('fk_guest_requests_shelfname_guest_shelves', type_='foreignkey')
        batch_op.drop_column('shelfname')

    op.drop_table('guest_shelves')
    # ### end Alembic commands ###
