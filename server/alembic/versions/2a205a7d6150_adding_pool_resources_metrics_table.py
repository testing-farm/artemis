# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Adding pool resources metrics table

Revision ID: 2a205a7d6150
Revises: 487f52cc5aef
Create Date: 2020-09-15 14:11:27.472692

"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '2a205a7d6150'
down_revision = '487f52cc5aef'
branch_labels = None
depends_on = None


def get_enum_type() -> Union[sa.Enum, postgresql.ENUM]:
    if op.get_bind().dialect.name == 'postgresql':
        enum = postgresql.ENUM(
            'LIMITS',
            'USAGE',
            name='poolresourcesmetricsdimensions',
            create_type=False
        )

        enum.create(op.get_bind())

        return enum

    return sa.Enum(
        'LIMITS',
        'USAGE',
        name='poolresourcesmetricsdimensions'
    )


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'metrics_pool_resources',
        sa.Column('poolname', sa.String(length=250), nullable=False),
        sa.Column('dimension', get_enum_type(), nullable=False),
        sa.Column('instances', sa.BigInteger(), nullable=True),
        sa.Column('cores', sa.BigInteger(), nullable=True),
        sa.Column('memory', sa.BigInteger(), nullable=True),
        sa.Column('diskspace', sa.BigInteger(), nullable=True),
        sa.Column('snapshots', sa.BigInteger(), nullable=True),
        sa.PrimaryKeyConstraint('poolname', 'dimension')
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('metrics_pool_resources')

    if op.get_bind().dialect.name == 'postgresql':
        op.execute("DROP TYPE poolresourcesmetricsdimensions;")

    # ### end Alembic commands ###
