# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Removes unused pool resource metrics tables

Revision ID: 17445bd3cd8d
Revises: c22acf6e42f9
Create Date: 2021-03-15 16:38:09.928170

"""
import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision = '17445bd3cd8d'
down_revision = 'c22acf6e42f9'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('metrics_pool_resources')
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'metrics_pool_resources',
        sa.Column('poolname', sa.VARCHAR(length=250), nullable=False),
        sa.Column('dimension', sa.VARCHAR(length=6), nullable=False),
        sa.Column('instances', sa.BIGINT(), nullable=True),
        sa.Column('cores', sa.BIGINT(), nullable=True),
        sa.Column('memory', sa.BIGINT(), nullable=True),
        sa.Column('diskspace', sa.BIGINT(), nullable=True),
        sa.Column('snapshots', sa.BIGINT(), nullable=True),
        sa.CheckConstraint("dimension IN ('LIMITS', 'USAGE')", name='poolresourcesmetricsdimensions'),
        sa.PrimaryKeyConstraint('poolname', 'dimension')
    )
    # ### end Alembic commands ###
