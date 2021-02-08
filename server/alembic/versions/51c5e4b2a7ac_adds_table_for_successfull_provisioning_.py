"""
Adds table for "successfull provisioning" metric

Revision ID: 51c5e4b2a7ac
Revises: 8f7a33b3e529
Create Date: 2021-02-09 13:09:37.501620

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '51c5e4b2a7ac'
down_revision = '8f7a33b3e529'
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'metrics_provisioning_success',
        sa.Column('pool', sa.String(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=False),
        sa.PrimaryKeyConstraint('pool')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('metrics_provisioning_success')
    # ### end Alembic commands ###