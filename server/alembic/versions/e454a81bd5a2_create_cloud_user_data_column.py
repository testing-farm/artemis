"""
create post_install_script column

Revision ID: e454a81bd5a2
Revises: 1d54a4ff03e8
Create Date: 2020-10-22 11:04:26.960592

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'e454a81bd5a2'
down_revision = '1d54a4ff03e8'
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('post_install_script', sa.Text(), nullable=True))


def downgrade():
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('post_install_script')
