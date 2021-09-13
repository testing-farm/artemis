"""
Convert guest pool data to JSON

Revision ID: 7fe045a4dcc4
Revises: 97d761c531e7
Create Date: 2021-09-13 09:13:11.723518

"""
from alembic import op
from tft.artemis.db import convert_column_json_to_str, convert_column_str_to_json

# revision identifiers, used by Alembic.
revision = '7fe045a4dcc4'
down_revision = '28e90f8952e9'
branch_labels = None
depends_on = None


def upgrade():
    convert_column_str_to_json(op, 'guest_requests', 'pool_data', rename_to='_pool_data')


def downgrade():
    convert_column_json_to_str(op, 'guest_requests', '_pool_data', rename_to='pool_data')
