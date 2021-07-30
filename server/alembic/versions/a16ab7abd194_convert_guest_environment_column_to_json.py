"""
Convert guest environment column to JSON

Revision ID: a16ab7abd194
Revises: 968af7e432c2
Create Date: 2021-07-30 10:07:45.042143

"""
from alembic import op
from tft.artemis.db import convert_column_json_to_str, convert_column_str_to_json

# revision identifiers, used by Alembic.
revision = 'a16ab7abd194'
down_revision = '968af7e432c2'
branch_labels = None
depends_on = None


def upgrade():
    convert_column_str_to_json(op, 'guest_requests', 'environment', rename_to='_environment')


def downgrade():
    convert_column_json_to_str(op, 'guest_requests', '_environment', rename_to='environment')
