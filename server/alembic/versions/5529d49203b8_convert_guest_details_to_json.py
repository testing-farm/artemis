"""
Convert guest event details to JSON

Revision ID: 5529d49203b8
Revises: 9844f8f59644
Create Date: 2021-07-28 16:04:51.125613

"""
from alembic import op
from tft.artemis.db import convert_column_json_to_str, convert_column_str_to_json

# revision identifiers, used by Alembic.
revision = '5529d49203b8'
down_revision = '72026ebfe96c'
branch_labels = None
depends_on = None


def upgrade():
    convert_column_str_to_json(op, 'guest_events', 'details', rename_to='_details')


def downgrade():
    convert_column_json_to_str(op, 'guest_events', '_details', rename_to='details')
