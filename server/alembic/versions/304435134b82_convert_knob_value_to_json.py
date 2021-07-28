"""
Convert knob value to JSON

Revision ID: 304435134b82
Revises: 9844f8f59644
Create Date: 2021-07-28 16:32:37.799409

"""

from alembic import op
from tft.artemis.db import convert_column_json_to_str, convert_column_str_to_json

# revision identifiers, used by Alembic.
revision = '304435134b82'
down_revision = 'a16ab7abd194'
branch_labels = None
depends_on = None


def upgrade():
    convert_column_str_to_json(op, 'knobs', 'value')


def downgrade():
    convert_column_json_to_str(op, 'knobs', 'value')
