"""
Convert pool properties to JSON

Revision ID: 968af7e432c2
Revises: 9844f8f59644
Create Date: 2021-07-30 09:02:24.874803

"""

from alembic import op
from tft.artemis.db import convert_column_json_to_str, convert_column_str_to_json

# revision identifiers, used by Alembic.
revision = '968af7e432c2'
down_revision = '9844f8f59644'
branch_labels = None
depends_on = None


def upgrade():
    convert_column_str_to_json(op, 'pools', 'parameters', rename_to='_parameters')


def downgrade():
    convert_column_json_to_str(op, 'pools', '_parameters', rename_to='parameters')
