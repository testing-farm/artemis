# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Convert guest user data to JSON

Revision ID: 97d761c531e7
Revises: 0404338f093a
Create Date: 2021-08-27 13:41:30.143126

"""

from alembic import op

from tft.artemis.db import convert_column_json_to_str, convert_column_str_to_json

# revision identifiers, used by Alembic.
revision = '97d761c531e7'
down_revision = '0404338f093a'
branch_labels = None
depends_on = None


def upgrade() -> None:
    convert_column_str_to_json(op, 'guest_requests', 'user_data', rename_to='_user_data')


def downgrade() -> None:
    convert_column_json_to_str(op, 'guest_requests', '_user_data', rename_to='user_data')
