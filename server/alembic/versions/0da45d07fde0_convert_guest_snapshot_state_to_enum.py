# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Convert guest/snapshot state to enum

Revision ID: 0da45d07fde0
Revises: 9844f8f59644
Create Date: 2021-07-27 18:38:03.569577

"""
from typing import Union

import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = '0da45d07fde0'
down_revision = '304435134b82'
branch_labels = None
depends_on = None


def get_enum_type() -> Union[sa.Enum, postgresql.ENUM]:
    if op.get_bind().dialect.name == 'postgresql':
        enum = postgresql.ENUM(
            'ERROR',
            'PENDING',
            'ROUTING',
            'PROVISIONING',
            'PROMISED',
            'PREPARING',
            'READY',
            'CONDEMNED',
            'RESTORING',
            'PROCESSING',
            'RELEASING',
            'CREATING',
            'STOPPING',
            'STOPPED',
            'STARTING',
            name='gueststate',
            create_type=True
        )

        # We need an explicit create() here, because the users table is being altered in a batch.
        enum.create(op.get_bind())

        return enum

    return sa.Enum(
        'ERROR',
        'PENDING',
        'ROUTING',
        'PROVISIONING',
        'PROMISED',
        'PREPARING',
        'READY',
        'CONDEMNED',
        'RESTORING',
        'PROCESSING',
        'RELEASING',
        'CREATING',
        'STOPPING',
        'STOPPED',
        'STARTING',
        name='gueststate'
    )

# This revision replaces a varchar column with a custom enum. To perform the change correctly, without
# breaking existing records, we need several steps:
#
# * add a temporary enum column - we will copy existing `state` values to this column, casting them to their
# corresponding enum member ("routing" => "ROUTING")
# * drop the `state` column - it must go to make place for our future enum column. The values were copied to our
# temporary column.
# * re-create `state` column, this time as an enum.
# * copy values from the temporary columnt to this newly created `state` column, 1:1, no casting is needed since
# we're copying enum to enum.
# * drop the temporary column.
#
# The downgrade is similar, just reversed.
#
# The important bit is the conversion: SQLAlchemy `Enum` column uses a Python `enum` class to provide members,
# and creates a DB type from this class, using member **names** as DB type members. Python enum member values
# are not used. But we were storing them in DB, `state = "ruting"` - after this revision, there's no "routing"
# member of the enum, but "ROUTING". During the copy to the temporary column, we need to apply `upper()` to
# `state` values, to convert them to new uppercased enum members, and add DB-level casting, `::gueststate`.
#


def upgrade() -> None:
    state_enum = get_enum_type()

    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('__tmp_state', state_enum, server_default='ROUTING', nullable=False))

    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            op.get_bind().execute('UPDATE guest_requests SET __tmp_state = upper(state)::gueststate')
        else:
            op.get_bind().execute('UPDATE guest_requests SET __tmp_state = upper(state)')

    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('state')
        batch_op.add_column(sa.Column('state', state_enum, server_default='ROUTING', nullable=False))

    op.get_bind().execute('UPDATE guest_requests SET state = __tmp_state')

    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('__tmp_state')


def downgrade() -> None:
    state_enum = get_enum_type()

    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column('__tmp_state', state_enum, server_default='ROUTING', nullable=False))

    op.get_bind().execute('UPDATE guest_requests SET __tmp_state = state')

    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('state')
        batch_op.add_column(sa.Column('state', sa.String(length=250), server_default='routing', nullable=False))

    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            op.get_bind().execute('UPDATE guest_requests SET state = lower(__tmp_state::text)')
        else:
            op.get_bind().execute('UPDATE guest_requests SET state = lower(__tmp_state)')

    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('__tmp_state')

    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            batch_op.execute("DROP TYPE gueststate;")
