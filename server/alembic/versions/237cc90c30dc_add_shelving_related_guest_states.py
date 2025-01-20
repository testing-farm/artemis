# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Add shelving-related guest states

Revision ID: 237cc90c30dc
Revises: 3af7c26ec4f3
Create Date: 2023-03-22

"""
from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = '237cc90c30dc'
down_revision = 'b1dcd42e5d5c'
branch_labels = None
depends_on = None


def get_new_enum(name: str) -> Union[sa.Enum, postgresql.ENUM]:
    if op.get_bind().dialect.name == 'postgresql':
        enum = postgresql.ENUM(
            'ERROR',
            'PENDING',
            'SHELF_LOOKUP',
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
            'SHELVED',
            name=name,
            create_type=False
        )

        enum.create(op.get_bind())

        return enum

    return sa.Enum(
        'ERROR',
        'PENDING',
        'SHELF_LOOKUP',
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
        'SHELVED',
        name=name
    )


def get_old_enum(name: str) -> Union[sa.Enum, postgresql.ENUM]:
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
            name=name,
            create_type=False
        )

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
        name=name
    )


def upgrade() -> None:
    # create a temporary column, with the updated enum
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            '__tmp_state',
            get_new_enum('new_gueststate'),
            server_default='SHELF_LOOKUP',
            nullable=False
        ))

    # copy existing state to the temporary column
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            op.get_bind().execute(sa.text('UPDATE guest_requests SET __tmp_state = state::text::new_gueststate'))
        else:
            op.get_bind().execute(sa.text('UPDATE guest_requests SET __tmp_state = state'))

    # drop the current column and the current type
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('state')

    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            batch_op.execute(sa.text("DROP TYPE gueststate;"))

    # re-create the column, with the updated enum
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            'state',
            get_new_enum('gueststate'),
            server_default='SHELF_LOOKUP',
            nullable=False
        ))

    # copy saved state to this recreated column
    if op.get_bind().dialect.name == 'postgresql':
        op.get_bind().execute(sa.text('UPDATE guest_requests SET state = __tmp_state::text::gueststate'))
    else:
        op.get_bind().execute(sa.text('UPDATE guest_requests SET state = __tmp_state'))

    # drop the temporary column and its type
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('__tmp_state')

    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            batch_op.execute(sa.text("DROP TYPE new_gueststate;"))


def downgrade() -> None:
    # create a temporary column, with the old enum
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            '__tmp_state',
            get_old_enum('old_gueststate'),
            server_default='PENDING',
            nullable=False
        ))

    # copy existing state to the temporary column - handle UNSUPPORTED downgrade
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            op.get_bind().execute(
                sa.text(
                    "UPDATE guest_requests SET state = 'ERROR'::gueststate WHERE state in ('SHELF_LOOKUP', 'SHELVED')"
                )
            )
            op.get_bind().execute(sa.text('UPDATE guest_requests SET __tmp_state = state::text::old_gueststate'))
        else:
            op.get_bind().execute(
                sa.text(
                    "UPDATE guest_requests SET state = 'ERROR' WHERE state in ('SHELF_LOOKUP', 'SHELVED')"
                )
            )
            op.get_bind().execute(sa.text('UPDATE guest_requests SET __tmp_state = state'))

    # drop the current column and the current type
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('state')

    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            batch_op.execute(sa.text("DROP TYPE gueststate;"))

    # re-create the column, with the updated enum
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            'state',
            get_old_enum('gueststate'),
            server_default='ROUTING',
            nullable=False
        ))

    # copy saved state to this recreated column (no cast needed)
    if op.get_bind().dialect.name == 'postgresql':
        op.get_bind().execute(sa.text('UPDATE guest_requests SET state = __tmp_state::text::gueststate'))
    else:
        op.get_bind().execute(sa.text('UPDATE guest_requests SET state = __tmp_state'))

    # drop the temporary column and its type
    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        batch_op.drop_column('__tmp_state')

    with op.batch_alter_table('guest_requests', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            batch_op.execute(sa.text("DROP TYPE old_gueststate;"))
