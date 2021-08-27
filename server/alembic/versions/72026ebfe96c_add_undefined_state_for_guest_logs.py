"""
Add UNDEFINED state for guest logs

Revision ID: 72026ebfe96c
Revises: 0da45d07fde0
Create Date: 2021-08-09 10:03:38.317918

"""
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

from alembic import op

# revision identifiers, used by Alembic.
revision = '72026ebfe96c'
down_revision = '0da45d07fde0'
branch_labels = None
depends_on = None


def get_new_enum(name='guestlogstate'):
    if op.get_bind().dialect.name == 'postgresql':
        state_enum = postgresql.ENUM(
            'UNSUPPORTED',
            'PENDING',
            'IN_PROGRESS',
            'COMPLETE',
            'ERROR',
            name=name,
            create_type=True
        )

        # We need an explicit create() here, because the users table is being altered in a batch.
        state_enum.create(op.get_bind())

    else:
        state_enum = postgresql.ENUM(
            'UNSUPPORTED',
            'PENDING',
            'IN_PROGRESS',
            'COMPLETE',
            'ERROR',
            name=name
        )

    return state_enum


def get_old_enum(name='guestlogstate'):
    if op.get_bind().dialect.name == 'postgresql':
        state_enum = postgresql.ENUM(
            'PENDING',
            'IN_PROGRESS',
            'COMPLETE',
            'ERROR',
            name=name,
            create_type=True
        )

        # We need an explicit create() here, because the users table is being altered in a batch.
        state_enum.create(op.get_bind())

    else:
        state_enum = postgresql.ENUM(
            'PENDING',
            'IN_PROGRESS',
            'COMPLETE',
            'ERROR',
            name=name
        )

    return state_enum


def upgrade():
    # create a temporary column, with the updated enum
    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            '__tmp_state',
            get_new_enum(name='new_guestlogstate'),
            server_default='PENDING',
            nullable=False
        ))

    # copy existing state to the temporary column
    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            op.get_bind().execute('UPDATE guest_logs SET __tmp_state = state::text::new_guestlogstate')
        else:
            op.get_bind().execute('UPDATE guest_logs SET __tmp_state = state')

    # drop the current column and the current type
    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        batch_op.drop_column('state')

    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            batch_op.execute("DROP TYPE guestlogstate;")

    # re-create the column, with the updated enum
    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            'state',
            get_new_enum(),
            server_default='PENDING',
            nullable=False
        ))

    # copy saved state to this recreated column
    if op.get_bind().dialect.name == 'postgresql':
        op.get_bind().execute('UPDATE guest_logs SET state = __tmp_state::text::guestlogstate')
    else:
        op.get_bind().execute('UPDATE guest_logs SET state = __tmp_state')

    # drop the temporary column and its type
    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        batch_op.drop_column('__tmp_state')

    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            batch_op.execute("DROP TYPE new_guestlogstate;")


def downgrade():
    # create a temporary column, with the old enum
    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            '__tmp_state',
            get_old_enum(name='old_guestlogstate'),
            server_default='PENDING',
            nullable=False
        ))

    # copy existing state to the temporary column - handle UNSUPPORTED downgrade
    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            op.get_bind().execute("UPDATE guest_logs SET state = 'ERROR'::guestlogstate WHERE state = 'UNSUPPORTED'")
            op.get_bind().execute('UPDATE guest_logs SET __tmp_state = state::text::old_guestlogstate')
        else:
            op.get_bind().execute("UPDATE guest_logs SET state = 'ERROR' WHERE state = 'UNSUPPORTED'")
            op.get_bind().execute('UPDATE guest_logs SET __tmp_state = state')

    # drop the current column and the current type
    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        batch_op.drop_column('state')

    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            batch_op.execute("DROP TYPE guestlogstate;")

    # re-create the column, with the updated enum
    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            'state',
            get_old_enum(),
            server_default='PENDING',
            nullable=False
        ))

    # copy saved state to this recreated column (no cast needed)
    if op.get_bind().dialect.name == 'postgresql':
        op.get_bind().execute('UPDATE guest_logs SET state = __tmp_state::text::guestlogstate')
    else:
        op.get_bind().execute('UPDATE guest_logs SET state = __tmp_state')

    # drop the temporary column and its type
    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        batch_op.drop_column('__tmp_state')

    with op.batch_alter_table('guest_logs', schema=None) as batch_op:
        if op.get_bind().dialect.name == 'postgresql':
            batch_op.execute("DROP TYPE old_guestlogstate;")