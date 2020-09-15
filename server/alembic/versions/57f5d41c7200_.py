"""Intial database schema import

Revision ID: 57f5d41c7200
Revises:
Create Date: 2020-07-21 15:51:55.334506

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '57f5d41c7200'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table(
        'guest_events',
        sa.Column('_id', sa.Integer(), nullable=False),
        sa.Column('updated', sa.DateTime(), nullable=True),
        sa.Column('guestname', sa.String(length=250), nullable=False),
        sa.Column('eventname', sa.String(length=250), nullable=False),
        sa.Column('details', sa.Text(), nullable=True),
        sa.PrimaryKeyConstraint('_id')
    )
    op.create_table(
        'metrics',
        sa.Column('_id', sa.Integer(), nullable=False),
        sa.Column('count', sa.Integer(), nullable=True),
        sa.Column('updated', sa.DateTime(), nullable=True),
        sa.PrimaryKeyConstraint('_id')
    )
    op.create_table(
        'pools',
        sa.Column('poolname', sa.String(length=250), nullable=False),
        sa.Column('driver', sa.String(length=250), nullable=False),
        sa.Column('parameters', sa.Text(), nullable=False),
        sa.PrimaryKeyConstraint('poolname')
    )
    op.create_table(
        'priority_groups',
        sa.Column('name', sa.String(length=250), nullable=False),
        sa.PrimaryKeyConstraint('name')
    )
    op.create_table(
        'users',
        sa.Column('username', sa.String(length=250), nullable=False),
        sa.PrimaryKeyConstraint('username')
    )
    op.create_table(
        'sshkeys',
        sa.Column('keyname', sa.String(length=250), nullable=False),
        sa.Column('enabled', sa.Boolean(), nullable=True),
        sa.Column('ownername', sa.String(length=250), nullable=False),
        sa.Column('file', sa.String(length=250), nullable=False),
        sa.ForeignKeyConstraint(['ownername'], ['users.username'], ),
        sa.PrimaryKeyConstraint('keyname')
    )
    op.create_table(
        'guest_requests',
        sa.Column('guestname', sa.String(length=250), nullable=False),
        sa.Column('environment', sa.Text(), nullable=False),
        sa.Column('ownername', sa.String(length=250), nullable=False),
        sa.Column('priorityname', sa.String(length=250), nullable=True),
        sa.Column('poolname', sa.String(length=250), nullable=True),
        sa.Column('state', sa.String(length=250), nullable=False),
        sa.Column('address', sa.String(length=250), nullable=True),
        sa.Column('ssh_keyname', sa.String(length=250), nullable=False),
        sa.Column('ssh_port', sa.Integer(), nullable=False),
        sa.Column('ssh_username', sa.String(length=250), nullable=False),
        sa.Column('pool_data', sa.Text(), nullable=False),
        sa.ForeignKeyConstraint(['ownername'], ['users.username'], ),
        sa.ForeignKeyConstraint(['poolname'], ['pools.poolname'], ),
        sa.ForeignKeyConstraint(['priorityname'], ['priority_groups.name'], ),
        sa.ForeignKeyConstraint(['ssh_keyname'], ['sshkeys.keyname'], ),
        sa.PrimaryKeyConstraint('guestname')
    )
    op.create_table(
        'snapshot_requests',
        sa.Column('snapshotname', sa.String(length=250), nullable=False),
        sa.Column('guestname', sa.String(length=250), nullable=False),
        sa.Column('poolname', sa.String(length=250), nullable=True),
        sa.Column('state', sa.String(length=250), nullable=False),
        sa.Column('start_again', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['guestname'], ['guest_requests.guestname'], ),
        sa.ForeignKeyConstraint(['poolname'], ['pools.poolname'], ),
        sa.PrimaryKeyConstraint('snapshotname')
    )
    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('snapshot_requests')
    op.drop_table('guest_requests')
    op.drop_table('sshkeys')
    op.drop_table('users')
    op.drop_table('priority_groups')
    op.drop_table('pools')
    op.drop_table('metrics')
    op.drop_table('guest_events')
    # ### end Alembic commands ###