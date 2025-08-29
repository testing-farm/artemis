# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Drop snapshots table

Revision ID: b9963fb2b987
Revises: d4a6a1fb98fe
Create Date: 2025-08-29 10:06:25.701218

"""

from typing import Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

from tft.artemis.db import swap_enums

# revision identifiers, used by Alembic.
revision = 'b9963fb2b987'
down_revision = 'd4a6a1fb98fe'
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
            'SHELVED',
            name=name,
            create_type=False,
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
        'SHELVED',
        name=name,
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
            'SHELF_LOOKUP',
            name=name,
            create_type=False,
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
        'SHELF_LOOKUP',
        name=name,
    )


def upgrade() -> None:
    op.drop_table('snapshot_requests')

    swap_enums(
        op,
        'guest_requests',
        'state',
        'gueststate',
        'SHELF_LOOKUP',
        get_new_enum,
    )


def downgrade() -> None:
    swap_enums(
        op,
        'guest_requests',
        'state',
        'gueststate',
        'SHELF_LOOKUP',
        get_old_enum,
    )

    op.create_table(
        'snapshot_requests',
        sa.Column('snapshotname', sa.VARCHAR(length=250), nullable=False),
        sa.Column('guestname', sa.VARCHAR(length=250), nullable=False),
        sa.Column('poolname', sa.VARCHAR(length=250), nullable=True),
        sa.Column('state', sa.VARCHAR(length=250), nullable=False),
        sa.Column('start_again', sa.BOOLEAN(), nullable=False),
        sa.ForeignKeyConstraint(
            ['guestname'],
            ['guest_requests.guestname'],
        ),
        sa.ForeignKeyConstraint(
            ['poolname'],
            ['pools.poolname'],
        ),
        sa.PrimaryKeyConstraint('snapshotname'),
    )
