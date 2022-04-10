# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Convert SSH keys to use encrypted columns

Revision ID: 5b43d515411a
Revises: 97d761c531e7
Create Date: 2021-09-10 16:22:29.231313

"""
import sqlalchemy as sa
from sqlalchemy_utils import EncryptedType
from sqlalchemy_utils.types.encrypted.encrypted_type import AesEngine

from alembic import op
from tft.artemis.knobs import get_vault_password

# revision identifiers, used by Alembic.
revision = '5b43d515411a'
down_revision = '28e90f8952e9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('sshkeys', schema=None) as batch_op:
        batch_op.add_column(sa.Column(
            'private',
            EncryptedType(sa.String, get_vault_password(), AesEngine, 'pkcs5'),
            nullable=False,
            server_default=''
        ))
        batch_op.add_column(sa.Column(
            'public',
            EncryptedType(sa.String, get_vault_password(), AesEngine, 'pkcs5'),
            nullable=False,
            server_default=''
        ))

    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('sshkeys', schema=None) as batch_op:
        batch_op.drop_column('public')
        batch_op.drop_column('private')

    # ### end Alembic commands ###
