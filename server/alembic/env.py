# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import logging
from logging.config import fileConfig
from typing import Any, List

from alembic import context
from tft.artemis import db, get_db, get_logger

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

assert config is not None

# Interpret the config file for Python logging. This line sets up loggers basically.
#
# Sometimes we do not want env.py mess with the given configuration, hence the `None` test.
if config.config_file_name:
    fileConfig(config.config_file_name)

# add your model's MetaData object here
# for 'autogenerate' support
# from myapp import mymodel
# target_metadata = mymodel.Base.metadata
target_metadata = db.Base.metadata

# other values from the config, defined by the needs of env.py,
# can be acquired:
# my_important_option = config.get_main_option("my_important_option")
# ... etc.


def run_migrations_offline() -> None:
    """Run migrations in 'offline' mode.

    This configures the context with just a URL
    and not an Engine, though an Engine is acceptable
    here as well.  By skipping the Engine creation
    we don't even need a DBAPI to be available.

    Calls to context.execute() here emit the given string to the
    script output.

    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
    )

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    """Run migrations in 'online' mode.

    In this scenario we need to create an Engine
    and associate a connection with the context.

    """

    connectable = config.attributes.get('connectable', None) or get_db(get_logger()).engine

    # This trick should result in not generating a revision if there are no changes to schema.
    def process_revision_directives(context: str, revision: str, directives: List[Any]) -> None:
        assert config.cmd_opts

        if config.cmd_opts.autogenerate:
            script = directives[0]
            if script.upgrade_ops.is_empty():
                directives[:] = []
                logging.getLogger('alembic').info('No changes to schema detected')

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            process_revision_directives=process_revision_directives
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
