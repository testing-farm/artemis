# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os.path
import sys
from typing import Any, Dict, List, cast

import click
import gluetool.log
from gluetool.result import Error, Ok, Result

from .. import Failure, get_config, get_db, get_logger, load_validation_schema, validate_data
from ..db import DB, GuestTag, Pool, PriorityGroup, SSHKey, User, UserRoles, upsert
from ..drivers import GuestTagsType


def validate_config(
    logger: gluetool.log.ContextAdapter,
    server_config: Dict[str, Any]
) -> Result[List[str], Failure]:
    """
    Validate a server configuration data using a JSON schema.

    :return: either a list of validation errors, or a :py:class:`Failure` describing problem preventing
        the validation process.
    """

    # In this list we will accumulate all validation errors reported by `validate_data`.
    validation_errors: List[str] = []

    # First the overall server and common configuration
    r_schema = load_validation_schema('common.yml')

    if r_schema.is_error:
        return Error(r_schema.unwrap_error())

    r_validation = validate_data(server_config, r_schema.unwrap())

    if r_validation.is_error:
        return Error(r_validation.unwrap_error())

    validation_errors += [
        f'server: {error}'
        for error in r_validation.unwrap()
    ]

    for pool in server_config.get('pools', []):
        failure_details = {
            'pool': pool.get('name'),
            'pool_driver': pool.get('driver')
        }

        r_schema = load_validation_schema(os.path.join('drivers', pool.get('driver', '') + '.yml'))

        if r_schema.is_error:
            r_schema.unwrap_error().details.update(failure_details)

            return Error(r_schema.unwrap_error())

        r_validation = validate_data(pool.get('parameters'), r_schema.unwrap())

        if r_validation.is_error:
            r_validation.unwrap_error().details.update(failure_details)

            return r_validation

        validation_errors += [
            f'pool "{pool.get("name")}": {error}'
            for error in r_validation.unwrap()
        ]

    return Ok(validation_errors)


def config_to_db(
    logger: gluetool.log.ContextAdapter,
    db: DB,
    server_config: Dict[str, Any]
) -> None:
    # Note: the current approach of "init schema" is crappy, it basically either succeeds or fails at
    # the first conflict, skipping the rest. To avoid collisions, it must be refactored, and sooner
    # or later CLI will take over once we get full support for user accounts.
    #
    # When adding new bits, let's use a safer approach and test before adding possibly already existing
    # records.
    # Adding system and pool tags. We do not want to overwrite the existing value, only add those
    # that are missing. Artemis' default example of configuration tries to add as little as possible,
    # which means we probably don't return any tag user might have removed.

    r_validation = validate_config(logger, server_config)

    if r_validation.is_error:
        r_validation.unwrap_error().handle(logger)

        sys.exit(1)

    validation_errors = r_validation.unwrap()

    if validation_errors:
        gluetool.log.log_dict(
            logger.error,
            'configuration schema validation failed',
            validation_errors
        )

        sys.exit(1)

    with db.get_session() as session:
        def _add_tags(poolname: str, input_tags: GuestTagsType) -> None:
            for tag, value in input_tags.items():
                logger.info(f'  Adding {tag}={value}')

                r = upsert(
                    logger,
                    session,
                    GuestTag,
                    {
                        GuestTag.poolname: poolname,
                        GuestTag.tag: tag
                    },
                    insert_data={
                        GuestTag.value: value
                    },
                    update_data={
                        'value': value
                    }
                )

                assert r.is_ok and r.unwrap() is True, 'Failed to initialize guest tag record'

        # Add system-level tags
        logger.info('Adding system-level guest tags')

        _add_tags(GuestTag.SYSTEM_POOL_ALIAS, cast(GuestTagsType, server_config.get('guest_tags', {})))

        # Add pool-level tags
        for pool_config in server_config.get('pools', []):
            poolname: str = pool_config['name']

            logger.info(f'Adding pool-level guest tags for pool {poolname}')

            _add_tags(poolname, cast(GuestTagsType, pool_config.get('guest_tags', {})))

        logger.info('Adding priority groups')

        for priority_group_config in server_config.get('priority-groups', []):
            logger.info(f'  Adding priority group "{priority_group_config["name"]}"')

            r = upsert(
                logger,
                session,
                PriorityGroup,
                {
                    PriorityGroup.name: priority_group_config['name']
                },
                # TODO: `ON CONFLICT DO NOTHING` UPSERT makes the mess out of expected rows, both 0 and 1 are valid.
                expected_records=(0, 1)
            )

            assert r.is_ok and r.unwrap() is True, 'Failed to initialize priority group record'

        logger.info('Adding pools')

        # TODO: Azure driver can't guarantee proper authentication in case of more than one Azure pools, so need to
        # warn the user about this.
        azure_pools = 0

        for pool_config in server_config.get('pools', []):
            poolname = pool_config['name']

            logger.info(f'  Adding pool "{poolname}"')

            pool_parameters = pool_config.get('parameters', {})

            if pool_config['driver'] == 'openstack':
                if 'project-domain-name' in pool_parameters and 'project-domain-id' in pool_parameters:
                    Failure(
                        f'Pool "{poolname}" uses both project-domain-name and project-domain-id, name will be used'
                    ).handle(logger)

            elif pool_config['driver'] == 'azure':
                azure_pools += 1

            r = upsert(
                logger,
                session,
                Pool,
                {
                    Pool.poolname: poolname
                },
                insert_data={
                    Pool.driver: pool_config['driver'],
                    Pool._parameters: pool_parameters
                },
                update_data={
                    '_parameters': pool_parameters
                }
            )

            assert r.is_ok and r.unwrap() is True, 'Failed to initialize pool record'

        if azure_pools > 1:
            Failure('Multiple Azure pools are not supported at the moment, authentication may fail.').handle(logger)

        # Insert our bootstrap users.
        def _add_user(username: str, role: UserRoles) -> None:
            logger.info(f'Adding user "{username}" with role "{role.name}"')

            # TODO: must handle case when the user exists, since we basically overwrite the tokens...
            admin_token, admin_token_hash = User.generate_token()
            provisioning_token, provisioning_token_hash = User.generate_token()

            r = upsert(
                logger,
                session,
                User,
                {
                    User.username: username
                },
                insert_data={
                    User.admin_token: admin_token_hash,
                    User.provisioning_token: provisioning_token_hash
                },
                # TODO: `ON CONFLICT DO NOTHING` UPSERT makes the mess out of expected rows, both 0 and 1 are valid.
                expected_records=(0, 1)
            )

            assert r.is_ok and r.unwrap() is True, 'Failed to initialize user record'

#            if r.unwrap() is True:
#                logger.info('Default admin token for user "{}" is "{}"'.format(username, admin_token))
#                logger.info('Default provisioning token for user "{}" is "{}"'.format(username, provisioning_token))

        # In one of the future patches, this will get few changes:
        #
        # * create just the admin user - artemis-cli should be used to create other users
        # * accept username and token from env variables, instead of the config file
        for user_config in server_config.get('users', []):
            username = user_config['name']

            if 'role' in user_config:
                try:
                    role = UserRoles[user_config['role'].upper()]

                except KeyError:
                    raise Exception(f'Unknown role "{user_config["role"]}" of user "{username}"')

            else:
                role = UserRoles.USER

            _add_user(username, role)

        for key_config in server_config.get('ssh-keys', []):
            logger.info(f'Adding SSH key "{key_config["name"]}", owner by {key_config["owner"]}')

            # Private key *must* end with a new-line character. Make sure there's
            # exactly one.
            private = key_config['private'].strip() + '\n'

            r = upsert(
                logger,
                session,
                SSHKey,
                {
                    SSHKey.keyname: key_config['name']
                },
                insert_data={
                    SSHKey.enabled: True,
                    SSHKey.ownername: key_config['owner'],
                    SSHKey.private: private,
                    SSHKey.public: key_config['public'].strip(),
                    # When adding new key, leave `file` column empty - it will be dropped in the future,
                    # and we do not have any usable value for it.
                    SSHKey.file: ''

                },
                update_data={
                    # But, when *updating* the key, do not touch the `file` column - we do not want to overwrite.
                    # With `file` preserved, a downgrade to older Artemis should work, because those versions
                    # worked with keys in extra files, and we keep that information safe. We just don't have it
                    # for any *new* keys...
                    'private': private,
                    'public': key_config['public'].strip()
                }
            )

            assert r.is_ok and r.unwrap() is True, 'Failed to initialize SSH key record'


@click.group()
@click.pass_context
def cmd_root(ctx: Any) -> None:
    pass


@cmd_root.command(
    name='config-to-db',
    help='Write the given configuration into DB. Obeys all environment variables.'
)
@click.pass_context
def cmd_config_to_db(ctx: Any) -> None:
    logger = get_logger()
    server_config = get_config()
    db = get_db(logger)

    config_to_db(logger, db, server_config)


@cmd_root.command(
    name='validate-config',
    help='Validate the given configuration, without changing the DB. Obeys all environment variables.'
)
@click.pass_context
def cmd_validate_config(ctx: Any) -> None:
    logger = get_logger()
    server_config = get_config()

    r_validation = validate_config(logger, server_config)

    if r_validation.is_error:
        r_validation.unwrap_error().handle(logger)

        sys.exit(1)

    validation_errors = r_validation.unwrap()

    if validation_errors:
        logger.error('Validation failed!')

        for error in validation_errors:
            logger.error(f'* {error}')

        sys.exit(1)

    logger.info('Configuration is safe!')


if __name__ == '__main__':
    cmd_root()
