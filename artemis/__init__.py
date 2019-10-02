import argparse
import logging
import os
import sys

import gluetool

import artemis.drivers.openstack
import artemis.keys
import artemis.script
import artemis.vault


POOL_DRIVERS = {
    'openstack': artemis.drivers.openstack.OpenStackDriver
}


def _parse_args():
    # type: () -> argparse.Namespace

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '--config-dir',
        action='store',
        type=str,
        metavar='DIR',
        required=True
    )

    parser.add_argument(
        '--vault-password-file',
        action='store',
        type=str,
        metavar='FILE',
        required=True
    )

    return parser.parse_args(sys.argv[1:])


def main():
    # type: () -> int

    # hic sunt API server kick off

    options = _parse_args()

    logger = gluetool.log.Logging.setup_logger(
        level=logging.INFO
    )

    with open(options.vault_password_file, 'r') as f:
        vault = artemis.vault.Vault(f.read())

    script_engine = artemis.script.ScriptEngine()  # noqa
    key_store = artemis.keys.KeyStore(vault, os.path.join(options.config_dir, 'keys'))  # noqa

    pools = {}  # Dict[str, artemis.pools.PoolDriver]

    server_config = gluetool.utils.load_yaml(os.path.join(options.config_dir, 'server.yml'), logger=logger)

    for pool_config in server_config['pools']:
        pool_name = pool_config.pop('name')
        pool_driver_class = POOL_DRIVERS[pool_config.pop('driver')]

        pools[pool_name] = pool_driver_class(server_config, pool_config['parameters'])

    logger.info('Started & running...')

    result = pools['baseosci-openstack'].acquire_guest(
        artemis.environment.Environment(arch='x86_64', compose='foo'),
        key_store.get_key('artemis', 'master-key')
    )

    if result.is_error:
        logger.error('Failed to provision: {}'.format(result.error))

    else:
        guest = result.unwrap()

        logger.info('Provisioned a guest!')
        logger.info('{}'.format(guest))

        release_result = pools['baseosci-openstack'].release_guest(guest)

        if release_result.is_error:
            logger.error('Failed to release: {}'.format(release_result.error))

        else:
            logger.info('Guest released!')

    logger.info('... and we are done.')

    return 0


if __name__ == '__main__':
    sys.exit(main())
