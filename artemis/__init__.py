import argparse
import logging
import sys

import gluetool

import artemis.keys
import artemis.script
import artemis.vault


def _parse_args():
    # type: () -> argparse.Namespace

    parser = argparse.ArgumentParser()

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
    key_store = artemis.keys.KeyStore(vault)  # noqa

    logger.info('Started & running...')
    logger.info('... and we are done.')

    return 0


if __name__ == '__main__':
    sys.exit(main())
