#!/usr/bin/env python3

import os
import shutil
import sys

from celery import Celery
from celery.bin.celery import main as celery_main
from selinon import Config

from artemis import get_logger


def create_app():
    conf = {
        'broker_url': os.getenv('ARTEMIS_BROKER_URL'),
        'result_backend': os.getenv('ARTEMIS_BACKEND_URL')
    }

    app = Celery('app')
    app.config_from_object(conf)

    # Set Selinon configuration.
    Config.set_config_yaml('nodes.yaml', ['flows.yaml'])

    # Prepare Celery
    Config.set_celery_app(app)

    return app


def main():
    _LOGGER = get_logger()

    # Config.set_config_yaml('nodes.yaml', ['flows.yaml'])

    SELINON_DISPATCHER = bool(int(os.getenv('SELINON_DISPATCHER', '0')))
    QUEUES = list(Config.dispatcher_queues.values() if SELINON_DISPATCHER else Config.task_queues.values())

    _LOGGER.info("Worker will listen on %r", QUEUES)

    celery_path = shutil.which('gunicorn')

    # Act like we would invoke celery directly from command line.
    sys.argv = [
        celery_path,
        'worker',
        '--broker', os.getenv('ARTEMIS_BROKER_URL'),
        '--app', 'artemis.celery:APP',
        '--loglevel', 'INFO',
        '--concurrency=1',
        '--queues', ','.join(QUEUES),
        '--prefetch-multiplier=128',
        '-Ofair',
        '--without-gossip',
        '--without-mingle',
        '--without-heartbeat',
        # '--no-color',
    ]

    celery_main()


if __name__ == '__main__':
    main()

else:
    APP = create_app()
