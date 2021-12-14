#!/bin/bash

set -x

if [ "$(readlink -f $(dirname 0))" != "$PWD" ]; then
    echo "This script must be run from project root"
    exit 1
fi

trap 'kill $(jobs -p)' EXIT

export ARTEMIS_CONFIG_DIR="${ARTEMIS_CONFIG_DIR:-$(pwd)/configuration}"
export ARTEMIS_BROKER_URL="${ARTEMIS_BROKER_URL:-amqp://guest:guest@127.0.0.1:5672/?heartbeat=60&blocked_connection_timeout=60}"
export ARTEMIS_DB_URL="${ARTEMIS_DB_URL:-postgresql://artemis:artemis@127.0.0.1:5432/artemis}"
export ARTEMIS_CACHE_URL="${ARTEMIS_CACHE_URL:-redis://127.0.0.1:6379}"
export ARTEMIS_VAULT_PASSWORD_FILE="${ARTEMIS_VAULT_PASSWORD_FILE:-$ARTEMIS_CONFIG_DIR/.vault_pass}"

export ARTEMIS_LOG_JSON="${ARTEMIS_LOG_JSON:-no}"
export ARTEMIS_LOG_DB_POOL="${ARTEMIS_LOG_DB_POOL:-no}"
export ARTEMIS_LOG_DB_QUERIES="${ARTEMIS_LOG_DB_QUERIES:-no}"
export ARTEMIS_CLOSE_AFTER_DISPATCH="${ARTEMIS_CLOSE_AFTER_DISPATCH:-yes}"
export ARTEMIS_HOOK_ROUTE="${ARTEMIS_HOOK_ROUTE:-$(pwd)/configuration/ARTEMIS_HOOK_ROUTE.py}"
export ARTEMIS_HOOK_BEAKER_ENVIRONMENT_TO_IMAGE="${ARTEMIS_HOOK_BEAKER_ENVIRONMENT_TO_IMAGE:-$ARTEMIS_CONFIG_DIR/ARTEMIS_HOOK_BEAKER_ENVIRONMENT_TO_IMAGE.py}"
export ARTEMIS_HOOK_OPENSTACK_ENVIRONMENT_TO_IMAGE="${ARTEMIS_HOOK_OPENSTACK_ENVIRONMENT_TO_IMAGE:-$ARTEMIS_CONFIG_DIR/ARTEMIS_HOOK_OPENSTACK_ENVIRONMENT_TO_IMAGE.py}"
export ARTEMIS_HOOK_AWS_ENVIRONMENT_TO_IMAGE="${ARTEMIS_HOOK_AWS_ENVIRONMENT_TO_IMAGE:-$ARTEMIS_CONFIG_DIR/ARTEMIS_HOOK_AWS_ENVIRONMENT_TO_IMAGE.py}"
export ARTEMIS_HOOK_AZURE_ENVIRONMENT_TO_IMAGE="${ARTEMIS_HOOK_AZURE_ENVIRONMENT_TO_IMAGE:-$ARTEMIS_CONFIG_DIR/ARTEMIS_HOOK_AZURE_ENVIRONMENT_TO_IMAGE.py}"
export ARTEMIS_HOOK_BEAKER_ENVIRONMENT_TO_IMAGE="${ARTEMIS_HOOK_BEAKER_ENVIRONMENT_TO_IMAGE:-$ARTEMIS_CONFIG_DIR/ARTEMIS_HOOK_BEAKER_ENVIRONMENT_TO_IMAGE.py}"

export dramatiq_queue_prefetch=1

ARTEMIS_WORKER_OPTIONS="${ARTEMIS_WORKER_OPTIONS:-}"

if [ "$ARTEMIS_WORKER_PROCESSES" != "" ]; then
    ARTEMIS_WORKER_OPTIONS="-p ${ARTEMIS_WORKER_PROCESSES} ${ARTEMIS_WORKER_OPTIONS}"
fi

if [ "$ARTEMIS_WORKER_THREADS" != "" ]; then
    ARTEMIS_WORKER_OPTIONS="-t ${ARTEMIS_WORKER_THREADS} ${ARTEMIS_WORKER_OPTIONS}"
fi

if [ "$ARTEMIS_WORKER_QUEUES" != "" ]; then
    ARTEMIS_WORKER_OPTIONS="-Q ${ARTEMIS_WORKER_QUEUES} ${ARTEMIS_WORKER_OPTIONS}"
fi

if [ "$SKIP_DB_INIT" = "" ]; then
    poetry run alembic upgrade head || { echo "failed to upgrade DB Schema"; exit 1; }
    poetry run artemis-db-init-content config-to-db || { echo "failed to initialize DB content"; exit 1; }

    if [ "$ONLY_DB_INIT" != "" ]; then
        exit 0
    fi
fi

poetry run artemis-api-server &
poetry run artemis-dispatcher &
poetry run dramatiq $ARTEMIS_WORKER_OPTIONS tft.artemis.tasks tft.artemis.tasks.route_guest_request &
poetry run periodiq tft.artemis.tasks &

sleep 100000
