#!/bin/bash

set -x

trap 'kill $(jobs -p)' EXIT

export ARTEMIS_CONFIG_DIR="$(pwd)/configuration"
export ARTEMIS_BROKER_URL="amqp://guest:guest@127.0.0.1:5672"
export ARTEMIS_BACKEND_URL="redis://127.0.0.1:6379/0"
# export ARTEMIS_DB_URL="sqlite:///test.db"
export ARTEMIS_DB_URL="postgresql://artemis:artemis@127.0.0.1:5432/artemis"
export ARTEMIS_VAULT_PASSWORD_FILE="$(pwd)/configuration/.vault_pass"

export ARTEMIS_LOG_JSON=no
export ARTEMIS_LOG_DB_POOL=
export ARTEMIS_LOG_DB_QUERIES=debug
export ARTEMIS_HOOK_ROUTE="$(pwd)/configuration/ARTEMIS_HOOK_ROUTE.py"
export ARTEMIS_HOOK_OPENSTACK_ENVIRONMENT_TO_IMAGE="$(pwd)/configuration/ARTEMIS_HOOK_OPENSTACK_ENVIRONMENT_TO_IMAGE.py"
export ARTEMIS_HOOK_AWS_ENVIRONMENT_TO_IMAGE="$(pwd)/configuration/ARTEMIS_HOOK_AWS_ENVIRONMENT_TO_IMAGE.py"

ARTEMIS_WORKER_OPTIONS="${ARTEMIS_WORKER_OPTIONS:-}"

if [ "$ARTEMIS_WORKER_PROCESSES" != "" ]; then
    ARTEMIS_WORKER_OPTIONS="-p ${ARTEMIS_WORKER_PROCESSES} ${ARTEMIS_WORKER_OPTIONS}"
fi

if [ "$ARTEMIS_WORKER_THREADS" != "" ]; then
    ARTEMIS_WORKER_OPTIONS="-t ${ARTEMIS_WORKER_THREADS} ${ARTEMIS_WORKER_OPTIONS}"
fi

if [ "$ARTEMIS_WORKER_QUEUES" != "" ]; then
    ARTEMIS_WORKER_OPTIONS="-Q \"${ARTEMIS_WORKER_QUEUES}\" ${ARTEMIS_WORKER_OPTIONS}"
fi

artemis-init-postgres-schema

artemis-api-server &
artemis-dispatcher &
dramatiq $ARTEMIS_WORKER_OPTIONS artemis.tasks &

sleep 100000
