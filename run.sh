#!/bin/bash

set -x

trap 'kill $(jobs -p)' EXIT

export ARTEMIS_CONFIG_DIR="$(pwd)/artemis-configuration"
export ARTEMIS_BROKER_URL="amqp://guest:guest@127.0.0.1:5672"
export ARTEMIS_DB_URL="sqlite:///test.db"
export ARTEMIS_VAULT_PASSWORD_FILE="$(pwd)/artemis-configuration/.vault_pass"

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

docker run --rm --hostname my-rabbit --name some-rabbit --publish 5672:5672 rabbitmq:3 &

# Wait for rabbitmq to become available
sleep 10

artemis-api-server &
artemis-dispatcher &
dramatiq ${ARTEMIS_WORKER_OPTIONS} artemis.tasks &

sleep 1000
