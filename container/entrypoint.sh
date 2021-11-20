#!/bin/sh -x

terminate() {
    # optional terminate command, can be used to wait for specific conditions when the container should finish
    if [ -n "TERMINATE_COMMAND" ]; then
        $TERMINATE_COMMAND
    fi

    # no pid means we failed too early
    if [ -z "$PID" ]; then
        echo "Skipping termination, entrypoint failed too early"
        return
    fi

    echo "Terminating application"
    kill -TERM $PID

    # wait for the application to terminate
    wait $PID
}

# trap is needed to correctly propagate SIGTERM from container
trap terminate TERM INT

# name of the Artemis application to start
APP=$1

# helpers
error() { echo "Error: $@"; exit 1; }

# set HOME to something writable
export HOME=/tmp

# add artemis user
cp /etc/passwd /tmp/passwd
echo "artemis:x:`id -u`:`id -g`:,,,:/tmp:/bin/sh" >> /tmp/passwd
cat /tmp/passwd > /etc/passwd
rm -f /tmp/passwd

[ -z "$APP" ] && { error "No application to run passed to entrypoint script"; exit 1; }

expose_hooks() {
    # check if all required hooks are available in configuration and expose them in the environment
    for HOOK in $(cat /required_hooks); do
        HOOK_PATH=${ARTEMIS_CONFIG_DIR}/${HOOK}.py
        # Hook file is named after the environment variable
        if [ ! -e "$HOOK_PATH" ]; then
            error "Could not find hook '$HOOK' script in Artemis configuration '$HOOK_PATH'"
        fi
        eval "export $HOOK=$HOOK_PATH"
    done
}

# This is an important setting: do not allow Dramatiq to fetch more messages than needed. Fetch new message
# once task is done and completed, avoid pre-fetching multiple messages at once. Pre-fetching messes with
# priorities, and may lead to lost messages (although only in some very rare conditions).
# TODO: make this controllable via ARTEMIS_* variable.
export dramatiq_queue_prefetch=1

ARTEMIS_CONTAINER_LOG_METHOD="${ARTEMIS_CONTAINER_LOG_METHOD:-file}"
ARTEMIS_CONTAINER_LOG_PROMTAIL_CONFIG_FILEPATH="${ARTEMIS_CONTAINER_LOG_PROMTAIL_CONFIG_FILEPATH:-/promtail-config/promtail.yaml}"
ARTEMIS_CONTAINER_LOG_PROMTAIL_OPTIONS="${ARTEMIS_CONTAINER_LOG_PROMTAIL_OPTIONS:-}"

ARTEMIS_WORKER_OPTIONS="${ARTEMIS_WORKER_OPTIONS:-}"

if [ -z "$ARTEMIS_DB_URL" ]; then
    export ARTEMIS_DB_URL="${ARTEMIS_DB_PROTOCOL}://${ARTEMIS_DB_USERNAME}:${ARTEMIS_DB_PASSWORD}@${ARTEMIS_DB_HOST}/${ARTEMIS_DB_DATABASE}"
fi

if [ -z "$ARTEMIS_BROKER_URL" ]; then
    export ARTEMIS_BROKER_URL="${ARTEMIS_BROKER_PROTOCOL}://${ARTEMIS_BROKER_USERNAME}:${ARTEMIS_BROKER_PASSWORD}@${ARTEMIS_BROKER_HOST}"
fi

if [ "$ARTEMIS_WORKER_PROCESSES" != "" ]; then
    ARTEMIS_WORKER_OPTIONS="-p ${ARTEMIS_WORKER_PROCESSES} ${ARTEMIS_WORKER_OPTIONS}"
fi

if [ "$ARTEMIS_WORKER_THREADS" != "" ]; then
    ARTEMIS_WORKER_OPTIONS="-t ${ARTEMIS_WORKER_THREADS} ${ARTEMIS_WORKER_OPTIONS}"
fi

if [ "$ARTEMIS_WORKER_QUEUES" != "" ]; then
    ARTEMIS_WORKER_OPTIONS="-Q ${ARTEMIS_WORKER_QUEUES} ${ARTEMIS_WORKER_OPTIONS}"
fi

cd /APP

case $APP in
    api)
        COMMAND="poetry run artemis-api-server"
        ;;
    dispatcher)
        COMMAND="poetry run artemis-dispatcher"
        ;;
    initdb)
        # Initialize or upgrade the database to the latest version
        poetry run alembic upgrade head || { echo "failed to upgrade DB Schema"; exit 1; }
        # Initialize records from server.yml
        poetry run artemis-db-init-content config-to-db || { echo "failed to initialize DB content"; exit 1; }
        exit 0
        ;;
    scheduler)
        expose_hooks
        COMMAND="poetry run periodiq tft.artemis.tasks"
        ;;
    worker)
        expose_hooks
        COMMAND="poetry run dramatiq $ARTEMIS_WORKER_OPTIONS tft.artemis.tasks tft.artemis.tasks.route_guest_request"
        ;;
    *)
        echo "Unknown application '$APP'"
        exit 1
        ;;
esac

# We run the command in background to get his PID which is used to properly
# terminate it with SIGTERM signal.

if [ "$ARTEMIS_CONTAINER_LOG_METHOD" = "stdout" ]; then
    # Logs are streamed irectly to stdout/stderr.
    $COMMAND &
    PID=$!

elif [ "$ARTEMIS_CONTAINER_LOG_METHOD" = "file" ]; then
    # Logs from each application are logged in a separate timestamped file. Hostname helps
    # to identify the pod which run it.
    [ -z "$ARTEMIS_LOG_DIR" ] && ARTEMIS_LOG_DIR=$(mktemp -d)
    LOG_FILE="$ARTEMIS_LOG_DIR/$(date -u '+%Y-%m-%d_%H:%M:%S')_$(hostname).log"
    echo "Logging to '$LOG_FILE'"

    $COMMAND &>$LOG_FILE &
    PID=$!

    # Show logs from log file, retry until the log file appears (we run it as subprocess) ...
    tail -F $LOG_FILE &

elif [ "$ARTEMIS_CONTAINER_LOG_METHOD" = "promtail-pipe" ]; then
    # Logs from each application are piped to a promtail process. Requires a promtail config file, the path is
    # provided by $ARTEMIS_CONTAINER_LOG_PROMTAIL_CONFIG_FILEPATH variable.

    mkfifo /tmp/command-logging

    $COMMAND > /tmp/command-logging 2>&1 &
    PID=$!

    cat /tmp/command-logging | /usr/bin/promtail --stdin --config.file "$ARTEMIS_CONTAINER_LOG_PROMTAIL_CONFIG_FILEPATH" ${ARTEMIS_CONTAINER_LOG_PROMTAIL_OPTIONS} &

fi

wait $PID
