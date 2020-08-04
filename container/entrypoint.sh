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
}

# trap is needed to correctly propagate SIGTERM from container
trap terminate TERM INT

# activate virtualenv
. /APP/bin/activate

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

case $APP in
    api)
        COMMAND="artemis-api-server"
        ;;
    dispatcher)
        COMMAND="artemis-dispatcher"
        ;;
    initdb)
        # Ignore any errors for now here, we run the schema initialization at each API initialization.
        # We will soon replace this with alembic.
        artemis-init-postgres-schema
        exit 0
        ;;
    worker)
        expose_hooks
        COMMAND="dramatiq $ARTEMIS_WORKER_OPTIONS artemis.tasks"
        ;;
    *)
        echo "Unknown application '$APP'"
        exit 1
        ;;
esac

# Logs from each application are logged in a separate timestamped file. Hostname helps
# to identify the pod which run it.
[ -z "$ARTEMIS_LOG_DIR" ] && ARTEMIS_LOG_DIR=$(mktemp -d)
LOG_FILE="$ARTEMIS_LOG_DIR/$(date -u '+%Y-%m-%d_%H:%M:%S')_$(hostname).log"
echo "Logging to '$LOG_FILE'"

# We run the command in background to get his PID which is used to properly
# terminate it with SIGTERM signal.
$COMMAND &>$LOG_FILE &
PID=$!

# Show logs from log file, retry until the log file appears (we run it as subprocess) ...
tail -F $LOG_FILE &

wait $PID
