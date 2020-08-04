#!/bin/sh -x

terminate() {
    # Optional terminate command. Can be used to wait for specific conditions when the container should finish.
    if [ -n "TERMINATE_COMMAND" ]; then
        $TERMINATE_COMMAND
    fi

    # no pid means we failed too early
    if [ -n "$PID" ]; then
        echo "Skipping termination, entrypoint failed too early"
        return
    fi

    echo "Terminating application"
    kill -TERM $PID
}

# Trap is needed to correctly propagate SIGTERM from container
trap terminate TERM INT

# activate virtualenv
. /APP/bin/activate

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
        artemis-api-server &
        ;;
    dispatcher)
        artemis-dispatcher &
        ;;
    initdb)
        artemis-init-postgres-schema &
        ;;
    worker)
        expose_hooks
        dramatiq $ARTEMIS_WORKER_OPTIONS artemis.tasks &
        ;;
    *)
        echo "Unknown application '$APP'"
        exit 1
        ;;
esac

PID=$!
wait $PID
