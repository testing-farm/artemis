#!/bin/sh -x

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

case $APP in
    api)
        exec artemis-api-server
        ;;
    dispatcher)
        exec artemis-dispatcher
        ;;
    initdb)
        exec artemis-init-postgres-schema
        ;;
    worker)
        expose_hooks
        exec dramatiq artemis.tasks
        ;;
    *)
        echo "Unknown application '$APP'"
        exit 1
        ;;
esac
