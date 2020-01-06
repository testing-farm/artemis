#!/bin/sh -x

# activate virtualenv
. /APP/bin/activate

APP=$1

# set HOME to something writable
export HOME=/tmp

# add artemis user
cp /etc/passwd /tmp/passwd
echo "artemis:x:`id -u`:`id -g`:,,,:/tmp:/bin/sh" >> /tmp/passwd
cat /tmp/passwd > /etc/passwd
rm -f /tmp/passwd

[ -z "$APP" ] && { error "No application to run passed to entrypoint script"; exit 1; }

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
        exec dramatiq artemis.tasks
        ;;
    *)
        echo "Unknown application '$APP'"
        exit 1         
        ;;
esac
