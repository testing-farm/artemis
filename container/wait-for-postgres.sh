#!/bin/sh -x
# 
# Script waits for postgresql server availability
#

error() { echo "$@"; exit 1; }

[ -z "$POSTGRESQL_HOSTNAME" ] && error "POSTGRESQL_HOSTNAME environment variable not set"
[ -z "$POSTGRESQL_PORT" ] && error "POSTGRESQL_PORT environment variable not set"
[ -z "$POSTGRESQL_USER" ] && error "POSTGRESQL_USER environment variable not set"
[ -z "$POSTGRESQL_PASSWORD" ] && error "POSTGRESQL_PASSWORD environment variable not set"
[ -z "$WAIT_TIMEOUT" ] && WAIT_TIMEOUT=60
[ -z "$WAIT_TICK" ] && WAIT_TICK=1

check_postgres() {
    PGPASSWORD=$POSTGRESQL_PASSWORD timeout 1 psql -h $POSTGRESQL_HOSTNAME -p $POSTGRESQL_PORT -U $POSTGRESQL_USER -c '\conninfo'
    return $?
}

time=0
until check_postgres; do
    time=$((time + WAIT_TICK))
    [ $time -ge $WAIT_TIMEOUT ] && error "Failed to wait for postrgres to start"
    sleep $WAIT_TICK
done
