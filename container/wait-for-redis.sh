#!/bin/sh -x
#
# Script waits for redis availability
#

error() { echo "$@"; exit 1; }

[ -z "$REDIS_HOSTNAME" ] && error "REDIS_HOSTNAME environment variable not set"
[ -z "$REDIS_PORT" ] && error "REDIS_PORT environment variable not set"
[ -z "$WAIT_TIMEOUT" ] && WAIT_TIMEOUT=60
[ -z "$WAIT_TICK" ] && WAIT_TICK=1

check_redis() {
    timeout 1 printf "PING\r\n" | nc -w 1 $REDIS_HOSTNAME $REDIS_PORT | grep -q PONG
    return $?
}

time=0
until check_redis; do
    time=$((time + WAIT_TICK))
    [ $time -ge $WAIT_TIMEOUT ] && error "Failed to wait for redis to start"
    sleep $WAIT_TICK
done
