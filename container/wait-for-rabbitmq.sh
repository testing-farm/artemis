#!/bin/sh -x
# 
# Script waits for rabbitmq availability
#

error() { echo "$@"; exit 1; }

[ -z "$RABBITMQ_HOSTNAME" ] && error "RABBITMQ_HOSTNAME environment variable not set"
[ -z "$RABBITMQ_PORT" ] && error "RABBITMQ_PORT environment variable not set"
[ -z "$WAIT_TIMEOUT" ] && WAIT_TIMEOUT=60
[ -z "$WAIT_TICK" ] && WAIT_TICK=1

time=0
until timeout 1 curl --http0.9 -so - $RABBITMQ_HOSTNAME:$RABBITMQ_PORT | grep -q AMQP
do
    time=$((time + WAIT_TICK))
    [ $time -ge $WAIT_TIMEOUT ] && error "Failed to wait for rabbitmq to start"
    sleep $WAIT_TICK
done
