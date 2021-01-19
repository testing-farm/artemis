#!/bin/sh -x
# 
# Script waits for artemis api availability
#

error() { echo "$@"; exit 1; }

[ -z "$API_HOSTNAME" ] && error "API_HOSTNAME environment variable not set"
[ -z "$API_PORT" ] && error "API_PORT environment variable not set"
[ -z "$API_TIMEOUT" ] && API_TIMOEUT=10
[ -z "$WAIT_TIMEOUT" ] && WAIT_TIMEOUT=60
[ -z "$WAIT_TICK" ] && WAIT_TICK=1

time=0
until timeout $API_TIMEOUT curl -sf http://$API_HOSTNAME:$API_PORT/_docs
do
    time=$((time + WAIT_TICK))
    [ $time -ge $WAIT_TIMEOUT ] && error "Failed to wait for api to start"
    sleep $WAIT_TICK
done
