#!/bin/sh -eux

lscpu

cpus="$(lscpu -J | jq -r '.lscpu | .[] | select(.field == "CPU(s):") | .data')"

[ "$cpus" = "$EXPECTED" ] && exit 0
