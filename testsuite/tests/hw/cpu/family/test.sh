#!/bin/sh -eux

lscpu

[ "$(lscpu -J | jq -r '.lscpu | .[] | select(.field == "CPU family:") | .data')" = "${EXPECTED}" ] && exit 0
