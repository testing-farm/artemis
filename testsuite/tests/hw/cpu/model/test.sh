#!/bin/sh -eux

lscpu

[ "$(lscpu -J | jq -r '.lscpu | .[] | select(.field == "Model:") | .data')" = "${EXPECTED}" ] && exit 0
