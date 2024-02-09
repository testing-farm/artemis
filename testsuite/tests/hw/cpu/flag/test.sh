#!/bin/sh -eux

lscpu

lscpu -J | jq -r '.lscpu | .[] | select(.field == "Flags:") | .data' | tr ' ' '\n' | sort | grep "$EXPECTED" || exit 1
