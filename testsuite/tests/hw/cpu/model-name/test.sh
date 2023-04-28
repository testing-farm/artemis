#!/bin/sh -eux

lscpu

if [ "$(arch)" = "aarch64" ]; then
  lscpu -J | jq -r '.lscpu | .[] | select(.field == "BIOS Model name:") | .data' | egrep "$EXPECTED"
else
  lscpu -J | jq -r '.lscpu | .[] | select(.field == "Model name:") | .data' | egrep "$EXPECTED"
fi
