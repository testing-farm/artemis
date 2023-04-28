#!/bin/sh -eux

lscpu

sockets="$(lscpu -J | jq -r '.lscpu | .[] | select(.field == "Socket(s):") | .data')"
cores_per_socket="$(lscpu -J | jq -r '.lscpu | .[] | select(.field == "Core(s) per socket:") | .data')"

[ "$(( $sockets * $cores_per_socket ))" = "$EXPECTED" ] && exit 0
