#!/bin/sh -eux

ip link

[ "$(ip link | grep -E "[[:digit:]]: $TYPE" | wc -l)" = "$EXPECTED" ] && exit 0

exit 1
