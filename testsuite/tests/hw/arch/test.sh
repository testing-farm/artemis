#!/bin/sh -eux

arch

[ "$(arch)" = "${EXPECTED}" ] && exit 0
