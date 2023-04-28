#!/bin/sh -eux

[ "$(cat /sys/devices/cpu/caps/pmu_name)" = "${EXPECTED}" ] && exit 0
