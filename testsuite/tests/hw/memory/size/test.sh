#!/bin/sh -eux

cat /proc/meminfo
dmidecode

dmidecode -t 16 | egrep "Maximum Capacity: ${EXPECTED}"
