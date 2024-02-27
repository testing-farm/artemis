#!/bin/sh -eux

/usr/sbin/lszcrypt --verbose

/usr/sbin/lszcrypt | tail -n +3 | awk '{print $2}' | grep "$EXPECTED_ADAPTER"
/usr/sbin/lszcrypt | tail -n +3 | awk '{print $3}' | grep "$EXPECTED_MODE"
