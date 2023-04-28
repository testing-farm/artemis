#!/bin/sh -eux


if [ "$EXPECTED_METHOD" = "uefi" ]; then
    ls -al /sys/firmware/efi
else
    [ ! -d "/sys/firmware/efi" ] || exit 1
fi
