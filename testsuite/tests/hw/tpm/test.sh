#!/bin/sh -eux

ls -al /dev

if [ "$EXPECTED" = "1" ]; then
  [ -c /dev/tpm0 ] && [ ! -c /dev/tpmrm0 ] && exit 0

elif [ "$EXPECTED" = "2" ]; then
  [ -c /dev/tpm0 ] && [ -c /dev/tpmrm0 ] && exit 0

fi

exit 1
