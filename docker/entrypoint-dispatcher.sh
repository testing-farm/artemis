#!/bin/bash

set -x

. /APP/bin/activate

# Give broker time to boot up.
# Not a proper solution, we need somethign more sophisticated - wrapper checking the availability of the broker,
# or Artemis should check that on its own, because broker might be restarted and become unavailable temporarily.
sleep 5

exec artemis-dispatcher
