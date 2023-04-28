#!/bin/sh -eux

hostname

hostname | egrep "${EXPECTED}"
