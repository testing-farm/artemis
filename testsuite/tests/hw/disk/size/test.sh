#!/bin/sh -eux

fdisk -l

fdisk -l | egrep "Disk /dev/${EXPECTED_DEVICE}: ${EXPECTED_SIZE}"
