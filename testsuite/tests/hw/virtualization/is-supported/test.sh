#!/bin/sh -eux

systemctl start libvirtd

arch

lscpu

if [ "$(arch)" = "s390x" ]; then
    lshw
else
    dmidecode
fi

virsh capabilities

if [ "$(arch)" = "x86_64" ]; then
    if [ "$EXPECTED" = "yes" ]; then
        grep -E 'svm|vmx' /proc/cpuinfo && exit 0
    else
        grep -E 'svm|vmx' /proc/cpuinfo || exit 0
    fi
fi

exit 1
