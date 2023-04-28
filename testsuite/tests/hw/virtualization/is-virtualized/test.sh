#!/bin/sh -eux

if [ "$(arch)" = "s390x" ]; then
    lshw
else
    dmidecode
fi

virt-what

if [ "$(arch)" = "aarch64" ]; then
    needles="kvm"
elif [ "$(arch)" = "s390x" ]; then
    needles="ibm_systemz-kvm"
elif [ "$(arch)" = "x86_64" ]; then
    needles="(kvm|xen|xen-hvm)"
fi

if [ "$EXPECTED" = "yes" ]; then
    virt-what | egrep "$needles" && exit 0
else
    virt-what | egrep -v "$needles" && exit 0
fi

exit 1
