#!/bin/sh -eux

if [ "$(arch)" = "s390x" ]; then
    lshw
else
    dmidecode
fi

virt-what

if [ "$EXPECTED" = "KVM" ]; then
    needle="kvm"
elif [ "$EXPECTED" = "Nitro" ]; then
    # TODO: nitro is based on KVM, and reports as KVM...
    needle="does-not-exist"
elif [ "$EXPECTED" = "Xen" ]; then
    needle="xen"
fi

virt-what | egrep "$needle" && exit 0

exit 1
