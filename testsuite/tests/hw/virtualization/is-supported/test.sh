#!/bin/sh -eux

# Prove nested virtualization actually works: boot a throwaway VM that hard-requires
# KVM acceleration. Used for the x86_64 "yes" case, where Artemis provisions a
# nested-virt capable instance (C8i/M8i/R8i) with --cpu-options NestedVirtualization=enabled.
verify_nested_kvm() {
    modprobe kvm_intel 2>/dev/null || modprobe kvm_amd 2>/dev/null || true
    [ -e /dev/kvm ] || return 1
    virt-host-validate qemu | grep -i 'hardware virtualization' | grep -q PASS || return 1

    qemu=""
    for cand in qemu-system-x86_64 /usr/libexec/qemu-kvm qemu-kvm; do
        if command -v "$cand" >/dev/null 2>&1 || [ -x "$cand" ]; then
            qemu="$cand"
            break
        fi
    done
    [ -n "$qemu" ] || return 1

    img=/tmp/cirros-nested.img
    log=/tmp/nested-boot.log
    curl -fsSL -o "$img" \
        "https://download.cirros-cloud.net/0.6.2/cirros-0.6.2-x86_64-disk.img" || return 1

    timeout 120 "$qemu" \
        -enable-kvm -m 512 -nographic -serial mon:stdio \
        -drive file="$img",format=qcow2 >"$log" 2>&1 &
    qpid=$!

    booted=0
    i=0
    while [ "$i" -lt 100 ]; do
        if grep -qiE 'login:' "$log"; then
            booted=1
            break
        fi
        kill -0 "$qpid" 2>/dev/null || break
        sleep 1
        i=$((i + 1))
    done

    kill "$qpid" 2>/dev/null || true
    wait "$qpid" 2>/dev/null || true

    cat "$log"

    [ "$booted" -eq 1 ]
}

systemctl start libvirtd

arch

lscpu

if [ "$(arch)" = "s390x" ]; then
    lshw
else
    dmidecode
fi

virsh capabilities

if [ "$(arch)" = "aarch64" ]; then
    if [ "$EXPECTED" = "yes" ]; then
        virt-host-validate && exit 0
    else
        virt-host-validate || exit 0
    fi

elif [ "$(arch)" = "x86_64" ]; then
    if [ "$EXPECTED" = "yes" ]; then
        # CPU virtualization extension must be exposed to the guest, and KVM must
        # actually work (nested virtualization) - proven by booting a real VM.
        grep -E 'svm|vmx' /proc/cpuinfo && verify_nested_kvm && exit 0
    else
        grep -E 'svm|vmx' /proc/cpuinfo || exit 0
    fi
fi

exit 1
