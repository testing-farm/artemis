#!/bin/sh -eux

arch

lscpu

# The `ld.so --help` command is available in RHEL-8 like distriubution and higher
os_major_version=$(grep 'VERSION_ID=' /etc/os-release | awk -F '[^0-9]+' '{ print $2 }')
[ "$os_major_version" -ge 8 ] && ld.so --help

case "$(arch)" in
    "s390x")
        machine_type=$(lscpu | grep 'Machine type:' | awk '{print $3}')
        all=($EXP_S390x)
        for i in "${all[@]}" ; do
            [ "$i" = "${machine_type}" ] && exit 0
        done
        exit 1
        ;;
    "ppc64le")
        model_name=$(lscpu | grep "Model name:" | awk '{print $3}')
        all=($EXP_PPC64LE)
        for i in "${all[@]}" ; do
            [ "$i" = "${model_name}" ] && exit 0
        done
        exit 1
        ;;
    "x86_64")
        # When the `EXP_x86_64` envar is empty, no special requirement is needed, compatibility is implicit
        [ -z $EXP_x86_64 ] && exit 0

        # Taken from: https://unix.stackexchange.com/questions/631217/how-do-i-check-if-my-cpu-supports-x86-64-v2
        flags=$(cat /proc/cpuinfo | grep flags | head -n 1 | cut -d: -f2)
        case "$EXP_x86_64" in
            "x86-64-v2")
                support='awk "/cx16/&&/lahf/&&/popcnt/&&/sse4_1/&&/sse4_2/&&/ssse3/ {found=1} END {exit !found}"'
                ;;
            "x86-64-v3")
                support='awk "/avx/&&/avx2/&&/bmi1/&&/bmi2/&&/f16c/&&/fma/&&/abm/&&/movbe/&&/xsave/ {found=1} END {exit !found}"'
                ;;
            "x86-64-v4")
                support='awk "/avx512f/&&/avx512bw/&&/avx512cd/&&/avx512dq/&&/avx512vl/ {found=1} END {exit !found}"'
                ;;
            *)
                echo "unsupported test case"
                exit 1
                ;;
        esac
        echo "$flags" | eval $support && exit 0
        exit 1
        ;;
    "aarch64")
        # When the `EXP_AARCH_64` envar is empty, no special requirement is needed, compatibility is implicit
        [ -z $EXP_AARCH_64 ] && exit 0
        ;;
    *)
        echo "arch not supported for this test case"
        exit 1
esac
