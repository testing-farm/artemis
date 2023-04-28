#!/bin/sh -eux


case $KICKSTART in
    "basic")
        # Verify that the 'ksuser' was created with custom home directory name.
        cat /etc/passwd
        grep "ksuser" /etc/passwd || exit 1
        [ -d "/home/ksuser_homedir" ] || exit 1

        # Verify that the 'bind-utils' package is installed.
        rpm -q bind-utils || exit 1

        # Verify that the '%post' section happened according to the kickstart specification.
        grep "post-install script output" /var/log/kickstart_post.log || exit 1
        ;;
    "partitioning")
        free -m

        df -TB1

        # Verify the '/boot' partition
        file_system=$(df --output=fstype /boot | tail -n1)
        partition_size=$(df -B1 --output=size /boot | tail -n1)
        [ $file_system == "ext4" ] || exit 1
        # The actual size may differ. Check if the partition size is in the range of <500 MB, 520 MB>.
        # Note: sizes in condition are in Bytes.
        if (($partition_size < 500000000 || $partition_size > 520000000)); then
            echo "$partition_size is outside the range for /boot"
            exit 1
        fi

        # Verify the '/test' partition
        file_system=$(df --output=fstype /test | tail -n1)
        partition_size=$(df -B1 --output=size /test | tail -n1)
        [ $file_system == "xfs" ] || exit 1
        # The actual size may differ. Check if the partition size is in the range of <1000 MB, 1100 MB>.
        # Note: sizes in condition are in Bytes.
        if (($partition_size < 1000000000 || $partition_size > 1100000000)); then
            echo "$partition_size is outside the range for /test"
            exit 1
        fi

        # Verify the 'swap' size
        partition_size=$(free -m | tail -n 1 | awk '{print $2}')
        # The actual size may differ. Check if the partition size is in the range of <2040 MiB, 2060 MiB>.
        # Note: sizes in condition are in Mebibytes.
        if (($partition_size < 2040 || $partition_size > 2060)); then
            echo "$partition_size is outside the range for swap"
            exit 1
        fi
        ;;
esac
