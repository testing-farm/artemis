#!/bin/bash

# Check we have the correct number of arguments
[ $# -ge 2 ] && [ $# -le 3 ] || exit 1

INSTALL_TREE_URL="${1}"
KS_DIR=$(dirname ${2})
KS_FILENAME=$(basename ${2})
CMDLINE="${3}"

VMLINUZ_SRC="images/pxeboot/vmlinuz"
INITRD_SRC="images/pxeboot/initrd.img"

# Try to escalate privileges
[ $EUID == 0 ] || sudo bash "$0" "$@"

# Install prerequisite packages
dnf install -y kexec-tools

# Fetch PXE installer images
curl -LJo /tmp/vmlinuz "${INSTALL_TREE_URL}/${VMLINUZ_SRC}"
curl -LJo /tmp/initrd.img "${INSTALL_TREE_URL}/${INITRD_SRC}"

# Add kickstart to the initramfs
touch "${KS_DIR}/.ksinstall" "${KS_DIR}/.ksinprogress"
echo -e "${KS_FILENAME}\n.ksinstall\n.ksinprogress" | cpio -D "${KS_DIR}" -c -o >> /tmp/initrd.img

# Arm kexec
kexec -l /tmp/vmlinuz --initrd /tmp/initrd.img --command-line="no_timer_check net.ifnames=0 console=tty1 console=ttyS0,115200n8 inst.ks=file:/${KS_FILENAME} inst.sshd inst.repo=${INSTALL_TREE_URL} inst.noverifyssl ${CMDLINE}"

# Use systemctl to gracefully reboot into the installer
# Do it like this to give us some time for the SSH session to exit gracefully
trap "bash -c 'sleep 5; systemctl kexec' & disown -a" EXIT
