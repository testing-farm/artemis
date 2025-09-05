# FROM images.paas.redhat.com/testingfarm/rhel-bootc:9.8
FROM images.paas.redhat.com/bootc/rhel-bootc:RHEL-10.1-20250905.0

ARG TARGETARCH

RUN <<EOF
# Use strict mode
set -euo pipefail

if [ "$TARGETARCH" = "amd64" ]; then
  ARCH="x86_64"
elif [ "$TARGETARCH" = "arm64" ]; then
  ARCH="aarch64"
else
  # echo "Unsupported architecture"
  ARCH="$TARGETARCH"
fi

# Download yumrepogen
curl -ko yumrepogen https://gitlab.cee.redhat.com/api/v4/projects/72924/jobs/artifacts/main/raw/yumrepogen-$ARCH?job=compile
chmod +x yumrepogen

# Add RHEL repositories
./yumrepogen -compose-id RHEL-10.1-20250905.0 -insecure -arch $ARCH -outfile /etc/yum.repos.d/rhel.repo -enable BaseOS,AppStream
rm -f yumrepogen

# Add beaker-harness repository and install beakerlib and beakerlib-redhat
printf "[beaker-harness]\nname=beaker-harness\nbaseurl=http://beaker.engineering.redhat.com/harness/RedHatEnterpriseLinux10\nenabled=1\ngpgcheck=0" > /etc/yum.repos.d/beaker-harness.repo
dnf -y install beakerlib beakerlib-redhat

# Add Red Hat CA certificates
curl -ko /etc/pki/ca-trust/source/anchors/Current-IT-Root-CAs.pem https://certs.corp.redhat.com/certs/Current-IT-Root-CAs.pem
update-ca-trust

# Add disabled epel repository
dnf -y install https://dl.fedoraproject.org/pub/epel/epel-release-latest-10.noarch.rpm
sed -i 's/enabled=1/enabled=0/' /etc/yum.repos.d/epel.repo

# System update not yet fully supported
# https://redhat-internal.slack.com/archives/C02CU30L7GF/p1730486873277529?thread_ts=1730376872.876749&cid=C02CU30L7GF
# && dnf -y update
dnf -y install cloud-init rsync beakerlib beakerlib-redhat

# Remove repositories shipped in the container, we don't need them.
rm -vf /etc/yum.repos.d/{epel-cisco-openh264,redhat}.repo

# Disable RHSM
sed -i 's/enabled=1/enabled=0/' /etc/yum/pluginconf.d/subscription-manager.conf
EOF

ADD http://lab-02.rhts.eng.rdu.redhat.com/beaker/anamon3 /usr/local/sbin/anamon
RUN chmod 755 /usr/local/sbin/anamon

RUN dnf install -y curl restraint restraint-rhts audit chrony && \
    dnf -y clean all && \
    rm -rf /var/cache /var/lib/dnf
