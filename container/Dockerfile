#
# Container to run citool with gluetool modules
#
# Volume mounts:
#
#    /ARTIFACTS - all artifacts will be saved here
#    /CONFIG - place for configuration
#

# Fedora 32 based podman image, useful as it can run podman inside!
FROM quay.io/podman/stable:v2.0.6
LABEL maintainer="tft@redhat.com"

# workdir
WORKDIR /ARTIFACTS

# pycurl needs to be compiled against openssl to work properly
ENV PYCURL_SSL_BACKEND=openssl

# install all required dependencies
# WORKAROUND: install python2-rpm from f31, as it is not available for Fedora-32 anymore
RUN    ln -s /CONFIG /etc/citool.d \
    && dnf -y install ansible autoconf automake gcc git krb5-devel libcurl-devel \
                      libpq-devel libtool libxml2-devel make openssl-devel popt-devel \
                      poetry postgresql-devel python3-libselinux python2-devel \
                      python-unversioned-command redhat-rpm-config \
                      standard-test-roles koji python3-virtualenv \
    && dnf -y install --enablerepo=updates-testing tmt-provision-container rsync \
    && rpm -ivh --nodeps https://kojipkgs.fedoraproject.org//packages/rpm/4.15.1/2.fc31/x86_64/python2-rpm-4.15.1-2.fc31.x86_64.rpm \
    && python2 -m ensurepip \
    && dnf clean all \
    && bash -c "echo 'Host *' >> /etc/ssh/ssh_config" \
    && bash -c "echo '  StrictHostKeyChecking no' >> /etc/ssh/ssh_config" \
    && bash -c "echo '  UserKnownHostsFile /dev/null' >> /etc/ssh/ssh_config"

# copy the built package
COPY . /opt/gluetool-modules

# install gluetool-modules & citool
RUN    cd /opt/gluetool-modules \
    && poetry config virtualenvs.create false \
    && virtualenv -p python2 /opt/gluetool-venv \
    && source /opt/gluetool-venv/bin/activate \
    && poetry install \
    && ln -s /opt/gluetool-venv/bin/citool /usr/bin/citool \
    && ln -s /opt/gluetool-venv/bin/gluetool /usr/bin/gluetool \
    && rm -rf ~/.cache

# run citool as entrypoint
ENTRYPOINT ["/usr/bin/citool"]
CMD ["--help"]
