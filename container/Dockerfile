#
# Artemis container
#
# The entrypoint script specifies which application to run:
#
#   * api-server
#   * dispatcher
#   * wait-for-postgresql
#   * wait-for-rabbitmq
#   * scheduler
#   * worker
#

FROM quay.io/testing-farm/promtail:v2.2.1 as PROMTAIL_SOURCE
FROM registry.fedoraproject.org/fedora-minimal:36

COPY --from=PROMTAIL_SOURCE /promtail /usr/bin/

# This hack is widely applied to avoid python printing issues in docker containers.
# See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1

# default configuration directory
ENV CONFIGURATION=/configuration

# default home directory
ENV HOME=/tmp

# default kerberos ccache file
ENV KRB_CCACHE=/dev/shm/ccache

ENV PATH="/tmp/.local/bin:$PATH"

#
# Prepare virtual environment and install all required dependencies
#
RUN    microdnf -y install bash \
                           crypto-policies-scripts \
                           curl \
                           gcc \
                           g++ \
                           hostname \
                           krb5-workstation \
                           krb5-devel \
                           less \
                           libpq-devel \
                           libffi-devel \
                           libxml2-devel \
                           libxslt-devel \
                           make \
                           nmap-ncat \
                           openssh-clients \
                           openssl-devel \
                           postgresql \
                           python3.9 \
                           # required by `openstack`
                           which \
                           # for debugging
                           lsof \
                           procps-ng \
                           net-tools \
    && update-crypto-policies --set LEGACY \
    && microdnf clean all \
    && rm -rf /var/cache/dnf \
    && curl -sSL https://install.python-poetry.org | python3.9 - --version 1.4.2 \
    && sed -ri "s|\[libdefaults\]|\[libdefaults\]\n  default_ccache_name = FILE:$KRB_CCACHE|" /etc/krb5.conf

#
# Make sure AWS credentials are available from configuration
#
#  ~/.aws/config is symlinked to $CONFIGURATION/aws-config
#  ~/.aws/credentials is symlinked to $CONFIGURATION/aws-credentials
#
RUN    mkdir -p $HOME/.aws \
    && ln -s $CONFIGURATION/aws-config $HOME/.aws/config \
    && ln -s $CONFIGURATION/aws-credentials $HOME/.aws/credentials

#
# Make sure Beaker credentials are symlinked from configuration
#
#  /etc/beaker/client.conf is symlinked to $CONFIGURATION/beaker-client-config
#
RUN    mkdir -p /etc/beaker \
    && ln -s $CONFIGURATION/beaker-client-config /etc/beaker/client.conf

#
# We want Artemis to support also older SSH keys for now, Fedora 33+ has strong crypto enabled
# https://fedoraproject.org/wiki/Changes/StrongCryptoSettings2
#
RUN    mkdir $HOME/.ssh \
    && printf "Host *\n   PubkeyAcceptedKeyTypes +ssh-rsa" > $HOME/.ssh/config

#
# Promtail configuration space
#
RUN    mkdir -p /promtail-config \
    && chmod a+rx /promtail-config
COPY container/promtail-dummy.yaml /promtail-config/

#
# Add entrypoint
#
COPY container/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

#
# Add required hooks environment variables enumeration
#
COPY required_hooks /

#
# Add wait scripts
#
COPY container/wait-for-api.sh /
COPY container/wait-for-postgres.sh /
COPY container/wait-for-rabbitmq.sh /
COPY container/wait-for-redis.sh /
RUN chmod +x /wait-for-postgres.sh /wait-for-rabbitmq.sh /wait-for-api.sh /wait-for-redis.sh

#
# Copy Artemis sources and Alembic data and install Artemis
#
COPY server /APP/
# TODO: remove once server/client Makefiles wouldn't refer to their parent directory
COPY Makefile.lib /
RUN    cd /APP \
    # New parallel installer does not seem to work correctly, way too many crashes
    # when plenty of packages are needed.
    && poetry config experimental.new-installer false \
    && poetry config installer.parallel false \
    && PYTHON=python3.9 make install-no-dev \
    # Make Poetry configuration accesible to Poetry in containers
    && chmod a+rw /tmp/.config/pypoetry/config.toml

#
# Make sure we can edit /etc/passwd, required to set valid username when run via Openshift
#
RUN chmod g+rw /etc/passwd

#
# Entrypoint for all artemis apps
#
ENTRYPOINT ["/entrypoint.sh"]
