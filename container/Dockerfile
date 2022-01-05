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
FROM registry.fedoraproject.org/fedora-minimal:34

COPY --from=PROMTAIL_SOURCE /promtail /usr/bin/

    # This hack is widely applied to avoid python printing issues in docker containers.
    # See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1 \
    # default configuration directory
    CONFIGURATION=/configuration \
    # default home directory
    HOME=/tmp \
    # default kerberos ccache file
    KRB_CCACHE=/dev/shm/ccache \
    PATH="/tmp/.poetry/bin:$PATH"

# Entrypoint for all artemis apps
ENTRYPOINT ["/entrypoint.sh"]

    # Prepare virtual environment and install all required dependencies
RUN    microdnf -y install bash \
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
                           poetry \
                           python3.7 \
                           # required by `openstack`
                           which \
                           # for debugging
                           lsof \
                           procps-ng \
                           net-tools \
    && microdnf clean all \
    && rm -rf /var/cache/dnf \
    && sed -ri "s|\[libdefaults\]|\[libdefaults\]\n  default_ccache_name = FILE:$KRB_CCACHE|" /etc/krb5.conf \
    # Make sure we can edit /etc/passwd, required to set valid username when run via Openshift
    && chmod g+rw /etc/passwd \
    # Make sure AWS credentials are available from configuration
    #  ~/.aws/config is symlinked to $CONFIGURATION/aws-config
    #  ~/.aws/credentials is symlinked to $CONFIGURATION/aws-credentials
    && mkdir -p $HOME/.aws \
    && ln -s $CONFIGURATION/aws-config $HOME/.aws/config \
    && ln -s $CONFIGURATION/aws-credentials $HOME/.aws/credentials \
    # Make sure Beaker credentials are symlinked from configuration
    #  /etc/beaker/client.conf is symlinked to $CONFIGURATION/beaker-client-config
    && mkdir -p /etc/beaker \
    && ln -s $CONFIGURATION/beaker-client-config /etc/beaker/client.conf \
    # We want Artemis to support also older SSH keys for now, Fedora 33+ has strong crypto enabled
    # https://fedoraproject.org/wiki/Changes/StrongCryptoSettings2
    && mkdir $HOME/.ssh \
    && printf "Host *\n   PubkeyAcceptedKeyTypes +ssh-rsa" > $HOME/.ssh/config \
    # Promtail configuration space
    && mkdir -p /promtail-config \
    && chmod a+rx /promtail-config

# The following files are provided by the repository, therefore we should copy them as late as possible,
# to make use of the cached outcome of commands that come before COPY.
COPY container/promtail-dummy.yaml /promtail-config/
COPY container/entrypoint.sh /entrypoint.sh
COPY required_hooks /
COPY container/wait-for-api.sh /
COPY container/wait-for-postgres.sh /
COPY container/wait-for-rabbitmq.sh /
COPY container/wait-for-redis.sh /
# This is the actual Artemis source, with Alembic revisions included.
COPY server /APP/

# The following commands can be executed only after the COPY instructions did their job, therefore cannot be
# part of the big RUN instruction above.
    # Make entrypoint script executable
RUN    chmod +x /entrypoint.sh \
    # Make wait scripts executable
    && chmod +x /wait-for-postgres.sh /wait-for-rabbitmq.sh /wait-for-api.sh /wait-for-redis.sh \
    # Install Artemis
    && cd /APP \
    && PYTHON=python3.7 make install-no-dev \
    # Make Poetry configuration accesible to Poetry in containers
    && chmod a+rw /tmp/.config/pypoetry/config.toml
