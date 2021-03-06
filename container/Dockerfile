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

# Note that alpine from 3.11 uses python 3.8 which we do not yet support
FROM quay.io/testing-farm/alpine:3.10

# This hack is widely applied to avoid python printing issues in docker containers.
# See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1

# default configuration directory
ENV CONFIGURATION=/configuration

# default home directory
ENV HOME=/tmp

# default kerberos ccache file
ENV KRB_CCACHE=/dev/shm/ccache

ENV PATH="/tmp/.poetry/bin:$PATH"

#
# Prepare virtual environment and install all required dependencies
#
RUN    apk add --no-cache bash \
                          curl \
                          gcc \
                          g++ \
                          krb5 \
                          krb5-dev \
                          libffi-dev \
                          libxml2-dev \
                          libxslt-dev \
                          make \
                          musl-dev \
                          openssh \
                          openssl-dev \
                          postgresql \
                          postgresql-dev \
                          python3 \
                          python3-dev \
                          tzdata \
    && cp /usr/share/zoneinfo/Universal /etc/localtime \
    && echo "Universal" > /etc/timezone \
    && if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi \
    && python3 -m ensurepip \
    && pip3 install --no-cache --upgrade pip setuptools virtualenv wheel \
    && if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi \
    && curl -sSL https://raw.githubusercontent.com/python-poetry/poetry/master/get-poetry.py | python3 \
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
# Copy Artemis sources and Alembic data and install Artemis
#
COPY server /APP/
RUN    cd /APP \
    && poetry install --no-dev

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
RUN chmod +x /wait-for-postgres.sh /wait-for-rabbitmq.sh /wait-for-api.sh

#
# Make sure we can edit /etc/passwd
#
RUN chmod -R g+rwX /etc/passwd /tmp/.poetry

#
# Entrypoint for all artemis apps
#
ENTRYPOINT ["/entrypoint.sh"]
