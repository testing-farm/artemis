#
# Artemis container
#
# The entrypoint script specifies which application to run:
#
#   * api-server
#   * dispatcher
#   * wait-for-postgresql
#   * wait-for-rabbitmq
#   * worker
#

# Note that alpine from 3.11 uses python 3.8 which we do not yet support
FROM alpine:3.10

# This hack is widely applied to avoid python printing issues in docker containers.
# See: https://github.com/Docker-Hub-frolvlad/docker-alpine-python3/pull/13
ENV PYTHONUNBUFFERED=1

# default configuration directory
ENV CONFIGURATION=/configuration

# default home directory
ENV HOME=/tmp

# default kerberos ccache file
ENV KRB_CCACHE=/dev/shm/ccache

#
# Prepare virtual environment and install all required dependencies
#
RUN    apk add --no-cache bash \
                          curl \
                          gcc \
                          krb5 \
                          krb5-dev \
                          libffi-dev \
                          libxml2-dev \
                          libxslt-dev \
                          make \
                          musl-dev \
                          openssl-dev \
                          postgresql \
                          postgresql-dev \
                          python3 \
                          python3-dev \
    && if [ ! -e /usr/bin/python ]; then ln -sf python3 /usr/bin/python ; fi \
    && python3 -m ensurepip \
    && rm -r /usr/lib/python*/ensurepip \
    && pip3 install --no-cache --upgrade pip setuptools wheel \
    && if [ ! -e /usr/bin/pip ]; then ln -s pip3 /usr/bin/pip ; fi \
    && pip3 install -U virtualenv \
    && virtualenv -p /usr/bin/python3 /APP \
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
# Add setup.py and install all requirements
# Note: we do this first to avoid reinstalling of all requirements
#       for local development#
COPY setup.py /APP_SOURCE/
RUN    source /APP/bin/activate \
    && cd /APP_SOURCE \
    && python setup.py egg_info || true \
    && pip install -r artemis.egg-info/requires.txt

#
# Copy artemis source and install artemis from it
#
COPY artemis /APP_SOURCE/artemis/
RUN    source /APP/bin/activate \
    && cd /APP_SOURCE \
    && pip install . \
    && rm -rf /APP_SOURCE

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
RUN chmod g+w /etc/passwd

#
# Entrypoint for all artemis apps
#
ENTRYPOINT ["/entrypoint.sh"]
