#
# Artemis development script.
#
# Source to run.
#

# make sure this script is sources not executed in subshell
(return 0 2>/dev/null) || { echo -e "\e[31merror: script must be sourced not executed\e[0m"; exit 1; }

#
# vars
#
COMMAND=$1
OPTS="c:hs"
CONFIGURATION="configuration"

#
# helper functions
#
function info() { echo -e "\e[32m[+] $@\e[0m"; }
function error() { echo -e "\e[31merror: $@\e[0m"; }
function help() {
    cat <<EOF
usage: . develop.sh [-h] [-c PATH]

Description
Artemis development script. Runs artemis on a minishift instance via skaffold.

Options:
  -h         Print this help.
  -c         Configuration path (default: './configuration').
  -s         Run sanity only (sets up your environment).
EOF
}

#
# run sanity checks and bring the environment into an expected state
#
function sanity() {
    info "checking environment requirements"

    # check if script is sourced in root directory
    if [ ! -e .gitignore ]; then
        error "script must be sourced from project root directory"
        return 1
    fi

    # check if docker available
    if ! command -v docker &>/dev/null; then
        error "docker is not installed. Please install it first."
        return 1
    fi

    # check if skaffold available
    if ! command -v skaffold &>/dev/null; then
        error "skaffold is not installed. Please install it via https://skaffold.dev/docs/install/"
        return 1
    fi

    # check if minishift available
    if ! command -v minishift &>/dev/null; then
        error "minishift is not installed. Please install it via https://docs.okd.io/latest/minishift/getting-started/installing.html"
        return 1
    fi

    # check if minishift running
    if ! minishift status | grep -q "Minishift.*Running"; then
        info "starting minishift"
        minishift start
    fi

    # check for docker
    if ! docker version | grep -q "Docker Engine"; then
        error "docker is required for the development environemnt"
        return 1
    fi

    # next checks require minishift console details to be available
    eval $(minishift console --machine-readable)

    OC_STATUS=$(oc status)
    OC_STATUS_RETCODE=$?

    # login to minishift if needed
    if [ $OC_STATUS_RETCODE -ne 0 ] || ! grep -q "$HOST:$PORT" <<< "$OC_STATUS"; then
        info "logging into minishift instance '$HOST:$PORT'"
        oc login -u developer -p developer --insecure-skip-tls-verify $HOST:$PORT
    fi

    # next checks require minishift
    eval $(minishift docker-env)
    info "login to minishift's docker registry '$DOCKER_HOST'"
    if ! docker login -u developer -p $(oc whoami -t) $(minishift openshift registry) &>/dev/null; then
        error "Failed to login to minishift docker registry, cannot continue"
        error "Comand: docker login -u developer -p \$(oc whoami -t) \$(minishift openshift registry)"
        return 1
    fi

    # check if configuration available
    [ ! -d "configuration" ] && error "no artemis configuration found under 'configuration' directory. Please add it."

    # make sure configuration config map exists or update it
    if ! oc get configmap/artemis-configuration &>/dev/null; then
        # create configmap
        info "creating configuration config map from 'configuration' directory"
        oc create configmap artemis-configuration --from-file=configuration
    else
        # update configmap
        info "updating configuration config map from 'configuration' directory"
        oc create --dry-run -o json configmap artemis-configuration --from-file=configuration | oc replace -f -
    fi
}

#
# execute skaffold
#
function run_skaffold() {
    info "running skaffold"
    skaffold dev
}

#
# main
#
OPTIND=1
while getopts $OPTS OPTION
do
  case $OPTION in
    h)
        help
        return
        ;;
    c)
        CONFIGURATION=$OPTARG
        ;;
    s)
        info "run sanity only"
        sanity || return 1
        return
        ;;
  esac
done
shift $((OPTIND -1))

# sanity checks
sanity || return 1

# default - execute skaffold
if [ -z "$COMMAND" ]; then
    run_skaffold
fi
