{% if sysprofile %}
{% for snippet_profile in sysprofile|split(';') %}
# Snippet Profile: {{ snippet_profile }}
{% snippet snippet_profile %}
{% endfor  %}
{% else %}
{% if liveimg is undefined %}
{% snippet 'install_method' %}
{% endif %}

# bootc/ostreecontainer installation
ostreecontainer --stateroot={{ ostree_stateroot | default('default') }} --url={{ ostree_container_url }}{% if ostree_no_signature_verification is defined %} --no-signature-verification{% endif %}

{{ mode|default('text') }}
{% if manual is defined %}
{%- if has_ignoredisk_interactive %}ignoredisk --interactive{% endif %}

{% endif %}
{% if manual is undefined %}
{% if auth %}
auth {{ auth }}
{% endif %}
# System bootloader configuration
bootloader --location={{ boot_loc|default("mbr") }}{% if kernel_options_post %} --append="{{ kernel_options_post }}"{% endif %}{% if distro_tree is arch('ppc', 'ppc64', 'ppc64le') and has_leavebootorder is defined %} --leavebootorder{% endif %}{% if bootloader_type %} --{{ bootloader_type }}{% endif %}

{% snippet 'network' %}

{#
## Firewall configuration
## firewall in kickstart metadata will enable the firewall
## firewall=22:tcp,80:tcp will enable the firewall with ports 22 and 80 open.
## always allow port 12432 so that beah harness will support multihost
#}
firewall
{%- if firewall|default('disabled') == 'disabled' %} --disabled
{%- else %} --enabled --port=12432:tcp{% if firewall is defined %},{{ firewall }}{% endif %}
{% endif %}

# Run the Setup Agent on first boot
firstboot {{ firstboot|default('--disable') }}
# System keyboard
keyboard {{ keyboard|default('us') }}
# System language
lang {{ lang|default('en_US.UTF-8') }}

reboot
{% snippet 'password' %}
# SELinux configuration
selinux {{ selinux|default('--enforcing') }}

{% if skipx is defined %}
# Do not configure the X Window System
skipx
{% endif %}

{% snippet 'timezone' %}

{% snippet 'rhts_devices' %}
{% snippet 'rhts_partitions' %}
{% snippet distro.osversion.osmajor.osmajor %}
{% snippet distro.osversion.osmajor.name %}
{% snippet 'system' %}
{% if unsupported_hardware is defined and has_unsupported_hardware is defined %}
unsupported_hardware
{% endif %}

{% endif %}{# manual #}

{% endif %}{# sysprofile #}

%pre --log=/dev/console
{% snippet 'rhts_pre' %}
{% snippet (distro.osversion.osmajor.osmajor + '_pre') %}
{% snippet (distro.osversion.osmajor.name + '_pre') %}
{% snippet 'system_pre' %}
%end

%post --log=/dev/console
{# rhts_post #}
{% if distro.osversion.osmajor.name == 'Fedora' %}
# Disable yum repos supplied by fedora-release in favour of Beaker-supplied repos
# (this will match the repos used during installation).
sed -i -e '/\[fedora\]/,/^\[/s/enabled=1/enabled=0/' /etc/yum.repos.d/fedora.repo
{% if no_updates_repos is defined%}
sed -i -e '/\[updates\]/,/^\[/s/enabled=1/enabled=0/' /etc/yum.repos.d/fedora-updates.repo
{% endif %}
{% endif %}
set -x
{% snippet 'fetch_wrapper' %}

{% snippet 'install_done' %}
{% snippet 'clear_netboot' %}
{% if recipe %}
echo {{ recipe.id }} > /root/RECIPE.TXT
{% endif %}

# If netboot_method= is found in /proc/cmdline record it to /root
netboot_method=$(grep -oP "(?<=netboot_method=)[^\s]+(?=)" /proc/cmdline)
if [ -n "$netboot_method" ]; then
echo $netboot_method >/root/NETBOOT_METHOD.TXT
fi

{% if no_disable_readahead is undefined %}
if [ -f /etc/sysconfig/readahead ] ; then
    :
{% snippet 'readahead_sysconfig' %}
fi
{% if has_systemd is defined %}
systemctl disable systemd-readahead-collect.service
{% endif %}
{% endif %}
{% snippet 'linkdelay' %}

{# We normally want to make sure the system time is accurate, in case
 # a previous recipe has munged it. But if users want to opt out of this
 # behaviour they can set 'no_clock_sync'.
 #}
{% if no_clock_sync is undefined %}
if [ -e /etc/sysconfig/ntpdate ] ; then
{% if has_systemd is defined %}
    systemctl enable ntpdate.service
{% else %}
    chkconfig ntpdate on
{% endif %}
fi
if [ -e "/etc/sysconfig/ntpd" ]; then
{% if has_systemd is defined %}
    systemctl enable ntpd.service
{% else %}
    chkconfig ntpd on
{% endif %}
    GOT_G=$(/bin/cat /etc/sysconfig/ntpd | grep -E '^OPTIONS' | grep '\-g')

    if [ -z "$GOT_G" ]; then
        /bin/sed -i -r 's/(^OPTIONS\s*=\s*)(['\''|"])(.+)$/\1\2\-x \3 /' /etc/sysconfig/ntpd
    fi
fi
if [ -e /etc/chrony.conf ] ; then
    cp /etc/chrony.conf{,.orig}
    # use only DHCP-provided time servers, no default pool servers
    sed -i '/^server /d' /etc/chrony.conf
    cp /etc/sysconfig/network{,.orig}
    # setting iburst should speed up initial sync
    # https://bugzilla.redhat.com/show_bug.cgi?id=787042#c12
    echo NTPSERVERARGS=iburst >>/etc/sysconfig/network
{% if has_systemd is defined %}
    systemctl disable ntpd.service
    systemctl disable ntpdate.service
    systemctl enable chronyd.service
    systemctl enable chrony-wait.service
{% else %}
    chkconfig ntpd off
    chkconfig ntpdate off
    chkconfig chronyd on
{% endif %}
fi
{% endif %}

{% snippet 'grubport' %}
{% snippet 'boot_order' %}

{# docker_harness #}
# Create a file which will be read by the test harness
# to communicate with Beaker (fetch recipe, report results, etc)
cat <<"EOF" >/root/beaker-harness-env.sh
export BEAKER_LAB_CONTROLLER_URL="http://{{ lab_controller.fqdn }}:8000/"
export BEAKER_LAB_CONTROLLER={{ lab_controller.fqdn }}
export BEAKER_RECIPE_ID={{ recipe.id }}
export BEAKER_HUB_URL="{{ absolute_url('/', labdomain=True) }}"
EOF

mkdir /root/systemrepos
cp /etc/yum.repos.d/redhat.repo /etc/yum.repos.d/rhel.repo /root/systemrepos/ || true

# Create the Containerfile for the container
cat <<"__CONTAINERFILE_EOF__" > /root/Containerfile
{%- if harness_docker_base_image is not defined %}
{%- if distro.osversion.osmajor.name.lower() == "redhatenterpriselinux" %}
{%- set docker_registry="registry.access.redhat.com" %}
{%- set docker_image="ubi" + distro.osversion.osmajor.number + "/ubi-init" %}
{%- set docker_tag="latest" %}
{%- else %}
{%- set docker_registry="registry.hub.docker.com" %}
{%- set docker_image=distro.osversion.osmajor.name.lower() %}
{%- set docker_tag=distro.osversion.osmajor.number %}
{%- endif %}
{%- set harness_docker_base_image=docker_registry + "/" + docker_image + ":" + docker_tag %}
{%- endif %}

FROM {{ harness_docker_base_image }}
# MAINTAINER Beaker Developers <beaker-devel@lists.fedoraproject.org>
ENV container docker

# Add repos
RUN <<__CONTAINER_REPOS_EOF__
set -euo pipefail

# Add "traditional" Beaker task repo so that tasks from the
# central task repository can be executed as well.
{% if taskrepo %}
{% snippet 'taskrepo' %}
{% endif %}

{% if customrepos %}
# Add all custom repositories (defined using <repo/> elements)
{% for repo in customrepos %}
cat <<"EOF" >/etc/yum.repos.d/{{ repo.repo_id }}.repo
[{{ repo.repo_id }}]
name={{ repo.repo_id }}
baseurl={{ repo.path }}
enabled=1
gpgcheck=0
skip_if_unavailable=1
EOF
{% endfor %}
{% endif %}

{% if harnessrepo and no_default_harness_repo is not defined %}
{% set reponame, repourl = harnessrepo.split(',', 1) %}
cat <<"EOF" >/etc/yum.repos.d/{{ reponame }}.repo
[{{ reponame }}]
name={{ reponame }}
baseurl={{ repourl }}
enabled=1
gpgcheck=0
EOF
{% endif %}
__CONTAINER_REPOS_EOF__

# Relies on container being compatible with the host (RHEL)
COPY systemrepos/ /etc/yum.repos.d/

COPY beaker-harness-env.sh /etc/profile.d/beaker-harness-env.sh

RUN dnf -y update; dnf clean all

{% if contained_harness_entrypoint is not defined %}
# We assume that if the contained harness entrypoint is not
# defined, we are relying on systemd to start the harness
# for us
# Reference: http://developerblog.redhat.com/2014/05/05/running-systemd-within-docker-container/
{# In case we have fakesystemd installed, remove it #}
RUN dnf -y remove fakesystemd || true
RUN dnf -y install systemd; \
dnf clean all; \
(cd /lib/systemd/system/sysinit.target.wants/; for i in *; do [ "\$i" == systemd-tmpfiles-setup.service ] || rm -f "\$i"; done); \
rm -f /lib/systemd/system/multi-user.target.wants/*;\
rm -f /etc/systemd/system/*.wants/*;\
rm -f /lib/systemd/system/local-fs.target.wants/*; \
rm -f /lib/systemd/system/sockets.target.wants/*udev*; \
rm -f /lib/systemd/system/sockets.target.wants/*initctl*; \
rm -f /lib/systemd/system/basic.target.wants/*;\
rm -f /lib/systemd/system/anaconda.target.wants/*;
VOLUME [ "/sys/fs/cgroup" ]
{% endif %}

# Install the harness
RUN <<__CONTAINER_HARNESS_EOF__
set -euo pipefail

dnf -y install {{ harness|default('restraint restraint-rhts') }}
dnf -y --allowerasing install coreutils
dnf -y install beakerlib || true
dnf -y install beakerlib-redhat || true
dnf clean all
__CONTAINER_HARNESS_EOF__

RUN <<__CONTAINER_ANAMON_EOF__
set -euo pipefail

{% snippet 'fetch_wrapper' %}

{% snippet 'post_anamon' %}
sed -i 's/\(\/var\/log\)/\1\/host/g' /etc/sysconfig/anamon
__CONTAINER_ANAMON_EOF__

CMD {{ contained_harness_entrypoint|default('["/usr/sbin/init"]') }}
__CONTAINERFILE_EOF__

cat << EOF > /etc/systemd/system/beaker-harness-container.service
[Unit]
Description=Beaker test harness in a container
After=network.target NetworkManager-wait-online.service

[Service]
Type=simple
WorkingDirectory=/root
ExecStartPre=/usr/bin/podman build -t beaker-harness -f /root/Containerfile .
# Mount the host /mnt at /mnt so that the test data is preserved
# post container exit
ExecStart=/usr/bin/podman run --privileged -v /var/log:/var/log/host:ro {%- for path in contained_harness_ro_host_volumes|default('/etc/localtime')|split(',') %} -v {{ path }}:{{ path }}:ro{% endfor %}{%- for path in contained_harness_rw_host_volumes|default('/mnt,/root')|split(',') %} -v {{ path }}:{{ path }}:rw{% endfor %} --name beaker-harness -t beaker-harness
User=root
Group=root
TimeoutStartSec=0

[Install]
WantedBy=default.target
EOF

systemctl enable beaker-harness-container.service
# Some tasks may be using these directories (legacy!), so we create these on the host
# so that they are available when the host's /mnt is volume mounted
mkdir -p /mnt/testarea /mnt/scratchspace
{# docker_harness end #}

#Add test user account
useradd --password '$6$oIW3o2Mr$XbWZKaM7nA.cQqudfDJScupXOia5h1u517t6Htx/Q/MgXm82Pc/OcytatTeI4ULNWOMJzvpCigWiL4xKP9PX4.' test
{% snippet 'beaker_env' %}
{% snippet 'lab_env' %}
{% snippet 'ssh_keys' %}
{% if recipe.systemtype == 'Virtual' %}
if [ -d /etc/init ] ; then
    :
{% snippet 'virt_console_post' %}
fi
{% endif %}
{% if system and system.kernel_type.kernel_type == 'highbank' %}
{% snippet 'highbank' %}
{% endif %}
{% if system and system.kernel_type.kernel_type == 'mvebu' %}
{% snippet 'mvebu' %}
{% endif %}
{% snippet 'remote_post' %}
{% snippet 'disable_rhts_compat' %}
{# rhts_post end #}
{% snippet (distro.osversion.osmajor.osmajor + '_post') %}
{% snippet (distro.osversion.osmajor.name + '_post') %}
{% snippet 'system_post' %}
%end

{% snippet 'onerror' %}
{{ ks_appends|join('\n') }}
{% snippet 'postinstall_done' %}
{% snippet 'post_s390_reboot' %}
{% snippet 'postreboot' %}
