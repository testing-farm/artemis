{# Override distro-level option to indicate ostree/immutable installation is being performed #}
{% set has_rpmostree = True %}
{% set contained_harness = True %}

{% if sysprofile %}
{% for snippet_profile in sysprofile|split(';') %}
# Snippet Profile: {{ snippet_profile }}
{% snippet snippet_profile %}
{% endfor  %}
{% else %}

# BootC/ostreecontainer installation method
ostreecontainer --stateroot={{ ostree_stateroot|default('default') }} --url={{ ostree_container_url|default('images.paas.redhat.com/testingfarm/rhel-bootc:10.1') }} {% if ostree_no_signature_verification is defined %} --no-signature-verification{% endif %}

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
{% snippet 'rhts_post' %}
{% snippet (distro.osversion.osmajor.osmajor + '_post') %}
{% snippet (distro.osversion.osmajor.name + '_post') %}
{% snippet 'system_post' %}
%end

{% snippet 'onerror' %}
{{ ks_appends|join('\n') }}
{% snippet 'postinstall_done' %}
{% snippet 'post_s390_reboot' %}
{% snippet 'postreboot' %}
