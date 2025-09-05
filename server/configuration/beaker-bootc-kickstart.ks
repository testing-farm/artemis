{% snippet 'install_method' %}

# bootc/ostreecontainer installation
ostreecontainer --stateroot={{ ostree_stateroot | default('default') }} --url={{ ostree_container_url }}{% if ostree_no_signature_verification is defined %} --no-signature-verification{% endif %}

text

# System bootloader configuration
bootloader --location={{ boot_loc|default("mbr") }}{% if kernel_options_post %} --append="{{ kernel_options_post }}"{% endif %}{% if distro_tree is arch('ppc', 'ppc64', 'ppc64le') and has_leavebootorder is defined %} --leavebootorder{% endif %}{% if bootloader_type %} --{{ bootloader_type }}{% endif %}

{% snippet 'network' %}

reboot

{% snippet 'password' %}

zerombr
clearpart --all --initlabel

autopart

%pre --log=/dev/console
{% snippet 'rhts_pre' %}
%end

%post --log=/dev/console
{% snippet 'rhts_post' %}
%end

{% snippet 'onerror' %}
{% snippet 'postinstall_done' %}
