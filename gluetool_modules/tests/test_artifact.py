import pytest
from gluetool_modules.libs.artifacts import splitFilename


@pytest.mark.parametrize('nevr,parsed_nevr', [
    # NVRA
    ('java-1.8.0-openjdk-1.8.0.242.b02-0.0.ea.el7_7.x86_64',
     ('java-1.8.0-openjdk', '1.8.0.242.b02', '0.0.ea.el7_7', '', 'x86_64')),
    ('openssh-8.0p1-3.2.el8.i386', ('openssh', '8.0p1', '3.2.el8', '', 'i386')),
    ('sqlite-3.26.0-4.el8_1.s390x', ('sqlite', '3.26.0', '4.el8_1', '', 's390x')),
    ('sqlite-3.26.0-4.el8_0.ppc64', ('sqlite', '3.26.0', '4.el8_0', '', 'ppc64')),
    ('openssh-8.0p1-3.1.el8.aarch64', ('openssh', '8.0p1', '3.1.el8', '', 'aarch64')),
    ('sos-3.2-28.el6_7.4.x86_64.rpm', ('sos', '3.2', '28.el6_7.4', '', 'x86_64')),
    ('sqlite-3.26.0-4.el8_1.i386.rpm', ('sqlite', '3.26.0', '4.el8_1', '', 'i386')),
    ('sqlite-3.26.0-4.el8_0.s390x.rpm', ('sqlite', '3.26.0', '4.el8_0', '', 's390x')),
    ('sos-3.2-28.el6_7.4.ppc64.rpm', ('sos', '3.2', '28.el6_7.4', '', 'ppc64')),
    ('sqlite-3.26.0-3.el8_1.aarch64.rpm', ('sqlite', '3.26.0', '3.el8_1', '', 'aarch64')),

    # NVRA - module builds
    ('pki-core-devel-10.6-8010020190912123424.8ba0ffbe.x86_64',
     ('pki-core-devel', '10.6', '8010020190912123424.8ba0ffbe', '', 'x86_64')),
    ('389-ds-devel-1.4-8010020190903200205.eb48df33.i386',
     ('389-ds-devel', '1.4', '8010020190903200205.eb48df33', '', 'i386')),
    ('python27-devel-2.7-8010020190903182548.51c94b97.s390x',
     ('python27-devel', '2.7', '8010020190903182548.51c94b97', '', 's390x')),
    ('httpd-devel-2.4-8010020190829143335.cdc1202b.ppc64',
     ('httpd-devel', '2.4', '8010020190829143335.cdc1202b', '', 'ppc64')),
    ('nginx-devel-1.16-8010020190829151810.cdc1202b.aarch64',
     ('nginx-devel', '1.16', '8010020190829151810.cdc1202b', '', 'aarch64')),
    ('squid-devel-4-8010020190823133019.cdc1202b.x86_64.rpm',
     ('squid-devel', '4', '8010020190823133019.cdc1202b', '', 'x86_64')),
    ('mariadb-10.3-8010020190902091509.cdc1202b.i386.rpm',
     ('mariadb', '10.3', '8010020190902091509.cdc1202b', '', 'i386')),
    ('squid-4-8010020190823133019.cdc1202b.s390x.rpm',
     ('squid', '4', '8010020190823133019.cdc1202b', '', 's390x')),
    ('satellite-5-client-1.0-8010020190621091459.cdc1202b.ppc64.rpm',
     ('satellite-5-client', '1.0', '8010020190621091459.cdc1202b', '', 'ppc64')),
    ('ruby-2.6-8010020190711095715.cdc1202b.aarch64.rpm',
     ('ruby', '2.6', '8010020190711095715.cdc1202b', '', 'aarch64')),

    # NEVRA
    ('redhat-rpm-config-0:121-1.el8.x86_64', ('redhat-rpm-config', '121', '1.el8', '0', 'x86_64')),
    ('cockpit-composer-1:11-1.el8.i386', ('cockpit-composer', '11', '1.el8', '1', 'i386')),
    ('util-linux-2:2.32.1-22.el8.s390x', ('util-linux', '2.32.1', '22.el8', '2', 's390x')),
    ('virtio-win-3:1.9.10-2.el8.ppc64', ('virtio-win', '1.9.10', '2.el8', '3', 'ppc64')),
    ('gcc-toolset-9-binutils-4:2.32-17.el8_1.aarch64', ('gcc-toolset-9-binutils', '2.32', '17.el8_1', '4', 'aarch64')),
    ('virt-viewer-5:7.0-9.el8.x86_64.rpm', ('virt-viewer', '7.0', '9.el8', '5', 'x86_64')),
    ('certmonger-6:0.79.7-6.el8.i386.rpm', ('certmonger', '0.79.7', '6.el8', '6', 'i386')),
    ('NetworkManager-7:1.22.0-2.el8.s390x.rpm', ('NetworkManager', '1.22.0', '2.el8', '7', 's390x')),
    ('util-linux-8:2.32.1-21.el8.ppc64.rpm', ('util-linux', '2.32.1', '21.el8', '8', 'ppc64')),
    ('fribidi-9:1.0.4-8.el8.aarch64.rpm', ('fribidi', '1.0.4', '8.el8', '9', 'aarch64')),

    # NVRA - collection builds
    ('rh-nodejs4-nodejs-npm-user-validate-0.1.1-2.el7.x86_64',
     ('rh-nodejs4-nodejs-npm-user-validate', '0.1.1', '2.el7', '', 'x86_64')),
    ('rh-perl524-perl-ExtUtils-Manifest-1.70-366.el7.i386',
     ('rh-perl524-perl-ExtUtils-Manifest', '1.70', '366.el7', '', 'i386')),
    ('rh-java-common-apache-commons-discovery-0.5-10.1.el7.s390x',
     ('rh-java-common-apache-commons-discovery', '0.5', '10.1.el7', '', 's390x')),
    ('rh-maven35-xpp3-1.1.4-15.c.2.el7.ppc64', ('rh-maven35-xpp3', '1.1.4', '15.c.2.el7', '', 'ppc64')),
    ('rh-mongodb26-2.0-20.el7.aarch64', ('rh-mongodb26', '2.0', '20.el7', '', 'aarch64')),
    ('rh-postgresql94-postgresql-9.4.14-2.el7.x86_64.rpm',
     ('rh-postgresql94-postgresql', '9.4.14', '2.el7', '', 'x86_64')),
    ('rh-nodejs4-nodejs-4.6.2-7.el7.i386.rpm', ('rh-nodejs4-nodejs', '4.6.2', '7.el7', '', 'i386')),
    ('rh-mysql57-2.3-4.el7.s390x.rpm', ('rh-mysql57', '2.3', '4.el7', '', 's390x')),
    ('rh-postgresql10-3.1-1.el7.ppc64.rpm', ('rh-postgresql10', '3.1', '1.el7', '', 'ppc64')),
    ('rh-ruby25-2.5-2.el7.aarch64.rpm', ('rh-ruby25', '2.5', '2.el7', '', 'aarch64')),

    # NVR.src.rpm (SRPM names)
    ('java-1.8.0-openjdk-1.8.0.242.b02-0.0.ea.el7_7.src.rpm',
     ('java-1.8.0-openjdk', '1.8.0.242.b02', '0.0.ea.el7_7', '', 'src')),
    ('openssh-8.0p1-3.2.el8.src.rpm', ('openssh', '8.0p1', '3.2.el8', '', 'src')),
    ('sqlite-3.26.0-4.el8_1.src.rpm', ('sqlite', '3.26.0', '4.el8_1', '', 'src')),
    ('sqlite-3.26.0-4.el8_0.src.rpm', ('sqlite', '3.26.0', '4.el8_0', '', 'src')),
    ('openssh-8.0p1-3.1.el8.src.rpm', ('openssh', '8.0p1', '3.1.el8', '', 'src')),
    ('sos-3.2-28.el6_7.4.src.rpm', ('sos', '3.2', '28.el6_7.4', '', 'src')),
    ('sqlite-3.26.0-4.el8_1.src.rpm', ('sqlite', '3.26.0', '4.el8_1', '', 'src')),
    ('sqlite-3.26.0-4.el8_0.src.rpm', ('sqlite', '3.26.0', '4.el8_0', '', 'src')),
    ('sos-3.2-28.el6_7.4.src.rpm', ('sos', '3.2', '28.el6_7.4', '', 'src')),
    ('sqlite-3.26.0-3.el8_1.src.rpm', ('sqlite', '3.26.0', '3.el8_1', '', 'src')),
])
def test_splitFilename(nevr, parsed_nevr):
    assert splitFilename(nevr) == parsed_nevr
