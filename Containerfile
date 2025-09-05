FROM images.paas.redhat.com/testingfarm/rhel-bootc:10.1

ADD http://lab-02.rhts.eng.rdu.redhat.com/beaker/anamon3 /usr/local/sbin/anamon
RUN chmod 755 /usr/local/sbin/anamon

RUN dnf install -y curl restraint restraint-rhts audit chrony && \
    dnf -y clean all && \
    rm -rf /var/cache /var/lib/dnf
