Testing Environment Protocol
============================

To specify what environment should provisioner provide when asked for guest(s), one needs to describe attributes of such environment. It's up to provisioning modules to decode the information, and provision guest that would - according to their best knowledge - satisfy the request.

.. note::

   This is effectively a work in progress - it is motivated by a need to separate Restraint and OpenStack,
   and I really believe we would use more advanced description over the time, e.g. one based on FMF
   or test case relevancy.


Query
-----

None, the packet serves as an input, it is being passed to ``provision`` shared function of provisioning modules.


Packet
------

.. py:attribute:: compose

    (``str``) Identification of the compose to be used for testing. It can be pretty much any string value, its purpose is to allow provisioning modules to chose the best distro/image/etc. suitable for the job. It will depend on what modules are connected in the pipeline, how they are configured and other factors. E.g. when dealing with ``workflow-tomorrow``, it can carry a tree name as known to Beaker, ``RHEL-7.5-updates-20180724.1`` or ``RHEL-6.10``; the provisioner should then deduce what guest configuration (arch & distro, arch & OpenStack image, and so on) would satisfy such request.

.. py:attribute:: arch

   (``str``) Architecture that should be used for testing.
