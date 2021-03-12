Provisioner Capabilities Protocol
=================================

Users of provisioners may need to find out what capabilities provisioner can provide, what services it can handle. For this purpose, user can query provisioner, and receive information packet, describing provisioner capabilities.


Query
-----

Provisioner should provide shared function ``provisioner_capabilities``. No required parameters.


Packet
------

.. py:attribute:: available_arches

   ``list(str)`` of architectures the provisioner can provide.
