Protocols
=========

Several agreements exist on form and meaning of data exchanged by modules via their shared functions. Some of these are explicit and enforceable by language, e.g. artifact providers connect to their backends and provide an artifact representation - instance of documented and well-known class (Koji/Brew task, Copr task, ...) - to other modules, while other exchanges are not cast in language stone. Given the lack of common shared ground between modules, disallowing use of a parent class for encapsulating such exchange of information while giving different modules ways to present their own child classes, it's hard to force modules to comply with "interface" description by common language means. Therefore, we have to establish these exchanges by documenting them properly, letting modules to opt-in, announcing to their user they follow a set of **protocols**.

A protocol describes an optional **query** and corresponding response **packet**, listing required arguments of the query, required and optional attributes and their types and meanings of the response. Usually, the query is implemented by a shared function, returning the packet, but protocols may be defined without need for the query part - exchange of specified packet may be agreed method of communication between multiple shared functions, to pass relevant information between modules.


Known protocols
---------------

.. toctree::
   :maxdepth: 1

   cache
   provisioner-capabilities
   testing-environment
