Installation tests for gluetool-modules
---------------------------------------

This is a collection of installation tests written with the help of `Test Management Tool (tmt) <https://tmt.readthedocs.io/>`

These tests verify that gluetool-modules is installable on recent Fedora, RHEL8 and CentOS8.

We are using TMT here to support this great tool and dogfood it.

How are these tests run
~~~~~~~~~~~~~~~~~~~~~~~

These tests are executed as part of the Gitlab CI pipelines. As the Gitlab CI workers run containers, we use `tmt` with local provisioner
to run the tests directly in the container there

How to run tests manually
~~~~~~~~~~~~~~~~~~~~~~~~~

Please note that ``tmt`` is not added to our virtual environment as it is currently Python3 only, so to install it, use this copr repository:

    dnf -y copr enable psss/tmt
    dnf -y install tmt

For testing and debugging, you can run this test easily using ``tmt`` tool. It will run it in a container via podman, so you
do not need to be afraid it somehow affects your localhost.

To run all installation tests:

    poetry run tmt run

To list all available test plans:

    poetry run tmt plan ls

To run one specific plan:

    poetry run tmt run plan --name /plans/rhel8
