Collection of gluetool modules used by Testing Farm Team
---------------------------------------------------------

Documentation
-------------

For more information see the generated documentation

https://gluetool-modules.readthedocs.io

Testing
-------

How to run one concrete test
~~~~~~~~~~~~~~~~~~~~~~~~~~~~

To run a concrete test, you can call tox this way.

    tox -e py27-unit-tests -- gluetool_modules/tests/test_wow.py::test_with_basic_params
