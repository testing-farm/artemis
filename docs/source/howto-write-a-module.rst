How to: write a module
======================

Before moving on to the module implementation, set up your development environment. See :doc:`DEVELOPMENT` for details.

In this tutorial, you will see a simplicity of writing ``citool`` module. By the end, you will have a module that communicates with a public `API <https://catfact.ninja/>`_ and provide random facts to itself and subsequent modules in the pipeline.

Name and description
--------------------

The module is a class that inherits the ``gluetool.Module`` and it's stored in ``gluetool_modules/`` folder.
After inheriting, you need to define class variables ``name`` and ``description``.

The ``name`` identifies a module in a pipeline and must be unique. The ``description`` defines a description of the module and will be visible in ``citool -l`` and module help.


.. code-block:: python

    # cat_facts_api.py

    import gluetool

    class CatFactsAPI(gluetool.Module):
        name = 'cat-facts-api'
        description = 'Provide access to the cat facts API'

So far, the module doesn't have any functionality, but ``citool`` can already identify it. You can check it if you write ``citool -l`` or ``citool cat-facts-api --help`` in a command line.

.. code-block:: plain

    $ citool -l
    Available modules
        cat-facts-api         Provide access to the cat facts API

    $ citool cat-facts-api --help
    usage: cat-facts-api [options]

    optional arguments:
      -h, --help  show this help message and exit

Basic methods
-------------

The module has 3 basic methods:
    * ``sanity()`` - executed before any module starts.
    * ``execute()`` - executed when previous module ``execute()`` finished.
    * ``destroy()`` - executed in reverse order after all modules finished.

Let's add one of the basic methods. The ``execute()`` method is a main entrypoint of the module. Obviously, it implements the main logic of the module.

.. code-block:: python
    :emphasize-lines: 9-10

    # cat_facts_api.py

    import gluetool

    class CatFactsAPI(gluetool.Module):
        name = 'cat-facts-api'
        description = 'Provide access to the cat facts API'

        def execute(self):
            self.info('I like cats!')

After that, you can start a pipeline with this module.

.. code-block:: shell

    $ citool cat-facts-api
    [00:00:00] [+] [cat-facts-api] I like cats!

Basic logging
-------------

The ``self.info()`` is a simple method to print an info string to the command line. If you want to print a warning or debug information, use ``self.warn()`` and ``self.debug()``.

.. code-block:: python
    :emphasize-lines: 11-12

    # cat_facts_api.py

    import gluetool

    class CatFactsAPI(gluetool.Module):
        name = 'cat-facts-api'
        description = 'Provide access to the cat facts API'

        def execute(self):
            self.info('I like cats!')
            self.warn('Cats hate me!')
            self.debug("Actually, I don't like them")

.. code-block:: shell

    $ citool cat-facts-api
    [00:00:00] [+] [cat-facts-api] I like cats!
    [00:00:00] [W] [cat-facts-api] Cats hate me!

.. note::
    As you have noticed, the debug message doesn't appear on the command line. If you want to see it on the command line, add ``-d`` (WARNING: very verbose!) or ``-v`` (WARNING: even more verbose than ``-d``!) as a ``citool`` option in the command line. The best way to see it is by logging in the log file. Add ``-o DEBUG_FILE`` as an option to log messages with at least DEBUG level or ``-v VERBOSE_FILE`` to log messages with VERBOSE level.

Shared function
---------------

The shared function is a method of the module instance that other modules can use. It allows communication and collaboration of modules inside a pipeline. Our shared function will request a fact about cats from the API. To expose the shared function add its name to ``shared_functions`` list (a module class attribute) and ``citool`` will recognize the function as shared.

.. code-block:: python
    :emphasize-lines: 6, 11-25

    # cat_facts_api.py

    import gluetool

    BASEURL='https://catfact.ninja/'

    class CatFacts(gluetool.Module):
        name = 'cat-facts-api'
        description = 'Provide access to the cat facts API'

        shared_functions = ['get_fact']

        def get_fact(self):
            url = '{}fact'.format(BASEURL)
            json = self.get_json(url)
            if json:
                fact = json['fact']
                self.debug(fact)
                return fact

        def get_json(self, url):
            with gluetool.utils.requests() as R: # wraped requests module with better logging
                r = R.get(url)
                if r.status_code == R.codes.ok:
                    return r.json()
                # error handling is explained later

        def execute(self):
            self.info('I like cats!')

For using the function we need to make another module. The module will print a result of the function. Before calling the shared function it needs to be checked. The ``self.require_shared()`` method checks if a shared function is provided or print traceback otherwise.

.. code-block:: python

    # cat_fact.py

    import gluetool

    class CatFacts(gluetool.Module):
        name = 'cat-fact'
        description = 'Get a fact from API and print it'

        def execute(self):
            self.require_shared('get_fact') # check if shared function is available
            fact = self.shared('get_fact') # call the shared function
            self.info(fact)

And if you make a pipeline from these modules, you will see a fact on your command line


.. code-block:: plain

    $ citool cat-facts-api cat-fact

    [00:00:00] [+] [cat-facts-api] I like cats!
    [00:00:00] [+] [cat-fact] Cats' hearing stops at 65 kHz (kilohertz)

.. note::

    The ``citool`` runs the modules sequentially as placed on the command line. A shared function is made visible after the module had been run, so it is available only to next modules on the command line.

    .. code-block:: plain

         $ citool foo cats-fact-api cat-fact bar
                            |
                            +------------------>
                             visibility of
                               get_fact()

Options and module configuration
--------------------------------

The `API <https://catfact.ninja/>`_ provides variable ``max_length`` which defines a maximum length of a fact. What if we want to add a default value and change the value of this variable from the command line later? Here ``options`` is coming to help us. The ``options`` is a dictionary defined in the module. It provides 3 layers of values (will be described later), a method to access options and pretty output in the help message of a module. The method ``self.option('option-name')`` give access to the option of the module. It returns the value or ``None`` if the value is not defined. According to the best practices, we should get rid of the global variable ``BASEURL`` and move it to the ``options`` as well.

.. code-block:: python
    :emphasize-lines: 9-21, 26-29

    # cat_facts_api.py

    import gluetool
    from gluetool.utils import requests

    class CatFacts(gluetool.Module):
        name = 'cat-facts-api'
        description = 'Provide access to the cat facts API'

        options = {
            'baseurl': {
                'help': 'Baseurl of the API',
                'type': str,
                'default': 'https://catfact.ninja'
            }
            'max-length': {                    # name of the option
                'help': 'Max length of fact',  # short description of the option
                'type': int,                   # type of the variable
                'default': 140                 # default value
            }
        }

        shared_functions = ['get_fact']

        def get_fact(self):
            url = '{}/fact?max_length={}'.format(
                self.option('baseurl'),
                self.option('max-length')
            )
            json = self.get_json(url)
            if json:
                fact = json['fact']
                self.debug(fact)
                return fact

        def get_json(self, url):
            with gluetool.utils.requests() as R:
                r = R.get(url)
                if r.status_code == R.codes.ok:
                    return r.json()

        def execute(self):
            self.info('I like cats!')

There are 3 layers of defining the value of an option (a later layer overrides the previous one):
    * The value defined by the default key in the option’s dictionary
    * The value read from the module configuration
    * The value read from the module’s command line argument

The first one is mentioned in the example above. For the second one, we need to make a configuration file in INI format for the module. The file will be stored in ``citool-config/config/`` directory and its name will be the same as the name of the module.

.. code-block:: plain

    # cat-facts-api

    [default]
    max-length = 100

Now, the used value will be 100 instead of 140.

The last layer represents an option of the module in the command line. For example, if you execute the next command, the default value will be 50:

.. code-block:: plain

    $ citool cat-facts-api --max-length 50 cat-fact

Multiple configurations
-----------------------

In some situations, we need to have several configurations for one module. The only thing you need to do is making a new config file with another name.

.. code-block:: plain

    # short-cat-facts-api

    [default]
    max-length = 20

And then you can apply the config by joining a config name to the module with ':' separator.

.. code-block:: plain

    $ citool short-cat-facts-api:cat-facts-api cat-fact

    [00:00:00] [+] [cat-facts-api] I like cats!
    [00:00:00] [E] Exception raised in module 'cat-fact': fact
    [00:00:00] [E] Exiting with status -1


Oops, an error was raised. I guess the `API <https://catfact.ninja/>`_ doesn't have any fact with length 20 or less. And that brings us to the next part.


Exceptions
----------

The ``citool`` has next exceptions:

    * ``GlueError`` - A generic exception.
    * ``GlueSoftError`` - An exception that caused outside of ``citool`` infrastructure.
    * ``GlueRetryError`` - Retry ``citool`` exception
    * ``GlueCommandError`` - An exception during running bash command.

In this case, ``GlueSoftError`` is most suitable for the issue.

.. code-block:: python
    :emphasize-lines: 3, 9, 11

    # cat_facts_api.py

    from gluetool.glue import GlueSoftError
    ...
        def get_json(self, url):
            with gluetool.utils.requests() as R:
                r = R.get(url)
                if r.status_code != R.codes.ok:
                    raise SoftGlueError('Status code of the response is {}'. format(r.status_code))
                if not r.json():
                    raise SoftGlueError('Status is "OK" but json is empty.', )
                return r.json()
    ...

Now, the output of the previous pipeline looks like:

.. code-block:: plain

    $ citool short-cat-facts-api:cat-facts-api cat-fact

    [00:00:00] [+] [cat-facts-api] I like cats!
    [00:00:00] [E] Exception raised in module 'cat-fact': Status is "OK" but json is empty.

Advanced logging
----------------

Also, the `API <https://catfact.ninja/>`_ can return a list of facts. Let's write another shared function to provide the functionality.

.. code-block:: python
    :emphasize-lines: 14-18, 21, 23-31

    #cat_facts_api.py
    ...
        options = {
            'baseurl': {
                'help': 'Baseurl of the API',
                'type': str,
                'default': 'https://catfact.ninja'
            }
            'max-length': {
                'help': 'Max length of fact',
                'type': int,
                'default': 140
            },
            'limit': {
                'help': 'limit the number of facts',
                'type': int,
                'default': 3
            }
        }

        shared_functions = ['get_fact', 'get_facts']

        def get_facts(self):
            url = '{}/facts?limit={}&max_length={}'.format(
                self.option('baseurl'),
                self.option('limit'),
                self.option('max-length')
            )
            json = self.get_json(url)
            facts = json['data']
            return facts
    ...

In ``citool`` are 3 methods for advanced logging:
    * ``log_dict`` log structured data as a JSON or a Python list.
    * ``log_blob`` log unstructured data as an output of a command.
    * ``log_table`` log a formatted table.

Despite the fact that ``log_dict`` **is recommended for JSON**, we will try all of these methods with the list of facts for learning purpose. The methods need to know one of the logger methods they will use, a label to show the meaning of the logged data and data that will be logged.

.. code-block:: python
    :emphasize-lines: 4, 13-16

    # cat_fact.py

    import gluetool
    from gluetool.log import log_dict, log_blob, log_tabl

    class CatFacts(gluetool.Module):
        name = 'cat-fact'
        description = 'Get a fact from API and print it'

        def execute(self):
            self.require_shared('get_fact') # check if shared function is available
            facts = self.shared('get_facts') # call the shared function
            log_dict(self.info,'List of facts as a dict', facts)
            log_blob(self.info,'List of facts as unstructured data', facts)
            log_table(self.info,'List of facts as a table', facts)

The output of the pipeline will look like:

.. code-block:: plain

    $ citool cat-facts-api cat-fact

    [00:00:00] [+] [cat-fact] List of facts as a dict:
    [
        {
            "fact": "A form of AIDS exists in cats.",
            "length": 30
        },
        {
            "fact": "The leopard is the most widespread of all big cats.",
            "length": 51
        },
        {
            "fact": "Cats make about 100 different sounds. Dogs make only about 10.",
            "length": 62
        }
    ]
    [00:00:00] [+] [cat-fact] List of facts as unstructured data:
    ---v---v---v---v---v---
    [{u'length': 30, u'fact': u'A form of AIDS exists in cats.'}, {u'length': 51, u'fact': u'The leopard is the most widespread of all big cats.'}, {u'length': 62, u'fact': u'Cats make about 100 different sounds. Dogs make only about 10.'}]
    ---^---^---^---^---^---
    [00:00:00] [+] [cat-fact] List of facts as a table:
    --  --------------------------------------------------------------
    30  A form of AIDS exists in cats.
    51  The leopard is the most widespread of all big cats.
    62  Cats make about 100 different sounds. Dogs make only about 10.
    --  --------------------------------------------------------------

Docstring
---------

The ``citool`` supports a "reStructuredText" docstring recommended by `PEP <https://www.python.org/dev/peps/pep-0287/>`_. The framework parse docstrings in the module and print it in a module help.

The final module looks like:

.. code-block:: python
    :emphasize-lines: 8-12, 37-42, 54-59

    #cat_facts_api.py

    import gluetool
    from gluetool.glue import SoftGlueError
    from gluetool.utils import requests

    class CatFactsAPI(gluetool.Module):
        """
        Cat facts module.

        The module provides two endpoints of the cat facts API.
        """
        name = 'cat-facts-api'
        description = 'Provide access to the cat facts API'

        options = {
            'baseurl': {
                'help': 'Baseurl of the API',
                'type': str,
                'default': 'https://catfact.ninja'
            }
            'max-length': {
                'help': 'Max length of fact',
                'type': int,
                'default': 140
            },
            'limit': {
                'help': 'limit the number of facts',
                'type': int,
                'default': 3
            }
        }

        shared_functions = ['get_fact', 'get_facts']

        def get_facts(self):
            """
            Get a list of facts from the API or raise an error otherwise

            :rtype: list(str)
            :returns: A list of facts with `max-length` defined on options
            """
            url = '{}/facts?limit={}&max_length={}'.format(
                self.option('baseurl'),
                self.option('limit'),
                self.option('max-length')
            )
            json = self.get_json(url)
            facts = json['data']
            return facts


        def get_fact(self):
            """
            Get a fact from the API or raise an error otherwise

            :rtype: str
            :returns: A fact with `max-length` defined on options
            """
            url = '{}facts?max_length={}'.format(
                self.option('baseurl'),
                self.option('max-length')
            json = self.get_json(url)
            fact = json['fact']
            self.debug(fact)
            return fact


        def get_json(self, url):
            with gluetool.utils.requests() as R:
                r = R.get(url)
                if r.status_code != R.codes.ok:
                    raise SoftGlueError('Status code of the response is {}'. format(r.status_code))
                if not r.json():
                    raise SoftGlueError('Status is "OK" but json is empty.', )
                return r.json()


        def execute(self):
            self.info('I like cats!')

And the output of ``--help`` is following:

.. code-block:: plain

    $citool cat-facts-api --help

    usage: cat-facts-api [options]

        Cat facts module.

        The module provides two endpoints of the cat facts API.

    optional arguments:
      -h, --help            show this help message and exit
      --limit LIMIT         limit the number of facts
      --max-length MAX_LENGTH
                            Max length of fact

    ** Shared functions **

      get_fact()

        Get a fact from the API or raise an error otherwise

        rtype:
           str

        returns:
           A fact with *max-length* defined on options

      get_facts()

        Get a list of facts from the API or raise an error otherwise

        rtype:
           list(str)

        returns:
           A list of facts with *max-length* defined on options

Testing
-------

A module isn't complete if it doesn't have tests. Tests are stored in ``gluetool_modules/tests/`` folder and a filename of tests start with ``test_``. Tests are powered by the `pytest <https://docs.pytest.org/en/latest/contents.html#>`_ framework and automated by `tox <https://tox.readthedocs.io/en/latest/>`_.

The basic test which will test loadability of the module consists of a `fixture <https://docs.pytest.org/en/latest/fixture.html>`_ that will represent a module and a test case that will try to manually load a module to a pipeline.

.. code-block:: python

    #test_cat_fact_api.py

    import pytest # main testing framework

    import gluetool_modules.cat_facts_api # importing of a module that will be tested
    from . import check_loadable, create_module # helper function to easy creating of a module


    # The fixture provides a created module, the main access to a module for testing.
    @pytest.fixture(name='module')
    def fixture_module():
        # the function returns glue and module instances. We are interested in the module only.
        return create_module(gluetool_modules.cat_facts_api.CatFactsAPI)[1]


    def test_loadable(module):
        check_loadable(module.glue, 'gluetool_modules/cat_facts_api.py', 'CatFactsAPI')

.. warning::
    If you put your module in a subdirectory in `gluetool_modules` the import will change. For example if you put it into subdirectory `testing` the module import would be `import gluetool_modules.testing.cat_facts_api`

After that, you can call ``tox`` from the ``gluetool-modules`` folder to run all types of tests for all modules. If you want to reduce waiting of the end of testing, you can call ``tox -e py27-unit-tests -- gluetool_modules/tests/test_cat_facts_api.py`` to unit test the module.

.. note::
    If you have a ``pip`` error that contains ``"no such option: --process-dependency-links"``, try to downgrade the ``pip`` to the version ``18.1`` and install ``tox-virtualenv-no-download`` via ``pip`` to your virtual environment.
