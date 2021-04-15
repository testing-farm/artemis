#!/usr/bin/env python

# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Generate RST files documenting modules.
"""

import inspect
import os
import sys
import re

import gluetool


LOGGER = gluetool.log.Logging.setup_logger()
OUTPUT_DIR = 'docs/source'

MOD_TEMPLATE = """
``{{ name }}``
{{ title_underline }}

**{{ description }}**

.. automoddesc:: {{ modpath }}.{{ klass }}
   :noindex:


Shared functions
----------------

{{ shared_functions }}


Options
-------

.. argparse::
   :filename: source/module_parsers.py
   :func: get_parser_{{ klass }}
   :prog: {{ name }}
"""

SHARED_TEMPLATE = """
.. automethod:: {{ modpath }}.{{ klass }}.{{ shared_name }}
   :noindex:

"""

ARGS_TEMPLATE = """

def get_parser_{{ klass }}():
    from {{ modpath }} import {{ klass }}
    return {{ klass }}._create_args_parser()
"""


def gather_module_data():
    LOGGER.info('gathering data on all available modules')

    glue = gluetool.Glue()
    glue.modules = glue.discover_modules()

    cwd = os.getcwd() + '/'
    modules = []
    classes = {}

    for name, properties in glue.modules.iteritems():
        # These modules are provided by gluetool, therefore they are not easily importable
        # by Sphinx. Skipping them to allow Sphinx to continue with our local modules.
        if name in ('bash-completion', 'dep-list', 'yaml-pipeline'):
            continue

        klass = properties.klass.__name__
        if klass in classes:
            continue

        classes[klass] = True

        # get file where class is stored
        filepath = inspect.getfile(properties.klass)

        # strip the CWD out
        filepath = filepath.replace(os.path.commonprefix([cwd, filepath]), '')

        modpath = os.path.splitext(filepath)[0].replace('/', '.')

        # strip tox modpath out
        modpath = re.sub(r'\.tox\..*\.site-packages\.', '', modpath)
        modpath = re.sub(r'\.tox\..*\.gluetool_modules.', '', modpath)

        # pylint: disable=line-too-long
        if properties.klass.description:
            description = properties.klass.description

        else:
            description = 'Module did not provide a description'

        filepath = filepath.replace('-', '_')

        try:
            stat = os.stat(filepath)

        except OSError:
            stat = None

        modules.append({
            'name': name,
            'description': description,
            'klass': klass,
            'filepath': filepath,
            'modclass': properties.klass,
            'modpath': modpath,
            'filepath_mtime': stat.st_mtime if stat else sys.maxint
        })

    return modules


def write_module_doc(module_data, output_dir):
    doc_file = '{}/modules/{}.rst'.format(output_dir, module_data['name'])

    try:
        doc_mtime = os.stat(doc_file).st_mtime

    except BaseException:
        doc_mtime = 0

    if module_data['filepath_mtime'] <= doc_mtime:
        LOGGER.info('skipping module {} because it was not modified'.format(module_data['name']))
        return

    module_data['title_underline'] = '=' * (4 + len(module_data['name']))

    shared_functions = module_data['modclass'].shared_functions
    if shared_functions:
        module_data['shared_functions'] = '\n'.join([
            # pylint: disable=line-too-long
            gluetool.utils.render_template(SHARED_TEMPLATE, shared_name=name, **module_data)
            for name in shared_functions
        ])

    else:
        module_data['shared_functions'] = ''

    with open(doc_file, 'w') as f:
        f.write(gluetool.utils.render_template(MOD_TEMPLATE, **module_data))
        f.flush()

    LOGGER.info('module {} doc page written'.format(module_data['name']))


def write_args_parser_getters(modules, output_dir):
    with open('{}/module_parsers.py'.format(output_dir), 'w') as f:
        f.write('# pylint: disable=invalid-name,protected-access\n')

        for module_data in modules:
            f.write(gluetool.utils.render_template(ARGS_TEMPLATE, **module_data) + '\n')

        f.flush()


def write_index_doc(modules, output_dir):
    with open('docs/source/modules.txt', 'r') as f:
        with open('{}/modules.rst'.format(output_dir), 'w') as g:
            g.write(f.read().format(modules='\n'.join(sorted([
                # pylint: disable=line-too-long
                '{}\n'.format(
                    gluetool.utils.render_template(
                        '`{{ name }} <modules/{{ name }}.html>`_\n\n  {{ description }}\n',
                        **module_data
                    )
                )
                for module_data in modules
            ]))))
            g.flush()


def main():
    output_dir = OUTPUT_DIR if len(sys.argv) == 1 else sys.argv[1]
    modules = gather_module_data()

    for module_data in modules:
        write_module_doc(module_data, output_dir)

    write_args_parser_getters(modules, output_dir)
    write_index_doc(modules, output_dir)


if __name__ == '__main__':
    main()
