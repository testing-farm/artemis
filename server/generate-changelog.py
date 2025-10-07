#!/usr/bin/env python

# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import re
import sys

import jinja2

USAGE = """
git log ... | generate-changelog.py [-h|--help]

Pipe an output of `git log` command to this script, to get changelog entries, according to
https://keepachangelog.com/en/1.0.0/.

For example:

$ git log <last version tag>..master | poetry run ./generate-changelog.py
$ git show | poetry run ./generate-changelog.py
"""


SECTION_NAMES = ['Added', 'Changed', 'Deprecated', 'Removed', 'Fixed', 'Security']


SECTION_PATTERNS = {
    re.compile(rf'(?i)^{section_name.lower()}\s*:\s*.+$'): section_name for section_name in SECTION_NAMES
}


SECTION_TEMPLATE = jinja2.Template("""
## {{ SECTION_NAME }}
{% for item in SECTION_ITEMS %}
* {{ item }}
{%- endfor %}
""")


def usage() -> None:
    print(USAGE)


def main() -> None:
    section_items: dict[str, list[str]] = {section_name: [] for section_name in SECTION_NAMES}

    for line in sys.stdin:
        line = line.strip()

        for pattern, section_name in SECTION_PATTERNS.items():
            if not pattern.match(line):
                continue

            section_items[section_name].append(line.split(':', 1)[1].strip())

    for name, items in section_items.items():
        if not items:
            continue

        print(SECTION_TEMPLATE.render(SECTION_NAME=name, SECTION_ITEMS=items).strip())
        print()
        print()


if __name__ == '__main__':
    if (len(sys.argv) == 2 and sys.argv[1].lower() in ('-h', '--help')) or sys.stdin.isatty():
        usage()

        sys.exit(0)

    main()
