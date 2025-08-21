# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import io
import os
from unittest import mock

import pytest
import rich.console
from tft.artemis_cli import print_guest_logs


def _load_expected_data(relative_path: str):
    dir_path = os.path.dirname(os.path.realpath(__file__))
    with open(os.path.join(dir_path, relative_path)) as f:
        return f.read()


@pytest.mark.parametrize(
    ('raw_log', 'expected_file'),
    [
        # Make sure ansi color codes are stripped
        (
            '\x1b[H\x1b[J\x1b[1;1H\x1b[1;1H10    \x1b[1;1H9    \x1b[1;1H8    \x1b[1;1H7    \x1b[1;1H6    \x1b[1;1H5 logs',
            'data/ansi_logs',
        ),
        # Make sure that if log is less than 2 * 10 (default value of split-by-line var) lines its contents won't be
        # printed out twice
        ('line1\nline2\nline3\n', 'data/short_log'),
        (
            'the 1-9 lines should be shown\n'
            + '\n'.join(str(i) for i in range(1, 19))
            + '\nlines 10 - 18 should be shown as well',
            'data/short_log_head_tail_split_overlap',
        ),
        # the usual long log case
        ('\n'.join(str(i) for i in range(1, 42)), 'data/long_log'),
    ],
)
def test_print_table_logs(raw_log, expected_file):
    configuration_mock = mock.Mock(output_format='table')
    console = rich.console.Console(file=io.StringIO(), width=120)
    print_guest_logs(
        configuration_mock,
        [
            {
                'blob': raw_log,
                'contenttype': 'text/plain',
                'state': 'in-progress',
                'url': None,
                'updated': '2024-05-14T13:30:03',
                'expires': None,
            }
        ],
        console,
    )
    res = console.file.getvalue()
    expected = _load_expected_data(expected_file)
    assert res == expected
