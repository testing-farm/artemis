# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import io
import json
from unittest import mock

import rich.console
from tft.artemis_cli import print_pools


SAMPLE_POOLS = [
    {'poolname': 'pool-azure-2', 'driver': 'azure'},
    {'poolname': 'pool-azure-1', 'driver': 'azure'},
    {'poolname': 'pool-aws-1', 'driver': 'aws'},
]


def test_print_pools_table():
    cfg = mock.Mock(output_format='table')
    console = rich.console.Console(file=io.StringIO(), width=120)

    print_pools(cfg, SAMPLE_POOLS, console)

    output = console.file.getvalue()

    assert 'Pool' in output
    assert 'Driver' in output
    assert 'aws' in output
    assert 'azure' in output
    assert 'pool-aws-1' in output
    assert 'pool-azure-1' in output
    assert 'pool-azure-2' in output

    # Pool column comes before Driver column
    assert output.index('Pool') < output.index('Driver')


def test_print_pools_table_sorted():
    cfg = mock.Mock(output_format='table')
    console = rich.console.Console(file=io.StringIO(), width=120)

    print_pools(cfg, SAMPLE_POOLS, console)

    output = console.file.getvalue()

    assert output.index('pool-aws-1') < output.index('pool-azure-1')
    assert output.index('pool-azure-1') < output.index('pool-azure-2')


def test_print_pools_json():
    cfg = mock.Mock(output_format='json')
    console = rich.console.Console(file=io.StringIO(), width=120)

    print_pools(cfg, SAMPLE_POOLS, console)

    output = console.file.getvalue()
    data = json.loads(output)

    assert data == SAMPLE_POOLS


def test_print_pools_empty():
    cfg = mock.Mock(output_format='table')
    console = rich.console.Console(file=io.StringIO(), width=120)

    print_pools(cfg, [], console)

    output = console.file.getvalue()

    assert 'Pool' in output
    assert 'Driver' in output
