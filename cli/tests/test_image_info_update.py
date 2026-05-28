# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import io
import json
from unittest import mock

import rich.console
from tft.artemis_cli import parse_metrics, print_image_info_update


SAMPLE_POOLS = [
    {'poolname': 'pool-azure-2', 'driver': 'azure'},
    {'poolname': 'pool-azure-1', 'driver': 'azure'},
    {'poolname': 'pool-aws-1', 'driver': 'aws'},
]

SAMPLE_METRICS_RAW = """\
# HELP pool_image_info_updated_timestamp Last time pool image info has been updated.
# TYPE pool_image_info_updated_timestamp gauge
pool_image_info_updated_timestamp{pool="pool-aws-1"} 1.7e+09
pool_image_info_updated_timestamp{pool="pool-azure-1"} 1.8e+09
pool_image_info_updated_timestamp{pool="pool-azure-2"} 1.9e+09
"""

SAMPLE_METRICS = parse_metrics(SAMPLE_METRICS_RAW)


def test_print_image_info_update_table():
    cfg = mock.Mock(output_format='table')
    console = rich.console.Console(file=io.StringIO(), width=120)

    print_image_info_update(cfg, SAMPLE_POOLS, SAMPLE_METRICS, console)

    output = console.file.getvalue()

    assert 'Pool' in output
    assert 'Driver' in output
    assert 'Last Updated' in output
    assert 'pool-aws-1' in output
    assert 'pool-azure-1' in output
    assert 'pool-azure-2' in output
    assert 'aws' in output
    assert 'azure' in output


def test_print_image_info_update_sorted():
    cfg = mock.Mock(output_format='table')
    console = rich.console.Console(file=io.StringIO(), width=120)

    print_image_info_update(cfg, SAMPLE_POOLS, SAMPLE_METRICS, console)

    output = console.file.getvalue()

    assert output.index('pool-aws-1') < output.index('pool-azure-1')
    assert output.index('pool-azure-1') < output.index('pool-azure-2')


def test_print_image_info_update_json():
    cfg = mock.Mock(output_format='json')
    console = rich.console.Console(file=io.StringIO(), width=120)

    print_image_info_update(cfg, SAMPLE_POOLS, SAMPLE_METRICS, console)

    output = console.file.getvalue()
    data = json.loads(output)

    assert len(data) == 3
    assert all(
        'poolname' in entry and 'driver' in entry and 'updated' in entry
        for entry in data
    )
    assert all(isinstance(entry['updated'], float) for entry in data)


def test_print_image_info_update_empty():
    cfg = mock.Mock(output_format='table')
    console = rich.console.Console(file=io.StringIO(), width=120)

    print_image_info_update(cfg, [], SAMPLE_METRICS, console)

    output = console.file.getvalue()

    assert 'Pool' in output
    assert 'Driver' in output
    assert 'Last Updated' in output


def test_print_image_info_update_nan_timestamp():
    cfg = mock.Mock(output_format='table')
    console = rich.console.Console(file=io.StringIO(), width=120)

    nan_metrics_raw = """\
# HELP pool_image_info_updated_timestamp Last time pool image info has been updated.
# TYPE pool_image_info_updated_timestamp gauge
pool_image_info_updated_timestamp{pool="pool-aws-1"} NaN
"""
    nan_metrics = parse_metrics(nan_metrics_raw)

    print_image_info_update(cfg, SAMPLE_POOLS, nan_metrics, console)

    output = console.file.getvalue()

    assert 'pool-aws-1' in output
    assert 'N/A' in output
