# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import os
from typing import Any, Dict, List, Optional

import gluetool.log
import gluetool.utils
import pytest

from .provisioning import GuestRequest, run_herd


@dataclasses.dataclass
class MatrixItem:
    compose: str
    arch: str = 'x86_64'
    pool: Optional[str] = None

    deadline: Optional[datetime.timedelta] = None


@pytest.fixture(name='matrix_from_file')
def fixture_matrix_from_file() -> List[MatrixItem]:
    matrix: List[MatrixItem] = []
    matrix_specs = gluetool.utils.load_yaml(os.environ['HERD_MATRIX_FILEPATH'])

    if 'HERD_VARIABLES_FILEPATH' not in os.environ:
        variables: Dict[str, Any] = {}

    else:
        variables = gluetool.utils.load_yaml(os.environ['HERD_VARIABLES_FILEPATH'])

    for matrix_item_spec in matrix_specs:
        deadline = None

        if matrix_item_spec.get('deadline'):
            deadline = datetime.timedelta(seconds=int(matrix_item_spec['deadline']))

        for _ in range(matrix_item_spec.get('repeat', 1)):
            matrix += [
                MatrixItem(
                    compose=gluetool.utils.render_template(matrix_item_spec['compose'], **variables),
                    arch=matrix_item_spec['arch'],
                    pool=matrix_item_spec.get('pool'),
                    deadline=deadline
                )
            ]

    return matrix


@pytest.mark.remote_integration
@pytest.mark.skipif(
    os.getenv('HERD_MATRIX_FILEPATH') is None,
    reason='Provide file with desired provisioning matrix via HERD_MATRIX_FILEPATH envvar'
)
def test_provision_matrix_file(matrix_from_file: List[MatrixItem]) -> None:
    def populate(guests: List[GuestRequest]) -> None:
        for matrix_item in matrix_from_file:
            print(f'matrix item: {matrix_item.compose} {matrix_item.arch}')

            guest = GuestRequest.submit(
                compose=matrix_item.compose,
                arch=matrix_item.arch,
                pool=matrix_item.pool,
                compose_raw=matrix_item.compose,
                deadline=matrix_item.deadline
            )

            if guest is not None:
                guests.append(guest)

    guests = run_herd(populate)

    table = [
        ['guestname', 'compose', 'compose', 'arch', 'pool', 'state']
    ]

    for guest in guests:
        assert guest.guestname is not None

        table += [
            [
                guest.guestname,
                guest.details["compose_raw"],
                guest.details["compose"],
                guest.details["arch"],
                guest.details['pool'],
                guest.state
            ]
        ]

    print(gluetool.log.format_table(table, headers='firstrow', tablefmt='psql'))
