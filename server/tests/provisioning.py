# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import datetime
import json
import logging
import os
import statistics
import subprocess
import sys
import threading
import time
from typing import Any, Callable, Dict, List, Optional

import colorama


@dataclasses.dataclass
class GuestRequest:
    guestname: Optional[str] = None
    state: str = 'missing'

    active: bool = True

    details: Dict[str, Any] = dataclasses.field(default_factory=dict)

    ctime: datetime.datetime = dataclasses.field(default_factory=datetime.datetime.utcnow)
    state_mtime: datetime.datetime = dataclasses.field(default_factory=datetime.datetime.utcnow)
    ftime: Optional[datetime.datetime] = None

    deadline: Optional[datetime.timedelta] = None

    @classmethod
    def submit(
        cls,
        compose: str,
        arch: str,
        pool: Optional[str] = None,
        deadline: Optional[datetime.timedelta] = None,
        **details: Any
    ) -> Optional['GuestRequest']:
        details['compose'] = compose
        details['arch'] = arch
        details['pool'] = pool

        cli_options = [
            os.getenv('HERD_ARTEMIS_CLI', 'artemis-cli'),
            'guest',
            'create',
            '--keyname', 'ci-key',
            '--compose', compose,
            '--arch', arch,
            '--user-data', '{"owner": "artemis-tests"}'  # noqa: FS003
        ]

        if pool is not None:
            cli_options += ['--pool', pool]

        try:
            output = subprocess.check_output(cli_options)

        except subprocess.CalledProcessError:
            logging.error('failed to submit request', exc_info=sys.exc_info())

            return None

        return GuestRequest(
            guestname=json.loads(output)['guestname'],
            state='routing',
            details=details,
            ctime=datetime.datetime.utcnow(),
            deadline=deadline
        )

    def update(self) -> bool:
        assert self.guestname is not None

        try:
            output = subprocess.check_output(
                [
                    os.getenv('HERD_ARTEMIS_CLI', 'artemis-cli'),
                    'guest',
                    'inspect',
                    self.guestname
                ]
            )

        except subprocess.CalledProcessError:
            logging.error(f'{self.guestname}: failed to inspect request', exc_info=sys.exc_info())

            return False

        if self.deadline is not None and (datetime.datetime.utcnow() - self.ctime) >= self.deadline:
            self.state = 'cancelled'

            self.cancel()

        else:
            self.state = json.loads(output)['state']

        if self.state in ('ready', 'error', 'cancelled'):
            self.ftime = datetime.datetime.utcnow()

        return True

    def cancel(self) -> bool:
        if self.guestname is None:
            return True

        try:
            subprocess.check_output(
                [
                    os.getenv('HERD_ARTEMIS_CLI', 'artemis-cli'),
                    'guest',
                    'cancel',
                    self.guestname
                ]
            )

        except subprocess.CalledProcessError:
            logging.error(f'{self.guestname}: failed to cancel request', exc_info=sys.exc_info())

            return False

        self.active = False

        return True

    @property
    def duration(self) -> datetime.timedelta:
        return (self.ftime or datetime.datetime.utcnow()) - self.ctime

    @property
    def state_age(self) -> datetime.timedelta:
        return datetime.datetime.utcnow() - self.state_mtime


class HerdPrinter(threading.Thread):
    KEEP_PRINTING = True

    def __init__(self, guests: List[GuestRequest]) -> None:
        super(HerdPrinter, self).__init__(target=self.do_run, args=(guests,), daemon=False)

    def do_run(self, guests: List[GuestRequest]) -> None:
        start = datetime.datetime.utcnow()

        print(f' {colorama.Fore.YELLOW}routing{colorama.Fore.RESET} => {colorama.Fore.MAGENTA}provisioning{colorama.Fore.RESET} => {colorama.Fore.BLUE}promised{colorama.Fore.RESET} => {colorama.Fore.CYAN}preparing{colorama.Fore.RESET} => {colorama.Fore.GREEN}ready{colorama.Fore.RESET} | {colorama.Fore.RED}error{colorama.Fore.RESET} | {colorama.Fore.LIGHTRED_EX}cancelled{colorama.Fore.RESET}')  # noqa: E501
        print()

        while self.KEEP_PRINTING:
            signs = []

            for request in guests:
                if request.state == 'routing':
                    signs.append(f'{colorama.Fore.YELLOW}*')

                elif request.state == 'provisioning':
                    signs.append(f'{colorama.Fore.MAGENTA}*')

                elif request.state == 'promised':
                    signs.append(f'{colorama.Fore.BLUE}*')

                elif request.state == 'preparing':
                    signs.append(f'{colorama.Fore.CYAN}*')

                elif request.state == 'ready':
                    signs.append(f'{colorama.Fore.GREEN}*')

                elif request.state == 'cancelled':
                    signs.append(f'{colorama.Fore.LIGHTRED_EX}*')

                elif request.state in ('error'):
                    signs.append(f'{colorama.Fore.RED}*')

                elif request.state == 'removed':
                    signs.append(f'{colorama.Fore.WHITE}*')

                else:
                    signs.append(f'{colorama.Fore.WHITE}*')

            print(''.join(signs) + colorama.Fore.RESET)

            time.sleep(10)

        end = datetime.datetime.utcnow()

        print(str(end - start))


def run_herd(populate: Callable[[List[GuestRequest]], None]) -> List[GuestRequest]:
    guests: List[GuestRequest] = []

    populate(guests)

    printer = HerdPrinter(guests)
    printer.start()

    all_done = False

    while not all_done:
        all_done = True

        for request in guests:
            if request.state == 'missing':
                continue

            if request.active is not True:
                continue

            all_done = False

            request.update()

            if request.state in ('ready', 'error'):
                request.cancel()

        time.sleep(10)

    printer.KEEP_PRINTING = False
    printer.join()

    durations = [
        guest.duration.total_seconds()
        for guest in guests
        if guest.state == 'ready' and guest.duration is not None
    ]

    if durations:
        print(f'Min:    {min(durations)}')
        print(f'Mean:   {statistics.mean(durations)}')
        print(f'Median: {statistics.median(durations)}')
        print(f'Max:    {max(durations)}')

    return guests
