# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import json
import os.path
import shutil
import subprocess
import sys
import tempfile
import time
import urllib
import urllib.parse
from time import sleep
from typing import Any, Dict, Generator, List, Optional, cast

import click
import click_completion
import rich.table
import semver
import stackprinter

from . import (DEFAULT_API_RETRIES, DEFAULT_API_TIMEOUT,
               DEFAULT_RETRY_BACKOFF_FACTOR, BasicAuthConfiguration,
               Configuration, artemis_create, artemis_delete, artemis_inspect,
               artemis_update, confirm, fetch_artemis, load_yaml,
               print_broker_tasks, print_events, print_guest_logs,
               print_guests, print_json, print_knobs, print_shelves,
               print_table, print_tasks, print_users, print_yaml,
               validate_struct)

# to prevent infinite loop in pagination support
PAGINATION_MAX_COUNT = 10000

stackprinter.set_excepthook(
    style='darkbg2',
    source_lines=7,
    show_signature=True,
    show_vals='all',
    reverse=False,
    add_summary=False
)

click_completion.init()


API_FEATURE_VERSIONS = {
    feature: semver.VersionInfo.parse(version)
    for feature, version in (
        ('fixed-virtualization-hypervisor-enum', '0.0.58'),
        ('shelving', '0.0.56'),
        ('watchdog-delay', '0.0.56'),
        ('fixed-hw-validation', '0.0.55'),
        ('kickstart', '0.0.53'),
        ('hw-constraints-boot-method', '0.0.32'),
        ('hw-constraints-network', '0.0.28'),
        # Dummy version - we can't actually check the constraints to assure this. That could change if we could verify
        # the constraints with a schema, and that would mean gain access to Artemis server package...
        ('hw-constraints-disk-as-list', '0.0.27'),
        ('log-types', '0.0.26'),
        ('skip-prepare-verify-ssh', '0.0.24'),
        ('hw-constraints', '0.0.19'),
        ('arch-under-hw', '0.0.19'),
        ('supported-baseline', '0.0.17')
    )
}

# FIXME Actual values from artemis_db.GuestLogContentType?
ALLOWED_LOGS = [
    'console:dump/blob',
    'console:dump/url',
    'console:interactive/url',
    'sys.log:dump/url',
    'flasher-debug:dump/url',
    'flasher-debug:dump/blob',
    'flasher-event:dump/url',
    'flasher-event:dump/blob'
]


@click.group()
@click.pass_context
@click.option(
    '-o', '--output-format',
    type=click.Choice(['table', 'json', 'yaml']),
    default='table',
    help='Format of table-like output'
)
@click.option(
    '--config',
    type=str,
    default=click.get_app_dir('artemis-cli'),
    help='Path to the configuration directory'
)
@click.option(
    '--api-timeout',
    type=int,
    default=DEFAULT_API_TIMEOUT,
    help='API request timeout (seconds)'
)
@click.option(
    '--api-retries',
    type=int,
    default=DEFAULT_API_RETRIES,
    help='Number of API retries'
)
@click.option(
    '--api-retry-backoff-factor',
    type=int,
    default=DEFAULT_RETRY_BACKOFF_FACTOR,
    help='API retry backoff factor (seconds)'
)
def cli_root(
    ctx: Any,
    config: str,
    output_format: str,
    api_timeout: int,
    api_retries: int,
    api_retry_backoff_factor: int
) -> None:
    ctx.ensure_object(Configuration)

    cfg = cast(
        Configuration,
        ctx.obj
    )

    cfg.config_dirpath = os.path.expanduser(config)
    cfg.config_filepath = os.path.join(cfg.config_dirpath, 'config.yaml')

    if not os.path.exists(cfg.config_dirpath) or not os.path.exists(cfg.config_filepath):
        if ctx.invoked_subcommand != 'init':
            cfg.logger.info(f'Config file {cfg.config_filepath} does not exists, running configuration wizard.')

        ctx.invoke(cmd_init)
        sys.exit(0)

    cfg.raw_config = load_yaml(cfg.config_filepath)

    validation = validate_struct(cfg.raw_config, 'config')

    if not validation.result or cfg.raw_config is None:
        cfg.logger.error(
            f'Config file {cfg.config_filepath} must be updated, found following validation errors:',
            exit=False
        )

        for error in validation.errors:
            cfg.logger.error(f'* {error.message}', exit=False)

        if cfg.raw_config is None:
            cfg.logger.error('Empty configuration file', exit=False)

        cfg.logger.info('Running configuration wizard.')

        ctx.invoke(cmd_init)
        sys.exit(0)

    cfg.output_format = output_format

    cfg.install_http_retries(api_timeout, api_retries, api_retry_backoff_factor)

    cfg.artemis_api_url = cfg.raw_config['artemis_api_url']
    cfg.artemis_api_version = semver.VersionInfo.parse(cfg.raw_config['artemis_api_version'])
    assert cfg.artemis_api_url is not None

    if 'broker' in cfg.raw_config:
        cfg.broker_management_hostname = cfg.raw_config['broker']['management']['hostname']
        cfg.broker_management_port = cfg.raw_config['broker']['management']['port']
        cfg.broker_management_username = cfg.raw_config['broker']['management']['username']
        cfg.broker_management_password = cfg.raw_config['broker']['management']['password']

    if 'authentication' in cfg.raw_config:
        cfg.authentication_method = cfg.raw_config['authentication']['method']

        if cfg.authentication_method == 'basic':
            if 'basic' not in cfg.raw_config['authentication']:
                cfg.logger.error('Authentication method "basic" requires "basic" configuration')

            cfg.basic_auth = BasicAuthConfiguration(
                username=cfg.raw_config['authentication']['basic']['username'],
                provisioning_token=cfg.raw_config['authentication']['basic']['tokens']['provisioning'],
                admin_token=cfg.raw_config['authentication']['basic']['tokens']['admin']
            )

    if 'provisioning_poll_interval' in cfg.raw_config:
        cfg.provisioning_poll_interval = cfg.raw_config['provisioning_poll_interval']


@cli_root.group(name='guest', short_help='Guest related commands')
@click.pass_obj
def cmd_guest(cfg: Configuration) -> None:
    pass


@cmd_guest.command(name='create', short_help='Create provisioning request')
@click.option('--keyname', required=True, help='name of ssh key')
@click.option('--priority-group', help='name of priority group')
@click.option('--arch', required=True, help='architecture')
@click.option('--hw-constraints', required=False, default=None, help='Optional HW constraints.')
@click.option('--kickstart', required=False, default=None, help='Optional Kickstart specification.')
@click.option('--shelf', required=False, default=None, help='Shelf to use to serve the request')
@click.option('--compose', required=True, help='compose id')
@click.option('--pool', help='name of the pool')
@click.option('--snapshots', is_flag=True, help='require snapshots support')
@click.option('--spot-instance/--no-spot-instance', is_flag=True, default=None, help='require spot instance support')
@click.option('--post-install-script', help='Path to user data script to be executed after vm becomes active')
@click.option(
    '--skip-prepare-verify-ssh/--no-skip-prepare-verify-ssh',
    is_flag=True,
    default=False,
    help='If set, provisioning will skip SSH verification step.'
)
@click.option(
    '--user-data',
    default=None,
    help='Optional JSON mapping to attach to the request.'
)
@click.option('--wait', is_flag=True, help='Wait for guest provisioning to finish before exiting')
@click.option('--log-types', '-l', default=None, metavar='logname:contenttype',
              help='Types of logs that guest should support', type=click.Choice(ALLOWED_LOGS), multiple=True)
@click.option(
    '--watchdog-dispatch-delay',
    type=int,
    default=None,
    help='Watchdog dispatch delay in seconds'
)
@click.option(
    '--watchdog-period-delay',
    type=int,
    default=None,
    help='Watchdog dispatch period in seconds'
)
@click.option(
    '--count',
    type=int,
    default=1,
    help='How many guests to provision at once'
)
@click.option(
    '--test',
    is_flag=True,
    default=False,
    help='If specified, provisioned guest(s) would be returned right after provisioning'
)
@click.pass_context
def cmd_guest_create(
        ctx: Any,
        count: int,
        keyname: Optional[str] = None,
        arch: Optional[str] = None,
        hw_constraints: Optional[str] = None,
        kickstart: Optional[str] = None,
        shelf: Optional[str] = None,
        compose: Optional[str] = None,
        pool: Optional[str] = None,
        snapshots: Optional[bool] = None,
        spot_instance: Optional[bool] = None,
        priority_group: Optional[str] = None,
        post_install_script: Optional[str] = None,
        skip_prepare_verify_ssh: bool = False,
        user_data: Optional[str] = None,
        wait: Optional[bool] = None,
        log_types: Optional[List[str]] = None,
        watchdog_dispatch_delay: Optional[int] = None,
        watchdog_period_delay: Optional[int] = None,
        test: bool = False
) -> None:
    cfg = cast(
        Configuration,
        ctx.obj
    )

    if test and not wait:
        cfg.logger.error('--test cannot be used without --wait')

    assert cfg.artemis_api_version is not None

    environment: Dict[str, Any] = {}

    data: Dict[str, Any] = {
        'environment': environment,
        'keyname': keyname,
        'priority_group': 'default-priority',
        'user_data': {}
    }

    if cfg.artemis_api_version < API_FEATURE_VERSIONS['supported-baseline']:
        cfg.logger.error('Unsupported API version {}, the oldest supported is {}'.format(
            cfg.artemis_api_version,
            API_FEATURE_VERSIONS['supported-baseline']
        ))

    if cfg.artemis_api_version >= API_FEATURE_VERSIONS['skip-prepare-verify-ssh']:
        data['skip_prepare_verify_ssh'] = skip_prepare_verify_ssh

    elif skip_prepare_verify_ssh is True:
        cfg.logger.error('--skip-prepare-verify-ssh is supported with API v0.0.24 and newer')

    if cfg.artemis_api_version >= API_FEATURE_VERSIONS['watchdog-delay']:
        data['watchdog_dispatch_delay'] = watchdog_dispatch_delay
        data['watchdog_period_delay'] = watchdog_period_delay

    elif watchdog_dispatch_delay is not None or watchdog_period_delay is not None:
        cfg.logger.error(
            f'custom watchdog delays are available with API {API_FEATURE_VERSIONS["watchdog-delay"]} and newer')

    if cfg.artemis_api_version >= API_FEATURE_VERSIONS['hw-constraints']:
        environment['hw'] = {
            'arch': arch
        }

        if hw_constraints is not None:
            try:
                environment['hw']['constraints'] = json.loads(hw_constraints)

            except Exception as exc:
                cfg.logger.error(f'failed to parse HW constraints: {exc}')

    elif hw_constraints is not None:
        cfg.logger.error('HW constraints are supported with API 0.0.19 and newer')

    if cfg.artemis_api_version < API_FEATURE_VERSIONS['arch-under-hw']:
        environment['arch'] = arch

    if cfg.artemis_api_version >= API_FEATURE_VERSIONS['kickstart']:
        environment['kickstart'] = {}

        if kickstart:
            try:
                environment['kickstart'] = json.loads(kickstart)
            except Exception as exc:
                cfg.logger.error(f'failed to parse kickstart data: {exc}')

    elif kickstart is not None:
        cfg.logger.error(f'--kickstart is supported with API {API_FEATURE_VERSIONS["kickstart"]} and newer')

    if cfg.artemis_api_version >= API_FEATURE_VERSIONS['shelving']:
        data['shelfname'] = shelf

    elif shelf is not None:
        cfg.logger.error(f'--shelf is supported with API {API_FEATURE_VERSIONS["shelving"]} and newer')

    if user_data is not None:
        try:
            data['user_data'] = json.loads(user_data)

        except Exception as exc:
            cfg.logger.error(f'failed to parse user data: {exc}')

    environment['os'] = {'compose': compose}

    if pool:
        environment['pool'] = pool

    if snapshots:
        environment['snapshots'] = True

    environment['spot_instance'] = spot_instance

    post_install = None
    if post_install_script:
        # check that post_install_script is a valid file and read it
        if os.path.isfile(post_install_script):
            cfg.logger.info('post-install-script argument is treated as a file')

            with open(post_install_script) as f:
                post_install = f.read()

        # check that post_install_script is a valid url, if it is - try to download the script
        elif urllib.parse.urlparse(post_install_script).netloc:
            res = cfg.http_session.get(post_install_script)

            if res.ok:
                cfg.logger.info('post-install-script argument is treated as a url')

                # NOTE(ivasilev) content is bytes so a decode step is necessary
                post_install = res.content.decode("utf-8")

        # If neither of the first 2 steps worked - treat as raw data
        if not post_install:
            cfg.logger.info('post-install-script argument is treated as a raw script')

            # Treat the data as script contents
            # NOTE(ivasilev) Need to remove possible string escaping like \\n
            post_install = post_install_script.replace('\\n', '\n')

    data['post_install_script'] = post_install

    if cfg.artemis_api_version >= API_FEATURE_VERSIONS['log-types']:
        log_types = log_types if log_types else []
        data['log_types'] = list({tuple(log.split('/', 1)) for log in log_types})

    elif log_types:
        cfg.logger.error(f'--log-types is supported with API {API_FEATURE_VERSIONS["log-types"]} and newer')
        sys.exit(1)

    def _create_guests() -> Generator[Any, None, None]:
        for _ in range(count):
            response = artemis_create(cfg, 'guests/', data)

            if not response.ok:
                cfg.logger.unhandled_api_response(response)

            yield response.json()

    if not wait:
        print_guests(cfg, list(_create_guests()))
        return

    if cfg.output_format == 'table':
        def before() -> None:
            cfg.console.clear()

        def on_update(guests: List[Dict[str, Any]]) -> None:
            cfg.console.clear()

            print_guests(cfg, guests)

        def after(guests: List[Dict[str, Any]]) -> None:
            pass

    else:
        def before() -> None:
            pass

        def on_update(guests: List[Dict[str, Any]]) -> None:
            pass

        def after(guests: List[Dict[str, Any]]) -> None:
            print_guests(cfg, guests)

    before()

    guests = list(_create_guests())

    print_guests(cfg, guests)

    with cfg.console.status('Waiting for guests to become ready...', spinner='dots'):
        while True:
            current_guests: List[Any] = guests[:]

            for i, guest in enumerate(current_guests):
                guestname = guest['guestname']
                old_state = guest['state']

                response = artemis_inspect(cfg, 'guests', guestname)

                if not response.ok:
                    cfg.logger.unhandled_api_response(response)

                guests[i] = guest = response.json()
                new_state = guest['state']

                if old_state != new_state:
                    on_update(guests)

            if all(guest['state'] in ('ready', 'error') for guest in guests):
                break

            sleep(cfg.provisioning_poll_interval)

        after(guests)

    all_ready = all(guest['state'] == 'ready' for guest in guests)
    any_error = any(guest['state'] == 'error' for guest in guests)

    if test:
        if all_ready:
            cfg.logger.success('Provisioning finished, guests are ready.')

        elif any_error:
            cfg.logger.error('Provisioning finished with an error.', exit=False)

        ctx.invoke(cmd_cancel, guestnames=[guest['guestname'] for guest in guests])

        sys.exit(1 if any_error else 0)

    else:
        if all_ready:
            cfg.logger.success('Provisioning finished, guests are ready.')

        elif any_error:
            cfg.logger.error('Provisioning finished with an error.')


@cmd_guest.command(name='inspect', short_help='Inspect provisioning request')
@click.argument('guestname', metavar='ID', default=None,)
@click.pass_obj
def cmd_guest_inspect(cfg: Configuration, guestname: str) -> None:
    response = artemis_inspect(cfg, 'guests', guestname)

    if response.ok:
        print_guests(cfg, [response.json()])

    else:
        cfg.logger.unhandled_api_response(response)


@cmd_guest.command(name='cancel', short_help='Cancel provisioning request')
@click.option(
    '--continue-on-error/--no-continue-on-error',
    default=False,
    help='When set, errors would be logged but CLI would continue with next guest request in the list'
)
@click.argument('guestnames', metavar='ID...', default=None, nargs=-1,)
@click.pass_obj
def cmd_cancel(cfg: Configuration, guestnames: List[str], continue_on_error: bool = False) -> None:
    for guestname in guestnames:
        response = artemis_delete(cfg, 'guests', guestname)

        if response.ok:
            cfg.logger.success(f'guest {guestname} has been canceled')

        elif response.status_code == 404:
            cfg.logger.error(f'guest {guestname} not found', exit=not continue_on_error)

        elif response.status_code == 409:
            cfg.logger.warning(f'guest {guestname} is shelved or owns snapshots, remove them first')

        else:
            cfg.logger.unhandled_api_response(response, exit=not continue_on_error)


@cmd_guest.command(name='list', short_help='List provisioning requests')
@click.option(
    '--sort-by',
    type=click.Choice(['ctime']),
    default='ctime'
)
@click.option(
    '--sort-order',
    type=click.Choice(['asc', 'desc']),
    default='asc'
)
@click.option(
    '--jq-filter',
    type=str,
    help='An optional jq-like filter applied to the list of all guest requests retrieved.'
)
@click.pass_obj
def cmd_guest_list(
    cfg: Configuration,
    sort_by: str = 'ctime',
    sort_order: str = 'asc',
    jq_filter: Optional[str] = None
) -> None:
    response = artemis_inspect(cfg, 'guests', '')

    if response.ok:
        guests = cast(List[Dict[str, Any]], response.json())

        guests.sort(key=lambda x: cast(str, x[sort_by]))

        if sort_order == 'desc':
            guests.reverse()

        print_guests(cfg, guests, jq_filter=jq_filter)

    else:
        cfg.logger.unhandled_api_response(response)


@cmd_guest.command(name='events', short_help='List event log')
@click.argument('guestname', metavar='ID', required=False, default=None)
@click.option('--page-size', type=int, default=50, help='Number of events per page')
@click.option('--page', type=int, default=None, help='Page number')
@click.option('--since', type=str, default=None, help='Since time')
@click.option('--until', type=str, default=None, help='Until time')
@click.option('--first', type=int, default=None, help='First N events')
@click.option('--last', type=int, default=None, help='Last N events')
@click.pass_obj
def cmd_guest_events(
        cfg: Configuration,
        page_size: int,
        guestname: Optional[str] = None,
        page: Optional[int] = None,
        since: Optional[str] = None,
        until: Optional[str] = None,
        first: Optional[int] = None,
        last: Optional[int] = None
) -> None:
    """
    Prints event log.

    When optional guestname is given, only events related to this guest are show. Events can be paginated and limited
    by date and time.
    """

    params: Dict[str, Any] = {
        # sorting by 'updated', 'asc' is default, 'desc' is used for --last
        'sort_field': 'updated',
        'sort_by': 'asc'
    }

    for param in ['page_size', 'page', 'since', 'until']:
        value = locals().get(param)

        if value is not None:
            params[param] = value

    if len([x for x in [first, last, page] if x]) > 1:
        cfg.logger.error('--first, --last and --page cannot be used together')

        sys.exit(1)

    if first:
        params['page_size'] = first
        params['page'] = 1

    if last:
        params['page_size'] = last
        params['page'] = 1
        params['sort_by'] = 'desc'

    if guestname:
        # get events for given guest
        rid = f'{guestname}/events'
    else:
        # get all events
        rid = 'events'

    events: List[Dict[str, Any]] = []

    if page or first or last:
        # request for specific page
        response = artemis_inspect(cfg, 'guests', rid, params=params)

        if response.ok:
            events = response.json()

        else:
            cfg.logger.unhandled_api_response(response)

    else:
        # get all pages
        for page in range(1, PAGINATION_MAX_COUNT):
            params['page'] = page

            response = artemis_inspect(cfg, 'guests', rid, params=params)

            if response.ok:
                new_events = response.json()

                events += new_events

                if len(new_events) < page_size:
                    # last page, result is complete
                    break

            else:
                cfg.logger.unhandled_api_response(response)

        else:
            cfg.logger.error(f'reached limit of {PAGINATION_MAX_COUNT} pages')

    if last:
        # for --last, sorting has opposit order, need to reverse here
        events.reverse()

    print_events(cfg, events)


@cmd_guest.command(name='logs', short_help='Get specific logs from the guest')
@click.argument('guestname', metavar='ID', default=None,)
@click.option(
    '--log',
    'logname',
    required=True,
    type=click.Choice(choices=ALLOWED_LOGS),
    metavar='LOG-NAME:VARIANT/CONTENT-TYPE',
    help='A log to acquire. '
    f'One of {", ".join(ALLOWED_LOGS)}.'
)
@click.option('--wait', is_flag=True, default=False, help='Poll the server till the log is ready')
@click.option('--force', is_flag=True, default=False, help='Force request')
@click.pass_obj
def cmd_guest_log(
        cfg: Configuration,
        guestname: str,
        logname: str,
        wait: bool,
        force: bool
) -> None:
    if force:
        response = fetch_artemis(
            cfg,
            f'/guests/{guestname}/logs/{logname}',
            method='post',
            allow_statuses=[202]
        )

    else:
        response = fetch_artemis(
            cfg,
            f'/guests/{guestname}/logs/{logname}',
            allow_statuses=[200, 404, 409]
        )

        if response.status_code == 404:
            # first time asking for this type of log
            response = fetch_artemis(
                cfg,
                f'/guests/{guestname}/logs/{logname}',
                method='post',
                allow_statuses=[202]
            )

        elif response.status_code == 409:
            # exists, but it's expired
            # TODO: yes, it runs virtually the same code as 404 above, and these two will be merged once things
            # settle down.
            response = fetch_artemis(
                cfg,
                f'/guests/{guestname}/logs/{logname}',
                method='post',
                allow_statuses=[202]
            )

    if not response.ok:
        cfg.logger.unhandled_api_response(response)

    log = response.json()

    if not wait:
        if logname:
            print_guest_logs(cfg, [log])

    else:
        cfg.console.clear()

        with cfg.console.status('Waiting for guest log to become ready...', spinner='dots'):
            while True:
                response = fetch_artemis(
                    cfg,
                    f'/guests/{guestname}/logs/{logname}',
                    allow_statuses=[200, 404, 409]
                )

                # the request may still report conflict, until Artemis actually gets to it.
                if response.status_code in (404, 409):
                    pass

                elif response.status_code == 200:
                    log = response.json()

                    cfg.console.clear()

                    print_guest_logs(cfg, [log], console=cfg.console)

                    state = log['state']

                    if state in ('complete', 'unsupported', 'error'):
                        break

                    if state == 'in-progress' and logname.endswith('/blob') and log['blob']:
                        break

                else:
                    cfg.logger.unhandled_api_response(response)

                time.sleep(cfg.provisioning_poll_interval)

        if log['state'] in ('unsupported', 'error'):
            cfg.logger.error('failed to obtain guest request log')

        if log['state'] in ('completed', 'in-progress'):
            cfg.logger.success('guest log obtained')


# XXX FIXME(ivasilev) Switch to the generalized guest logs approach with console url being a special log type
@cmd_guest.group(name='console', short_help='Console related commands')
@click.pass_obj
def cmd_console(cfg: Configuration) -> None:
    pass


@cmd_console.command(name='url', short_help='Acquire console url of a guest')
@click.argument('guestname', metavar='ID', default=None,)
@click.pass_obj
def cmd_console_url(cfg: Configuration, guestname: str) -> None:
    response = fetch_artemis(
        cfg,
        f'/guests/{guestname}/logs/console/url'
    )

    if response.ok:
        print_guest_logs(cfg, [response.json()])

    else:
        cfg.logger.unhandled_api_response(response)


@cli_root.command(name='init', short_help='Initialize configuration file.')
@click.pass_obj
def cmd_init(cfg: Configuration) -> None:
    """
    Using a series of questions, initialize a configuration file. Some information can be extracted automatically,
    other bits must be explicitly provided by the user.
    """

    cfg.console.print(f"""

Following sequence of questions will help you setup configuration for Artemis CLI.

Configuration file location is {cfg.config_filepath}

Feel free to quit anytime, nothing is saved until the very last step.
""")

    #
    # Artemis API
    #
    cfg.console.rule('[bold red]Artemis API URL')
    artemis_api_url = cfg.console.input(
        ':question_mark: URL of Artemis API (for example "http://artemis.example.com/v0.0.18"): '
    )

    cfg.console.rule('[bold red]Artemis API version')
    artemis_api_version = cfg.console.input(
        ':question_mark: API version to use when talking to Artemis (for example "0.0.18"): '
    )

    tmp_config_file = tempfile.NamedTemporaryFile(mode='w', delete=False)

    with tmp_config_file:
        print(f"""---

artemis_api_url: {artemis_api_url}
artemis_api_version: {artemis_api_version}
""", file=tmp_config_file)

        tmp_config_file.flush()

    cfg.console.rule()

    if confirm('Do you wish to view the configuration file, possibly modifying it?', default=True, console=cfg.console):
        click.edit(filename=tmp_config_file.name)

    if confirm('Do you wish to save this as your configuration file?', default=False, console=cfg.console):
        assert cfg.config_dirpath is not None
        assert cfg.config_filepath is not None

        os.makedirs(cfg.config_dirpath, exist_ok=True)

        if os.path.exists(cfg.config_filepath):
            os.unlink(cfg.config_filepath)

        shutil.copy(tmp_config_file.name, cfg.config_filepath)

        cfg.console.log(':+1: [green]Saved, your config file has been updated.[/green]')

    else:
        cfg.console.log(':+1: [yellow]Your answers were thrown away.[/yellow]')


@cli_root.group(name='knob', short_help='Knob related commands')
@click.pass_obj
def cmd_knob(cfg: Configuration) -> None:
    pass


@cmd_knob.command(name='list', short_help='List all knobs')
@click.option(
    '--jq-filter',
    type=str,
    help='An optional jq-like filter applied to the list of all knobs retrieved.'
)
@click.pass_obj
def cmd_knob_list(cfg: Configuration, jq_filter: Optional[str] = None) -> None:
    response = artemis_inspect(cfg, 'knobs', '')

    if response.ok:
        knobs = cast(List[Dict[str, Any]], response.json())

        print_knobs(cfg, knobs, jq_filter=jq_filter)

    else:
        cfg.logger.unhandled_api_response(response)


@cmd_knob.command(name='get', short_help='Get knob value')
@click.argument('knobname', required=True, type=str)
@click.pass_obj
def cmd_knob_get(
        cfg: Configuration,
        knobname: str
) -> None:
    response = artemis_inspect(cfg, 'knobs', knobname)

    if response.ok:
        print_knobs(cfg, [response.json()])

    elif response.status_code == 404:
        cfg.logger.error(f'knob "{knobname}" does not exist')

    else:
        cfg.logger.unhandled_api_response(response)


@cmd_knob.command(name='set', short_help='Set knob value')
@click.argument('knobname', required=True, type=str)
@click.argument('value', required=True, type=str)
@click.pass_obj
def cmd_knob_set(
        cfg: Configuration,
        knobname: str,
        value: str
) -> None:
    response = artemis_update(cfg, f'knobs/{knobname}', {'value': value})

    if response.ok:
        print_knobs(cfg, [response.json()])

    elif response.status_code == 404:
        cfg.logger.error(f'knob "{knobname}" does not exist')

    else:
        cfg.logger.unhandled_api_response(response)


@cmd_knob.command(name='delete', short_help='Remove knob')
@click.argument('knobname', required=True, type=str)
@click.pass_obj
def cmd_knob_delete(
        cfg: Configuration,
        knobname: str
) -> None:
    response = artemis_delete(cfg, 'knobs', knobname)

    if response.ok:
        cfg.logger.success(f'knob "{knobname}" has been removed')

    elif response.status_code == 404:
        cfg.logger.error(f'knob "{knobname}" does not exist')

    else:
        cfg.logger.unhandled_api_response(response)


@cli_root.group(name='shelf', short_help='Guest shelves management commands')
@click.pass_obj
def cmd_shelf(cfg: Configuration) -> None:
    pass


@cmd_shelf.command(name='create', short_help='Create a new shelf')
@click.argument('shelfname', required=True, type=str)
@click.pass_obj
def cmd_shelf_create(
    cfg: Configuration,
    shelfname: str,
) -> None:
    response = artemis_create(cfg, f'shelves/{shelfname}', {})

    if response.ok:
        print_shelves(cfg, [response.json()])

    else:
        cfg.logger.unhandled_api_response(response)


@cmd_shelf.command(name='inspect', short_help='Inspect guest shelf')
@click.argument('shelfname', required=True, type=str)
@click.pass_obj
def cmd_shelf_inspect(cfg: Configuration, shelfname: str) -> None:
    response = artemis_inspect(cfg, 'shelves', shelfname)

    if response.ok:
        print_shelves(cfg, [response.json()])

    else:
        cfg.logger.unhandled_api_response(response)


@cmd_shelf.command(name='delete', short_help='Remove a guest shelf and release all shelved guests')
@click.argument('shelfname', required=True, type=str)
@click.pass_obj
def cmd_shelf_delete(cfg: Configuration, shelfname: str) -> None:
    response = artemis_delete(cfg, 'shelves', shelfname)

    if response.ok:
        cfg.logger.success(f'shelf {shelfname} was deleted')

    elif response.status_code == 404:
        cfg.logger.error(f'shelf {shelfname} not found')

    else:
        cfg.logger.unhandled_api_response(response)


@cmd_shelf.command(name='list', short_help='List available shelves')
@click.option(
    '--sort-by',
    type=click.Choice(['shelfname']),
    default='shelfname'
)
@click.option(
    '--sort-order',
    type=click.Choice(['asc', 'desc']),
    default='asc'
)
@click.option(
    '--jq-filter',
    type=str,
    help='An optional jq-like filter applied to the list of all shelves retrieved.'
)
@click.pass_obj
def cmd_shelf_list(
    cfg: Configuration,
    sort_by: str = 'shelfname',
    sort_order: str = 'asc',
    jq_filter: Optional[str] = None
) -> None:
    response = artemis_inspect(cfg, 'shelves', '')

    if response.ok:
        shelves = cast(List[Dict[str, Any]], response.json())

        shelves.sort(key=lambda x: cast(str, x[sort_by]))

        if sort_order == 'desc':
            shelves.reverse()

        print_shelves(cfg, shelves, jq_filter=jq_filter)

    else:
        cfg.logger.unhandled_api_response(response)


@cmd_shelf.group(name='guest', short_help='Guest related commands')
@click.pass_obj
def cmd_shelf_guest(cfg: Configuration) -> None:
    pass


@cmd_shelf_guest.command(name='cancel', short_help='Cancel shelved guests')
@click.option(
    '--continue-on-error/--no-continue-on-error',
    default=False,
    help='When set, errors would be logged but CLI would continue with next guest request in the list'
)
@click.argument('guestnames', metavar='ID...', default=None, nargs=-1,)
@click.pass_obj
def cmd_cancel_shelved_guest(cfg: Configuration, guestnames: List[str], continue_on_error: bool = False) -> None:
    for guestname in guestnames:
        response = artemis_delete(cfg, 'shelves/guests', guestname)

        if response.ok:
            cfg.logger.success(f'guest {guestname} has been cancelled')

        elif response.status_code == 404:
            cfg.logger.error(f'shelved guest {guestname} not found', exit=not continue_on_error)

        else:
            cfg.logger.unhandled_api_response(response, exit=not continue_on_error)


@cli_root.group(name='user', short_help='User management commands')
@click.pass_obj
def cmd_user(cfg: Configuration) -> None:
    pass


@cmd_user.group(name='token', short_help='User token management commands')
@click.pass_obj
def cmd_token(cfg: Configuration) -> None:
    pass


@cmd_user.command(name='list', short_help='List all users')
@click.option(
    '--jq-filter',
    type=str,
    help='An optional jq-like filter applied to the list of all users retrieved.'
)
@click.pass_obj
def cmd_user_list(cfg: Configuration, jq_filter: Optional[str] = None) -> None:
    response = artemis_inspect(cfg, 'users', '')

    if response.ok:
        users = cast(List[Dict[str, Any]], response.json())

        print_users(cfg, users, jq_filter=jq_filter)

    else:
        cfg.logger.unhandled_api_response(response)


@cmd_user.command(name='inspect', short_help='Inspect a user')
@click.argument('username', required=True, type=str)
@click.pass_obj
def cmd_user_inspect(
    cfg: Configuration,
    username: str
) -> None:
    response = artemis_inspect(cfg, 'users', username)

    if response.ok:
        print_users(cfg, [response.json()])

    else:
        cfg.logger.unhandled_api_response(response)


@cmd_user.command(name='create', short_help='Create a user')
@click.argument('username', required=True, type=str)
@click.argument('role', required=True, type=click.Choice(['USER', 'ADMIN'], case_sensitive=False))
@click.pass_obj
def cmd_user_create(
        cfg: Configuration,
        username: str,
        role: str
) -> None:
    response = artemis_create(cfg, f'users/{username}', {'role': role})

    if response.ok:
        print_users(cfg, [response.json()])

    else:
        cfg.logger.unhandled_api_response(response)


@cmd_user.command(name='delete', short_help='Delete a user')
@click.argument('username', required=True, type=str)
@click.pass_obj
def cmd_user_delete(
    cfg: Configuration,
    username: str
) -> None:
    response = artemis_delete(cfg, 'users', username)

    if response.ok:
        cfg.logger.success(f'user "{username}" has been removed')

    elif response.status_code == 404:
        cfg.logger.error(f'user "{username}" does not exist')

    else:
        cfg.logger.unhandled_api_response(response)


@cmd_token.command(name='reset', short_help='Reset user\'s token')
@click.argument('username', required=True, type=str)
@click.argument('tokentype', required=True, type=click.Choice(['provisioning', 'admin'], case_sensitive=False))
@click.pass_obj
def cmd_user_token_reset(
    cfg: Configuration,
    username: str,
    tokentype: str
) -> None:
    response = artemis_create(cfg, f'users/{username}/tokens/{tokentype}/reset', {})

    if response.ok:
        if cfg.output_format == 'table':
            token = response.json()

            table = rich.table.Table()

            for header in ['Token type', 'Token']:
                table.add_column(header)

            table.add_row(token['tokentype'], token['token'])

            print_table(table)

        elif cfg.output_format == 'json':
            print_json(response.json())

        elif cfg.output_format == 'yaml':
            print_yaml(response.json())

    elif response.status_code == 404:
        cfg.logger.error(f'user "{username}" does not exist')

    else:
        cfg.logger.unhandled_api_response(response)


@cli_root.group(name='status', short_help='Status and introspection commands')
@click.pass_obj
def cmd_status(cfg: Configuration) -> None:
    pass


@cmd_status.command(name='tasks', short_help='Display current tasks')
@click.pass_obj
def cmd_status_tasks(cfg: Configuration) -> None:
    response = fetch_artemis(cfg, '/_status/workers/traffic')

    if not response.ok:
        cfg.logger.unhandled_api_response(response)

    print_tasks(cfg, response.json())


@cmd_status.command(name='top', short_help='Display current tasks in a top-like fashion')
@click.option('--tick', metavar='N', type=int, default=10, help='Refresh output every N seconds')
@click.pass_obj
def cmd_status_top(cfg: Configuration, tick: int) -> None:
    with cfg.console.status('Updating task list...', spinner='dots') as status:
        while True:
            status.update('Updating task list...')
            response = fetch_artemis(cfg, '/_status/workers/traffic')

            if not response.ok:
                cfg.logger.unhandled_api_response(response)

            tasks = response.json()

            cfg.console.clear()
            print_tasks(cfg, tasks)

            status.update(f'Updating every {tick} seconds...')
            sleep(tick)


@cmd_status.command(name='broker', short_help='Display current broker messages in a top-like fashion')
@click.option('--tick', metavar='N', type=int, default=10, help='Refresh output every N seconds')
@click.option('--include-dead-letters', is_flag=True, help='Report also dead letter queues.')
@click.pass_obj
def cmd_status_broker(cfg: Configuration, tick: int, include_dead_letters: bool) -> None:
    assert cfg.broker_management_hostname
    assert cfg.broker_management_port
    assert cfg.broker_management_username
    assert cfg.broker_management_password

    rabbitmqadm_command: List[str] = [
        'rabbitmqadmin',
        '--format', 'pretty_json',
        '--host', cfg.broker_management_hostname,
        '--port', str(cfg.broker_management_port),
        '--username', cfg.broker_management_username,
        '--password', cfg.broker_management_password
    ]

    with cfg.console.status('Updating broker task list...', spinner='dots') as status:
        queues = json.loads(subprocess.check_output(rabbitmqadm_command + ['list', 'queues']).decode())

        while True:
            status.update('Updating broker task list...')

            def _iter_tasks(queues) -> Generator[Any, None, None]:
                for queue in queues:
                    if queue['name'].endswith('.XQ') and not include_dead_letters:
                        continue

                    output = json.loads(subprocess.check_output(rabbitmqadm_command + [
                            'get',
                            f'queue={queue["name"]}',
                            'ackmode=ack_requeue_true',
                            'count=999999'
                        ]
                    ))

                    for message in output:
                        payload = json.loads(message['payload'])

                        payload['routing_key'] = queue['name']

                        yield payload

            cfg.console.clear()
            print_broker_tasks(cfg, list(_iter_tasks(queues)))

            status.update(f'Updating every {tick} seconds...')
            sleep(tick)
