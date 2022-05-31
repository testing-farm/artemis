# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import json
import sys
from typing import Any, Callable, Dict, List, NamedTuple, Optional, cast

import click
import jsonschema
import pkg_resources
import requests
import requests.adapters
import rich.console
import rich.highlighter
import rich.json
import rich.syntax
import rich.table
import rich.text
import ruamel.yaml
import ruamel.yaml.compat
import semver
import urlnormalizer

DEFAULT_API_TIMEOUT = 10
DEFAULT_API_RETRIES = 10
# should lead to delays of 0.5, 1, 2, 4, 8, 16, 32, 64, 128, 256 seconds
DEFAULT_RETRY_BACKOFF_FACTOR = 1

# If our terminal is not a terminal, enforce width to be very big to avoid wrapping and truncating lines when
# redirected into a file or pipe.
_console_width: Optional[int] = None if sys.stdout.isatty() else 10000

DEFAULT_CONSOLE = rich.console.Console(width=_console_width)
DEFAULT_LOGGING_CONSOLE = rich.console.Console(stderr=True, width=_console_width)


class ValidationResult(NamedTuple):
    """
    Represents schema validation result
    """
    result: bool
    errors: List[Any]


class Logger:
    """
    Simple class providing semantic logging.
    """

    def __init__(
        self,
        context: Optional[str] = None,
        console: Optional[rich.console.Console] = None
    ) -> None:
        self.context = context
        self.console = console or DEFAULT_LOGGING_CONSOLE

        self._context_prefix = f'[{context}] ' if context else ''

    def info(self, msg: str, icon: str = ':information:', colorize: bool = True) -> None:
        if colorize:
            color_enable, color_reset = '[white]', '[/white]'

        else:
            color_enable, color_reset = '', ''

        self.console.print(f'{icon} {color_enable}{msg}{color_reset}')

    def success(self, msg: str, icon: str = ':+1:', colorize: bool = True) -> None:
        if colorize:
            color_enable, color_reset = '[green]', '[/green]'

        else:
            color_enable, color_reset = '', ''

        self.console.print(f'{icon} {color_enable}{msg}{color_reset}')

    def warning(self, msg: str, icon: str = ':heavy_exclamation_mark:', colorize: bool = True) -> None:
        if colorize:
            color_enable, color_reset = '[yellow]', '[/yellow]'

        else:
            color_enable, color_reset = '', ''

        self.console.print(f'{icon} {color_enable}{msg}{color_reset}')

    def error(
        self,
        msg: str,
        icon: str = ':-1:',
        colorize: bool = True,
        exception: bool = False,
        exit: bool = True
    ) -> None:
        if colorize:
            color_enable, color_reset = '[red]', '[/red]'

        else:
            color_enable, color_reset = '', ''

        self.console.print(f'{icon} {color_enable}{msg}{color_reset}')

        if exception:
            self.console.print_exception()

        if exit:
            sys.exit(1)

    def unhandled_api_response(self, response: requests.Response, exit: bool = True) -> None:
        message = [
            f'unhandled API response, HTTP {response.status_code}'
        ]

        if response.content:
            try:
                message += [
                    '',
                    f'API message: {response.json()["message"]}'
                ]

            except Exception:
                self.warning('cannot extract better message from API response')

        self.error('\n'.join(message), exit=exit)


class TimeoutHTTPAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.timeout = kwargs.pop('timeout', DEFAULT_API_TIMEOUT)

        super().__init__(*args, **kwargs)

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:  # type: ignore[override]
        kwargs.setdefault('timeout', self.timeout)

        return super().send(request, **kwargs)


@dataclasses.dataclass
class BasicAuthConfiguration:
    username: str
    provisioning_token: str
    admin_token: str


@dataclasses.dataclass
class Configuration:
    console = DEFAULT_CONSOLE
    logger: Logger = Logger(console=DEFAULT_LOGGING_CONSOLE)

    raw_config: Optional[Any] = None

    config_dirpath: Optional[str] = None
    config_filepath: Optional[str] = None

    completion_shell: Optional[str] = None

    output_format: str = 'human'

    artemis_api_url: Optional[str] = None
    artemis_api_version: Optional[semver.VersionInfo] = None

    authentication_method: Optional[str] = None
    basic_auth: Optional[BasicAuthConfiguration] = None

    provisioning_poll_interval: float = 10

    http_session: requests.Session = dataclasses.field(default_factory=requests.Session)

    def install_http_retries(
        self,
        timeout: int,
        retries: int,
        retry_backoff_factor: int
    ) -> None:
        retry_strategy = requests.packages.urllib3.util.retry.Retry(  # type: ignore[attr-defined]
            total=retries,
            status_forcelist=[
                429,  # Too Many Requests
                500,  # Internal Server Error
                502,  # Bad Gateway
                503,  # Service Unavailable
                504   # Gateway Timeout
            ],
            method_whitelist=[
                'HEAD', 'GET', 'POST', 'DELETE', 'PUT'
            ],
            backoff_factor=retry_backoff_factor
        )

        timeout_adapter = TimeoutHTTPAdapter(
            timeout=timeout,
            max_retries=retry_strategy
        )

        self.http_session.mount('https://', timeout_adapter)
        self.http_session.mount('http://', timeout_adapter)


def _yaml_to_string(data: Any, indent: Optional[int] = 2) -> str:
    stream = ruamel.yaml.compat.StringIO()

    Y = ruamel.yaml.YAML()
    Y.indent(sequence=indent, mapping=indent, offset=0)
    Y.dump(data, stream)

    return stream.getvalue()


def _string_to_yaml(yaml: str) -> Any:
    stream = ruamel.yaml.compat.StringIO(yaml)

    return ruamel.yaml.safe_load(stream)


# A full-fledged YAML highlighter would be better...
class YAMLHighlighter(rich.highlighter.JSONHighlighter):
    pass


class RichYAML:
    """
    A renderable which pretty prints YAML.

    Args:
        json (str): JSON encoded data.
        indent (Union[None, int, str], optional): Number of characters to indent by. Defaults to 2.
        highlight (bool, optional): Enable highlighting. Defaults to True.
    """

    def __init__(
        self,
        yaml: str,
        indent: Optional[int] = 2,
        highlight: bool = True
    ) -> None:
        # normalize by converting from string to data structure and back, and apply indent
        data = _string_to_yaml(yaml)
        yaml = _yaml_to_string(data, indent=indent)

        highlighter = YAMLHighlighter() if highlight else rich.highlighter.NullHighlighter()
        self.text = highlighter(yaml)

        self.text.no_wrap = True
        self.text.overflow = None

    @classmethod
    def from_data(
        cls,
        data: Any,
        indent: Optional[int] = 2,
        highlight: bool = True
    ) -> 'RichYAML':
        return cls(_yaml_to_string(data), indent=indent, highlight=highlight)

    def __rich__(self) -> rich.text.Text:
        return self.text


def load_yaml(filepath: str) -> Any:
    with open(filepath) as f:
        return ruamel.yaml.safe_load(f)


def save_yaml(data: Any, filepath: str) -> None:
    with open(filepath, 'w') as f:
        ruamel.yaml.dump(data, f)


def validate_struct(data: Any, schema_name: Any) -> ValidationResult:
    schema_filepath = pkg_resources.resource_filename('tft.artemis_cli', f'schemas/{schema_name}.yaml')
    schema = load_yaml(schema_filepath)

    try:
        jsonschema.validate(instance=data, schema=schema)

        return ValidationResult(True, [])

    except jsonschema.exceptions.ValidationError:
        validator = jsonschema.Draft4Validator(schema)

        return ValidationResult(
            False,
            validator.iter_errors(data)
        )


def fetch_remote(
    cfg: Configuration,
    url: str,
    logger: Optional[Logger] = None,
    method: str = 'get',
    request_kwargs: Optional[Dict[str, Any]] = None,
    on_error: Optional[Callable[[requests.Response, Dict[str, Any]], None]] = None,
    allow_statuses: Optional[List[int]] = None
) -> requests.Response:

    allow_statuses = allow_statuses or [200, 201]

    logger = logger or Logger()
    request_kwargs = request_kwargs or {}

    url = urlnormalizer.normalize_url(url)

    if method == 'get':
        res = cfg.http_session.get(url, **request_kwargs)

    elif method == 'post':
        res = cfg.http_session.post(url, **request_kwargs)

    elif method == 'delete':
        res = cfg.http_session.delete(url, **request_kwargs)

    elif method == 'put':
        res = cfg.http_session.put(url, **request_kwargs)

    if res.status_code not in allow_statuses:
        if on_error:
            on_error(res, request_kwargs)

        else:
            logger.error(f'Failed to communicate with remote url {url}, responded with code {res.status_code}')

    return res


def fetch_artemis(
    cfg: Configuration,
    endpoint: str,
    method: str = 'get',
    request_kwargs: Optional[Dict[str, Any]] = None,
    logger: Optional[Logger] = None,
    allow_statuses: Optional[List[int]] = None
) -> requests.Response:
    assert cfg.artemis_api_url is not None

    logger = logger or Logger()

    def _error_callback(res: requests.Response, request_kwargs: Dict[str, Any]) -> None:
        assert logger is not None

        logger.error(f"""
Failed to communicate with Artemis API Server, responded with code {res.status_code}: {res.reason}'

Request:

  {res.request.url}

  {request_kwargs}
""")

    if cfg.authentication_method == 'basic':
        from requests.auth import HTTPBasicAuth

        assert cfg.basic_auth is not None

        if request_kwargs is None:
            request_kwargs = {}

        request_kwargs['auth'] = HTTPBasicAuth(
            cfg.basic_auth.username,
            # TODO: pick proper token based on URL
            cfg.basic_auth.provisioning_token
        )

    return fetch_remote(
        cfg,
        f'{cfg.artemis_api_url}/{endpoint}',
        logger=logger,
        method=method,
        request_kwargs=request_kwargs,
        on_error=_error_callback,
        allow_statuses=allow_statuses
    )


def artemis_inspect(
    cfg: Configuration,
    resource: str,
    rid: str,
    params: Optional[Dict[str, Any]] = None,
    data: Optional[Dict[str, Any]] = None,
    logger: Optional[Logger] = None
) -> requests.Response:
    return fetch_artemis(
        cfg,
        f'/{resource}/{rid}',
        request_kwargs={'json': data, 'params': params},
        logger=logger
    )


def artemis_create(
    cfg: Configuration,
    resource: str,
    data: Dict[str, Any],
    logger: Optional[Logger] = None
) -> requests.Response:
    return fetch_artemis(
        cfg,
        f'/{resource}',
        method='post',
        request_kwargs={'json': data},
        logger=logger
    )


def artemis_update(
    cfg: Configuration,
    resource: str,
    data: Dict[str, Any],
    logger: Optional[Logger] = None
) -> requests.Response:
    return fetch_artemis(
        cfg,
        f'/{resource}',
        method='put',
        request_kwargs={'json': data},
        logger=logger
    )


def artemis_restore(
    cfg: Configuration,
    resource: str,
    rid: str,
    data: Optional[Dict[str, Any]] = None,
    logger: Optional[Logger] = None
) -> requests.Response:
    return fetch_artemis(
        cfg,
        f'/{resource}/{rid}/restore',
        method='post',
        request_kwargs={'json': data},
        logger=logger
    )


def artemis_delete(
    cfg: Configuration,
    resource: str,
    rid: str,
    logger: Optional[Logger] = None
) -> requests.Response:
    return fetch_artemis(
        cfg,
        f'{resource}/{rid}',
        method='delete',
        logger=logger,
        allow_statuses=[200, 201, 204, 404, 409]
    )


def confirm(
    msg: str,
    default: bool = False,
    abort: bool = False,
    console: Optional[rich.console.Console] = None
) -> Any:
    console = console or DEFAULT_CONSOLE

    response = console.input(f'{msg} (yes|no) ')

    if response.lower() in ('y', 'yes'):
        return True

    if response.lower() in ('n', 'no') and abort:
        raise click.Abort()

    return False


def print_table(table: rich.table.Table, console: Optional[rich.console.Console] = None) -> None:
    (console or DEFAULT_CONSOLE).print(table)


def print_json(data: Any, console: Optional[rich.console.Console] = None) -> None:
    (console or DEFAULT_CONSOLE).print(json.dumps(data, sort_keys=True, indent=4))


def print_yaml(data: Any, console: Optional[rich.console.Console] = None) -> None:
    (console or DEFAULT_CONSOLE).print(_yaml_to_string(data, indent=2))


CollectionType = List[Dict[str, Any]]


def print_collection(
    cfg: Configuration,
    collection: CollectionType,
    tabulate: Callable[[CollectionType], rich.table.Table],
    console: Optional[rich.console.Console] = None
) -> None:
    if cfg.output_format == 'table':
        print_table(tabulate(collection), console=console)

    elif cfg.output_format == 'json':
        print_json(collection, console=console)

    elif cfg.output_format == 'yaml':
        print_yaml(collection, console=console)


GUEST_STATE_COLORS = {
    'routing': 'yellow',
    'provisioning': 'magenta',
    'promised': 'blue',
    'preparing': 'cyan',
    'ready': 'green',
    'cancelled': 'red',
    'error': 'red'
}


def colorize_guest_state(state: str) -> str:
    color = GUEST_STATE_COLORS.get(state, 'white')

    return f'[{color}]{state}[/{color}]'


def print_guests(
    cfg: Configuration,
    guests: CollectionType,
    console: Optional[rich.console.Console] = None
) -> None:
    def tabulate(guests: CollectionType) -> rich.table.Table:
        table = rich.table.Table()

        for header in ['Guestname', 'Compose', 'Arch', 'Pool', 'State', 'CTime / MTime', 'Address', 'User Data']:
            table.add_column(header, no_wrap=(header == 'Guestname'))

        for guest in guests:
            table.add_row(
                guest['guestname'],
                guest['environment']['os']['compose'],
                guest['environment']['hw']['arch'],
                guest['environment']['pool'],
                colorize_guest_state(guest['state']),
                f'{guest["ctime"]}\n{guest["state_mtime"]}',
                guest['address'],
                RichYAML.from_data(guest['user_data']) if guest['user_data'] else ''
            )

        return table

    print_collection(cfg, guests, tabulate, console=console)


_eventname_emojis = {
    'entered-task': ':point_right:',
    'finished-task': ':point_left:',
    'state-changed': ':birthday_cake:',
    'created': ':baby:'
}


def print_events(
    cfg: Configuration,
    events: CollectionType,
    console: Optional[rich.console.Console] = None
) -> None:
    def tabulate(events: CollectionType) -> rich.table.Table:
        table = rich.table.Table()

        for header in ['Time', 'Event', 'Guestname', 'Details']:
            table.add_column(header)

        for event in events:
            eventname = event['eventname']
            details = event['details']

            if eventname == 'state-changed':
                current_state = colorize_guest_state(details['current_state'])
                new_state = colorize_guest_state(details['new_state'])

                details = f'{current_state} :point_right: {new_state}'

            else:
                details = RichYAML.from_data(details) if details else ''

            eventname_emoji = _eventname_emojis.get(eventname, ':information:')
            eventname = f'{eventname_emoji} {eventname}'

            table.add_row(
                event['updated'],
                eventname,
                event['guestname'],
                details
            )

        return table

    print_collection(cfg, events, tabulate, console=console)


def print_knobs(
    cfg: Configuration,
    knobs: CollectionType,
    console: Optional[rich.console.Console] = None
) -> None:
    def tabulate(knobs: CollectionType) -> rich.table.Table:
        table = rich.table.Table()

        for header in ['Name', 'Value', 'Type', 'Editable', 'Help']:
            table.add_column(header)

        for knob in sorted(knobs, key=lambda x: cast(str, x['name'])):
            table.add_row(
                knob['name'],
                ('yes' if knob['value'] else 'no') if isinstance(knob['value'], bool) else str(knob['value']),
                knob['cast'],
                'yes' if knob['editable'] else 'no',
                knob['help']
            )

        return table

    print_collection(cfg, knobs, tabulate, console=console)


def print_users(
    cfg: Configuration,
    users: CollectionType,
    console: Optional[rich.console.Console] = None
) -> None:
    def tabulate(users: CollectionType) -> rich.table.Table:
        table = rich.table.Table()

        for header in ['Name', 'Role']:
            table.add_column(header)

        for user in sorted(users, key=lambda x: cast(str, x['username'])):
            table.add_row(
                user['username'],
                user['role']
            )

        return table

    print_collection(cfg, users, tabulate, console=console)


def print_guest_logs(
    cfg: Configuration,
    logs: CollectionType,
    console: Optional[rich.console.Console] = None
) -> None:
    def tabulate(logs: CollectionType) -> rich.table.Table:
        table = rich.table.Table()

        for header in ['Content Type', 'State', 'URL', 'Updated', 'Expires']:
            table.add_column(header)

        for log in logs:
            table.add_row(
                log['contenttype'],
                log['state'],
                log['url'],
                log['updated'],
                log['expires']
            )

        return table

    print_collection(cfg, logs, tabulate, console=console)


def print_tasks(
    cfg: Configuration,
    tasks: CollectionType,
    console: Optional[rich.console.Console] = None
) -> None:
    def tabulate(tasks: CollectionType) -> rich.table.Table:
        table = rich.table.Table()

        for header in ['Task', 'Arguments', 'CTime']:
            table.add_column(header)

        for task in tasks:
            table.add_row(
                task['actor'].replace('_', '-'),
                RichYAML.from_data(task['args']) if task['args'] else '',
                task['ctime']
            )

        return table

    print_collection(cfg, tasks, tabulate, console=console)
