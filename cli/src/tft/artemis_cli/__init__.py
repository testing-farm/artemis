import concurrent.futures
import dataclasses
import json
import re
import shlex
import subprocess
import sys
from typing import (Any, Callable, Dict, Iterable, List, NamedTuple, NoReturn,
                    Optional, Tuple, TypeVar)

import click
import click_spinner
import jsonschema
import pkg_resources
import requests
import requests.adapters
import rich
import rich.console
import rich.markup
import rich.table
import ruamel.yaml
import ruamel.yaml.compat
import semver
import urlnormalizer

REGEX_URL = re.compile(r'(?i)http(s)?:\/\/(www\.)?[^\s()\[\]<>]+')


DEFAULT_API_TIMEOUT = 10
DEFAULT_API_RETRIES = 10
# should lead to delays of 0.5, 1, 2, 4, 8, 16, 32, 64, 128, 256 seconds
DEFAULT_RETRY_BACKOFF_FACTOR = 1


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

    def __init__(self, context: Optional[str] = None) -> None:
        self.context = context

        self._context_prefix = '[{}] '.format(context) if context else ''

    def debug(self, msg: str) -> None:
        # We need to introduce options controling logging output first!
        # click.echo()
        pass

    def info(self, msg: str) -> None:
        click.echo(YELLOW('{}{}'.format(self._context_prefix, msg)))

    def warn(self, msg: str) -> None:
        click.echo(YELLOW('{}{}'.format(self._context_prefix, msg)))

    def error(self, msg: str) -> NoReturn:
        click.echo(RED('{}{}'.format(self._context_prefix, msg)), err=True)

        sys.exit(1)

    def success(self, msg: str) -> None:
        click.echo(GREEN('{}{}'.format(self._context_prefix, msg)))


class TimeoutHTTPAdapter(requests.adapters.HTTPAdapter):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self.timeout = kwargs.pop('timeout', DEFAULT_API_TIMEOUT)

        super().__init__(*args, **kwargs)

    def send(self, request: requests.PreparedRequest, **kwargs: Any) -> requests.Response:    # type: ignore
        kwargs.setdefault('timeout', self.timeout)

        return super().send(request, **kwargs)


@dataclasses.dataclass
class BasicAuthConfiguration:
    username: str
    provisioning_token: str
    admin_token: str


@dataclasses.dataclass
class Configuration:
    raw_config: Optional[Any] = None

    logger: Logger = dataclasses.field(default_factory=Logger)

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
        retry_strategy = requests.packages.urllib3.util.retry.Retry(
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


# Colorization
def BLUE(s: str) -> str:
    return click.style(s, fg='blue')


def CYAN(s: str) -> str:
    return click.style(s, fg='cyan')


def GREEN(s: str) -> str:
    return click.style(s, fg='green')


def RED(s: str) -> str:
    return click.style(s, fg='red')


def YELLOW(s: str) -> str:
    return click.style(s, fg='yellow')


def WHITE(s: str) -> str:
    return click.style(s, fg='white')


def NL() -> None:
    click.echo('')


def load_yaml(filepath: str) -> Any:
    with open(filepath, 'r') as f:
        return ruamel.yaml.safe_load(f)


def save_yaml(data: Any, filepath: str) -> None:
    with open(filepath, 'w') as f:
        ruamel.yaml.dump(data, f)


def validate_struct(data: Any, schema_name: Any) -> ValidationResult:
    schema_filepath = pkg_resources.resource_filename('tft.artemis_cli', 'schemas/{}.yaml'.format(schema_name))
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


def prettify_json(flag: bool, data: Any) -> str:
    if not flag:
        return json.dumps(data)

    return json.dumps(data, sort_keys=True, indent=4)


def prettify_yaml(flag: bool, data: Any) -> str:
    Y = ruamel.yaml.YAML()

    if flag:
        Y.indent(sequence=2, mapping=2, offset=0)

    stream = ruamel.yaml.compat.StringIO()

    Y.dump(data, stream)

    return stream.getvalue()


def execute_command(
    cmd: List[str],
    spinner: bool = False,
    logger: Optional[Logger] = None,
    accept_exit_codes: Optional[Iterable[int]] = None,
    **kwargs: Any
):
    # type: (...) -> subprocess.CompletedProcess[bytes]

    # add "accepted exit codes" when needed

    accept_exit_codes = accept_exit_codes or [0]

    logger = logger or Logger()

    with click_spinner.spinner(disable=not spinner):
        try:
            result = subprocess.run(cmd, **kwargs)

        except subprocess.SubprocessError as exc:
            logger.error('Failed to complete command: {}'.format(exc))

    if result.returncode not in accept_exit_codes:
        logger.error("""
Failed to complete command, exited with code {}:

{}

STDOUT: ---v---v---v---v---v---
{}
        ---^---^---^---^---^---

STDERR: ---v---v---v---v---v---
{}
        ---^---^---^---^---^---
""".format(
            result.returncode,
            shlex.quote(' '.join(cmd)),
            result.stdout.decode('utf-8') if result.stdout else '',
            result.stderr.decode('utf-8') if result.stderr else ''
        ))

    return result


def fetch_remote(
    cfg: Configuration,
    url: str,
    logger: Optional[Logger] = None,
    spinner: bool = False,
    method: str = 'get',
    request_kwargs: Optional[Dict[str, Any]] = None,
    on_error: Optional[Callable[[requests.Response, Dict[str, Any]], None]] = None,
    allow_statuses: Optional[List[int]] = None
) -> requests.Response:

    allow_statuses = allow_statuses or [200, 201]

    logger = logger or Logger()
    request_kwargs = request_kwargs or {}

    url = urlnormalizer.normalize_url(url)

    with click_spinner.spinner(disable=not spinner):
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
            logger.error(
                'Failed to communicate with remote url {}, responded with code {}'.format(url, res.status_code)
            )

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
    if not logger:
        logger = Logger()

    def _error_callback(res: requests.Response, request_kwargs: Dict[str, Any]) -> None:
        assert logger is not None

        logger.error(
            'Failed to communicate with Artemis API Server, responded with code {}: {}'
            '\nRequest:\n{}\n{}'.format(res.status_code, res.reason, res.request.url, request_kwargs)
        )

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
        '{}/{}'.format(cfg.artemis_api_url, endpoint),
        logger,
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
        '/{}/{}'.format(resource, rid),
        request_kwargs={'json': data, 'params': params},
        logger=None
    )


def artemis_create(
    cfg: Configuration,
    resource: str,
    data: Dict[str, Any],
    logger: Optional[Logger] = None
) -> requests.Response:
    return fetch_artemis(
        cfg,
        '/{}'.format(resource),
        method='post',
        request_kwargs={'json': data},
        logger=None
    )


def artemis_update(
    cfg: Configuration,
    resource: str,
    data: Dict[str, Any],
    logger: Optional[Logger] = None
) -> requests.Response:
    return fetch_artemis(
        cfg,
        '/{}'.format(resource),
        method='put',
        request_kwargs={'json': data},
        logger=None
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
        '/{}/{}/restore'.format(resource, rid),
        method='post',
        request_kwargs={'json': data},
        logger=None
    )


def artemis_delete(
    cfg: Configuration,
    resource: str,
    rid: str,
    logger: Optional[Logger] = None
) -> requests.Response:
    return fetch_artemis(
        cfg,
        '{}/{}'.format(resource, rid),
        method='delete',
        logger=None,
        allow_statuses=[200, 201, 204, 404, 409]
    )


def artemis_get_console_url(
    cfg: Configuration,
    resource: str,
    rid: str,
    logger: Optional[Logger] = None
) -> requests.Response:
    return fetch_artemis(
        cfg,
        '/{}/{}/console/url'.format(resource, rid),
        request_kwargs={},
        logger=None
    )


def confirm(
    cfg: Configuration,
    msg: str,
    force: bool,
    default: bool = False,
    abort: bool = False,
) -> Any:
    """Wrapped click.confirm function to print to stderr."""
    assert cfg.logger is not None

    if force:
        return force

    if cfg.output_format == 'human':
        click.echo(msg, nl=False)
        return click.confirm('', default=default, abort=abort, err=True)

    if abort:
        cfg.logger.info(msg)
        raise click.Abort()

    return False


def prompt(cfg: Configuration, msg: str, type: Any = None, default: Optional[str] = None) -> Any:
    """Wrapped click.prompt function to print to stderr."""
    assert cfg.logger is not None

    if cfg.output_format == 'human':
        click.echo(msg, nl=False)
        return click.prompt('', type=type, default=default, err=True)

    cfg.logger.error(
        'click.prompt() unsupported in non-human output mode, please use the command-line options instead'
    )


def rich_escape_json_list(string: str) -> str:
    """
    This function replaces square brackets representing JSON lists of `json.dumps()` output.
    Rich markup tags (e.g [red]text[/red]) stored in JSON strings will be preserved.
    """

    # Split the string at every '"' into list, every odd index of this list is outside JSON string,
    # every square bracket in these places every square bracket will be doubled (escaped).
    string_list = string.split('"')
    for i in range(0, len(string_list), 2):
        string_list[i] = rich.markup.escape(string_list[i])

    return '"'.join(string_list)


def print_table(cfg: Configuration, table: List[List[str]], format: Optional[str] = None) -> None:
    console = rich.get_console()

    if not format:
        format = 'json' if cfg.output_format != 'human' else 'text'

    def _to_items() -> List[Dict[str, str]]:
        as_list = []

        headers = table[0]

        for row in table[1:]:
            as_list.append({header.lower().replace(' ', '_'): cell for header, cell in zip(headers, row)})

        return as_list

    def _replace_link(link: Any) -> str:
        return '[link={}]LINK[/link]'.format(link.group())

    if format == 'text':
        if len(table) > 1:
            rich_table = rich.table.Table(box=rich.box.HEAVY_HEAD)

            for header in table[0]:
                rich_table.add_column(header)

            for row in table[1:]:
                rich_row = []
                for cell in row:
                    rich_cell = cell if isinstance(cell, str) else rich_escape_json_list(prettify_json(True, cell))

                    # Add clickable 'LINK' button next to every url in case the link gets broken into multiple lines
                    rich_cell = REGEX_URL.sub(_replace_link, rich_cell)
                    rich_row.append(rich_cell)
                rich_table.add_row(*rich_row)

            console.print(rich_table)

    # Before printing in JSON or YAML format, we need to get rid of every markup tag inside strings. This is done
    # using Console.render_str creates a Text object which correctly parses the tags, .plain property returns the
    # original string without any formatting.
    elif format == 'json':
        printable = rich_escape_json_list(prettify_json(True, _to_items()))
        click.echo(console.render_str(printable).plain)

    elif format == 'yaml':
        printable = prettify_yaml(True, _to_items())
        click.echo(console.render_str(printable).plain)

    else:
        assert False, 'Table format {} is not supported'


JobReturnType = TypeVar('JobReturnType')
JobCallbackType = Callable[..., JobReturnType]
JobType = Tuple[JobCallbackType[JobReturnType], List[Any], Dict[str, Any]]


def execute_jobs(
    jobs: List[JobType[JobReturnType]],
    max_workers: Optional[int] = None
):
    # type: (...) -> List[concurrent.futures.Future[JobReturnType]]

    futures = []

    with concurrent.futures.ThreadPoolExecutor(max_workers=max_workers) as executor:
        for callback, args, kwargs in jobs:
            futures.append(executor.submit(callback, *args, **kwargs))

        done, pending = concurrent.futures.wait(futures)

        assert not pending

    return futures
