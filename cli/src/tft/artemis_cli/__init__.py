import concurrent.futures
import json
import pkg_resources
import shlex
import subprocess
import sys

import click
import click_spinner
import dataclasses
import jsonschema
import requests
import ruamel.yaml
import ruamel.yaml.compat
import tabulate
import urlnormalizer

from typing import cast, Any, Callable, Dict, Iterable, List, NamedTuple, NoReturn, Optional, Tuple, TypeVar

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


@dataclasses.dataclass
class Configuration:
    raw_config: Optional[Any] = None

    logger: Optional[Logger] = None

    config_dirpath: Optional[str] = None
    config_filepath: Optional[str] = None

    completion_shell: Optional[str] = None

    output_format: str = 'human'

    artemis_api_url: str = None

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

    return cast(str, stream.getvalue())


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
    url: str,
    logger: Optional[Logger] = None,
    spinner: bool = False,
    method: str = 'get',
    request_kwargs: Optional[Dict[str, Any]] = None,
    on_error: Optional[Callable[[requests.Response], None]] = None,
    allow_statuses: Optional[List[int]] = None
) -> requests.Response:

    allow_statuses = allow_statuses or [200, 201]

    logger = logger or Logger()
    request_kwargs = request_kwargs or {}

    url = urlnormalizer.normalize_url(url)

    with click_spinner.spinner(disable=not spinner):
        if method == 'get':
            res = requests.get(url, **request_kwargs)

        elif method == 'post':
            res = requests.post(url, **request_kwargs)

        elif method == 'delete':
            res = requests.delete(url, **request_kwargs)

    if res.status_code not in allow_statuses:
        if on_error:
            on_error(res, request_kwargs)

        else:
            logger.error(
                'Failed to communicate with remote url {}, responded with code {}'.format(url, res.status_code)
            )

    return res

def fetch_artemis(
    cfg,
    endpoint,
    method='get',
    request_kwargs=None,
    logger=None,
    allow_statuses=None
):
    assert cfg.artemis_api_url is not None
    if not logger:
        logger = Logger()
    def _error_callback(res: requests.Response, request_kwargs) -> None:
        assert logger is not None

        logger.error(
                'Failed to communicate with Artemis API Server, responded with code {}: {}'
                '\nRequest:\n{}\n{}'.format(res.status_code, res.reason, res.request.url, request_kwargs)
        )

    return fetch_remote(
        '{}/{}'.format(cfg.artemis_api_url, endpoint),
        logger,
        method=method,
        request_kwargs=request_kwargs,
        on_error=_error_callback,
        allow_statuses=allow_statuses
    )

def artemis_inspect(cfg, resource, rid, params=None, data=None, logger=None):
    return fetch_artemis(cfg, '/{}/{}'.format(resource, rid), request_kwargs={'json': data, 'params': params}, logger=None)

def artemis_create(cfg, resource, data, logger=None):
    return fetch_artemis(cfg, '/{}'.format(resource), method='post', request_kwargs={'json': data}, logger=None)

def artemis_restore(cfg, resource, rid, data=None, logger=None):
    return fetch_artemis(cfg, '/{}/{}/restore'.format(resource, rid), method='post', request_kwargs={'json': data}, logger=None)

def artemis_delete(cfg, resource, rid, logger=None):
    return fetch_artemis(cfg, '{}/{}'.format(resource, rid), method='delete', logger=None, allow_statuses=[200, 201, 404])

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


def print_table(
    table: List[List[str]],
    format: str = 'text'
) -> None:
    def _to_items() -> List[Dict[str, str]]:
        as_list = []

        headers = table[0]

        for row in table[1:]:
            as_list.append({
                header: cell for header, cell in zip(headers, row)
            })

        return as_list

    if format == 'text':
        printable = tabulate.tabulate(
            table,
            headers='firstrow',
            tablefmt='psql'
        )

    elif format == 'json':
        printable = prettify_json(True, _to_items())

    elif format == 'yaml':
        printable = prettify_yaml(True, _to_items())

    else:
        assert False, 'Table format {} is not supported'

    click.echo(printable)


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
