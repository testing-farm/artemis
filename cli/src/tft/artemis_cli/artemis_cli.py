import os.path
import requests
import sys
import tempfile
import shutil
import json
import urllib

import click
import click_completion
import stackprinter

from typing import Optional
from tft import artemis_cli
from . import Logger, Configuration, fetch_remote, NL, GREEN, RED, YELLOW, WHITE, prettify_json, \
              artemis_inspect, artemis_create, artemis_restore, artemis_delete, prompt, confirm \

from typing import cast, Any

# to prevent infinite loop in pagination support
PAGINATION_MAX_COUNT=10000

stackprinter.set_excepthook(
    style='darkbg2',
    source_lines=7,
    show_signature=True,
    show_vals='all',
    reverse=False,
    add_summary=False
)

click_completion.init()


@click.group()
@click.pass_context
@click.option('--config', type=str, default=click.get_app_dir('artemis-cli'), help='Path to the configuration directory')
def cli_root(ctx: Any, config: str) -> None:
    ctx.ensure_object(Configuration)

    cfg = cast(
        Configuration,
        ctx.obj
    )

    cfg.logger = Logger()
    cfg.config_dirpath = os.path.expanduser(config)
    cfg.config_filepath = os.path.join(cfg.config_dirpath, 'config.yaml')

    if not os.path.exists(cfg.config_dirpath) or not os.path.exists(cfg.config_filepath):
        if ctx.invoked_subcommand != 'init':
            click.echo(RED(
                'Config file {} does not exists, running configuration wizard'.format(cfg.config_filepath),
            ))

        ctx.invoke(cmd_init)
        sys.exit(0)

    cfg.raw_config = artemis_cli.load_yaml(cfg.config_filepath)

    validation = artemis_cli.validate_struct(cfg.raw_config, 'config')

    if not validation.result or cfg.raw_config is None:

        click.echo(RED(
            'Config file {} must be updated, found following validation errors:'.format(cfg.config_filepath),
        ))

        for error in validation.errors:
            NL()
            click.echo(RED(
                '  * {}'.format(error.message)
            ))
            NL()
        if cfg.raw_config is None:
            NL()
            click.echo(RED('Empty configuration file'))
            NL()


        click.echo(YELLOW(
            'Running configuration wizard'
        ))

        ctx.invoke(cmd_init)
        sys.exit(0)

    cfg.artemis_api_url = cfg.raw_config['artemis_api_url']
    assert cfg.artemis_api_url is not None


@cli_root.group(name='snapshot', short_help='Snapshots related commands')
@click.pass_obj
def cmd_snapshot(cfg: Configuration) -> None:
    pass


@cmd_snapshot.command(name='create', short_help='Create snapshot of a guest')
@click.option('--guest', required=True, help='Guest id')
@click.option('--no-start-again', is_flag=True, help='Do not start the guest after snapshotting')
@click.pass_obj
def cmd_snapshot_create(
        cfg: Configuration,
        guest: str,
        no_start_again: bool
) -> None:
    data = {
        'start_again': not no_start_again
    }

    response = artemis_create(cfg, 'guests/{}/snapshots'.format(guest), data=data)
    cfg.logger.info(prettify_json(True, response.json()))


@cmd_snapshot.command(name='inspect', short_help='Inspect snapshot of a guest')
@click.option('--guest', required=True, help='Guest id')
@click.option('--snapshot', required=True, help='Snapshot id')
@click.pass_obj
def cmd_snapshot_inspect(
        cfg: Configuration,
        guest: str,
        snapshot: str,
) -> None:
    response = artemis_inspect(cfg, 'guests/{}/snapshots'.format(guest), snapshot)
    cfg.logger.info(prettify_json(True, response.json()))


@cmd_snapshot.command(name='restore', short_help='Restore snapshot of a guest')
@click.option('--guest', required=True, help='Guest id')
@click.option('--snapshot', required=True, help='Snapshot id')
@click.pass_obj
def cmd_snapshot_restore(
        cfg: Configuration,
        guest: str,
        snapshot: str,
) -> None:
    response = artemis_restore(cfg, 'guests/{}/snapshots'.format(guest), snapshot)
    cfg.logger.info(prettify_json(True, response.json()))


@cmd_snapshot.command(name='cancel', short_help='Delete snapshot of a guest')
@click.option('--guest', required=True, help='Guest id')
@click.option('--snapshot', required=True, help='Snapshot id')
@click.pass_obj
def cmd_snapshot_cancel(
        cfg: Configuration,
        guest: str,
        snapshot: str,
) -> None:
    artemis_delete(cfg, 'guests/{}/snapshots'.format(guest), snapshot)
    # TODO: add 404 handling
    cfg.logger.info('snapshot "{}" has been canceled'.format(snapshot))


@cli_root.group(name='guest', short_help='Guest related commands')
@click.pass_obj
def cmd_guest(cfg: Configuration) -> None:
    pass

@cmd_guest.command(name='create', short_help='Create provisioning request')
@click.option('--keyname', required=True, help='name of ssh key')
@click.option('--priority-group', help='name of priority group')
@click.option('--arch', required=True, help='architecture')
@click.option('--compose', required=True, help='compose id')
@click.option('--pool', help='name of the pool')
@click.option('--snapshots', is_flag=True, help='require snapshots support')
@click.option('--post-install-script', help='Path to user data script to be executed after vm becomes active')
@click.pass_obj
def cmd_guest_create(
        cfg: Configuration,
        keyname: str = None,
        arch: str = None,
        compose: str = None,
        pool: str = None,
        snapshots = False,
        priority_group = None,
        post_install_script: str = None
) -> None:
    environment = {}
    environment['arch'] = arch
    environment['os'] = {'compose': compose}

    if pool:
        environment['pool'] = pool

    if snapshots:
        environment['snapshots'] = True

    post_install = None
    if post_install_script:
        logger=Logger()
        # check that post_install_script is a valid file and read it
        if os.path.isfile(post_install_script):
            with open(post_install_script) as f:
                post_install = f.read()
        # check that post_install_script is a valid url, if it is - try to download the script
        elif urllib.parse.urlparse(post_install_script).netloc:
            res = requests.get(post_install_script)
            if res.ok:
                # NOTE(ivasilev) content is bytes so a decode step is necessary
                post_install = res.content.decode("utf-8")
            else:
                logger.error("Could not fetch post-install-script {}".format(post_install_script))
        else:
            # not a file and cant be downloaded
            logger.error("Post-install-script {} is not present locally and can't be downloaded".format(
                post_install_script))

    data = {
            'environment': environment,
            'keyname': keyname,
            'priority_group': 'default-priority',
            'post_install_script': post_install,
            }

    response = artemis_create(cfg, 'guests/', data)
    print(prettify_json(True, response.json()))


@cmd_guest.command(name='inspect', short_help='Inspect provisioning request')
@click.argument('guestname', metavar='ID', default=None,)
@click.pass_obj
#def cmd_guest_inspect(cfg: Configuration, guestname: str) -> None:
def cmd_guest_inspect(cfg: Configuration, guestname: str) -> None:
    response = artemis_inspect(cfg, 'guests', guestname)
    print(prettify_json(True, response.json()))


@cmd_guest.command(name='cancel', short_help='Cancel provisioning request')
@click.argument('guestname', metavar='ID', default=None,)
@click.pass_obj
def cmd_cancel(cfg: Configuration, guestname: str) -> None:
    logger=Logger()
    response = artemis_delete(cfg, 'guests', guestname, logger=logger)
    if response.status_code == 404:
        logger.error('guest "{}" has not been found'.format(guestname))
    elif response.status_code == 409:
        logger.error('guest "{}" has provisioned snapshots. Remove the snapshots first'.format(guestname))
    if response.ok:
        logger.info('guest "{}" has been canceled'.format(guestname))


@cmd_guest.command(name='list', short_help='List provisioning requests')
@click.pass_obj
def cmd_guest_list(cfg: Configuration) -> None:
    response = artemis_inspect(cfg, 'guests', '')
    print(prettify_json(True, response.json()))

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
        guestname: Optional[str],
        page_size: Optional[int],
        page: Optional[int],
        since: Optional[str],
        until: Optional[str],
        first: Optional[int],
        last: Optional[int]
)-> None:
    """
    Prints event log

    Optional argument guestname limits events only to given guest.
    Event log support pagination (with default value on Artemi server).
    Events can be also limited by first N values.
    """
    params = {}
    # sorting by 'updated', 'asc' is default, 'desc' is used for --last
    params['sort_field'] = 'updated'
    params['sort_by'] = 'asc'

    def _set_param(name, value):
        if value:
            params[name] = value

    for param in ['page_size', 'page', 'since', 'until']:
        _set_param(param, locals().get(param))

    if len([x for x in [first, last, page] if x]) > 1:
        cfg.logger = Logger()
        Logger().error('only one of --first, --last and --page parameters could be used at once')

    if first:
        params['page_size'] = first
        params['page'] = 1

    if last:
        params['page_size'] = last
        params['page'] = 1
        params['sort_by'] = 'desc'

    if guestname:
        # get events for given guest
        rid = '{}/events'.format(guestname)
    else:
        # get all events
        rid = 'events'

    if page or first or last:
        # request for specific page
        response = artemis_inspect(cfg, 'guests', rid , params=params)
        results_json = response.json()
    else:
        # get all pages
        results_json = []
        for page in range(1, PAGINATION_MAX_COUNT):
            params['page'] = page
            response = artemis_inspect(cfg, 'guests', rid , params=params)
            results_json = results_json + response.json()
            if len(response.json()) < page_size:
                # last page, result is complete
                break
        else:
            Logger().error('Pagination: reached limit {} pages'.format(PAGINATION_MAX_COUNT))

    if last:
        # for --last, sorting has opposit order, need to reverse here
        results_json.reverse()

    print(prettify_json(True, results_json))


@cli_root.command(name='init', short_help='Initialize configuration file.')
@click.pass_obj
def cmd_init(cfg: Configuration) -> None:
    """
    Using a series of questions, initialize a configuration file. Some information can be extracted automatically,
    other bits must be explicitly provided by the user.
    """

    # We try to use one way to do the same thing, including "printing to terminal". For that purpose,
    # we have Logger class and cfg.logger and so on. But in this particular function, we want to print
    # large pile of text, with colors, and that's more readable without logger. So, here's the exception...

    # Oh God, how I miss the preprocessor ...
    def TITLE(s: str) -> None:
        click.echo(YELLOW(s))

    def TEXT(s: str) -> None:
        click.echo(WHITE(s))

    def ERROR(s: str) -> None:
        click.echo(RED(s))

    def WARN(s: str) -> None:
        click.echo(GREEN(s))

    def SUCCESS(s: str) -> None:
        click.echo(GREEN(s))

    def QUESTION(s: str) -> str:
        return YELLOW(s)

    TEXT("""
Hi! Following sequence of questions will help you setup configuration for this tool.
Configuration file is placed at {}

Feel free to interrupt it anytime, nothing is saved until the very last step.
""". format(cfg.config_filepath))

    #
    # Artemis API
    #
    TITLE('** Artemis API URL **')
    TEXT("""
URL of Artemis API, for example 'http://artemis.example.com'
Currently artemis-cli needs just this URL.
""")

    artemis_api_url = prompt(
        cfg,
        QUESTION('Enter URL of Artemis API'),
        type=str,
        default=None
    )

    NL()

    tmp_config_file = tempfile.NamedTemporaryFile(mode='w', delete=False)

    with tmp_config_file:
        print("""---

artemis_api_url: {artemis_api_url}
""".format(**locals()), file=tmp_config_file)

        tmp_config_file.flush()

    if confirm(
        cfg,
        QUESTION('Do you wish to check the configuration file, possibly modifying it?'),
        False,
        default=True
    ):
        click.edit(filename=tmp_config_file.name)

    if confirm(
        cfg,
        QUESTION('Do you wish to save this as your configuration file?'),
        False,
        default=False
    ):
        assert cfg.config_dirpath is not None
        assert cfg.config_filepath is not None

        os.makedirs(cfg.config_dirpath, exist_ok=True)

        if os.path.exists(cfg.config_filepath):
            os.unlink(cfg.config_filepath)

        shutil.copy(tmp_config_file.name, cfg.config_filepath)

        SUCCESS('Saved, your config file has been updated')

    else:
        WARN('Ok, your answers were thrown away.')

