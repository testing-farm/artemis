import click
import tft.praxis
import tft.praxis.environment
import tft.praxis.root

from . import Configuration, Logger, artemis_create, artemis_inspect, artemis_delete

from typing import Optional
# from . import Logger, Configuration, NL, GREEN, RED, YELLOW, WHITE, prettify_json, \
#              artemis_inspect, artemis_create, artemis_delete, prompt, confirm

# from typing import cast, Any

# to prevent infinite loop in pagination support
PAGINATION_MAX_COUNT = 10000


cli_root = tft.praxis.root.create_cli_root(entry_points=['artemis_cli.command_plugins'])


class ArtemisDeployment(tft.praxis.environment.EnvironmentDimension):
    name = 'artemis'
    label = 'Artemis deployment'
    command_name = 'artemis'
    metavar = 'NAME'


cmd_env = ArtemisDeployment.create_root_command()


@cli_root.group(name='guest', short_help='Guest related commands')
@click.pass_obj
def cmd_guest(cfg: Configuration) -> None:
    pass


@cmd_guest.command(name='create', short_help='Create provisioning request')
@click.option('--keyname', required=True, help='name of ssh key')
@click.option('--priority-group', help='name of priority group')
@click.option('--arch', required=True, help='architecture')
@click.option('--compose', help='compose id')
@click.option('--beaker-distro', help='name of beaker distro')
@click.option('--openstack-image', help='name of openstack image')
@click.option('--aws-image', help='name of aws image')
@click.option('--snapshots', is_flag=True, help='require snapshots support')
@click.pass_obj
def cmd_guest_create(
        cfg: Configuration,
        keyname: Optional[str] = None,
        arch: Optional[str] = None,
        compose: Optional[str] = None,
        beaker_distro: Optional[str] = None,
        openstack_image: Optional[str] = None,
        aws_image: Optional[str] = None,
        snapshots: bool = False,
        priority_group: Optional[str] = None
) -> None:
    num_of_options = sum([int(bool(o)) for o in [compose, beaker_distro, openstack_image, aws_image]])
    if num_of_options != 1:
        Logger().error("""
Exactly one of these options is needed:

--compose OR --beaker-distro OR --openstack-image --OR aws-image
""")

    environment = {}
    environment['arch'] = arch
    if compose:
        environment['compose'] = {'id': compose}
    elif beaker_distro:
        environment['compose'] = {'beaker': {'distro': beaker_distro}}
    elif openstack_image:
        environment['compose'] = {'openstack': {'image': openstack_image}}
    elif aws_image:
        environment['compose'] = {'aws': {'image': aws_image}}
    if snapshots:
        environment['snapshots'] = True

    data = {
            'environment': environment,
            'keyname': keyname,
            'priority_group': 'default-priority'
            }

    response = artemis_create(cfg, 'guests/', data)
    print(tft.praxis.prettify_json(response.json()))


@cmd_guest.command(name='inspect', short_help='Inspect provisioning request')
@click.argument('guestname', metavar='ID', default=None,)
@click.pass_obj
def cmd_guest_inspect(cfg: Configuration, guestname: str) -> None:
    response = artemis_inspect(cfg, 'guests', guestname)
    print(tft.praxis.prettify_json(response.json()))


@cmd_guest.command(name='cancel', short_help='Cancel provisioning request')
@click.argument('guestname', metavar='ID', default=None,)
@click.pass_obj
def cmd_cancel(cfg: Configuration, guestname: str) -> None:
    logger = Logger()
    response = artemis_delete(cfg, 'guests', guestname, logger=logger)
    if response.ok:
        logger.info(f'guest "{guestname}" has been canceled')


@cmd_guest.command(name='list', short_help='List provisioning requests')
@click.pass_obj
def cmd_guest_list(cfg: Configuration) -> None:
    response = artemis_inspect(cfg, 'guests', '')
    print(tft.praxis.prettify_json(True, response.json()))


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
) -> None:
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
        rid = f'{guestname}/events'
    else:
        # get all events
        rid = 'events'

    if page or first or last:
        # request for specific page
        response = artemis_inspect(cfg, 'guests', rid, params=params)
        results_json = response.json()
    else:
        # get all pages
        results_json = []
        for page in range(1, PAGINATION_MAX_COUNT):
            params['page'] = page
            response = artemis_inspect(cfg, 'guests', rid, params=params)
            results_json = results_json + response.json()
            if len(response.json()) < page_size:
                # last page, result is complete
                break
        else:
            Logger().error(f'Pagination: reached limit {PAGINATION_MAX_COUNT} pages')

    if last:
        # for --last, sorting has opposit order, need to reverse here
        results_json.reverse()

    print(tft.praxis.prettify_json(True, results_json))


@click.command(name='init', short_help='Initialize configuration file.')
@click.pass_obj
def cmd_init(cfg: Configuration) -> None:
    """
    Using a series of questions, initialize a configuration file. Some information can be extracted automatically,
    other bits must be explicitly provided by the user.
    """

    import tft.praxis.commands.init

    class ConfigInitializer(tft.praxis.commands.init.ConfigInitializer):
        def init_config(self) -> None:
            self.config = {
                'environment-dimensions': {
                    'artemis-deployment': {
                        'known-items': [
                            'default'
                        ],
                        'default': {
                            'api-url': None
                        }
                    }
                }
            }

        def ask(self) -> None:
            self.TEXT("""
Hi! Following sequence of questions will help you setup configuration for this tool.

Feel free to interrupt it anytime, nothing is saved until the very last step.
""")

            # TODO: query and the actual distinct deployments

            #
            # Artemis API
            #
            self.TITLE('** Artemis API URL **')
            self.TEXT("""
URL of Artemis API, for example 'http://artemis.example.com'. Currently artemis-cli needs just this URL.
""")

            self.config['environment-dimensions']['artemis-deployments']['default']['api-url'] = self.prompt(
                'Enter URL of Artemis API',
                type=str,
                default=None
            )

            self.NL()
