import bs4
import collections
import re
import sys

from six import reraise

import gluetool
from gluetool import GlueError
from gluetool.log import log_dict
from gluetool.utils import fetch_url, PatternMap, IncompatibleOptionsError

# Type annotations
from typing import cast, Any, Callable, Dict, List, Optional, Tuple, Type, Union  # noqa


DEFAULT_NIGHTLY_LISTING = '<default url>'  # type: str
DEFAULT_BU_LISTING = '<default url>'  # type: str
SEPARATOR = ';'


class GuessEnvironment(gluetool.Module):
    """
    "Guess" arch/compose/distro/image/product/wow relevancy distro.

    Goal of this module is to at least partialy answer question about the testing environment
    for a given artifact - deduce what composes, architectures and other properties are
    necessary to begin with. Following modules may change or extend these.

    User can choose from different possible methods of "guessing":

    * ``autodetect``: module will use artifact to deduce as many properties possible
      using mapping files (``--{distro,compose, image,product,wow-relevancy-distro}-pattern-map``)

    * ``force``: instead of autodetection, use specified properties. Use ``--compose``, ``--distro``,
      ``--image``, ``--product`` and ``--wow-relevancy-distro`` options to set actual values.

    * ``recent``: (Only for images) use ``--image`` option as a hint - a regular
      expression, with one matching group, that tells module what image names should be
      considered for selection, and which part of the image name is the key. Images are
      then sorted by their respective key values, and the most recent one is used.
      E.g. ``--image 'Fedora-Cloud-Base-25-(\\d+)\\.\\d'`` will use *date* part
      of image name as a key (e.g. ``20170102``).

    * ``nightly``: (Only for distro) check the nightly composes, and choose the recent available. Use ``--distro``
      option to specify which distro you talk about (e.g. ``RHEL-7.4`` will check RHEL-7.4
      nightlies, and you'll get something like ``RHEL-7.4-20170223.n.0``.

    * ``buc``: (Only for distro) check the batch update composes, and choose the recent
      available. Use ``--distro`` option to specify which distro you talk about
      (e.g. ``RHEL-7.3`` will check RHEL-7.3 composes, and you'll get something like
      ``RHEL-7.3-updates-20170405.0``.

    .. note::
       For guessing we use destination tag with a fallback to build target where applicable. Destination tag provides
       the most relevant information, build target is kept for backward compatibility.
    """

    name = 'guess-environment'
    # pylint: disable=line-too-long
    description = 'Guess testing environment properties (compose/arch/distro/image/wow relevancy env) for artifacts'

    options = [
        ('Methods', {
            'compose-method': {
                'help': 'What method to use for compose "guessing" (default: %(default)s).',
                'choices': ('autodetect', 'target-autodetection', 'force'),
                'default': 'autodetect'
            },
            'distro-method': {
                'help': 'What method to use for distro "guessing" (default: %(default)s).',
                'choices': ('autodetect', 'target-autodetection', 'force', 'nightly', 'buc'),
                'default': 'autodetect'
            },
            'image-method': {
                'help': 'What method to use for image "guessing" (default: %(default)s).',
                'choices': ('autodetect', 'target-autodetection', 'force', 'recent'),
                'default': 'autodetect'
            },
            'product-method': {
                'help': 'What method to use for product "guessing" (default: %(default)s).',
                'choices': ('autodetect', 'target-autodetection', 'force'),
                'default': 'autodetect'
            },
            'wow-relevancy-distro-method': {
                'help': 'What method to use for wow relevancy distro "guessing" (default: %(default)s).',
                'choices': ('autodetect', 'target-autodetection', 'force'),
                'default': 'autodetect'
            }
        }),
        ('Specifications', {
            'compose': {
                'help': 'Compose specification, to help your method with guessing (default: none).',
                'action': 'append',
                'default': []
            },
            'distro': {
                'help': 'Distro specification, to help your method with guessing (default: none).',
                'action': 'append',
                'default': []
            },
            'image': {
                'help': 'Image specification, to help your method with guessing',
            },
            'product': {
                'help': 'Product identification, to help your method with guessing.'
            },
            'wow-relevancy-distro': {
                'help': 'Wow relevancy distro identification, to help your method with guessing.'
            }
        }),
        ('Distro-listings', {
            'nightly-listing': {
                'help': """
                        URL where list of nightly composes lies, in a form of web server's
                        directory listing (default: %(default)s).
                        """,
                'default': DEFAULT_NIGHTLY_LISTING
            },
            'bu-listing': {
                'help': """
                        URL where list of batch update composes lies, in a form of web server's
                        directory listing (default: %(default)s).
                        """,
                'default': DEFAULT_BU_LISTING
            }
        }),
        ('Pattern-maps', {
            'arch-compatibility-map': {
                'help': """
                        Mapping between artifact arches and the actual arches we can use to test them (e.g. i686
                        can be tested on both x86_64 and i686 boxes (default: %(default)s).
                        """,
                'metavar': 'FILE',
                'default': None
            },
            'arch-completeness-map': {
                'help': """
                        Mapping between build target and a list of arches that represent *complete* set of arches
                        we can test for artifacts of such target (default: %(default)s).
                        """,
                'metavar': 'FILE',
                'default': None
            },
            'compose-pattern-map': {
                'help': 'Mapping between build target and one or more composes (default: none).',
                'metavar': '(destination_tag|build_target):PATH',
                'default': []
            },
            'distro-pattern-map': {
                'help': 'Test and path to a file with distro patterns (default: none).',
                'metavar': '(destination_tag|build_target):PATH',
                'action': 'append',
                'default': []
            },
            'image-pattern-map': {
                'help': 'Test and path to a file with image patterns (default: none).',
                'metavar': '(destination_tag|build_target):PATH',
                'action': 'append',
                'default': []
            },
            'product-pattern-map': {
                'help': 'Test and path to a file with product patterns (default: none).',
                'metavar': '(destination_tag|build_target):PATH',
                'action': 'append',
                'default': []
            },
            'wow-relevancy-distro-pattern-map': {
                'help': 'Test and path to a file with wow relevancy distro patterns (default: none).',
                'metavar': '(destination_tag|build_target):PATH',
                'action': 'append',
                'default': []
            }
        }),
        ('Testing', {
            'test-guessing': {
                'help': 'Print the guessed values, except `wow_relevancy_distro`, which needs additional data.',
                'action': 'store_true'
            }
        })
    ]

    shared_functions = ['compose', 'distro', 'image', 'product', 'wow_relevancy_distro']

    supported_dryrun_level = gluetool.glue.DryRunLevels.DRY

    def __init__(self, *args, **kwargs):
        # type: (Any, Any) -> None
        super(GuessEnvironment, self).__init__(*args, **kwargs)

        self._distro = {}  # type: Dict[str, Union[str, List[str]]]
        self._image = {}  # type: Dict[str, Union[str, List[str]]]
        self._product = {}  # type: Dict[str, Union[str, List[str]]]
        self._wow_relevancy_distro = {}  # type: Dict[str, Union[str, List[str]]]

    def compose(self):
        # type: () -> Union[str, List[str]]
        """
        Return guessed compose value

        :rtype: Union[str, List[str]]
        """
        if self._compose['result'] is None:
            self.execute_method(self._compose)
        return self._compose['result']

    def distro(self):
        # type: () -> Union[str, List[str]]
        """
        Return guessed distro value

        :rtype: Union[str, List[str]]
        """
        if self._distro['result'] is None:
            self.execute_method(self._distro)
        return self._distro['result']

    def image(self):
        # type: () -> Union[str, List[str]]
        """
        Return guessed image name

        :rtype: Union[str, List[str]]
        """
        if self._image['result'] is None:
            self.execute_method(self._image)
        return self._image['result']

    def product(self):
        # type: () -> Union[str, List[str]]
        """
        Return guessed product.

        :rtype: Union[str, List[str]]
        """
        if self._product['result'] is None:
            self.execute_method(self._product)
        return self._product['result']

    def wow_relevancy_distro(self, distro):
        # type: (Any) -> Union[str, List[str]]
        """
        Return guessed wow relevancy distro.
        Wow relevancy distro is a part of wow environment and is used for defining distro wow needs to test.
        For example, a user needs to run tests for an upcoming minor release. In this case we can't just pass
        `distro` to wow, because the `distro` describes a released version.

        :param distro: beaker distro with which the wow relevancy distro is related to
        :rtype: Union[str, List[str]]
        """
        if self._wow_relevancy_distro['result'] is None:
            self.execute_method(self._wow_relevancy_distro, distro)
        return self._wow_relevancy_distro['result']

    @gluetool.utils.cached_property
    def _arch_compatibility_map(self):
        # type: () -> Dict[str, List[str]]

        if not self.option('arch-compatibility-map'):
            return {}

        return cast(
            Dict[str, List[str]],
            gluetool.utils.load_yaml(self.option('arch-compatibility-map'), logger=self.logger)
        )

    @gluetool.utils.cached_property
    def _arch_completeness_map(self):
        # type: () -> Optional[PatternMap]

        if not self.option('arch-completeness-map'):
            return None

        return PatternMap(self.option('arch-completeness-map'), logger=self.logger)

    def pattern_map(self, source, test):
        # type: (Dict[str, Union[str, List[str]]]) -> PatternMap
        def _create_buc_repl(hint_repl):
            # type: (Any) -> Any
            def _replace(pattern, target):
                # type: (Any, Any) -> Any
                """
                Use `hint_repl` function - which was created by `_create_simple_repl` - to get
                a hint which is then used to find out the batch update compose.
                """

                hint = hint_repl(pattern, target)
                self.debug("hint is '{}'".format(hint))

                return self._find_buc_for_distro(hint)

            return _replace

        def _create_nightly_repl(hint_repl):
            # type: (Any) -> Any
            def _replace(pattern, target):
                # type: (Any, Any) -> Any
                """
                Use `hint_repl` function - which was created by `_create_simple_repl` - to get
                a hint which is then used to find out the nightly compose.
                """

                hint = hint_repl(pattern, target)
                self.debug("hint is '{}'".format(hint))

                return self._find_nightly_for_distro(hint)

            return _replace

        spices = {'BUC': _create_buc_repl,
                  'NIGHTLY': _create_nightly_repl} if source['type'] == "distro" else None

        pattern_map_path = source['pattern-map'].get(test, None)

        if not pattern_map_path:
            return None

        return PatternMap(pattern_map_path,
                          allow_variables=True,
                          spices=spices,
                          logger=self.logger)

    def _get_latest_finished_compose(self, base_url, hint):
        # type: (str, str) -> Optional[str]
        """
        Fetch index page listing several composes from BASE_URL, and try to find
        the most recent and FINISHED one, using HINT to limit set of examined
        composes - if the composes starts with HINT, we'll check it.

        :param str base_url: URL of the index page. It should be a directory listing,
          with links leading to relevant composes.
        :param str hint: what composes should be examined - it the name of compose
          starts with `hint`, it's one of ours.
        :returns: name of the compose, or `None`.
        """

        # Fetch the index
        try:
            _, content = fetch_url(base_url, logger=self.logger)

        except GlueError:
            raise GlueError('Cannot get list of available composes at {}'.format(base_url))

        # Find all <a/> elements from the index
        soup = bs4.BeautifulSoup(content, 'html.parser')

        # [(text, href), ...]
        composes = [(link.string.replace('/', ''), link['href'])
                    for link in soup.find_all('a') if link.string.startswith(hint)]

        log_dict(self.debug, 'available composes:', composes)

        for name, href in sorted(composes, key=lambda x: x[0], reverse=True):
            self.debug("checking status of '{}'".format(name))

            # Check compose status
            url = '{}/{}/STATUS'.format(base_url, href)

            try:
                _, content = fetch_url(url, logger=self.logger)

            except GlueError:
                self.warn("Cannot find out status of '{}'".format(name))
                continue

            if content.strip() != 'FINISHED':
                self.debug("'{}' not marked as finished".format(name))
                continue

            # Get its ID
            url = '{}/{}/COMPOSE_ID'.format(base_url, href)

            try:
                _, content = fetch_url(url, logger=self.logger)

            except GlueError:
                self.warn("Cannot find out ID of '{}'".format(name))
                continue

            return content.strip()

        return None

    def _find_buc_for_distro(self, hint):
        # type: (str) -> str
        """
        Find batch update compose for a given distro.

        :param str hint: Values like "RHEL-7.3", "RHEL-6.8", etc.
        :returns: BU compose name.
        """

        self.debug("Looking for latest valid BU compose for '{}'".format(hint))

        # First, try to take "latest-FOO" shortcut
        url = self.option('bu-listing') + '/latest-{}'.format(hint) + '/COMPOSE_ID'

        try:
            _, content = fetch_url(url, logger=self.logger)
            return content.strip()

        except GlueError:
            self.warn("Cannot find shortcut '/latest-{}'".format(hint))

        # Ok, so there's no "/latest-<hint>" directory, lets iterate over all available composes
        # under "/<hint>"
        distro = self._get_latest_finished_compose('{}/{}'.format(self.option('bu-listing'), hint), hint)

        if distro is None:
            raise GlueError('None of examined BU composes was acceptable')

        return distro

    def _find_nightly_for_distro(self, hint):
        # type: (str) -> str
        """
        Find nightly compose for a give distro.

        :param str hint: Values like "RHEL-7.3", "RHEL-6.8", etc.
        :returns: Nightly compose name.
        """

        self.debug("Looking for latest valid nightly compose for '{}'".format(hint))

        distro = self._get_latest_finished_compose(self.option('nightly-listing'), hint)

        if distro is None:
            raise GlueError('None of examined nightly composes was acceptable')

        return distro

    def _guess_recent(self, source):
        # type: (Dict[str, Union[str, List[str]]]) -> None
        self.require_shared('openstack')

        hint = '^{}$'.format(source['specification'])
        self.debug("using pattern '{}' as a hint".format(hint))

        try:
            hint_pattern = re.compile(hint)

        except re.error as exc:
            raise GlueError("cannot compile hint pattern '{}': {}".format(hint, str(exc)))

        possible_image = collections.namedtuple('possible_image', ['key', 'name'])
        possible_images = []

        for image in self.shared('openstack').images.list():
            match = hint_pattern.match(image.name)
            if not match:
                continue

            try:
                possible_images.append(possible_image(key=match.group(1), name=image.name))

            except IndexError:
                raise GlueError("Cannot deduce the key from image name '{}'".format(image.name))

        if not possible_images:
            raise GlueError("No image found for hint '{}'".format(hint))

        log_dict(self.debug, 'possible images', possible_images)

        source['result'] = sorted(possible_images, key=lambda x: x.key)[-1].name

    def _guess_nightly(self, source):
        # type: (Dict[str, Union[str, List[str]]]) -> None
        source['result'] = [
            self._find_nightly_for_distro(s.strip()) for s in source['specification']
        ]

    def _guess_buc(self, source):
        # type: (Dict[str, Union[str, List[str]]]) -> None
        source['result'] = [
            self._find_buc_for_distro(s.strip()) for s in source['specification']
        ]

    def _guess_force(self, source):
        # type: (Dict[str, Union[str, List[str]]]) -> None
        if source['type'] in ('compose', 'distro'):
            source['result'] = gluetool.utils.normalize_multistring_option(source['specification'])

        else:
            source['result'] = source['specification']

    def _guess_autodetect(self, source, test, tag, *args):
        # type: (Dict[str, Union[str, List[str]]], str) -> bool

        # wow relevancy distro is related not only to tag, but on beaker distro as well
        if source['type'] == 'wow_relevancy_distro':
            # wow relevancy distro is passed from the *args
            tag = SEPARATOR.join([tag, args[0]])

        try:
            pattern_map = self.pattern_map(source, test)

            if not pattern_map:
                self.warn("no map for test '{}'".format(test))
                return False

            source['result'] = pattern_map.match(tag, multiple=(source['type'] in ['compose', 'distro']))
            return True

        except GlueError as exc:
            if exc.message.startswith('Could not match string'):
                return False

            # in case ther matching failed for some unexpected reason
            reraise(*sys.exc_info())

    def _guess_target_autodetect(self, source, *args):
        # type: (Dict[str, Union[str, List[str]]]) -> None
        self.require_shared('primary_task')
        primary_task = self.shared('primary_task')

        result = None

        # by default we match with destination_tag
        if primary_task.destination_tag:
            result = self._guess_autodetect(source, 'destination_tag', primary_task.destination_tag, *args)

        else:
            self.warn('primary task does not have destination tag')

        # we fallback to build target for legacy reasons
        if not result:
            result = self._guess_autodetect(source, 'build_target', primary_task.target, *args)

        # raise and error if no match
        if not result:
            raise GlueError("Failed to autodetect '{}', no match found".format(source['type']))

    _methods = {
        'autodetect': _guess_target_autodetect,
        'force': _guess_force,
        'target-autodetection': _guess_target_autodetect,
        'recent': _guess_recent,  # Only for images
        'nightly': _guess_nightly,  # Only for distro
        'buc': _guess_buc  # Only for distro
    }

    def _pack_sources(self):
        """
        Packs necessary for guessing values to dict.
        This solution provides the same parameters for guessing methods
        what makes guessing methods universal for all types of guessing target
        """

        def _parse_pattern_map(option):
            maps = {}

            for pattern_map_spec in gluetool.utils.normalize_multistring_option(self.option(option)):
                try:
                    test, path = pattern_map_spec.split(':', 1)

                except ValueError:
                    # Keep things backward compatible - if there's no test, assume build target.
                    test = 'build_target'
                    path = pattern_map_spec

                maps[test] = path

            return maps

        self._compose = {
            'type': 'compose',
            'specification': self.option('compose'),
            'method': self.option('compose-method'),
            'pattern-map': _parse_pattern_map('compose-pattern-map'),
            'result': None
        }
        self._distro = {
            'type': 'distro',
            'specification': self.option('distro'),
            'method': self.option('distro-method'),
            'pattern-map': _parse_pattern_map('distro-pattern-map'),
            'result': None
        }
        self._image = {
            'type': 'image',
            'specification': self.option('image'),
            'method': self.option('image-method'),
            'pattern-map': _parse_pattern_map('image-pattern-map'),
            'result': None
        }
        self._product = {
            'type': 'product',
            'specification': self.option('product'),
            'method': self.option('product-method'),
            'pattern-map': _parse_pattern_map('product-pattern-map'),
            'result': None
        }
        self._wow_relevancy_distro = {
            'type': 'wow_relevancy_distro',
            'specification': self.option('wow-relevancy-distro'),
            'method': self.option('wow-relevancy-distro-method'),
            'pattern-map': _parse_pattern_map('wow-relevancy-distro-pattern-map'),
            'result': None
        }

    def sanity(self):
        # type: () -> None

        # Packs sources here, because self.option is unavailable in __init__
        self._pack_sources()

        specification_required = ('force', 'recent', 'nightly', 'buc')
        specification_ignored = ('autodetect', 'target-autodetection',)

        for source in [self._compose, self._distro, self._image, self._product, self._wow_relevancy_distro]:

            if source['method'] == 'target-autodetection' and not source['pattern-map']:
                raise GlueError(
                    "--{}-pattern-map option is required with method '{}'".format(
                        source['type'], source['method']))

            if source['method'] in specification_required and source['specification'] is None:
                raise IncompatibleOptionsError(
                    "--{} option is required with method '{}'".format(source['type'], source['method']))

            if source['method'] in specification_ignored and source['specification'] not in [None, []]:
                raise IncompatibleOptionsError(
                    "--{} option is ignored with method '{}'".format(source['type'], source['method']))

    def execute_method(self, source, *args):
        # type: (Dict[str, Union[str, List[str]]]) -> None

        method = self._methods.get(source['method'], None)  # type: ignore
        if method is None:
            raise IncompatibleOptionsError("Unknown 'guessing' method '{}'".format(source['method']))

        method(self, source, *args)

        log_dict(self.info, 'Using {}'.format(source['type']), source['result'])

    def execute(self):

        if self.option('test-guessing'):
            log_dict(self.info, 'Guessed environment', {
                'compose': self.compose(),
                'distro': self.distro(),
                'image': self.image(),
                'product': self.product()
            })
