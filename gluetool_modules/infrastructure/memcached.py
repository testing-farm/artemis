import json
import threading
import urllib

from pymemcache.client import base

import gluetool
from gluetool.log import LoggerMixin, log_dict
from gluetool.result import Result


DEFAULT_DUMP_FETCH_TIMEOUT = 60
DEFAULT_DUMP_FETCH_TICK = 10


# Our custom serializer/deserializer - memcached accepts strings, we switch between Python data structures
# and strings using JSON library. Gluetool's support is not usable as it tends to replace Python objects
# with their __repr__ which is usually not possible to deserialize. This way we can at least catch such
# objects by raising an exception.
def _json_serializer(key, value):
    # sends strings as they are, set flag to 1 to announce it's pure string
    if isinstance(value, str):
        return value, 1

    # dump the rest
    return json.dumps(value), 2


def _json_deserializer(key, value, flags):
    # if the flag is 1, the value was a string
    if flags == 1:
        return value

    # when the flag is 2, it was something more complicated
    if flags == 2:
        return json.loads(value)

    raise gluetool.GlueError('Data in cache has invalid format')


class Cache(LoggerMixin, object):
    """
    Provides access to cache API.
    """

    def __init__(self, module, client):
        super(Cache, self).__init__(module.logger)

        self._module = module
        self._client = client

        # guards access to self._client - apparently, it's not thread-safe by default
        self._lock = threading.Lock()

    def get(self, key, default=None):
        """
        Retrieve value for a given key.

        :param str key: cache key.
        :param default: value returned in case the key is not present in the cache.
        :returns: a value of the key when the key exists, or ``default`` when it does not.
        """

        with self._lock:
            value = self._client.get(key, default=default)

        log_dict(self.debug, "get '{}'".format(key), value)

        return value

    def gets(self, key, default=None, cas_default=None):
        """
        Retrieve value for a given key and its CAS tag.

        :param str key: cache key.
        :param default: value returned in case the key is not present in the cache.
        :param str cas_default: CAS tag returned in case the key is not present in the cache.
        :rtype: tuple(object, str)
        :returns: tuple of two items, either value and CAS tag when the key exists, or provided default values
            when it does not.
        """

        with self._lock:
            value, cas_tag = self._client.gets(key, default=default, cas_default=cas_default)

        log_dict(self.debug, "gets '{}' (CAS {})".format(key, cas_tag), value)

        return value, cas_tag

    def add(self, key, value):
        """
        Add a key with a given value.

        :param str key: cache key.
        :param value: desired value of the key.
        :rtype: bool
        :returns: ``True`` when the key didn't exist and the value was stored, or ``False`` when the key
            already existed.
        """

        log_dict(self.debug, "add '{}'".format(key), value)

        with self._lock:
            return self._client.add(key, value, noreply=False)

    def set(self, key, value):
        """
        Set a value of a given key.

        :param str key: cache key.
        :param value: desired value of the key.
        :rtype: bool
        :returns: ``True`` when the value was successfully changed, ``False`` otherwise.
        """

        log_dict(self.debug, "set '{}'".format(key), value)

        with self._lock:
            return self._client.set(key, value, noreply=False)

    def cas(self, key, value, tag):
        """
        *Check And Set* operation. Set a value of a given key but only when it didn't change - to honor this
        condition, a CAS tag is used. It is retrieved with the value via ``gets`` method and passed to ``cas``
        method. If CAS tag stored in cache hasn't been changed - changes wit hevery change of the key value -
        new value is set. Otherwise, it is left unchanged and ``cas`` reports back to the caller the key value
        has been updated by someone else in the meantime.

        :param str key: cache key.
        :param value: desired value of the key.
        :param str tag: CAS tag previously recieved in return value of ``gets``.
        :returns: ``None`` when the key didn't exist - in such case it is **not** created! ``True`` when new value
            was successfully set, or ``False`` when the key has changed and CAS tag didn't match the one stored
            in cache.
        """

        log_dict(self.debug, "cas '{}' (CAS {})".format(key, tag), value)

        if not isinstance(tag, str):
            raise gluetool.GlueError('CAS tag must be a string, {} found instead'.format(type(tag)))

        with self._lock:
            return self._client.cas(key, value, tag, noreply=False)

    def delete(self, key):
        """
        Delete a given key.

        :param str key: cache key.
        :rtype: bool
        :returns: ``True`` if the key was removed, or ``False`` if it wasn't, e.g. when no such key was found.
        """

        self.debug("delete '{}'".format(key))

        with self._lock:
            return self._client.delete(key, noreply=False)

    def dump(self, separator='/'):
        """
        Dump content of the cache in a form of nested dictionaries, forming a tree and subtrees based on key
        and their components.

        :param str separator: separator delimiting levels of keys. E.g. ``foo/bar/baz`` uses ``/`` as
            a separator.
        :rtype: dict
        :returns: nested dictionaries. For the ``foo/bar/baz`` example above, ``{'foo': {'bar': {'baz': <value>}}}``
            would be returned.
        """

        # We obtain a "metadump" - basically slightly complicated list of all keys in the case, with some
        # other metadata. We cut out all these keys, and then we ask cache to provide values. Then we split
        # keys to their bits, and we construct pile of nested dictionaries of keys and values.

        def _fetch_metadump():
            with self._lock:
                response = self._client._misc_cmd(['lru_crawler metadump all\r\n'], 'metadump all', False)

            log_dict(self.debug, 'metadump response', response)

            if response and response[0] == 'BUSY currently processing crawler request':
                return Result.Error('remote server is busy')

            return Result.Ok(response)

        metadump = gluetool.utils.wait('metadump available', _fetch_metadump,
                                       timeout=self._module.option('dump-fetch-timeout'),
                                       tick=self._module.option('dump-fetch-tick'))

        dump = {}

        # metadump consists of a list of strings
        for part in metadump:
            # each string contains multiple lines
            for line in part.splitlines():
                line = line.strip()

                if line == 'END':
                    break

                # line is a sequence of 'foo=bar' items, separated by space
                info = line.split(' ')

                # first item is 'key=...' - the key we're looking for
                key = info[0].split('=')[1].strip()

                # key can contain "weird" characters, e.g. strange things like '/' or '#' - they are encoded
                # in metadump (%2F and so on), `unquote` will give us the decoded string
                key = urllib.unquote(key)

                key_path = key.split(separator)

                # Beginning with the `dump` dictionary, travel down the road and initialize necessary subdictionaries.
                # Ignore the very last bit of the key - this will be set to the value of the key.
                store = dump
                for step in key_path[0:-1]:
                    if step not in store:
                        store[step] = {}

                    store = store[step]

                store[key_path[-1]] = self.get(key)

        return dump


class Memcached(gluetool.Module):
    """
    Provides access to Memcached server.
    """

    name = 'memcached'
    description = 'Provides access to Memcached server.'

    options = {
        'dump-fetch-timeout': {
            'help': 'Wait this many seconds for dump to become available (default: %(default)s).',
            'metavar': 'SECONDS',
            'default': DEFAULT_DUMP_FETCH_TIMEOUT
        },
        'dump-fetch-tick': {
            'help': 'Wait this many seconds between attempts of fetching dump (default: %(default)s).',
            'metavar': 'SECONDS',
            'default': DEFAULT_DUMP_FETCH_TICK
        },
        'server-hostname': {
            'help': 'Memcached server hostname.',
            'type': str
        },
        'server-port': {
            'help': 'Memcached server port.',
            'type': int
        }
    }

    required_options = ('server-hostname', 'server-port')

    shared_functions = ('cache',)

    # `cached_property` is NOT thread-safe - when multiple threads try to access the property,
    # they may get unpredictable number of different instances...
    #
    # Until a fix lands in upstream, we have to deal with it here by providing our own locks :/
    def __init__(self, *args, **kwargs):
        super(Memcached, self).__init__(*args, **kwargs)

        self._lock = threading.RLock()

        self._client = None
        self._cache = None

    def _get_client(self):
        with self._lock:
            if not self._client:
                self._client = base.Client((self.option('server-hostname'), self.option('server-port')),
                                           serializer=_json_serializer, deserializer=_json_deserializer)

            return self._client

    def _get_cache(self):
        with self._lock:
            if not self._cache:
                self._cache = Cache(self, self._get_client())

            return self._cache

#    @gluetool.utils.cached_property
#    def _client(self):
#        return base.Client((self.option('server-hostname'), self.option('server-port')),
#                           serializer=_json_serializer, deserializer=_json_deserializer)

#    @gluetool.utils.cached_property
#    def _cache(self):
#        cache = Cache(self, self._client)
#
#        log_dict(self.debug, 'cache content', cache.dump())
#
#        return cache

    def cache(self):
        """
        Returns an object providing access to the cache.

        Follows :doc:`Testing Environment Protocol </protocols/cache>`.
        """

        return self._get_cache()
