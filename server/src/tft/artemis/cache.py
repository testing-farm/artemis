"""
Cache primitives.

Helpful building blocks for cache operations.
"""

import datetime
import json
from typing import Callable, Dict, Generator, List, Optional, Tuple, Type, TypeVar, cast

import gluetool.log
import redis
from gluetool.result import Error, Ok, Result

from . import Failure, SerializableContainer, safe_call, safe_call_and_handle

S = TypeVar('S', bound='SerializableContainer')


# Our helper types - Redis library does have some types, but they are often way too open for our purposes.
# We often can provide more restricting types.
RedisScanIterType = Callable[[str], Generator[bytes, None, None]]

RedisIncrType = Callable[[str, int], None]
RedisDecrType = RedisIncrType

RedisGetType = Callable[[str], Optional[bytes]]
RedisSetType = Callable[[str, bytes, Optional[int]], None]

RedisHIncrByType = Callable[[str, str, int], None]
RedisHGetType = Callable[[str, str], Optional[bytes]]
# TODO: hmset is deprecated, hset should be used instead, but hset takes mapping as a keyword parameter
# and that's not easy enough to express here with Callable. Leaving that for another patch.
RedisHSet = Callable[[str, bytes, bytes], None]
RedisHMSet = Callable[[str, Dict[bytes, bytes]], None]
RedisHGetAllType = Callable[[str], Optional[Dict[bytes, bytes]]]

RedisDeleteType = Callable[[str], None]
RedisRenameType = Callable[[str, str], None]
RedisExpireType = Callable[[str, int], None]


#
# Manipulation of basic cache types
#

def delete_cache_value(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    key: str
) -> None:
    """
    Return a raw value of a given cache key.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param key: cache key to retrieve.
    :returns: value of the metric.
    """

    return safe_call_and_handle(logger, cast(RedisDeleteType, cache.delete), key)


def get_cache_value(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    key: str
) -> Optional[bytes]:
    """
    Return a raw value of a given cache key.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param key: cache key to retrieve.
    :returns: value of the metric.
    """

    return safe_call_and_handle(logger, cast(RedisGetType, cache.get), key)


def set_cache_value(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    key: str,
    value: Optional[bytes] = None,
    ttl: Optional[int] = None
) -> None:
    """
    Set a raw value of a given cache key.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param key: cache key to set.
    :param value: value to set the key to.
    :param ttl: if set, metric would expire in ``ttl`` seconds, and will be removed from cache.
    """

    if value is None:
        safe_call_and_handle(logger, cast(RedisDeleteType, cache.delete), key)

    else:
        safe_call_and_handle(logger, cast(RedisSetType, cache.set), key, value, ttl)


def inc_cache_value(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    key: str,
    amount: int = 1
) -> None:
    """
    Increment a value by 1. If the key does not exist yet, it is set to `0` and incremented.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param key: key to increment.
    :param amount: amount to increment by.
    """

    safe_call_and_handle(logger, cast(RedisIncrType, cache.incr), key, amount)


def dec_cache_value(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    key: str,
    amount: int = 1
) -> None:
    """
    Decrement a value by 1. If the key does not exist yet, it is set to `0` and decremented.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param key: key to decrement.
    :param amount: amount to decrement by.
    """

    safe_call_and_handle(logger, cast(RedisDecrType, cache.decr), key, amount)


def inc_cache_field(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    key: str,
    field: str,
    amount: int = 1
) -> None:
    """
    Increment a value field by 1. If the key field does not exist yet, it is set to `0` and incremented.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param key: key the field belongs to.
    :param field: field to increment.
    :param amount: amount to increment by.
    """

    safe_call_and_handle(logger, cast(RedisHIncrByType, cache.hincrby), key, field, amount)


def dec_cache_field(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    key: str,
    field: str,
    amount: int = 1
) -> None:
    """
    Decrement a value field by 1. If the key field does not exist yet, it is set to `0` and decremented.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param key: key the field belongs to.
    :param field: field to decrement.
    :param amount: amount to decrement by.
    """

    safe_call_and_handle(logger, cast(RedisHIncrByType, cache.hincrby), key, field, -1 * amount)


def set_cache_fields(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    key: str,
    fields: Optional[Dict[bytes, bytes]] = None,
    ttl: Optional[int] = None
) -> None:
    """
    Set a raw values of fields of a given cache key.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param key: cache key to set.
    :param fields: fields and their values.
    :param ttl: if set, metric would expire in ``ttl`` seconds, and will be removed from cache.
    """

    if fields is None:
        safe_call_and_handle(logger, cast(RedisDeleteType, cache.delete), key)

        return

    safe_call_and_handle(
        logger,
        cast(RedisHMSet, cache.hmset),
        key,
        {
            field: value
            for field, value in fields.items()
        }
    )

    if ttl is not None:
        safe_call_and_handle(logger, cast(RedisExpireType, cache.expire), ttl)


def iter_cache_fields(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    key: str
) -> Generator[Tuple[bytes, bytes], None, None]:
    """
    Iterate over pairs of fields and their values for a given key.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param key: key to retrieve.
    :yields: pairs of field names and their values.
    """

    # Redis returns everything as bytes, therefore we need to decode field names to present them as strings
    # and convert values to integers. To make things more complicated, lack of type annotations forces us
    # to wrap `hgetall` with `cast` calls.

    all_fields = safe_call_and_handle(logger, cast(RedisHGetAllType, cache.hgetall), key)

    if all_fields is None:
        return

    for field, value in all_fields.items():
        yield field, value


def iter_cache_keys(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    match: str
) -> Generator[bytes, None, None]:
    """
    Iterate over key names.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param match: only keys matching this glob pattern would be listed.
    :yields: cache keys.
    """

    try:
        for metric in cast(RedisScanIterType, cache.scan_iter)(match):
            yield metric

    except Exception as exc:
        # TODO: try with safe_call_and_handle, but that's not tested with `yield` yet.
        Failure.from_exc('exception raised inside a safe block', exc).handle(logger)


#
# Manipulation of cached sets
#

def refresh_cached_set(
    cache: redis.Redis,
    key: str,
    items: Dict[str, SerializableContainer]
) -> Result[None, Failure]:
    """
    Store a given set of items in a cache.

    Items are srialized into JSON blobs, and the whole set atomically replaces the current value
    of a given key.

    A special key, `{key}.updated`, is set to current time to indicate when the cached set
    has been refreshed.

    :param cache: cache instance to use for cache access.
    :param key: key holding the set.
    :param items: set of items to store.
    :returns: ``None`` when refresh went well, or an error.
    """

    key_updated = f'{key}.updated'

    if not items:
        # When we get an empty set of items, we should remove the key entirely, to make queries looking for
        # return `None` aka "not found". It's the same as if we'd try to remove all entries, just with one
        # action.
        safe_call(
            cast(RedisDeleteType, cache.delete),
            key
        )

        safe_call(
            cast(RedisSetType, cache.set),
            key_updated,
            datetime.datetime.timestamp(datetime.datetime.utcnow())
        )

        return Ok(None)

    # Two steps: create new structure, and replace the old one. We cannot check the old one
    # and remove entries that are no longer valid.
    new_key = f'{key}.new'

    r_action = safe_call(
        cast(RedisHMSet, cache.hmset),
        new_key,
        {
            item_key.encode(): json.dumps(item.serialize_to_json()).encode()
            for item_key, item in items.items()
        }
    )

    if r_action.is_error:
        return Error(r_action.unwrap_error())

    safe_call(
        cast(RedisRenameType, cache.rename),
        new_key,
        key
    )

    safe_call(
        cast(RedisSetType, cache.set),
        key_updated,
        datetime.datetime.timestamp(datetime.datetime.utcnow())
    )

    return Ok(None)


def get_cached_set(
    cache: redis.Redis,
    key: str,
    item_klass: Type[S]
) -> Result[Dict[str, S], Failure]:
    """
    Retrieve cached set of items.

    Items are unserialized into a given type, and the whole set is returned.

    See :py:func:`get_cached_items_as_list` for the variant returning items in a list.

    :param cache: cache instance to use for cache access.
    :param key: key holding the set.
    :param item_klass: a class to use for unserialization.
    :returns: the retrieved set, or an error.
    """

    r_fetch = safe_call(
        cast(RedisHGetAllType, cache.hgetall),
        key
    )

    if r_fetch.is_error:
        return Error(r_fetch.unwrap_error())

    serialized = r_fetch.unwrap()

    items: Dict[str, S] = {}

    if serialized is None:
        return Ok(items)

    for item_key, item_serialized in serialized.items():
        r_unserialize = safe_call(item_klass.unserialize_from_json, json.loads(item_serialized.decode('utf-8')))

        if r_unserialize.is_error:
            return Error(r_unserialize.unwrap_error())

        items[item_key.decode('utf-8')] = r_unserialize.unwrap()

    return Ok(items)


def get_cached_set_as_list(
    cache: redis.Redis,
    key: str,
    item_klass: Type[S]
) -> Result[List[S], Failure]:
    """
    Retrieve cached set of items in the form of a list of items.

    See :py:func:`get_cached_set` for the variant returning the set as a mapping.

    :param cache: cache instance to use for cache access.
    :param key: key holding the set.
    :param item_klass: a class to use for unserialization.
    :returns: a list of items of the set, or an error.
    """

    r_fetch = get_cached_set(cache, key, item_klass)

    if r_fetch.is_error:
        return Error(r_fetch.unwrap_error())

    items = r_fetch.unwrap()

    return Ok(list(items.values()) if items else [])


def get_cached_set_item(
    cache: redis.Redis,
    key: str,
    item_key: str,
    item_klass: Type[S]
) -> Result[Optional[S], Failure]:
    """
    Retrieve one item of a cached set of items.

    Item is unserialized into a given type.

    :param cache: cache instance to use for cache access.
    :param key: key holding the set.
    :param item_key: name of the item within the set.
    :param item_klass: a class to use for unserialization.
    :returns: the retrieved item, ``None`` when there is no such item, or an error.
    """

    r_fetch = safe_call(
        cast(RedisHGetType, cache.hget),
        key,
        item_key
    )

    if r_fetch.is_error:
        return Error(r_fetch.unwrap_error())

    serialized = r_fetch.unwrap()

    if serialized is None:
        return Ok(None)

    r_unserialize = safe_call(item_klass.unserialize_from_json, json.loads(serialized.decode('utf-8')))

    if r_unserialize.is_error:
        return Error(r_unserialize.unwrap_error())

    return Ok(r_unserialize.unwrap())
