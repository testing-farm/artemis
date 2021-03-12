Cache Protocol
==============

Modules may provide a cache other modules could use to store data temporarily. API must be thread- and process-safe, safely supporting use from multiple threads and processes.

A *key* is a string. Use of structured keys is recommended - pick a character, e.g. ``/``, and use it to construct hierarchical keys, describing a tree-like structure. This is, however, just a recommendation - for cache use, a key is opaque and its content has not other meaning than being a pointer to a value.

A *value* is a structured data. Basic Python data structures are supported - dictionaries, lists, tuples, built-in types like integers or strings. Objects of user-defined classes may or may not be supported.


Query
-----

None, often the shared function providing access to cache interface bears name ``cache``.


Packet
------

.. py:method:: add(key, value)

   Add a key with a given value.

   :param str key: cache key.
   :param value: desired value of the key.
   :rtype: bool
   :returns: ``True`` when the key didn't exist and the value was stored, or ``False`` when the key
       already existed.


.. py:method:: get(key, default=None)

   Retrieve value for a given key.

   :param str key: cache key.
   :param default: value returned in case the key is not present in the cache.
   :returns: a value of the key when the key exists, or ``default`` when it does not.


.. py:method:: gets(key, default=None, cas_default=None)

   Retrieve value for a given key and its CAS tag.

   :param str key: cache key.
   :param default: value returned in case the key is not present in the cache.
   :param str cas_default: CAS tag returned in case the key is not present in the cache.
   :rtype: tuple(object, str)
   :returns: tuple of two items, either value and CAS tag when the key exists, or provided default values
       when it does not.


.. py:method:: set(key, value)

   Set a value of a given key.

   :param str key: cache key.
   :param value: desired value of the key.
   :rtype: bool
   :returns: ``True`` when the value was successfully changed, ``False`` otherwise.


.. py:method:: cas(key, value, tag)

   *Check And Set* operation. Set a value of a given key but only when it didn't change - to honor this
   condition, a CAS tag is used. It is retrieved with the value via ``gets`` method and passed to ``cas``
   method. If CAS tag stored in cache hasn't been changed - changes with every change of the key value -
   new value is set. Otherwise, it is left unchanged and ``cas`` reports back to the caller the key value
   has been updated by someone else in the meantime.

   :param str key: cache key.
   :param value: desired value of the key.
   :param str tag: CAS tag previously recieved in return value of ``gets``.
   :returns: ``None`` when the key didn't exist - in such case it is **not** created! ``True`` when new value
       was successfully set, or ``False`` when the key has changed and CAS tag didn't match the one stored
       in cache.


.. py:method:: delete(key)

   Delete a given key.

   :param str key: cache key.
   :rtype: bool
   :returns: ``True`` if the key was removed, or ``False`` if it wasn't, e.g. when no such key was found.


.. py:method:: dump(separator='/')

   Dump content of the cache in a form of nested dictionaries, forming a tree and subtrees based on key
   and their components.

   :param str separator: separator delimiting levels of keys. E.g. ``foo/bar/baz`` uses ``/`` as
       a separator.
   :rtype: dict
   :returns: nested dictionaries. For the ``foo/bar/baz`` example above, ``{'foo': {'bar': {'baz': <value>}}}``
       would be returned.
