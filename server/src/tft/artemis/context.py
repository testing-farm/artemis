"""
Context variables.

These are global, "shared" names for important objects that together represent a certain "execution context"
our code runs in. The entry points - places that call methods like :py:func:`get_logger` and :py:func:`get_db`,
usually the first piece of code that runs in reaction to events like HTTP connection or delivered message - are
expected to set these variables properly. It is then expected that following paths will update them as needed,
for example :py:data:`LOGGER` will gain more logging context and therefore the initial object would be replaced
with more specific loggers.

Vast majority of our code expects very similar set of inputs - logger, db, session and so on. This approach
should keep things typed and correctly propagated while allowing the expansion of this virtual "context" by
simply addition of a new variable.

See :py:mod:`contextvars` docs for details, in general these variables are stored as thread local data (not
completely true since they also play nicely with asyncio). Our work is being done in threads, tasks and API
requests are handled by threads with very visible entry points (actor, API handler), therefore it seems both
fitting our approach and safe at the same time - as long as the entry points take care of updating the variables
properly. But, we already have to pass an updated logger instance down the stream, we can assign it to a context
variable instead, therefore it shouldn't bring more work.

On the other hand, things become less visible, code becomes depending on an apparently shared global state,
shared global variables. The names are shared, the values are *not*, thanks to thread-local magic. It seems
possible to develop fixtures to make this code easily testable, and we need to chose very carefuly which code
we switch to context variables and which would continue take arguments as its inputs. Code that exists in
multiple incarnations with the same API (task actors, metric syncs) may benefit greatly from this - no need
to pass N variables to each and every function plus a big red warning "this may use context variables" should
prevent most of the issues.
"""

import contextvars
import functools
from typing import Any, Callable, Dict, Tuple, TypeVar

import gluetool.log
import redis
import sqlalchemy.orm.session

from . import get_cache, get_logger
from .db import DB

T = TypeVar('T')

LOGGER: contextvars.ContextVar[gluetool.log.ContextAdapter] = contextvars.ContextVar('LOGGER', default=get_logger())
DATABASE: contextvars.ContextVar[DB] = contextvars.ContextVar('DATABASE')
SESSION: contextvars.ContextVar[sqlalchemy.orm.session.Session] = contextvars.ContextVar('SESSION')
CACHE: contextvars.ContextVar[redis.Redis] = contextvars.ContextVar('CACHE', default=get_cache(LOGGER.get()))

#: Context variables available as injectables.
CONTEXT_PROVIDERS: Dict[Tuple[str, Any], contextvars.ContextVar[Any]] = {
    ('logger', gluetool.log.ContextAdapter): LOGGER,
    ('db', DB): DATABASE,
    ('session', sqlalchemy.orm.session.Session): SESSION,
    ('cache', redis.Redis): CACHE
}


def with_context(fn: Callable[..., T]) -> Callable[..., T]:
    """
    Decorate function to accept context variables.

    To declare the will to accept a particular variable, declare it as a keyword parameter with a given name and type:

    * ``logger`` :py:class:`gluetool.logger.ContextAdapter` - :py:data:`LOGGER`
    * ``db`` :py:class:`tft.artemis.db.DB` - :py:data:`DATABASE`
    * ``session`` :py:class:`sqlalchemy.orm.session.Session` - :py:data:`SESSION`
    * ``cache`` :py:class:`redis.Redis` - :py:data:`CACHE`

    The objects available for injecting are provided by :py:data:`CONTEXT_PROVIDERS` mapping.

    .. code-block:: python

       @with_context
       def foo(i: int, logger: ContextAdapter, bar: Optional[str] = 'baz') -> str:
           return str(i)

        foo(1)  # `foo(1, logger=LOGGER.get(), bar='baz')` on background

    .. warning::

       At this moment, the type annotations are not enough to express the optionality of some keyword
       arguments - not their values, but the arguments themselves can be missing. This together with
       some extensions that will land in Python 3.10 makes it hard to properly type this decorator
       and the decorated function.

       This means that decorated functions accept any positional and keyword arguments as far as type
       checking machinery is concerned. Which is what it does under the hood, but on the outside, the
       signature should rather prevent such calls instead of allowing them :/

    :param fn: callable to decorate.
    :returns: decorated ``fn``.
    """

    annotation = fn.__annotations__

    @functools.wraps(fn)
    def wrapper(*args: Any, **kwargs: Any) -> T:
        for (name, type_), var in CONTEXT_PROVIDERS.items():
            if name not in annotation or annotation[name] is not type_:
                continue

            kwargs[name] = var.get()

        return fn(*args, **kwargs)

    return wrapper
