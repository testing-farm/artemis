"""
Classes and functions dealing with metrics.

Our metrics are stored in the database. To transport them through our code, we use dataclasses based on
:py:class:`MetricsBase` class. These are then responsible for loading their data from the database and
conversion to Prometheus-compatible objects, and for providing easy-to-use methods to update metrics
in their area.

Our metrics are split into several sections, grouped together by the subsystem or other shared properties,
and together they form a tree of :py:class:`MetricsBase` classes, starting with :py:class:`Metrics` which
then links to :py:class:`DBMetrics` and other areas. :py:class:`MetricsBase` itself is *not* a dataclass
since it provides only methods, and therefore does not need to be declared as container - that's left
to its offsprings.
"""

import collections
import dataclasses
import datetime
import enum
import json
import os
import platform
import threading
import time
from typing import Any, Callable, Dict, Generic, List, Optional, Tuple, Type, TypeVar, Union, cast

import gluetool.log
# Disable the default, global, shared registry - we do not want our Prometheus metrics to be registered with this
# registry, we do have our own, one fully under our control. Since the default registry is the default value of
# `registry` keyword arguments of metrics classes, the only way how to get rid of this integration seems to be to
# set it to `None`, effectively turning these arguments to `registry=None`.
#
# It just have to be done *before* importing any of these objects, because the keyword argument defaults are evaluated
# when the function is declared. Setting `REGISTRY` to `None` after import wouldn't change the default value of any
# keyword argument.
import prometheus_client.registry
import redis
import sqlalchemy
import sqlalchemy.orm.session
import sqlalchemy.sql.schema
from gluetool.result import Error, Ok, Result
from mypy_extensions import Arg

from . import __VERSION__, Failure
from . import db as artemis_db
from . import safe_call
from .cache import dec_cache_field, dec_cache_value, get_cache_value, inc_cache_field, inc_cache_value, \
    iter_cache_fields, iter_cache_keys, set_cache_value
from .context import SESSION, with_context
from .guest import GuestState
from .knobs import KNOB_POOL_ENABLED, KNOB_WORKER_PROCESS_METRICS_TTL

prometheus_client.registry.REGISTRY = None

import prometheus_client.utils  # noqa: E402
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, Info, generate_latest  # noqa: E402
from prometheus_client.metrics import MetricWrapperBase  # noqa: E402

# Guest age buckets are not all same, but:
#
# * first hour split into intervals of 5 minutes,
# * next 47 hours, by hour,
# * and the rest.
GUEST_AGE_BUCKETS: List[int] = \
    list(range(300, 3600, 300)) \
    + list(range(3600, 49 * 3600, 3600)) \
    + [prometheus_client.utils.INF]


# Message processing time buckets, in milliseconds. Spanning from 5 milliseconds up to 900 seconds.
# Taken from the Prometheus middleware Dramatiq provides - not suited for our needs, but the bucket
# setup is not incompatible with our architecture.
MESSAGE_DURATION_BUCKETS = (
    # -> 1s
    5, 10, 25, 50, 75, 100, 250, 500, 750, 1000,
    # -> 10s
    2500, 5000, 7500, 10000,
    # -> 60s
    30000, 60000,
    # -> 600s/10m
    120000, 180000, 240000, 300000, 360000, 420000, 480000, 540000, 600000,
    # -> 900s/15m
    900000,
    prometheus_client.utils.INF
)


# Machine provisioning time buckets, in seconds. Spanning from 60 seconds up to 24 hours.
# First hour split by minute, next 23 hours, by hour
PROVISION_DURATION_BUCKETS = \
    list(range(60, 3600, 60)) \
    + list(range(3600, 23 * 3600 + 3600, 3600)) \
    + [prometheus_client.utils.INF]


# HTTP request processing time buckets, in milliseconds. Spanning from 5 milliseconds up to 15 seconds.
HTTP_REQUEST_DURATION_BUCKETS = (
    # -> 1s
    5, 10, 25, 50, 75, 100, 250, 500, 750, 1000,
    # -> 15s
    2500, 5000, 7500, 10000, 15000,
    prometheus_client.utils.INF
)

# CLI call duration buckets, in seconds. Spanning from 1 second up to 10 minutes.
CLI_CALL_DURATION_BUCKETS = (
    # -> 60 seconds
    1, 2, 5, 10, 20, 30, 40, 50, 60,
    # -> 600 seconds
    120, 180, 240, 300, 360, 420, 480, 540, 600,
    prometheus_client.utils.INF
)


def reset_counters(metric: Union[Counter, Gauge]) -> None:
    """
    Reset each existing labeled metric to zero. After that, we can use ``inc()`` again.

    :param metric: metric whose labeled sub-metrics we need to reset.
    """

    for labeled_metric in metric._metrics.values():
        labeled_metric._value.set(0)


def reset_histogram(metric: Histogram) -> None:
    """
    Reset each bucket and the total sum to zero. After that, the metric is ready to be filled with updated data.

    :param metric: histogram to reset.
    """

    if hasattr(metric, '_metrics'):
        for labeled_metric in metric._metrics.values():
            labeled_metric._sum.set(0)

            for i, _ in enumerate(metric._upper_bounds):
                labeled_metric._buckets[i].set(0)

    else:
        metric._sum.set(0)

        for i, _ in enumerate(metric._upper_bounds):
            metric._buckets[i].set(0)


V = TypeVar('V', bound=MetricWrapperBase)
U = TypeVar('U')
T = TypeVar('T', bound=int)
S = TypeVar('S', bound=Tuple[str, ...])

FloatBound = TypeVar('FloatBound', bound=float)
LabelBound = TypeVar('LabelBound', bound=Tuple[str, ...])


class _PrometheusAdapter(Generic[S, V]):
    _metric_class: Type[V]

    def __init__(self, parent: 'MetricBase', labels: S) -> None:
        self.parent = parent
        self.labels = labels

    def register_with_prometheus(self, registry: CollectorRegistry) -> V:
        return self._metric_class(
            self.parent.name,
            self.parent.help,
            labelnames=self.labels,
            registry=registry
        )

    def update_prometheus(self, metric: V) -> Result[None, Failure]:
        raise NotImplementedError()


def _update_prometheus_gauge(parent: 'MetricBase[Tuple[()]]', metric: Gauge) -> Result[None, Failure]:
    assert parent.value is not None

    reset_counters(metric)

    metric._value.set(parent.value)

    return Ok(None)


def _update_prometheus_gauge_labeled(
    parent: 'MetricBase[Dict[LabelBound, float]]',
    metric: Gauge
) -> Result[None, Failure]:
    assert parent.value is not None

    reset_counters(metric)

    for labels, count in parent.value.items():
        metric.labels(*labels)._value.set(count)

    return Ok(None)


_update_prometheus_counter = _update_prometheus_gauge
_update_prometheus_counter_labeled = _update_prometheus_gauge_labeled


def _update_prometheus_histogram(
    parent: 'MetricBase[Dict[int, float]]',
    metric: Histogram
) -> Result[None, Failure]:
    assert parent.value is not None

    reset_histogram(metric)

    for bucket_threshold, count in parent.value.items():
        bucket_index = parent.histogram_buckets.index(
            prometheus_client.utils.INF if bucket_threshold == 'inf' else int(bucket_threshold)
        )

        metric._buckets[bucket_index].set(count)
        metric._sum.inc(int(bucket_threshold) * count)

    return Ok(None)


RuntimeReaderType = Callable[[], Result[U, Failure]]


class StorageAdapter(Generic[U]):
    def __init__(self, parent: 'MetricBase') -> None:
        self.parent = parent

    def read(self) -> Result[U, Failure]:
        raise NotImplementedError()

    def inc(self) -> Result[None, Failure]:
        raise NotImplementedError()


class RuntimeStorageAdapter(StorageAdapter[U]):
    def __init__(self, parent: 'MetricBase', reader: RuntimeReaderType) -> None:
        super().__init__(parent)

        self.reader = reader

    def read(self) -> Result[U, Failure]:
        return self.reader()


class CacheStorageAdapter(StorageAdapter[U]):
    def __init__(self, parent: 'MetricBase', cache_key: str) -> None:
        super().__init__(parent)

        self.cache_key = cache_key


class CacheCounterStorageAdapter(CacheStorageAdapter[float]):
    @with_context
    def read(
        self,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[float, Failure]:
        value = get_metric(logger, cache, self.cache_key)

        return Ok(float('NaN') if value is None else float(value))

    @with_context
    def inc(
        self,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        inc_metric(logger, cache, self.cache_key)

        return Ok(None)


LabeledCounterValueType = Dict[Tuple[str, ...], float]


class LabeledCachedCounterStorageAdapter(StorageAdapter[LabeledCounterValueType]):
    @classmethod
    @with_context
    def read(
        cls,
        parent: 'MetricBase',
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[LabeledCounterValueType, Failure]:
        # When labels are not empty, values are stored in cache as a mapping, with names constructed from labels
        # (label1:label2:label3:...).
        assert parent.labels is not None

        return Ok({
            tuple(field.split(':', len(parent.labels) - 1)): value
            for field, value in get_metric_fields(logger, cache, parent.cache_key).items()
        })

    @classmethod
    @with_context
    def inc(
        cls,
        parent: 'MetricBase',
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis,
        *field_components: str
    ) -> Result[None, Failure]:
        assert parent.labels
        assert len(field_components) == len(parent.labels)

        inc_metric_field(logger, cache, parent.cache_key, ':'.join(field_components))

        return Ok(None)


class MetricBase(Generic[U]):
    def __init__(
        self,
        *,
        name: str,
        help: str,
    ) -> None:
        self.name = name
        self.help = help

        self.storage_adapter: Optional[StorageAdapter] = None
        self.prometheus_adapter: Optional[_PrometheusAdapter] = None

        self.prometheus_metric: Optional[MetricWrapperBase] = None

        self.value: Optional[U] = None

    def inc(self) -> Result[None, Failure]:
        return self.storage_adapter.inc()

    def sync(self) -> Result[None, Failure]:
        r_value = self.storage_adapter.read()

        if r_value.is_error:
            return Error(r_value.unwrap_error())

        self.value = r_value.unwrap()

        return Ok(None)

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        self.prometheus_metric = self.prometheus_adapter.register_with_prometheus(registry, self)

    def update_prometheus(self) -> Result[None, Failure]:
        assert self.prometheus_metric

        return self.prometheus_adapter.update_prometheus(self, self.prometheus_metric)


def _construct_trivial_metric(
    *,
    name: str,
    help: str,
    monotonic: bool = False,
    #    histogram_buckets: Optional[List[int]] = None,
    runtime_reader: Optional[Callable[[], Result[U, Failure]]] = None
) -> MetricBase[float]:
    class _TrivialMetric(MetricBase[Tuple[()], float]):
        pass

        if runtime_reader:
            storage_adapter: StorageAdapter = RuntimeStorageAdapter(self, runtime_reader)

        else:
            storage_adapter = CachedCounterStorageAdapter

    return _TrivialMetric(
        name=name,
        help=help,
        prometheus_adapter=prometheus_adapter,
        storage_adapter=storage_adapter
    )


def metric(
    *,
    name: str,
    help: str,
    monotonic: bool = False,
    labels: Optional[Tuple[str, ...]] = None,
    #    storage_adapter: Type[StorageAdapter],
    #    prometheus_adapter: Type[PrometheusAdapter],
    #    histogram_buckets: Optional[List[int]] = None,
    runtime_reader: Optional[Callable[[], Result[U, Failure]]] = None
    #    read_from_system: Optional[Callable[[], Result[U, Failure]]] = None
) -> MetricBase:
    # assert prometheus_adapter is not PrometheusHistogramAdapter or histogram_buckets, ''

    if labels:
        pass



        class _TrivialMetric(MetricBase[Tuple, float]):
            pass

        if runtime_reader:
            storage_adapter: StorageAdapter = RuntimeStorageAdapter(self, runtime_reader)

        else:
            storage_adapter = CachedCounterStorageAdapter

        return _TrivialMetric(
            name=name,
            help=help,
            prometheus_adapter=prometheus_adapter,
            storage_adapter=storage_adapter
        )

class _PrometheusGaugeAdapter(_PrometheusAdapter[S, Gauge]):
    _metric_class = Gauge

    def update_prometheus(self, metric: Gauge) -> Result[None, Failure]:
        assert self.parent.value is not None

        reset_counters(metric)

        if self.labels:
            value = cast(Dict[S, float], self.parent.value)

            for labels, count in value.items():
                metric.labels(*labels)._value.set(count)

        else:
            metric._value.set(self.parent.value)

        return Ok(None)


class LabeledMetric(MetricBase[S, T, Dict[S, T]]):
    @with_context
    def read_from_cache(self, logger: gluetool.log.ContextAdapter, cache: redis.Redis) -> Result[Dict[S, T], Failure]:
        # When labels are not empty, values are stored in cache as a mapping, with names constructed from labels
        # (label1:label2:label3:...).
        assert self.labels is not None

        return Ok(
            {
                cast(S, tuple(field.split(':', len(self.labels) - 1))): cast(T, value)
                for field, value in get_metric_fields(logger, cache, self.cache_key).items()
            }
        )

    @with_context
    def inc(
        self,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis,
        *args: str
    ) -> Result[None, Failure]:
        assert self.labels
        assert len(args) == len(self.labels)

        inc_metric_field(logger, cache, self.cache_key, ':'.join(args))

        return Ok(None)



    db_pool_size: TrivialMetric[int] = TrivialMetric(
        name='db_pool_size',
        help='Maximal number of connections available in the pool.',
        prometheus_adapter=PrometheusGaugeAdapter,
        read_from_system=lambda: DBPoolMetrics._read_db_pool_property('size')
    )






class MetricsBase:
    """
    Base class for all containers carrying metrics around.
    """

    _metric_container_fields: List['MetricsBase']
    _metric_fields: List['MetricBase']

    def __post_init__(self) -> None:
        """
        Collect all fields that are child classes of this base class.

        This list is then used to automagically call :py:func:`sync` and other methods for these fields.

        .. note::

           This method is called by dataclasses implementation,
           see https://docs.python.org/3.7/library/dataclasses.html#post-init-processing
        """

        self._metric_container_fields = [
            self.__dict__[field.name]
            for field in dataclasses.fields(self)
            if isinstance(self.__dict__[field.name], MetricsBase)
        ]

        self._metric_fields = [
            self.__dict__[field.name]
            for field in dataclasses.fields(self)
            if isinstance(self.__dict__[field.name], MetricBase)
        ]

    def sync(self) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        .. note::

           **Requires** the context variables defined in :py:mod:`tft.artemis` to be set properly.

        The default implementation delegates the call to all child fields that are descendants of ``MetricsBase``
        class.
        """

        for container in self._metric_container_fields:
            container.sync()

        for metric in self._metric_fields:
            metric.sync()

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        The default implementation delegates the call to all child fields that are descendants of ``MetricsBase``
        class.

        :param registry: Prometheus registry to attach metrics to.
        """

        for container in self._metric_container_fields:
            container.register_with_prometheus(registry)

        for metric in self._metric_fields:
            metric.register_with_prometheus(registry)

    def update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.

        The default implementation delegates the call to all child fields that are descendants of ``MetricsBase``
        class.
        """

        for container in self._metric_container_fields:
            container.update_prometheus()

        for metric in self._metric_fields:
            metric.update_prometheus()


@dataclasses.dataclass
class DBPoolMetrics(MetricsBase):
    """
    Database connection pool metrics.
    """

    @staticmethod
    @with_context
    def _read_db_pool_property(property_name: str, db: artemis_db.DB) -> Result[int, Failure]:
        if not hasattr(db.engine.pool, property_name) or not callable(db.engine.pool.property_name):
            return Ok(0)

        return Ok(getattr(db.engine.pool, property_name)())

    db_pool_size: TrivialMetric[int] = TrivialMetric(
        name='db_pool_size',
        help='Maximal number of connections available in the pool.',
        prometheus_adapter=PrometheusGaugeAdapter,
        read_from_system=lambda: DBPoolMetrics._read_db_pool_property('size')
    )

    db_pool_checked_in: TrivialMetric[int] = TrivialMetric(
        name='db_pool_checked_in',
        help='Current number of connections checked in',
        prometheus_adapter=PrometheusGaugeAdapter,
        read_from_system=lambda: DBPoolMetrics._read_db_pool_property('checked_in_connections')
    )

    db_pool_checked_out: TrivialMetric[int] = TrivialMetric(
        name='db_pool_checked_out',
        help='Current number of connections checked out',
        prometheus_adapter=PrometheusGaugeAdapter,
        read_from_system=lambda: DBPoolMetrics._read_db_pool_property('checked_out_connections')
    )

    db_pool_overflow: TrivialMetric[int] = TrivialMetric(
        name='db_pool_overflow',
        help='Current overflow of connections',
        prometheus_adapter=PrometheusGaugeAdapter,
        read_from_system=lambda: DBPoolMetrics._read_db_pool_property('current_overflow')
    )


@dataclasses.dataclass
class DBMetrics(MetricsBase):
    """
    Database metrics.
    """

    #: Database connection pool metrics.
    pool: DBPoolMetrics = dataclasses.field(default_factory=DBPoolMetrics)


class PoolResourcesMetricsDimensions(enum.Enum):
    """
    Which of the pool resource metrics to track, limits or usage.
    """

    LIMITS = 'LIMITS'
    USAGE = 'USAGE'


@dataclasses.dataclass
class PoolNetworkResources:
    """
    Describes current values of a single (virtual) network available to the pool.
    """

    # The idea is to store IPv4 and IPv6 as different networks. Might not work, though, in that case we can rename
    # this field, e.g. `ipv4_addresses`, and add IPv6 variant. Let's see how it aligns with the real world out there.
    addresses: Optional[int] = None
    """
    Number of IP addresses.
    """


@dataclasses.dataclass
class PoolResources(MetricsBase):
    """
    Describes current values of pool resources.

    The class is intentionally left "dimension-less", not tied to limits nor usage side of the equation, as the
    actual resource types do not depend on this information.

    All fields are optional, leaving them unset signals the pool driver is not able/not interested in tracking
    the given field.

    This is a main class we use for transporting resources metrics between
    interested parties.

    .. note::

       Memory and diskspace is tracked as integers, not using :py:class:`pint.Quantity`. This will be resolved
       to stick with Pint wherever we use a value with units.
    """

    _KEY = 'metrics.pool.{poolname}.resources.{dimension}'
    _KEY_UPDATED_TIMESTAMP = 'metrics.pool.{poolname}.resources.{dimension}.updated_timestamp'

    _TRIVIAL_FIELDS = ('instances', 'cores', 'memory', 'diskspace', 'snapshots')
    _COMPOUND_FIELDS = ('networks',)

    instances: Optional[int]
    """
    Number of instances (or machines, VMs, servers, etc. - depending on pool's
    terminology).
    """

    cores: Optional[int]
    """
    Number of CPU cores. Given the virtual nature of many pools, cores are more
    common commodity than CPUs.
    """

    memory: Optional[int]
    """
    Size of RAM, in bytes.
    """

    diskspace: Optional[int]
    """
    Size of disk space, in bytes.
    """

    snapshots: Optional[int]
    """
    Number of instance snapshots.
    """

    networks: Dict[str, PoolNetworkResources] = dataclasses.field(default_factory=dict)
    """
    Network resources, i.e. number of addresses and other network-related metrics.
    """

    updated_timestamp: Optional[float] = None
    """
    Time when these metrics were updated, as UNIX timestamp.
    """

    def __init__(self, poolname: str, dimension: PoolResourcesMetricsDimensions) -> None:
        """
        Resource metrics of a particular pool.

        :param poolname: name of the pool whose metrics we're tracking.
        :param dimension: whether this instance describes limits or usage.
        """

        super(PoolResources, self).__init__()

        self._key = PoolResources._KEY.format(poolname=poolname, dimension=dimension.value)
        self._key_updated_timestamp = PoolResources._KEY_UPDATED_TIMESTAMP.format(
            poolname=poolname, dimension=dimension.value
        )

        self.instances = None
        self.cores = None
        self.memory = None
        self.diskspace = None
        self.snapshots = None
        self.networks = {}

        self.updated_timestamp = None

        self.__post_init__()

    @with_context
    def sync(self, cache: redis.Redis) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param cache: cache instance to use for cache access.
        """

        super(PoolResources, self).sync()

        r_serialized = safe_call(cast(Callable[[str], Optional[str]], cache.get), self._key)

        # TODO: needs fix when we start catching errors in metric handling
        if r_serialized.is_error:
            return

        serialized = json.loads(r_serialized.unwrap() or '{}')

        # Since we decided to store in the simplest possible manner, loading is where we "pay the price".
        #
        # We have the serialized JSON blob representing the original `PoolResources` instance, with its fields
        # now being keys and so on. We can replace values in this class by using this serialized blob and storing
        # it in our `__dict__`, except for `networks`. In the serialized form, `networks` is a list of mappings,
        # and we need to restore it as a list of dataclasses. Therefore, `networks` need a bit more work,
        # constructing a list of classes from each mapping.

        self.__dict__.update(serialized)

        self.networks = {
            network_name: PoolNetworkResources(**serialized_network)
            for network_name, serialized_network in serialized.get('networks', {}).items()
        }

        updated = cast(
            Callable[[str], Optional[bytes]],
            cache.get
        )(self._key_updated_timestamp)

        self.updated_timestamp = updated if updated is None else float(updated)

    @with_context
    def store(self, cache: redis.Redis) -> None:
        """
        Store currently carried values in the storage.

        :param cache: cache instance to use for cache access.
        """

        # Storing the data can be actually quite simple: since we're using dataclasses, we can serialize the whole
        # container as a JSON blob. There's no need to store each field as a separate key.
        #
        # This method will take care of serialization of `networks` list as well, since `asdict` can deal with
        # nested dataclasses.

        safe_call(
            cast(Callable[[str, str], None], cache.set),
            self._key,
            json.dumps(dataclasses.asdict(self))
        )

        safe_call(
            cast(Callable[[str, float], None], cache.set),
            self._key_updated_timestamp,
            datetime.datetime.timestamp(datetime.datetime.utcnow())
        )


class PoolResourcesUsage(PoolResources):
    """
    Describes current usage of pool resources.
    """

    def __init__(self, poolname: str) -> None:
        """
        Resource usage of a particular pool.

        :param poolname: name of the pool whose metrics we're tracking.
        """

        super(PoolResourcesUsage, self).__init__(poolname, PoolResourcesMetricsDimensions.USAGE)


class PoolResourcesLimits(PoolResources):
    """
    Describes current limits of pool resources.
    """

    def __init__(self, poolname: str) -> None:
        """
        Resource limits of a particular pool.

        :param poolname: name of the pool whose metrics we're tracking.
        """

        super(PoolResourcesLimits, self).__init__(poolname, PoolResourcesMetricsDimensions.LIMITS)


@dataclasses.dataclass
class PoolResourcesDepleted:
    """
    Describes whether and which pool resources have been depleted.
    """

    available_network_count: int = 0

    instances: bool = False
    cores: bool = False
    memory: bool = False
    diskspace: bool = False
    snapshots: bool = False

    # Depleted networks are listed as names only, no deeper structure. We could change this to mapping between
    # network names and, for example, a boolean or a structure describing which network resource is depleted, but
    # at this moment, all we need to know is whether or not is the network depleted, nothing more.
    networks: List[str] = dataclasses.field(default_factory=list)

    def is_depleted(self) -> bool:
        """
        Test whether any of resources is marked as depleted.

        :returns: ``True`` when any of the fields is marked as depleted, or if there are available networks
            but all of them are marked as depleted; ``False`` otherwise.
        """

        return any([getattr(self, field) for field in PoolResources._TRIVIAL_FIELDS]) \
            or (self.available_network_count != 0 and len(self.networks) == self.available_network_count)

    def depleted_resources(self) -> List[str]:
        """
        Collect depleted resources.

        :returns: list of names of depleted resources. Trivial resources (CPU cores, RAM, etc.) are represented
            by their names, networks are represented as network name prefixed with ``network.``, e.g. ``network.foo``.
        """

        return [
            fieldname
            for fieldname in PoolResources._TRIVIAL_FIELDS
            if getattr(self, fieldname) is True
        ] + [
            'network.{}'.format(network_name)
            for network_name in self.networks
        ]


@dataclasses.dataclass
class PoolResourcesMetrics(MetricsBase):
    """
    Describes resources of a pool, both limits and usage.
    """

    limits: PoolResourcesLimits
    usage: PoolResourcesUsage

    def __init__(self, poolname: str) -> None:
        """
        Resource metrics of a particular pool.

        :param poolname: name of the pool whose metrics we're tracking.
        """

        self.limits = PoolResourcesLimits(poolname)
        self.usage = PoolResourcesUsage(poolname)

        self.__post_init__()

    def get_depletion(
        self,
        is_enough: Callable[[str, int, int], bool]
    ) -> PoolResourcesDepleted:
        """
        Compare limits and usage and yield :py:class:`PoolResourcesDepleted` instance describing depleted resources.

        :param is_enough: a callback called for every resource, with resource name,
            its limit and usage as arguments. Returns ``True`` when there is enough
            resources, ``False`` otherwise.
        :returns: :py:class:`PoolResourcesDepleted` instance listing which resources are depleted.
        """

        delta = PoolResourcesDepleted()

        for fieldname in PoolResources._TRIVIAL_FIELDS:
            limit, usage = getattr(self.limits, fieldname), getattr(self.usage, fieldname)

            # Skip undefined values: if left undefined, pool does not care about this dimension.
            if not limit or not usage:
                continue

            setattr(delta, fieldname, not is_enough(fieldname, limit, usage))

        delta.available_network_count = len(self.limits.networks)

        for network_name, network_limit in self.limits.networks.items():
            network_usage = self.usage.networks.get(network_name)

            # Networks that don't report any usage are treated as having enough resources - again, pool does not care
            # about this network enough to provide data.
            if network_usage is None:
                continue

            if network_limit.addresses is None or network_usage.addresses is None:
                continue

            if is_enough(f'network.addresses.{network_name}', network_limit.addresses, network_usage.addresses):
                continue

            delta.networks.append(network_name)

        return delta


ResourceCostType = int


class ResourceType(enum.Enum):
    """
    Resource type used in cost tracking.
    """

    VIRTUAL_MACHINE = 'virtual-machine'
    DISK = 'disk'
    STATIC_IP = 'static-ip'
    NETWORK_INTERFACE = 'network-interface'
    VIRTUAL_NETWORK = 'virtual-network'


@dataclasses.dataclass
class PoolCostsMetrics(MetricsBase):
    """
    Cumulative cost produced by a pool.
    """

    virtual_machine: Optional[ResourceCostType]
    disk: Optional[ResourceCostType]
    static_ip: Optional[ResourceCostType]
    network_interface: Optional[ResourceCostType]
    virtual_network: Optional[ResourceCostType]

    def __init__(self, poolname: str) -> None:
        """
        Cost metrics of a particular pool.

        :param poolname: name of the pool whose costs we are tracking.
        """

        self._key = 'metrics.pool.{poolname}.cost.cumulative_cost'.format(poolname=poolname)

        self.virtual_machine = None
        self.disk = None
        self.static_ip = None
        self.network_interface = None
        self.virtual_network = None

    @with_context
    def sync(self, cache: redis.Redis, logger: gluetool.log.ContextAdapter) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param cache: cache instance to use for cache access.
        :param logger: logger to use for logging.
        """

        for field, count in get_metric_fields(logger, cache, self._key).items():
            setattr(self, field.replace('-', '_'), count)

    @with_context
    def inc_costs(
        self,
        resource_type: ResourceType,
        value: ResourceCostType,
        cache: redis.Redis,
        logger: gluetool.log.ContextAdapter
    ) -> None:
        """
        Increment cost.

        :param cache: cache instance to use for cache access.
        :param logger: logger to use for logging.
        :param value: value (in cents) to increase the cumulative_cost.
        :param resource_type: resource type whose value is being incremented.
        """

        inc_metric_field(logger, cache, self._key, resource_type.value, value)


@dataclasses.dataclass
class PoolMetrics(MetricsBase):
    """
    Metrics of a particular pool.
    """

    _KEY_ERRORS = 'metrics.pool.{poolname}.errors'
    _KEY_CLI_CALLS = 'metrics.pool.{poolname}.cli-calls'
    _KEY_CLI_EXIT_CODES = 'metrics.pool.{poolname}.cli-calls.exit-codes'
    _KEY_CLI_CALLS_DURATIONS = 'metrics.pool.{poolname}.cli-calls.durations'

    # Image & flavor refresh process does not have their own metrics, hence using this container to track the "last
    # update" timestamp.
    _KEY_INFO_UPDATED_TIMESTAMP = 'metrics.pool.{poolname}.{info}.updated_timestamp'

    poolname: str
    enabled: bool
    routing_enabled: bool

    resources: PoolResourcesMetrics
    costs: PoolCostsMetrics

    current_guest_request_count: int
    current_guest_request_count_per_state: Dict[GuestState, int]

    errors: Dict[str, int]

    image_info_updated_timestamp: Optional[float]
    flavor_info_updated_timestamp: Optional[float]

    # commandname => count
    cli_calls: Dict[str, int]
    # commandname:exitcode => count
    cli_calls_exit_codes: Dict[Tuple[str, str], int]
    # bucket:commandname => count
    cli_calls_durations: Dict[Tuple[str, str], int]

    def __init__(self, poolname: str) -> None:
        """
        Metrics of a particular pool.

        :param poolname: name of the pool whose metrics we're tracking.
        """

        self.key_errors = self._KEY_ERRORS.format(poolname=poolname)

        self.key_image_info_refresh_timestamp = self._KEY_INFO_UPDATED_TIMESTAMP.format(
            poolname=poolname,
            info='image'
        )
        self.key_flavor_info_refresh_timestamp = self._KEY_INFO_UPDATED_TIMESTAMP.format(
            poolname=poolname,
            info='flavor'
        )

        self.key_cli_calls = self._KEY_CLI_CALLS.format(poolname=poolname)
        self.key_cli_calls_exit_codes = self._KEY_CLI_EXIT_CODES.format(poolname=poolname)
        self.key_cli_calls_durations = self._KEY_CLI_CALLS_DURATIONS.format(poolname=poolname)

        self.poolname = poolname
        self.enabled = False
        self.routing_enabled = True

        self.resources = PoolResourcesMetrics(poolname)
        self.costs = PoolCostsMetrics(poolname)

        self.current_guest_request_count = 0
        self.current_guest_request_count_per_state = {}

        self.errors = {}

        self.image_info_updated_timestamp = None
        self.flavor_info_updated_timestamp = None

        self.cli_calls = {}
        self.cli_calls_exit_codes = {}
        self.cli_calls_durations = {}

        self.__post_init__()

    @staticmethod
    @with_context
    def _refresh_info_updated_timestamp(
        pool: str,
        info: str,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        safe_call(
            cast(Callable[[str, float], None], cache.set),
            PoolMetrics._KEY_INFO_UPDATED_TIMESTAMP.format(poolname=pool, info=info),
            datetime.datetime.timestamp(datetime.datetime.utcnow())
        )

        return Ok(None)

    @staticmethod
    def refresh_image_info_updated_timestamp(
        pool: str
    ) -> Result[None, Failure]:
        """
        Update "latest updated" timestamp of pool image info cache to current time.

        :param pool: pool whose cache has been updated.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        return PoolMetrics._refresh_info_updated_timestamp(pool, 'image')

    @staticmethod
    def refresh_flavor_info_updated_timestamp(
        pool: str
    ) -> Result[None, Failure]:
        """
        Update "latest updated" timestamp of pool flavor info cache to current time.

        :param pool: pool whose cache has been updated.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        return PoolMetrics._refresh_info_updated_timestamp(pool, 'flavor')

    @staticmethod
    @with_context
    def inc_error(
        pool: str,
        error: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase counter for a given pool error by 1.

        :param pool: pool that provided the instance.
        :param error: error to track.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, PoolMetrics._KEY_ERRORS.format(poolname=pool), error)
        return Ok(None)

    @staticmethod
    @with_context
    def inc_cli_call(
        poolname: str,
        commandname: str,
        exit_code: int,
        duration: float,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase counter for a given CLI command by 1.

        :param poolname: pool that executed the command.
        :param commandname: command "ID" - something to tell commands and group of commands apart.
        :param exit_code: exit code of the command.
        :param duration: duration of the command session, in seconds.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        # raw count
        inc_metric_field(
            logger,
            cache,
            PoolMetrics._KEY_CLI_CALLS.format(poolname=poolname),
            commandname
        )

        # exit code
        inc_metric_field(
            logger,
            cache,
            PoolMetrics._KEY_CLI_EXIT_CODES.format(poolname=poolname),
            f'{commandname}:{exit_code}'
        )

        # duration
        bucket = min([threshold for threshold in CLI_CALL_DURATION_BUCKETS if threshold > duration])

        inc_metric_field(
            logger,
            cache,
            PoolMetrics._KEY_CLI_CALLS_DURATIONS.format(poolname=poolname), '{}:{}'.format(bucket, commandname))

        return Ok(None)

    @with_context
    def sync(
        self,
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        cache: redis.Redis
    ) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param cache: cache instance to use for cache access.
        """

        super(PoolMetrics, self).sync()

        r_enabled = KNOB_POOL_ENABLED.get_value(session=session, poolname=self.poolname)

        if r_enabled.is_error:
            r_enabled.unwrap_error().handle(logger)

            return

        self.enabled = r_enabled.unwrap() or False  # True => True, False => False, None => False

        # avoid circular imports
        from .routing_policies import KNOB_ROUTE_POOL_ENABLED

        r_routing_enabled = KNOB_ROUTE_POOL_ENABLED.get_value(session=session, poolname=self.poolname)

        # TODO: sync should return Result
        if r_routing_enabled.is_error:
            r_routing_enabled.unwrap_error().handle(logger)

            return

        self.routing_enabled = r_routing_enabled.unwrap()

        self.current_guest_request_count = cast(
            Tuple[int],
            session.query(sqlalchemy.func.count(artemis_db.GuestRequest.guestname))  # type: ignore[no-untyped-call]
            .filter(artemis_db.GuestRequest.poolname == self.poolname)
            .one()
        )[0]

        self.current_guest_request_count_per_state = {
            state: 0
            for state in GuestState.__members__.values()
        }

        self.current_guest_request_count_per_state.update({
            GuestState(record[0]): record[1]
            for record in cast(
                List[Tuple[str, int]],
                session.query(  # type: ignore[no-untyped-call]
                    artemis_db.GuestRequest.state,
                    sqlalchemy.func.count(artemis_db.GuestRequest.state)
                )
                .filter(artemis_db.GuestRequest.poolname == self.poolname)
                .group_by(artemis_db.GuestRequest.state)
                .all()
            )
        })

        self.errors = {
            errorname: count
            for errorname, count in get_metric_fields(logger, cache, self.key_errors).items()
        }

        updated = cast(
            Callable[[str], Optional[bytes]],
            cache.get
        )(self.key_image_info_refresh_timestamp)

        self.image_info_updated_timestamp = updated if updated is None else float(updated)

        updated = cast(
            Callable[[str], Optional[bytes]],
            cache.get
        )(self.key_flavor_info_refresh_timestamp)

        self.flavor_info_updated_timestamp = updated if updated is None else float(updated)

        # commandname => count
        self.cli_calls = {
            field: count
            for field, count in get_metric_fields(
                logger,
                cache,
                self._KEY_CLI_CALLS.format(poolname=self.poolname)
            ).items()
        }

        # commandname:exit-code => count
        self.cli_calls_exit_codes = {
            cast(Tuple[str, str], tuple(field.split(':', 1))): count
            for field, count in get_metric_fields(
                logger,
                cache,
                self.key_cli_calls_exit_codes
            ).items()
        }

        # bucket:commandname => count
        self.cli_calls_durations = {
            cast(Tuple[str, str], tuple(field.split(':', 2))): count
            for field, count in get_metric_fields(
                logger,
                cache,
                self._KEY_CLI_CALLS_DURATIONS.format(poolname=self.poolname)).items()
        }


@dataclasses.dataclass
class UndefinedPoolMetrics(MetricsBase):
    """
    Metrics of an "undefined" pool, to handle values for guests that don't belong into any pool (yet).
    """

    poolname: str
    enabled: bool
    routing_enabled: bool

    resources: PoolResourcesMetrics
    costs: PoolCostsMetrics

    current_guest_request_count: int
    current_guest_request_count_per_state: Dict[GuestState, int]

    errors: Dict[str, int]

    image_info_updated_timestamp: Optional[float]
    flavor_info_updated_timestamp: Optional[float]

    cli_calls: Dict[str, int]
    cli_calls_exit_codes: Dict[Tuple[str, str], int]
    cli_calls_durations: Dict[Tuple[str, str], int]

    def __init__(self, poolname: str) -> None:
        """
        Metrics of a particular pool.

        :param poolname: name of the pool whose metrics we're tracking.
        """

        self.poolname = poolname
        self.enabled = False
        self.routing_enabled = True

        self.resources = PoolResourcesMetrics(poolname)
        self.costs = PoolCostsMetrics(poolname)

        self.current_guest_request_count = 0
        self.current_guest_request_count_per_state = {}

        self.errors = {}

        self.image_info_updated_timestamp = None
        self.flavor_info_updated_timestamp = None

        self.cli_calls = {}
        self.cli_calls_exit_codes = {}
        self.cli_calls_durations = {}

        self.__post_init__()

    @with_context
    def sync(self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        """

        super(UndefinedPoolMetrics, self).sync()

        # NOTE: sqlalchemy overloads operators to construct the conditions, and `is` is not overloaded. Therefore
        # in the query, we have to use `==` instead of more Pythonic `is`.

        self.current_guest_request_count = cast(
            Tuple[int],
            session.query(sqlalchemy.func.count(artemis_db.GuestRequest.guestname))  # type: ignore[no-untyped-call]
            .filter(artemis_db.GuestRequest.poolname == None)  # noqa: E711
            .one()
        )[0]

        self.current_guest_request_count_per_state = {
            state: 0
            for state in GuestState.__members__.values()
        }

        self.current_guest_request_count_per_state.update({
            GuestState(record[0]): record[1]
            for record in cast(
                List[Tuple[str, int]],
                session.query(  # type: ignore[no-untyped-call]
                    artemis_db.GuestRequest.state,
                    sqlalchemy.func.count(artemis_db.GuestRequest.state)
                )
                .filter(artemis_db.GuestRequest.poolname == None)  # noqa: E711
                .group_by(artemis_db.GuestRequest.state)
                .all()
            )
        })


@dataclasses.dataclass
class PoolsMetrics(MetricsBase):
    """
    General metrics shared by pools, and per-pool metrics.
    """

    # here is the space left for global pool-related metrics.

    pools: Dict[str, Union[PoolMetrics, UndefinedPoolMetrics]] = dataclasses.field(default_factory=dict)

    @with_context
    def sync(self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        """

        super(PoolsMetrics, self).sync()

        # Avoid circullar imports
        from .tasks import get_pools

        r_pools = get_pools(logger, session, enabled_only=False)

        if r_pools.is_error:
            r_pools.unwrap_error().handle(logger)

            self.pools = {}

        else:
            self.pools = {
                pool.poolname: PoolMetrics(pool.poolname)
                for pool in r_pools.unwrap()
            }

        self.pools['undefined'] = UndefinedPoolMetrics('undefined')

        for metrics in self.pools.values():
            metrics.sync()

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super(PoolsMetrics, self).register_with_prometheus(registry)

        def _create_pool_resource_metric(name: str, unit: Optional[str] = None) -> Gauge:
            return Gauge(
                'pool_resources_{}{}'.format(name, '_{}'.format(unit) if unit else ''),
                'Limits and usage of pool {}'.format(name),
                ['pool', 'dimension'],
                registry=registry
            )

        def _create_network_resource_metric(name: str, unit: Optional[str] = None) -> Gauge:
            return Gauge(
                'pool_resources_network_{}{}'.format(name, '_{}'.format(unit) if unit else ''),
                'Limits and usage of pool network {}'.format(name),
                ['pool', 'network', 'dimension'],
                registry=registry
            )

        self.POOL_ENABLED = Gauge(
            'pool_enabled',
            'Current enabled/disabled pool state by pool.',
            ['pool'],
            registry=registry
        )

        self.POOL_ROUTING_ENABLED = Gauge(
            'pool_routing_enabled',
            'Current enabled/disabled pool routing state by pool.',
            ['pool'],
            registry=registry
        )

        self.CURRENT_GUEST_REQUEST_COUNT = Gauge(
            'current_guest_request_count',
            'Current number of guest requests being provisioned by pool and state.',
            ['pool', 'state'],
            registry=registry
        )

        self.POOL_ERRORS = Counter(
            'pool_errors',
            'Overall total number of pool errors, per pool and error.',
            ['pool', 'error'],
            registry=registry
        )

        self.POOL_COSTS = Counter(
            'pool_costs',
            'Overall total cost of resources used by a pool, per pool and resource type.',
            ['pool', 'resource'],
            registry=registry
        )

        self.POOL_RESOURCES_INSTANCES = _create_pool_resource_metric('instances')
        self.POOL_RESOURCES_CORES = _create_pool_resource_metric('cores')
        self.POOL_RESOURCES_MEMORY = _create_pool_resource_metric('memory', unit='bytes')
        self.POOL_RESOURCES_DISKSPACE = _create_pool_resource_metric('diskspace', unit='bytes')
        self.POOL_RESOURCES_SNAPSHOTS = _create_pool_resource_metric('snapshot')

        self.POOL_RESOURCES_NETWORK_ADDRESSES = _create_network_resource_metric('addresses')

        self.POOL_RESOURCES_UPDATED_TIMESTAMP = _create_pool_resource_metric('updated_timestamp')

        self.POOL_IMAGE_INFO_UPDATED_TIMESTAMP = Gauge(
            'pool_image_info_updated_timestamp',
            'Last time pool image info has been updated.',
            ['pool'],
            registry=registry
        )

        self.POOL_FLAVOR_INFO_UPDATED_TIMESTAMP = Gauge(
            'pool_flavor_info_updated_timestamp',
            'Last time pool flavor info has been updated.',
            ['pool'],
            registry=registry
        )

        self.CLI_CALLS = Counter(
            'cli_calls',
            'Overall total number of CLI commands executed, per pool and command name.',
            ['pool', 'command'],
            registry=registry
        )

        self.CLI_CALLS_EXIT_CODES = Counter(
            'cli_calls_exit_codes',
            'Overall total number of CLI commands exit codes, per pool, command name and exit code.',
            ['pool', 'command', 'exit_code'],
            registry=registry
        )

        self.CLI_CALLS_DURATIONS = Histogram(
            'cli_call_duration_seconds',
            'The time spent executing CLI commands, by pool and command name.',
            ['pool', 'command'],
            buckets=CLI_CALL_DURATION_BUCKETS,
            registry=registry
        )

    def update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        super(PoolsMetrics, self).update_prometheus()

        reset_counters(self.POOL_ERRORS)
        reset_counters(self.POOL_COSTS)
        reset_counters(self.CLI_CALLS)
        reset_counters(self.CLI_CALLS_EXIT_CODES)
        reset_histogram(self.CLI_CALLS_DURATIONS)

        for poolname, pool_metrics in self.pools.items():
            self.POOL_ENABLED.labels(pool=poolname).set(1 if pool_metrics.enabled else 0)
            self.POOL_ROUTING_ENABLED.labels(pool=poolname).set(1 if pool_metrics.routing_enabled else 0)

            for state in pool_metrics.current_guest_request_count_per_state:
                self.CURRENT_GUEST_REQUEST_COUNT \
                    .labels(poolname, state.value) \
                    .set(pool_metrics.current_guest_request_count_per_state[state])

            for error, count in pool_metrics.errors.items():
                self.POOL_ERRORS.labels(pool=poolname, error=error)._value.set(count)

            for resource in ResourceType.__members__.values():
                value = getattr(pool_metrics.costs, resource.value.replace('-', '_'))

                self.POOL_COSTS \
                    .labels(pool=poolname, resource=resource.value) \
                    ._value.set(value if value is not None else float('NaN'))

            for gauge, metric_name in [
                (self.POOL_RESOURCES_INSTANCES, 'instances'),
                (self.POOL_RESOURCES_CORES, 'cores'),
                (self.POOL_RESOURCES_MEMORY, 'memory'),
                (self.POOL_RESOURCES_DISKSPACE, 'diskspace'),
                (self.POOL_RESOURCES_SNAPSHOTS, 'snapshots')
            ]:
                limit = getattr(pool_metrics.resources.limits, metric_name)
                usage = getattr(pool_metrics.resources.usage, metric_name)

                gauge \
                    .labels(pool=poolname, dimension='limit') \
                    .set(limit if limit is not None else float('NaN'))

                gauge \
                    .labels(pool=poolname, dimension='usage') \
                    .set(usage if usage is not None else float('NaN'))

            for network_name, network_metrics in pool_metrics.resources.limits.networks.items():
                self.POOL_RESOURCES_NETWORK_ADDRESSES \
                    .labels(pool=poolname, dimension='limit', network=network_name) \
                    .set(network_metrics.addresses if network_metrics.addresses is not None else float('NaN'))

            for network_name, network_metrics in pool_metrics.resources.usage.networks.items():
                self.POOL_RESOURCES_NETWORK_ADDRESSES \
                    .labels(pool=poolname, dimension='usage', network=network_name) \
                    .set(network_metrics.addresses if network_metrics.addresses is not None else float('NaN'))

            self.POOL_RESOURCES_UPDATED_TIMESTAMP \
                .labels(pool=poolname, dimension='limit') \
                .set(pool_metrics.resources.limits.updated_timestamp or float('NaN'))

            self.POOL_RESOURCES_UPDATED_TIMESTAMP \
                .labels(pool=poolname, dimension='usage') \
                .set(pool_metrics.resources.usage.updated_timestamp or float('NaN'))

            self.POOL_IMAGE_INFO_UPDATED_TIMESTAMP \
                .labels(pool=poolname) \
                .set(pool_metrics.image_info_updated_timestamp or float('NaN'))

            self.POOL_FLAVOR_INFO_UPDATED_TIMESTAMP \
                .labels(pool=poolname) \
                .set(pool_metrics.flavor_info_updated_timestamp or float('NaN'))

            for commandname, count in pool_metrics.cli_calls.items():
                self.CLI_CALLS \
                    .labels(pool=poolname, command=commandname) \
                    ._value.set(count)

            for (commandname, exit_code), count in pool_metrics.cli_calls_exit_codes.items():
                self.CLI_CALLS_EXIT_CODES \
                    .labels(pool=poolname, command=commandname, exit_code=exit_code) \
                    ._value.set(count)

            for (bucket_threshold, commandname), count in pool_metrics.cli_calls_durations.items():
                bucket_index = CLI_CALL_DURATION_BUCKETS.index(
                    prometheus_client.utils.INF if bucket_threshold == 'inf' else int(bucket_threshold)
                )

                self.CLI_CALLS_DURATIONS \
                    .labels(pool=poolname, command=commandname) \
                    ._buckets[bucket_index] \
                    .set(count)
                self.CLI_CALLS_DURATIONS \
                    .labels(pool=poolname, command=commandname) \
                    ._sum \
                    .inc(float(bucket_threshold) * count)


@dataclasses.dataclass
class ProvisioningMetrics(MetricsBase):
    """
    Provisioning metrics.
    """

    overall_provisioning_count: TrivialMetric[int] = TrivialMetric(
        name='overall_provisioning_count',
        help='Overall total number of all requested guest requests.',
        prometheus_adapter=PrometheusCounterAdapter
    )

    inc_requested = overall_provisioning_count.inc

    @staticmethod
    @with_context
    def _read_current_guest_request_count_total(session: sqlalchemy.orm.session.Session) -> Result[int, Failure]:
        return Ok(session.query(sqlalchemy.func.count(artemis_db.GuestRequest.guestname)).scalar())

    current_guest_request_count_total: TrivialMetric[int] = TrivialMetric(
        name='current_guest_request_count_total',
        help='Current total number of guest requests being provisioned.',
        prometheus_adapter=PrometheusCounterAdapter,
        read_from_system=_read_current_guest_request_count_total
    )

    overall_successfull_provisioning_count: LabeledMetric[Tuple[str], int] = LabeledMetric(
        name='overall_successfull_provisioning_count',
        help='Overall total number of all successfully provisioned guest requests by pool.',
        prometheus_adapter=PrometheusCounterAdapter,
        labels=('pool',)
    )

    inc_success = cast(
        Callable[[Arg(str, 'pool')], Result[None, Failure]],  # noqa: F821
        overall_successfull_provisioning_count.inc
    )

    overall_failover_count: LabeledMetric[Tuple[str, str], int] = LabeledMetric(
        name='overall_failover_count',
        help='Overall total number of failovers to another pool by source and destination pool.',
        prometheus_adapter=PrometheusCounterAdapter,
        labels=('from_pool', 'to_pool')
    )

    inc_failover = cast(
        Callable[[Arg(str, 'from_pool'), Arg(str, 'to_pool')], Result[None, Failure]],  # noqa: F821
        overall_failover_count.inc
    )

    overall_successfull_failover_count: LabeledMetric[Tuple[str, str], int] = LabeledMetric(
        name='overall_successfull_failover_count',
        help='Overall total number of successful failovers to another pool by source and destination pool.',
        prometheus_adapter=PrometheusCounterAdapter,
        labels=('from_pool', 'to_pool')
    )

    inc_failover_success = cast(
        Callable[[Arg(str, 'from_pool'), Arg(str, 'to_pool')], Result[None, Failure]],  # noqa: F821
        overall_successfull_failover_count.inc
    )

    @staticmethod
    @with_context
    def _read_guest_ages(
        session: sqlalchemy.orm.session.Session
    ) -> Result[Dict[Tuple[str, str, str], int], Failure]:
        # Using `query` directly, because we need just limited set of fields, and we need our `Query`
        # and `SafeQuery` to support this functionality (it should be just a matter of correct types).

        NOW = datetime.datetime.utcnow()

        buckets: Dict[Tuple[str, str, str], int] = collections.defaultdict(int)

        query = session.query(  # type: ignore[no-untyped-call]
            artemis_db.GuestRequest.state,
            artemis_db.GuestRequest.poolname,
            artemis_db.GuestRequest.ctime
        )

        for record in cast(List[Tuple[str, Optional[str], datetime.datetime]], query.all()):
            state, poolname, age = record[0], record[1], NOW - record[2]

            # Pick the smallest larger bucket threshold (e.g. age == 250 => 300, age == 3599 => 3600, ...)
            # There's always the last threshold, infinity, so the list should never be empty.
            age_threshold = min([threshold for threshold in GUEST_AGE_BUCKETS if threshold > age.total_seconds()])

            buckets[(state, poolname if poolname else 'unknown', str(age_threshold))] += 1

        return Ok(buckets)

    guest_ages: LabeledMetric[Tuple[str, str, str], int] = LabeledMetric(
        name='guest_request_age',
        help='Guest request ages by pool and state.',
        prometheus_adapter=PrometheusGaugeAdapter,
        labels=('pool', 'state', 'age_threshold')
    )

    # provisioning_durations: TrivialMetric[int] = TrivialMetric(
    #    name='provisioning_duration_seconds',
    #    help='The time spent provisioning a machine.',
    #    prometheus_adapter=HistogramAdapter,
    #    histogram_buckets=PROVISION_DURATION_BUCKETS
    # )

    # @staticmethod
    # @with_context
    # def inc_provisioning_durations(
    #     duration: int,
    # ) -> Result[None, Failure]:
    #    """
    #    Increment provisioning duration bucket by one.
    #
    #    The bucket is determined by the upper bound of the given ``duration``.
    #
    #    :param logger: logger to use for logging.
    #    :param duration: how long, in milliseconds, took actor to finish the task.
    #    :param cache: cache instance to use for cache access.
    #    :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
    #    """
    #
    #    bucket = min([threshold for threshold in PROVISION_DURATION_BUCKETS if threshold > duration])
    #
    #    inc_metric_field(logger, cache, ProvisioningMetrics._KEY_PROVISIONING_DURATIONS, '{}'.format(bucket))
    #
    #    return Ok(None)


@dataclasses.dataclass
class RoutingMetrics(MetricsBase):
    """
    Routing metrics.
    """

    overall_policy_calls_count: LabeledMetric[Tuple[str], int] = LabeledMetric(
        name='overall_policy_calls_count',
        help='Overall total number of policy call by policy name.',
        prometheus_adapter=PrometheusCounterAdapter,
        labels=('policy',)
    )

    inc_policy_called = cast(
        Callable[[Arg(str, 'policyname')], Result[None, Failure]],  # noqa: F821
        overall_policy_calls_count.inc
    )

    overall_policy_cancellations_count: LabeledMetric[Tuple[str], int] = LabeledMetric(
        name='overall_policy_cancellations_count',
        help='Overall total number of policy canceling a guest request by policy name.',
        prometheus_adapter=PrometheusCounterAdapter,
        labels=('policy',)
    )

    inc_policy_canceled = cast(
        Callable[[Arg(str, 'policyname')], Result[None, Failure]],  # noqa: F821
        overall_policy_cancellations_count.inc
    )

    overall_policy_rulings_count: LabeledMetric[Tuple[str, str, str], int] = LabeledMetric(
        name='overall_policy_rulings_count',
        help='Overall total number of policy rulings by policy name, pool name and whether the pool was allowed.',
        prometheus_adapter=PrometheusCounterAdapter,
        labels=('policy', 'pool', 'allowed'),
    )

    @staticmethod
    def inc_pool_allowed(
        policy_name: str,
        pool_name: str
    ) -> Result[None, Failure]:
        """
        Increase "pool allowed by policy" metric by 1.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :param policy_name: policy that made the decision.
        :param pool_name: pool that was allowed.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        return RoutingMetrics.overall_policy_rulings_count.inc(policy_name, pool_name, 'yes')

    @staticmethod
    def inc_pool_excluded(
        policy_name: str,
        pool_name: str
    ) -> Result[None, Failure]:
        """
        Increase "pool excluded by policy" metric by 1.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :param policy_name: policy that made the decision.
        :param pool_name: pool that was excluded.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        return RoutingMetrics.overall_policy_rulings_count.inc(policy_name, pool_name, 'no')


@dataclasses.dataclass
class TaskMetrics(MetricsBase):
    """
    Task and actor metrics.
    """

    overall_message_count: LabeledMetric[Tuple[str, str], int] = LabeledMetric(
        name='overall_message_count',
        help='Overall total number of messages processed by queue and actor.',
        prometheus_adapter=PrometheusCounterAdapter,
        labels=('queue_name', 'actor_name')
    )

    inc_overall_messages = cast(
        Callable[[Arg(str, 'queue'), Arg(str, 'actor')], Result[None, Failure]],  # noqa: F821
        overall_message_count.inc
    )

    overall_errored_message_count: LabeledMetric[Tuple[str, str], int] = LabeledMetric(
        name='overall_errored_message_count',
        help='Overall total number of errored messages by queue and actor.',
        prometheus_adapter=PrometheusCounterAdapter,
        labels=('queue', 'actor')
    )

    inc_overall_errored_messages = cast(
        Callable[[Arg(str, 'queue'), Arg(str, 'actor')], Result[None, Failure]],  # noqa: F821
        overall_errored_message_count.inc
    )

    self.OVERALL_RETRIED_MESSAGE_COUNT = Counter(
        'overall_retried_message_count',
        'Overall total number of retried messages by queue and actor.',
        ['queue_name', 'actor_name'],
        registry=registry
    )

    self.OVERALL_REJECTED_MESSAGE_COUNT = Counter(
        'overall_rejected_message_count',
        'Overall total number of rejected messages by queue and actor.',
        ['queue_name', 'actor_name'],
        registry=registry
    )

    self.CURRENT_MESSAGE_COUNT = Gauge(
        'current_message_count',
        'Current number of messages being processed by queue and actor.',
        ['queue_name', 'actor_name'],
        registry=registry
    )

    self.CURRENT_DELAYED_MESSAGE_COUNT = Gauge(
        'current_delayed_message_count',
        'Current number of messages being delayed by queue and actor.',
        ['queue_name', 'actor_name'],
        registry=registry
    )

    self.MESSAGE_DURATIONS = Histogram(
        'message_duration_milliseconds',
        'The time spent processing messages by queue and actor.',
        ['queue_name', 'actor_name', 'pool'],
        buckets=MESSAGE_DURATION_BUCKETS,
        registry=registry,
    )


    overall_retried_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    overall_rejected_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    current_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    current_delayed_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    message_durations: Dict[Tuple[str, str, str, str], int] = dataclasses.field(default_factory=dict)

    _KEY_OVERALL_RETRIED_MESSAGES = 'metrics.tasks.messages.overall.retried'
    _KEY_OVERALL_REJECTED_MESSAGES = 'metrics.tasks.messages.overall.rejected'
    _KEY_CURRENT_MESSAGES = 'metrics.tasks.messages.current'
    _KEY_CURRENT_DELAYED_MESSAGES = 'metrics.tasks.messages.current.delayed'
    _KEY_MESSAGE_DURATIONS = 'metrics.tasks.messages.durations'

    @staticmethod
    @with_context
    def inc_overall_retried_messages(
        queue: str,
        actor: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of all retried messages.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, TaskMetrics._KEY_OVERALL_RETRIED_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def inc_overall_rejected_messages(
        queue: str,
        actor: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of all rejected messages.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, TaskMetrics._KEY_OVERALL_REJECTED_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def inc_current_messages(
        queue: str,
        actor: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of messages currently being processed.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, TaskMetrics._KEY_CURRENT_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def dec_current_messages(
        queue: str,
        actor: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Decrement number of all messages currently being processed.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        dec_metric_field(logger, cache, TaskMetrics._KEY_CURRENT_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def inc_current_delayed_messages(
        queue: str,
        actor: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of delayed messages.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, TaskMetrics._KEY_CURRENT_DELAYED_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def dec_current_delayed_messages(
        queue: str,
        actor: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Decrement number of delayed messages.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        dec_metric_field(logger, cache, TaskMetrics._KEY_CURRENT_DELAYED_MESSAGES, '{}:{}'.format(queue, actor))
        return Ok(None)

    @staticmethod
    @with_context
    def inc_message_durations(
        queue: str,
        actor: str,
        duration: int,
        poolname: Optional[str],
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of messages in a duration bucket by one.

        The bucket is determined by the upper bound of the given ``duration``.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param duration: how long, in milliseconds, took actor to finish the task.
        :param poolname: if specified, task was working with a particular pool.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        bucket = min([threshold for threshold in MESSAGE_DURATION_BUCKETS if threshold > duration])

        inc_metric_field(
            logger,
            cache,
            TaskMetrics._KEY_MESSAGE_DURATIONS,
            '{}:{}:{}:{}'.format(queue, actor, bucket, poolname or 'undefined')
        )

        return Ok(None)

    @with_context
    def sync(
        self,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        """

        super(TaskMetrics, self).sync()

        # queue:actor => count
        self.overall_message_count = {
            cast(Tuple[str, str], tuple(field.split(':', 1))): count
            for field, count in get_metric_fields(logger, cache, self._KEY_OVERALL_MESSAGES).items()
        }
        self.overall_errored_message_count = {
            cast(Tuple[str, str], tuple(field.split(':', 1))): count
            for field, count in get_metric_fields(logger, cache, self._KEY_OVERALL_ERRORED_MESSAGES).items()
        }
        self.overall_retried_message_count = {
            cast(Tuple[str, str], tuple(field.split(':', 1))): count
            for field, count in get_metric_fields(logger, cache, self._KEY_OVERALL_RETRIED_MESSAGES).items()
        }
        self.overall_rejected_message_count = {
            cast(Tuple[str, str], tuple(field.split(':', 1))): count
            for field, count in get_metric_fields(logger, cache, self._KEY_OVERALL_REJECTED_MESSAGES).items()
        }
        self.current_message_count = {
            cast(Tuple[str, str], tuple(field.split(':', 1))): count
            for field, count in get_metric_fields(logger, cache, self._KEY_CURRENT_MESSAGES).items()
        }
        self.current_delayed_message_count = {
            cast(Tuple[str, str], tuple(field.split(':', 1))): count
            for field, count in get_metric_fields(logger, cache, self._KEY_CURRENT_DELAYED_MESSAGES).items()
        }
        # queue:actor:bucket:poolname => count
        # deal with older version which had only three dimensions (no poolname)
        self.message_durations = {}

        for field, count in get_metric_fields(logger, cache, self._KEY_MESSAGE_DURATIONS).items():
            field_split = tuple(field.split(':', 3))

            if len(field_split) == 3:
                field_split = field_split + ('undefined',)

            self.message_durations[cast(Tuple[str, str, str, str], field_split)] = count

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super(TaskMetrics, self).register_with_prometheus(registry)



    @with_context
    def update_prometheus(self, logger: gluetool.log.ContextAdapter, cache: redis.Redis) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        """

        super(TaskMetrics, self).update_prometheus()

        def _update_counter(prom_metric: Counter, source: Dict[Tuple[str, str], int]) -> None:
            reset_counters(prom_metric)

            for (queue_name, actor_name), count in source.items():
                prom_metric.labels(queue_name=queue_name, actor_name=actor_name)._value.set(count)

        _update_counter(self.OVERALL_MESSAGE_COUNT, self.overall_message_count)
        _update_counter(self.OVERALL_ERRORED_MESSAGE_COUNT, self.overall_errored_message_count)
        _update_counter(self.OVERALL_REJECTED_MESSAGE_COUNT, self.overall_rejected_message_count)
        _update_counter(self.OVERALL_RETRIED_MESSAGE_COUNT, self.overall_retried_message_count)
        _update_counter(self.CURRENT_MESSAGE_COUNT, self.current_message_count)
        _update_counter(self.CURRENT_DELAYED_MESSAGE_COUNT, self.current_delayed_message_count)

        # Reset all duration buckets and sums first
        reset_histogram(self.MESSAGE_DURATIONS)

        # Then, update each bucket with number of observations, and each sum with (observations * bucket threshold)
        # since we don't track the exact duration, just what bucket it falls into.
        for (queue_name, actor_name, bucket_threshold, poolname), count in self.message_durations.items():

            bucket_index = MESSAGE_DURATION_BUCKETS.index(
                prometheus_client.utils.INF if bucket_threshold == 'inf' else int(bucket_threshold)
            )

            self.MESSAGE_DURATIONS.labels(queue_name, actor_name, poolname)._buckets[bucket_index].set(count)
            self.MESSAGE_DURATIONS.labels(queue_name, actor_name, poolname)._sum.inc(float(bucket_threshold) * count)


@dataclasses.dataclass
class APIMetrics(MetricsBase):
    """
    API metrics (mostly HTTP traffic).
    """

    request_durations: Dict[Tuple[str, str, str], int] = dataclasses.field(default_factory=dict)
    request_count: Dict[Tuple[str, str, str], int] = dataclasses.field(default_factory=dict)
    request_inprogress_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)

    _KEY_REQUEST_DURATIONS = 'metrics.api.http.request.durations'
    _KEY_REQUEST_COUNT = 'metrics.api.http.request.total'
    _KEY_REQUEST_INPROGRESS_COUNT = 'metrics.api.http.request.in-progress'

    @staticmethod
    @with_context
    def inc_request_durations(
        method: str,
        path: str,
        duration: float,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of HTTP requests in a duration bucket by one.

        The bucket is determined by the upper bound of the given ``duration``.

        :param method: HTTP method.
        :param path: API endpoint requested.
        :param duration: how long, in milliseconds, took actor to finish the task.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        bucket = min([threshold for threshold in HTTP_REQUEST_DURATION_BUCKETS if threshold > duration])

        inc_metric_field(
            logger,
            cache,
            APIMetrics._KEY_REQUEST_DURATIONS,
            '{}:{}:{}'.format(method, bucket, path)
        )

        return Ok(None)

    @staticmethod
    @with_context
    def inc_requests(
        method: str,
        path: str,
        status: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of completed requests.

        :param method: HTTP method.
        :param path: API endpoint requested.
        :param status: final HTTP status.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, APIMetrics._KEY_REQUEST_COUNT, '{}:{}:{}'.format(method, status, path))
        return Ok(None)

    @staticmethod
    @with_context
    def inc_requests_in_progress(
        method: str,
        path: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of current requests.

        :param method: HTTP method.
        :param path: API endpoint requested.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, APIMetrics._KEY_REQUEST_INPROGRESS_COUNT, '{}:{}'.format(method, path))
        return Ok(None)

    @staticmethod
    @with_context
    def dec_requests_in_progress(
        method: str,
        path: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Decrement number of current requests.

        :param method: HTTP method.
        :param path: API endpoint requested.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        dec_metric_field(logger, cache, APIMetrics._KEY_REQUEST_INPROGRESS_COUNT, '{}:{}'.format(method, path))
        return Ok(None)

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super(APIMetrics, self).register_with_prometheus(registry)

        self.REQUEST_DURATIONS = Histogram(
            'http_request_duration_milliseconds',
            'Time spent processing a request.',
            ['method', 'path'],
            buckets=HTTP_REQUEST_DURATION_BUCKETS,
            registry=registry
        )

        self.REQUEST_COUNT = Counter(
            'http_requests_count',
            'Request count by method, path and status line.',
            ['method', 'path', 'status'],
            registry=registry
        )

        self.REQUESTS_INPROGRESS_COUNT = Gauge(
            'http_requests_inprogress_count',
            'Requests in progress by method and path',
            ['method', 'path'],
            registry=registry
        )

    @with_context
    def sync(self, logger: gluetool.log.ContextAdapter, cache: redis.Redis) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        """

        super(APIMetrics, self).sync()

        # NOTE: some paths may contain `:` => `path` must be the last bit, and `split()` must be called
        # with limited number of splits to prevent `path` exploding.

        # method:bucket:path => count
        self.request_durations = {
            cast(Tuple[str, str, str], tuple(field.split(':', 2))): count
            for field, count in get_metric_fields(logger, cache, self._KEY_REQUEST_DURATIONS).items()
        }

        # method:status:path => count
        self.request_count = {
            cast(Tuple[str, str, str], tuple(field.split(':', 2))): count
            for field, count in get_metric_fields(logger, cache, self._KEY_REQUEST_COUNT).items()
        }

        # method:path => count
        self.request_inprogress_count = {
            cast(Tuple[str, str], tuple(field.split(':', 1))): count
            for field, count in get_metric_fields(logger, cache, self._KEY_REQUEST_INPROGRESS_COUNT).items()
        }

    def update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        super(APIMetrics, self).update_prometheus()

        # Reset all duration buckets and sums first
        reset_histogram(self.REQUEST_DURATIONS)

        # Then, update each bucket with number of observations, and each sum with (observations * bucket threshold)
        # since we don't track the exact duration, just what bucket it falls into.
        for (method, bucket_threshold, path), count in self.request_durations.items():
            bucket_index = HTTP_REQUEST_DURATION_BUCKETS.index(
                prometheus_client.utils.INF if bucket_threshold == 'inf' else int(bucket_threshold)
            )

            self.REQUEST_DURATIONS \
                .labels(method=method, path=path) \
                ._buckets[bucket_index].set(count)
            self.REQUEST_DURATIONS \
                .labels(method=method, path=path) \
                ._sum.inc(float(bucket_threshold) * count)

        reset_counters(self.REQUEST_COUNT)

        for (method, status, path), count in self.request_count.items():
            self.REQUEST_COUNT \
                .labels(method=method, path=path, status=status) \
                ._value.set(count)

        reset_counters(self.REQUESTS_INPROGRESS_COUNT)

        for (method, path), count in self.request_inprogress_count.items():
            self.REQUESTS_INPROGRESS_COUNT \
                .labels(method=method, path=path) \
                ._value.set(count)


@dataclasses.dataclass
class WorkerMetrics(MetricsBase):
    """
    Proxy for metrics related to workers.
    """

    worker_process_count: Dict[str, Optional[int]] = dataclasses.field(default_factory=dict)
    worker_thread_count: Dict[str, Optional[int]] = dataclasses.field(default_factory=dict)
    worker_updated_timestamp: Dict[str, Optional[int]] = dataclasses.field(default_factory=dict)

    _KEY_WORKER_PROCESS_COUNT = 'metrics.workers.{worker}.processes'
    _KEY_WORKER_THREAD_COUNT = 'metrics.workers.{worker}.threads'
    _KEY_UPDATED_TIMESTAMP = 'metrics.workers.{worker}.updated_timestamp'

    @staticmethod
    @with_context
    def update_worker_counts(
        *,
        worker: str,
        processes: int,
        threads: int,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Update metrics for a given worker.

        :param worker: name of the worker.
        :param processes: number of worker processes.
        :param threads: number of worker threads.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        set_metric(
            logger,
            cache,
            WorkerMetrics._KEY_WORKER_PROCESS_COUNT.format(worker=worker),
            processes,
            ttl=KNOB_WORKER_PROCESS_METRICS_TTL.value
        )

        set_metric(
            logger,
            cache,
            WorkerMetrics._KEY_WORKER_THREAD_COUNT.format(worker=worker),
            threads,
            ttl=KNOB_WORKER_PROCESS_METRICS_TTL.value
        )

        set_metric(
            logger,
            cache,
            WorkerMetrics._KEY_UPDATED_TIMESTAMP.format(worker=worker),
            int(datetime.datetime.timestamp(datetime.datetime.utcnow())),
            ttl=KNOB_WORKER_PROCESS_METRICS_TTL.value
        )

        return Ok(None)

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super(WorkerMetrics, self).register_with_prometheus(registry)

        self.WORKER_PROCESS_COUNT = Gauge(
            'worker_process_count',
            'Number of processes by worker.',
            ['worker'],
            registry=registry
        )

        self.WORKER_THREAD_COUNT = Gauge(
            'worker_thread_count',
            'Number of threads by worker.',
            ['worker'],
            registry=registry
        )

        self.WORKER_UPDATED_TIMESTAMP = Gauge(
            'worker_updated_timestamp',
            'Last time worker info info has been updated.',
            ['worker'],
            registry=registry
        )

    @with_context
    def sync(self, logger: gluetool.log.ContextAdapter, cache: redis.Redis) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        """

        super(WorkerMetrics, self).sync()

        self.worker_process_count = {
            metric.decode().split('.')[2]: get_metric(logger, cache, metric.decode())
            for metric in iter_cache_keys(logger, cache, 'metrics.workers.*.processes')
        }

        self.worker_thread_count = {
            metric.decode().split('.')[2]: get_metric(logger, cache, metric.decode())
            for metric in iter_cache_keys(logger, cache, 'metrics.workers.*.threads')
        }

        self.worker_updated_timestamp = {
            metric.decode().split('.')[2]: get_metric(logger, cache, metric.decode())
            for metric in iter_cache_keys(logger, cache, 'metrics.workers.*.updated_timestamp')
        }

    def update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        super(WorkerMetrics, self).update_prometheus()

        reset_counters(self.WORKER_PROCESS_COUNT)
        reset_counters(self.WORKER_THREAD_COUNT)
        reset_counters(self.WORKER_UPDATED_TIMESTAMP)

        # TODO: move these into `reset_counters` - these should be more reliable, and we wouldn't have to
        # do the work on our own.
        self.WORKER_PROCESS_COUNT.clear()
        self.WORKER_THREAD_COUNT.clear()
        self.WORKER_UPDATED_TIMESTAMP.clear()

        for worker, processes in self.worker_process_count.items():
            self.WORKER_PROCESS_COUNT \
                .labels(worker=worker) \
                .set(processes)

        for worker, threads in self.worker_thread_count.items():
            self.WORKER_THREAD_COUNT \
                .labels(worker=worker) \
                .set(threads)

        for worker, timestamp in self.worker_updated_timestamp.items():
            self.WORKER_UPDATED_TIMESTAMP \
                .labels(worker=worker) \
                .set(timestamp if timestamp is None else float(timestamp))

    @staticmethod
    def spawn_metrics_refresher(
        logger: gluetool.log.ContextAdapter,
        worker_name: str,
        interval: int,
        metrics_getter: Callable[[Any], Result[Tuple[int, int], Failure]],
        thread_name: str = 'worker-metrics-refresher',
        worker_instance: Optional[Any] = None,
    ) -> threading.Thread:
        """
        Create and start a thread to refresh cached worker metrics.

        A thread is started, to call ``metrics_getter`` periodically. After each call, data provided by the callable
        are stored in a cache.

        The thread is marked as ``daemon``, therefore it is not necessary to stop it when caller decides to quit.

        :param logger: logger to use for logging.
        :param worker_name: name of the worker.
        :param worker_instance: instance of the worker. It is not inspected by the thread, and it's passed directly
            to ``metrics_getter``.
        :param interval: how often to refresh worker metrics.
        :param metrics_getter: a callable with one parameter, ``worker_instance``. It is called every iteration
            and should return a pair fo two values, number of worker processes and threads.
        :param thread_name: name of the refresher thread.
        :returns: running and daemonized thread.
        """

        def _refresh_loop() -> None:
            while True:
                r_metrics = metrics_getter(worker_instance)

                if r_metrics.is_error:
                    r_metrics.unwrap_error().handle(logger)

                else:
                    processes, threads = r_metrics.unwrap()

                    WorkerMetrics.update_worker_counts(
                        worker=worker_name,
                        processes=processes,
                        threads=threads
                    )

                time.sleep(interval)

        thread = threading.Thread(target=_refresh_loop, name=thread_name, daemon=True)
        thread.start()

        return thread


@dataclasses.dataclass
class Metrics(MetricsBase):
    """
    Global metrics that don't fit anywhere else, and also a root of the tree of metrics.
    """

    db: DBMetrics = DBMetrics()
    pools: PoolsMetrics = PoolsMetrics()
    provisioning: ProvisioningMetrics = ProvisioningMetrics()
    routing: RoutingMetrics = RoutingMetrics()
    tasks: TaskMetrics = TaskMetrics()
    api: APIMetrics = APIMetrics()
    workers: WorkerMetrics = WorkerMetrics()

    @prometheus(Info('artemis_package', 'Artemis packaging info. Labels provide information about package versions.'))
    def update(self, metric: Info) -> None:
        metric.info({
            'package_version': __VERSION__,
            'image_digest': os.getenv('ARTEMIS_IMAGE_DIGEST', '<undefined>'),
            'image_url': os.getenv('ARTEMIS_IMAGE_URL', '<undefined>')
        })

    @prometheus(Info('artemis_identity', 'Artemis identity info. Labels provide information about identity aspects.'))
    def update(self, metric: Info) -> None:
        metric.info({
            'api_node': platform.node(),
            'artemis_deployment': os.getenv('ARTEMIS_DEPLOYMENT', '<undefined>')
        })

    # Registry this tree of metrics containers is tied to.
    _registry: Optional[CollectorRegistry] = None

    @with_context
    def render_prometheus_metrics(self, db: artemis_db.DB) -> Result[bytes, Failure]:
        """
        Render plaintext output of Prometheus metrics representing values in this tree of metrics.

        .. note::

           **Requires** the context variables defined in :py:mod:`tft.artemis` to be set properly.

        :param db: DB instance to use for DB access.
        :returns: plaintext represenation of Prometheus metrics, encoded as ``bytes``.
        """

        def _render() -> bytes:
            with db.get_session() as session:
                SESSION.set(session)

                self.sync()

            self.update_prometheus()

            return cast(bytes, generate_latest(registry=self._registry))

        return safe_call(_render)


def upsert_metric(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    model: Type[artemis_db.Base],
    primary_keys: Dict[Any, Any],
    change: int
) -> None:
    """
    Update a stored value of a given metric.

    Wrapper for :py:func:`tft.artemis.db.upsert` to simplify its use when it comes to metrics. With metrics, we work
    with the following assumptions:

    * model (table) has one or more primary keys,
    * model has a "counter" column (called ``count``) which holds the value of the metric specified by primary keys.

    Therefore, this helper focuses on changing the counter, using primary keys to limit the change, or initialize
    the row if it doesn't exist yet.

    :param logger: logger to use for logging.
    :param session: DB session to use for DB access.
    :param model: SQLAlchemy model representing the metrics table we need to update.
    :param primary_keys: mapping of primary keys and their expected values. This mapping is used to limit
        the update to a particular record, or initialize new record if it doesn't exist yet.

        Primary keys - keys of the mapping - should be the columns of the given model.
    :param change: amount to add to ``count``.
    """

    # TODO: actually check if result of upsert was sucessful
    artemis_db.upsert(
        logger,
        session,
        model,
        primary_keys,
        insert_data={getattr(model, 'count'): 1},
        update_data={'count': getattr(model, 'count') + change}
    )


def upsert_inc_metric(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    model: Type[artemis_db.Base],
    primary_keys: Dict[Any, Any]
) -> None:
    """
    Increment a metric counter by 1.

    Implemented as a thin wrapper for :py:func:`upsert_metric`, therefore the parameters share their meaning.

    :param logger: logger to use for logging.
    :param session: DB session to use for DB access.
    :param model: SQLAlchemy model representing the metrics table we need to update.
    :param primary_keys: mapping of primary keys and their expected values. See :py:func:`upsert_metric`
        for more details.
    """

    upsert_metric(logger, session, model, primary_keys, 1)


def upsert_dec_metric(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    model: Type[artemis_db.Base],
    primary_keys: Dict[Any, Any]
) -> None:
    """
    Decrement a metric counter by 1.

    Implemented as a thin wrapper for :py:func:`upsert_metric`, therefore the parameters share their meaning.

    :param logger: logger to use for logging.
    :param session: DB session to use for DB access.
    :param model: SQLAlchemy model representing the metrics table we need to update.
    :param primary_keys: mapping of primary keys and their expected values. See :py:func:`upsert_metric`
        for more details.
    """

    upsert_metric(logger, session, model, primary_keys, -1)


def inc_metric(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    metric: str,
    amount: int = 1
) -> None:
    """
    Increment a metric counter by 1. If metric does not exist yet, it is set to `0` and incremented.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param metric: metric to increment.
    :param amount: amount to increment by.
    """

    inc_cache_value(logger, cache, metric, amount=amount)


def dec_metric(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    metric: str,
    amount: int = 1
) -> None:
    """
    Decrement a metric counter by 1. If metric does not exist yet, it is set to `0` and decremented.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param metric: metric to decrement.
    :param amount: amount to decrement by.
    """

    dec_cache_value(logger, cache, metric, amount=amount)


def inc_metric_field(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    metric: str,
    field: str,
    amount: int = 1
) -> None:
    """
    Increment a metric field counter by 1. If metric field does not exist yet, it is set to `0` and incremented.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param metric: parent metric to access.
    :param field: field to increment.
    :param amount: amount to increment by.
    """

    inc_cache_field(logger, cache, metric, field, amount=amount)


def dec_metric_field(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    metric: str,
    field: str,
    amount: int = 1
) -> None:
    """
    Decrement a metric field counter by 1. If metric field does not exist yet, it is set to `0` and decremented.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param metric: parent metric to access.
    :param field: field to decrement.
    :param amount: amount to decrement by.
    """

    dec_cache_field(logger, cache, metric, field, amount=amount)


def get_metric(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    metric: str
) -> Optional[int]:
    """
    Return a metric counter for the given metric.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param metric: metric name to retrieve.
    :returns: value of the metric.
    """

    # Redis returns everything as bytes, therefore we need to decode field names to present them as strings
    # and convert values to integers. To make things more complicated, lack of type annotations forces us
    # to wrap `get` with `cast` calls.

    value: Optional[bytes] = get_cache_value(logger, cache, metric)

    return value if value is None else int(value)


def set_metric(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    metric: str,
    value: Optional[int] = None,
    ttl: Optional[int] = None
) -> None:
    """
    Set a metric counter for the given metric.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param metric: metric name to retrieve.
    :param value: value to set to.
    :param ttl: if set, metric would expire in ``ttl`` seconds, and will be removed from cache.
    """

    # Redis returns everything as bytes, therefore we need to decode field names to present them as strings
    # and convert values to integers. To make things more complicated, lack of type annotations forces us
    # to wrap `get` with `cast` calls.

    set_cache_value(logger, cache, metric, value=str(value).encode() if value is not None else None, ttl=ttl)


def get_metric_fields(
    logger: gluetool.log.ContextAdapter,
    cache: redis.Redis,
    metric: str
) -> Dict[str, int]:
    """
    Return a mapping between fields and corresponding counters representing the given metric.

    :param logger: logger to use for logging.
    :param cache: cache instance to use for cache access.
    :param metric: metric name to retrieve.
    :returns: mapping between field and counters.
    """

    # Redis returns everything as bytes, therefore we need to decode field names to present them as strings
    # and convert values to integers. To make things more complicated, lack of type annotations forces us
    # to wrap `hgetall` with `cast` calls.

    return {
        field.decode(): int(value)
        for field, value in iter_cache_fields(logger, cache, metric)
    }
