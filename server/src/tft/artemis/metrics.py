# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

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

import dataclasses
import datetime
import enum
import json
import os
import platform
import threading
import time
from typing import TYPE_CHECKING, Any, Callable, Dict, List, Optional, Tuple, TypeVar, Union, cast

import gluetool.log
import prometheus_client.utils
import redis
import sqlalchemy
import sqlalchemy.orm.session
import sqlalchemy.sql.schema
from gluetool.result import Ok, Result
from prometheus_client import CollectorRegistry, Counter, Gauge, Histogram, Info, generate_latest

from . import __VERSION__, DATETIME_FMT, Failure, Sentry, SerializableContainer, TracingOp, db as artemis_db, safe_call
from .cache import (
    RedisGetType,
    dec_cache_field,
    dec_cache_value,
    get_cache_value,
    inc_cache_field,
    inc_cache_value,
    iter_cache_fields,
    iter_cache_keys,
    set_cache_value,
)
from .context import DATABASE, SESSION, with_context
from .guest import GuestState
from .knobs import KNOB_POOL_ENABLED, KNOB_SHELF_MAX_GUESTS, KNOB_WORKER_PROCESS_METRICS_TTL

if TYPE_CHECKING:
    from .drivers import PoolErrorCauses
    from .tasks import NamedActorArgumentsType


T = TypeVar('T')


UNDEFINED_POOL_NAME = 'undefined'


# Guest age buckets are not all same, but:
#
# * first hour split into intervals of 5 minutes,
# * next 47 hours, by hour,
# * and the rest.
GUEST_AGE_BUCKETS = \
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


@dataclasses.dataclass
class WorkerTrafficTask(SerializableContainer):
    """
    One "task" as recorded for the purpose of exposing current workload of various workers.
    """

    workername: str
    worker_pid: int
    worker_tid: int
    ctime: datetime.datetime
    queue: str
    actor: str
    args: 'NamedActorArgumentsType'

    def serialize(self) -> Dict[str, Any]:
        """
        Return Python built-in types representing the content of this container.

        :returns: serialized form of container items.
        """

        serialized = super().serialize()

        serialized['ctime'] = serialized['ctime'].strftime(DATETIME_FMT)

        return serialized

    @classmethod
    def unserialize(cls, serialized: Dict[str, Any]) -> 'WorkerTrafficTask':
        """
        Create container instance representing the content described with Python built-in types.

        :param serialized: serialized form of container.
        :returns: unserialized container.
        """

        serialized['ctime'] = datetime.datetime.strptime(serialized['ctime'], DATETIME_FMT)

        return cls(**serialized)


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


class MetricsBase:
    """
    Base class for all containers carrying metrics around.
    """

    _metric_container_fields: List['MetricsBase']

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

    @property
    def tracing_tags(self) -> Dict[str, str]:
        """
        Custom tracking span tags.

        :returns: container-specific tags for tracing span created by the :py:meth:`sync` method.
        """

        return {}

    def do_sync(self) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        .. note::

           **Requires** the context variables defined in :py:mod:`tft.artemis` to be set properly.

        The default implementation delegates the call to all child fields that are descendants of ``MetricsBase``
        class.
        """

        for container in self._metric_container_fields:
            container.sync()

    def sync(self) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

                .. note::

           **Requires** the context variables defined in :py:mod:`tft.artemis` to be set properly.

        The default implementation delegates the call to all child fields that are descendants of ``MetricsBase``
        class.

        Starts a new tracing span to trace the sync operations in this instance.
        """

        with Sentry.start_span(TracingOp.FUNCTION, description=f'{self.__class__.__name__}.sync') as tracing_span:
            for name, value in self.tracing_tags.items():
                tracing_span.set_tag(name, value)

            self.do_sync()

    def do_register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        The default implementation delegates the call to all child fields that are descendants of ``MetricsBase``
        class.

        :param registry: Prometheus registry to attach metrics to.
        """

        for container in self._metric_container_fields:
            container.register_with_prometheus(registry)

    def register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        The default implementation delegates the call to all child fields that are descendants of ``MetricsBase``
        class.

        :param registry: Prometheus registry to attach metrics to.
        """

        with Sentry.start_span(
            TracingOp.FUNCTION,
            description=f'{self.__class__.__name__}.register_with_prometheus'
        ) as tracing_span:
            for name, value in self.tracing_tags.items():
                tracing_span.set_tag(name, value)

            self.do_register_with_prometheus(registry)

    def do_update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.

        The default implementation delegates the call to all child fields that are descendants of ``MetricsBase``
        class.
        """

        for container in self._metric_container_fields:
            container.update_prometheus()

    def update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.

        The default implementation delegates the call to all child fields that are descendants of ``MetricsBase``
        class.
        """

        with Sentry.start_span(
            TracingOp.FUNCTION,
            description=f'{self.__class__.__name__}.update_prometheus'
        ) as tracing_span:
            for name, value in self.tracing_tags.items():
                tracing_span.set_tag(name, value)

            self.do_update_prometheus()


@dataclasses.dataclass
class DBPoolMetrics(MetricsBase):
    """
    Database connection pool metrics.
    """

    #: Total number of connections allowed to exist in the pool.
    size: int = 0

    #: Number of connections in the use.
    checked_in_connections: int = 0

    #: Number of idle connections.
    checked_out_connections: int = 0

    #: Maximal "overflow" of the pool, i.e. how many connections above the :py:attr:`size` are allowed.
    current_overflow: int = 0

    def do_sync(self) -> None:
        """
        Load values from the storage and update this container with up-to-date values.
        """

        super().do_sync()

        db = DATABASE.get()

        if not isinstance(db.engine.pool, sqlalchemy.pool.impl.QueuePool):
            self.size = 0
            self.checked_in_connections = 0
            self.checked_out_connections = 0
            self.current_overflow = 0

            return

        self.size = db.engine.pool.size()
        self.checked_in_connections = db.engine.pool.checkedin()
        self.checked_out_connections = db.engine.pool.checkedout()
        self.current_overflow = db.engine.pool.overflow()

    def do_register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super().do_register_with_prometheus(registry)

        self.POOL_SIZE = Gauge(
            'db_pool_size',
            'Maximal number of connections available in the pool',
            registry=registry
        )

        self.POOL_CHECKED_IN = Gauge(
            'db_pool_checked_in',
            'Current number of connections checked in',
            registry=registry
        )

        self.POOL_CHECKED_OUT = Gauge(
            'db_pool_checked_out',
            'Current number of connections out',
            registry=registry
        )

        self.POOL_OVERFLOW = Gauge(
            'db_pool_overflow',
            'Current overflow of connections',
            registry=registry
        )

    def do_update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        super().do_update_prometheus()

        self.POOL_SIZE.set(self.size)
        self.POOL_CHECKED_IN.set(self.checked_in_connections)
        self.POOL_CHECKED_OUT.set(self.checked_out_connections)
        self.POOL_OVERFLOW.set(self.current_overflow)


@dataclasses.dataclass
class DBMetrics(MetricsBase):
    """
    Database metrics.
    """

    #: Database connection pool metrics.
    pool: DBPoolMetrics = DBPoolMetrics()


class PoolMetricsBase(MetricsBase):
    """
    Base class for pool-specific metrics containers.
    """

    poolname: str

    def __init__(self, poolname: str) -> None:
        """
        Initialize common fields.

        :param poolname: name of the pool.
        """

        super().__init__()

        self.poolname = poolname

    @property
    def tracing_tags(self) -> Dict[str, str]:
        """
        Custom tracking span tags.

        :returns: container-specific tags for tracing span created by the :py:meth:`sync` method.
        """

        return {'poolname': self.poolname}


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
class PoolResources(PoolMetricsBase):
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

    _KEY = 'metrics.pool.{poolname}.resources.{dimension}'  # noqa: FS003
    _KEY_UPDATED_TIMESTAMP = 'metrics.pool.{poolname}.resources.{dimension}.updated_timestamp'  # noqa: FS003

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

    flavors: Dict[str, int] = dataclasses.field(default_factory=dict)
    """
    Flavor usage.
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

        super().__init__(poolname)

        self._key = PoolResources._KEY.format(poolname=poolname, dimension=dimension.value)  # noqa: FS002
        self._key_updated_timestamp = PoolResources._KEY_UPDATED_TIMESTAMP.format(  # noqa: FS002
            poolname=poolname, dimension=dimension.value
        )

        self.instances = None
        self.cores = None
        self.memory = None
        self.diskspace = None
        self.snapshots = None
        self.networks = {}
        self.flavors = {}

        self.updated_timestamp = None

        self.__post_init__()

    @with_context
    def do_sync(self, cache: redis.Redis) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param cache: cache instance to use for cache access.
        """

        super().do_sync()

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

        self.updated_timestamp = cast(
            RedisGetType[float],
            cache.get
        )(self._key_updated_timestamp)

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

        super().__init__(poolname, PoolResourcesMetricsDimensions.USAGE)


class PoolResourcesLimits(PoolResources):
    """
    Describes current limits of pool resources.
    """

    def __init__(self, poolname: str) -> None:
        """
        Resource limits of a particular pool.

        :param poolname: name of the pool whose metrics we're tracking.
        """

        super().__init__(poolname, PoolResourcesMetricsDimensions.LIMITS)


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
            f'network.{network_name}'
            for network_name in self.networks
        ]


@dataclasses.dataclass
class PoolResourcesMetrics(PoolMetricsBase):
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

        super().__init__(poolname)

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
    SECURITY_GROUP = 'security-group'


@dataclasses.dataclass
class PoolCostsMetrics(PoolMetricsBase):
    """
    Cumulative cost produced by a pool.
    """

    virtual_machine: Optional[ResourceCostType]
    disk: Optional[ResourceCostType]
    static_ip: Optional[ResourceCostType]
    network_interface: Optional[ResourceCostType]
    virtual_network: Optional[ResourceCostType]
    security_group: Optional[ResourceCostType]

    def __init__(self, poolname: str) -> None:
        """
        Cost metrics of a particular pool.

        :param poolname: name of the pool whose costs we are tracking.
        """

        super().__init__(poolname)

        self._key = f'metrics.pool.{poolname}.cost.cumulative_cost'

        self.virtual_machine = None
        self.disk = None
        self.static_ip = None
        self.network_interface = None
        self.virtual_network = None
        self.security_group = None

    @with_context
    def do_sync(self, cache: redis.Redis, logger: gluetool.log.ContextAdapter) -> None:
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
class PoolMetrics(PoolMetricsBase):
    """
    Metrics of a particular pool.
    """

    _KEY_ERRORS = 'metrics.pool.{poolname}.errors'  # noqa: FS003
    _KEY_ABORTS = 'metrics.pool.{poolname}.aborts'  # noqa: FS003
    _KEY_CLI_CALLS = 'metrics.pool.{poolname}.cli-calls'  # noqa: FS003
    _KEY_CLI_EXIT_CODES = 'metrics.pool.{poolname}.cli-calls.exit-codes'  # noqa: FS003
    _KEY_CLI_CALLS_DURATIONS = 'metrics.pool.{poolname}.cli-calls.durations'  # noqa: FS003

    # Image & flavor refresh process does not have their own metrics, hence using this container to track the "last
    # update" timestamp and other.
    _KEY_INFO_COUNT = 'metrics.pool.{poolname}.{info}.count'  # noqa: FS003
    _KEY_INFO_UPDATED_TIMESTAMP = 'metrics.pool.{poolname}.{info}.updated_timestamp'  # noqa: FS003

    enabled: bool
    routing_enabled: bool

    resources: PoolResourcesMetrics
    costs: PoolCostsMetrics

    current_guest_request_count: int
    current_guest_request_count_per_state: Dict[GuestState, int]

    errors: Dict[str, int]
    aborts: Dict[Tuple[str, str, str, str], int]

    image_info_count: Optional[float]
    image_info_updated_timestamp: Optional[float]
    flavor_info_count: Optional[float]
    flavor_info_updated_timestamp: Optional[float]

    # commandname => count
    cli_calls: Dict[str, int]
    # commandname:exit-code:cause => count
    cli_calls_exit_codes: Dict[Tuple[str, str, str], int]
    # bucket:commandname:exit-code:cause => count
    cli_calls_durations: Dict[Tuple[str, str, str, str], int]

    def __init__(self, poolname: str) -> None:
        """
        Metrics of a particular pool.

        :param poolname: name of the pool whose metrics we're tracking.
        """

        super().__init__(poolname)

        self.key_errors = self._KEY_ERRORS.format(poolname=poolname)  # noqa: FS002
        self.key_aborts = self._KEY_ABORTS.format(poolname=poolname)  # noqa: FS002

        self.key_image_info_count = self._KEY_INFO_COUNT.format(  # noqa: FS002
            poolname=poolname,
            info='image'
        )
        self.key_image_info_refresh_timestamp = self._KEY_INFO_UPDATED_TIMESTAMP.format(  # noqa: FS002
            poolname=poolname,
            info='image'
        )
        self.key_flavor_info_count = self._KEY_INFO_COUNT.format(  # noqa: FS002
            poolname=poolname,
            info='flavor'
        )
        self.key_flavor_info_refresh_timestamp = self._KEY_INFO_UPDATED_TIMESTAMP.format(  # noqa: FS002
            poolname=poolname,
            info='flavor'
        )

        self.key_cli_calls = self._KEY_CLI_CALLS.format(poolname=poolname)  # noqa: FS002
        self.key_cli_calls_exit_codes = self._KEY_CLI_EXIT_CODES.format(poolname=poolname)  # noqa: FS002
        self.key_cli_calls_durations = self._KEY_CLI_CALLS_DURATIONS.format(poolname=poolname)  # noqa: FS002

        self.enabled = False
        self.routing_enabled = True

        self.resources = PoolResourcesMetrics(poolname)
        self.costs = PoolCostsMetrics(poolname)

        self.current_guest_request_count = 0
        self.current_guest_request_count_per_state = {}

        self.errors = {}
        self.aborts = {}

        self.image_info_count = None
        self.image_info_updated_timestamp = None
        self.flavor_info_count = None
        self.flavor_info_updated_timestamp = None

        self.cli_calls = {}
        self.cli_calls_exit_codes = {}
        self.cli_calls_durations = {}

        self.__post_init__()

    @staticmethod
    @with_context
    def _refresh_info_count(
        pool: str,
        info: str,
        count: float,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        safe_call(
            cast(Callable[[str, float], None], cache.set),
            PoolMetrics._KEY_INFO_COUNT.format(poolname=pool, info=info),  # noqa: FS002
            count
        )

        return Ok(None)

    @staticmethod
    @with_context
    def _refresh_info_updated_timestamp(
        pool: str,
        info: str,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        safe_call(
            cast(Callable[[str, float], None], cache.set),
            PoolMetrics._KEY_INFO_UPDATED_TIMESTAMP.format(poolname=pool, info=info),  # noqa: FS002
            datetime.datetime.timestamp(datetime.datetime.utcnow())
        )

        return Ok(None)

    @staticmethod
    def refresh_image_info_metrics(
        pool: str,
        image_count: int
    ) -> Result[None, Failure]:
        """
        Update "latest updated" timestamp of pool image info cache to current time.

        :param pool: pool whose cache has been updated.
        :param image_count: number of cached image info entries.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        PoolMetrics._refresh_info_count(pool, 'image', image_count)
        PoolMetrics._refresh_info_updated_timestamp(pool, 'image')

        return Ok(None)

    @staticmethod
    def refresh_flavor_info_metrics(
        pool: str,
        flavor_count: int
    ) -> Result[None, Failure]:
        """
        Update "latest updated" timestamp of pool flavor info cache to current time.

        :param pool: pool whose cache has been updated.
        :param flavor_count: number of cached flavor info entries.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        PoolMetrics._refresh_info_count(pool, 'flavor', flavor_count)
        PoolMetrics._refresh_info_updated_timestamp(pool, 'flavor')

        return Ok(None)

    @staticmethod
    @with_context
    def inc_error(
        pool: str,
        error: 'PoolErrorCauses',
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

        inc_metric_field(logger, cache, PoolMetrics._KEY_ERRORS.format(poolname=pool), error.value)  # noqa: FS002
        return Ok(None)

    @staticmethod
    @with_context
    def inc_aborts(
        pool: str,
        instance_id: Optional[str],
        compose: str,
        arch: str,
        cause: 'PoolErrorCauses',
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase counter for a aborted instance by 1.

        :param pool: pool that provided the instance.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :param instance_id: optional ID identifying the aborted instance.
        :param compose: compose requested.
        :param arch: architecture requested.
        :param cause: cause of the abort.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(
            logger,
            cache,
            PoolMetrics._KEY_ABORTS.format(poolname=pool),  # noqa: FS002
            f'{instance_id or ""}:{compose}:{arch}:{cause.value}'
        )

        return Ok(None)

    @staticmethod
    @with_context
    def inc_cli_call(
        poolname: str,
        commandname: str,
        exit_code: int,
        duration: float,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis,
        cause: Optional['PoolErrorCauses'] = None,
    ) -> Result[None, Failure]:
        """
        Increase counter for a given CLI command by 1.

        :param poolname: pool that executed the command.
        :param commandname: command "ID" - something to tell commands and group of commands apart.
        :param exit_code: exit code of the command.
        :param duration: duration of the command session, in seconds.
        :param cause: optional string explaining the reason for non-zero exit code.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        # raw count
        inc_metric_field(
            logger,
            cache,
            PoolMetrics._KEY_CLI_CALLS.format(poolname=poolname),  # noqa: FS002
            commandname
        )

        # exit code
        inc_metric_field(
            logger,
            cache,
            PoolMetrics._KEY_CLI_EXIT_CODES.format(poolname=poolname),  # noqa: FS002
            f'{commandname}:{exit_code}:{cause.value if cause else ""}'
        )

        # duration
        bucket = min(threshold for threshold in CLI_CALL_DURATION_BUCKETS if threshold > duration)

        inc_metric_field(
            logger,
            cache,
            PoolMetrics._KEY_CLI_CALLS_DURATIONS.format(poolname=poolname),  # noqa: FS002
            f'{bucket}:{commandname}:{exit_code}:{cause.value if cause else ""}'
        )

        return Ok(None)

    @with_context
    def do_sync(
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

        super().do_sync()

        r_enabled = KNOB_POOL_ENABLED.get_value(session=session, entityname=self.poolname)

        if r_enabled.is_error:
            r_enabled.unwrap_error().handle(logger)

            return

        self.enabled = r_enabled.unwrap() or False  # True => True, False => False, None => False

        # avoid circular imports
        from .routing_policies import KNOB_ROUTE_POOL_ENABLED

        r_routing_enabled = KNOB_ROUTE_POOL_ENABLED.get_value(session=session, entityname=self.poolname)

        # TODO: sync should return Result
        if r_routing_enabled.is_error:
            r_routing_enabled.unwrap_error().handle(logger)

            return

        self.routing_enabled = r_routing_enabled.unwrap()

        self.current_guest_request_count = cast(
            Tuple[int],
            session.query(sqlalchemy.func.count(artemis_db.GuestRequest.guestname))
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
                session.query(
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

        self.aborts = {
            cast(Tuple[str, str, str, str], tuple(field.split(':', 4))): count
            for field, count in get_metric_fields(
                logger,
                cache,
                self._KEY_ABORTS.format(poolname=self.poolname)  # noqa: FS002
            ).items()
        }

        count = cast(
            Callable[[str], Optional[bytes]],
            cache.get
        )(self.key_image_info_count)

        self.image_info_count = count if count is None else float(count)

        self.image_info_updated_timestamp = cast(
            RedisGetType[float],
            cache.get
        )(self.key_image_info_refresh_timestamp)

        count = cast(
            Callable[[str], Optional[bytes]],
            cache.get
        )(self.key_flavor_info_count)

        self.flavor_info_count = count if count is None else float(count)

        self.flavor_info_updated_timestamp = cast(
            RedisGetType[float],
            cache.get
        )(self.key_flavor_info_refresh_timestamp)

        # commandname => count
        self.cli_calls = {
            field: count
            for field, count in get_metric_fields(
                logger,
                cache,
                self._KEY_CLI_CALLS.format(poolname=self.poolname)  # noqa: FS002
            ).items()
        }

        # commandname:exit-code:cause => count
        self.cli_calls_exit_codes = {
            cast(Tuple[str, str, str], tuple(field.split(':', 2))): count
            for field, count in get_metric_fields(
                logger,
                cache,
                self.key_cli_calls_exit_codes
            ).items()
        }

        # bucket:commandname:exit-code:cause => count
        self.cli_calls_durations = {
            cast(Tuple[str, str, str, str], tuple(field.split(':', 3))): count
            for field, count in get_metric_fields(
                logger,
                cache,
                self._KEY_CLI_CALLS_DURATIONS.format(poolname=self.poolname)  # noqa: FS002
            ).items()
        }


@dataclasses.dataclass
class UndefinedPoolMetrics(PoolMetricsBase):
    """
    Metrics of an "undefined" pool, to handle values for guests that don't belong into any pool (yet).
    """

    enabled: bool
    routing_enabled: bool

    resources: PoolResourcesMetrics
    costs: PoolCostsMetrics

    current_guest_request_count: int
    current_guest_request_count_per_state: Dict[GuestState, int]

    errors: Dict[str, int]
    aborts: Dict[Tuple[str, str, str, str], int]

    image_info_count: Optional[float]
    image_info_updated_timestamp: Optional[float]
    flavor_info_count: Optional[float]
    flavor_info_updated_timestamp: Optional[float]

    cli_calls: Dict[str, int]
    cli_calls_exit_codes: Dict[Tuple[str, str, str], int]
    cli_calls_durations: Dict[Tuple[str, str, str, str], int]

    def __init__(self, poolname: str) -> None:
        """
        Metrics of a particular pool.

        :param poolname: name of the pool whose metrics we're tracking.
        """

        super().__init__(poolname)

        self.enabled = False
        self.routing_enabled = True

        self.resources = PoolResourcesMetrics(poolname)
        self.costs = PoolCostsMetrics(poolname)

        self.current_guest_request_count = 0
        self.current_guest_request_count_per_state = {}

        self.errors = {}
        self.aborts = {}

        self.image_info_count = None
        self.image_info_updated_timestamp = None
        self.flavor_info_count = None
        self.flavor_info_updated_timestamp = None

        self.cli_calls = {}
        self.cli_calls_exit_codes = {}
        self.cli_calls_durations = {}

        self.__post_init__()

    @with_context
    def do_sync(self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        """

        super().do_sync()

        # NOTE: sqlalchemy overloads operators to construct the conditions, and `is` is not overloaded. Therefore
        # in the query, we have to use `==` instead of more Pythonic `is`.

        self.current_guest_request_count = cast(
            Tuple[int],
            session.query(sqlalchemy.func.count(artemis_db.GuestRequest.guestname))
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
                session.query(
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
    def do_sync(self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        """

        super().do_sync()

        # Avoid circular imports
        from .drivers import PoolDriver

        r_pools = PoolDriver.load_all(logger, session, enabled_only=False)

        if r_pools.is_error:
            r_pools.unwrap_error().handle(logger)

            self.pools = {}

        else:
            self.pools = {
                pool.poolname: PoolMetrics(pool.poolname)
                for pool in r_pools.unwrap()
            }

        self.pools[UNDEFINED_POOL_NAME] = UndefinedPoolMetrics(UNDEFINED_POOL_NAME)

        for metrics in self.pools.values():
            metrics.sync()

    def do_register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super().do_register_with_prometheus(registry)

        def _create_pool_resource_metric(name: str, unit: Optional[str] = None) -> Gauge:
            return Gauge(
                f'pool_resources_{name}{"_{}".format(unit) if unit else ""}',  # noqa: FS002
                f'Limits and usage of pool {name}',
                ['pool', 'dimension'],
                registry=registry
            )

        def _create_network_resource_metric(name: str, unit: Optional[str] = None) -> Gauge:
            return Gauge(
                f'pool_resources_network_{name}{"_{}".format(unit) if unit else ""}',
                f'Limits and usage of pool network {name}',
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

        self.POOL_ABORTS = Counter(
            'pool_aborts',
            'Overall total number of aborted pool instance, per pool and cause of error.',
            ['pool', 'instance_id', 'compose', 'arch', 'cause'],
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

        self.POOL_RESOURCES_FLAVORS = Gauge(
            'pool_resources_flavors',
            'Limits and usage of pool flavors',
            ['pool', 'dimension', 'flavor'],
            registry=registry
        )

        self.POOL_RESOURCES_UPDATED_TIMESTAMP = _create_pool_resource_metric('updated_timestamp')

        self.POOL_IMAGE_INFO_COUNT = Gauge(
            'pool_image_info_count',
            'Number of cached image info entries.',
            ['pool'],
            registry=registry
        )

        self.POOL_IMAGE_INFO_UPDATED_TIMESTAMP = Gauge(
            'pool_image_info_updated_timestamp',
            'Last time pool image info has been updated.',
            ['pool'],
            registry=registry
        )

        self.POOL_FLAVOR_INFO_COUNT = Gauge(
            'pool_flavor_info_count',
            'Number of cached flavor info entries.',
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
            'Overall total number of CLI commands exit codes, per pool, command name, exit code and cause of error.',
            ['pool', 'command', 'exit_code', 'cause'],
            registry=registry
        )

        self.CLI_CALLS_DURATIONS = Histogram(
            'cli_call_duration_seconds',
            'The time spent executing CLI commands, by pool, command name, exit code and cause of error.',
            ['pool', 'command', 'exit_code', 'cause'],
            buckets=CLI_CALL_DURATION_BUCKETS,
            registry=registry
        )

    def do_update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        super().do_update_prometheus()

        reset_counters(self.POOL_ERRORS)
        reset_counters(self.POOL_ABORTS)
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

            for (instance_id, compose, arch, cause), count in pool_metrics.aborts.items():
                self.POOL_ABORTS \
                    .labels(pool=poolname, instance_id=instance_id, compose=compose, arch=arch, cause=cause) \
                    ._value.set(count)

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

            for flavorname, count in pool_metrics.resources.limits.flavors.items():
                self.POOL_RESOURCES_FLAVORS \
                    .labels(pool=poolname, dimension='limit', flavor=flavorname) \
                    .set(count)

            for flavorname, count in pool_metrics.resources.usage.flavors.items():
                self.POOL_RESOURCES_FLAVORS \
                    .labels(pool=poolname, dimension='usage', flavor=flavorname) \
                    .set(count)

            self.POOL_RESOURCES_UPDATED_TIMESTAMP \
                .labels(pool=poolname, dimension='limit') \
                .set(pool_metrics.resources.limits.updated_timestamp or float('NaN'))

            self.POOL_RESOURCES_UPDATED_TIMESTAMP \
                .labels(pool=poolname, dimension='usage') \
                .set(pool_metrics.resources.usage.updated_timestamp or float('NaN'))

            self.POOL_IMAGE_INFO_COUNT \
                .labels(pool=poolname) \
                .set(pool_metrics.image_info_count or float('NaN'))

            self.POOL_IMAGE_INFO_UPDATED_TIMESTAMP \
                .labels(pool=poolname) \
                .set(pool_metrics.image_info_updated_timestamp or float('NaN'))

            self.POOL_FLAVOR_INFO_COUNT \
                .labels(pool=poolname) \
                .set(pool_metrics.flavor_info_count or float('NaN'))

            self.POOL_FLAVOR_INFO_UPDATED_TIMESTAMP \
                .labels(pool=poolname) \
                .set(pool_metrics.flavor_info_updated_timestamp or float('NaN'))

            for commandname, count in pool_metrics.cli_calls.items():
                self.CLI_CALLS \
                    .labels(pool=poolname, command=commandname) \
                    ._value.set(count)

            for (commandname, exit_code, cause), count in pool_metrics.cli_calls_exit_codes.items():
                self.CLI_CALLS_EXIT_CODES \
                    .labels(pool=poolname, command=commandname, exit_code=exit_code, cause=cause) \
                    ._value.set(count)

            for (bucket_threshold, commandname, exit_code, cause), count in pool_metrics.cli_calls_durations.items():
                bucket_index = CLI_CALL_DURATION_BUCKETS.index(
                    prometheus_client.utils.INF if bucket_threshold == 'inf' else int(bucket_threshold)
                )

                self.CLI_CALLS_DURATIONS \
                    .labels(pool=poolname, command=commandname, exit_code=exit_code, cause=cause) \
                    ._buckets[bucket_index] \
                    .set(count)
                self.CLI_CALLS_DURATIONS \
                    .labels(pool=poolname, command=commandname, exit_code=exit_code, cause=cause) \
                    ._sum \
                    .inc(float(bucket_threshold) * count)


@dataclasses.dataclass
class ProvisioningMetrics(MetricsBase):
    """
    Provisioning metrics.
    """

    _KEY_PROVISIONING_REQUESTED = 'metrics.provisioning.requested'
    _KEY_PROVISIONING_SUCCESS = 'metrics.provisioning.success'
    _KEY_FAILOVER = 'metrics.provisioning.failover'
    _KEY_FAILOVER_SUCCESS = 'metrics.provisioning.failover.success'
    _KEY_PROVISIONING_DURATIONS = 'metrics.provisioning.durations'
    _KEY_GUEST_STATE_TRANSITIONS = 'metrics.provisioning.guest.state.transitions'
    _KEY_EMPTY_ROUTING = 'metrics.routing.empty'

    requested: int = 0
    current: int = 0
    success: Dict[str, int] = dataclasses.field(default_factory=dict)
    failover: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    failover_success: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    empty_routing: Dict[str, int] = dataclasses.field(default_factory=dict)

    # We want to maybe point fingers on pools where guests are stuck, so include pool name and state as labels.
    guest_ages: List[Tuple[GuestState, Optional[str], datetime.timedelta]] = dataclasses.field(default_factory=list)
    provisioning_durations: Dict[str, int] = dataclasses.field(default_factory=dict)

    # pool:current-state:new-state => count
    guest_state_transitions: Dict[Tuple[str, str, str], int] = dataclasses.field(default_factory=dict)

    @staticmethod
    @with_context
    def inc_requested(
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase :py:attr:`requested` metric by 1.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric(logger, cache, ProvisioningMetrics._KEY_PROVISIONING_REQUESTED)
        return Ok(None)

    @staticmethod
    @with_context
    def inc_success(
        pool: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase :py:attr:`success` metric by 1.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :param pool: pool that provided the instance.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, ProvisioningMetrics._KEY_PROVISIONING_SUCCESS, pool)
        return Ok(None)

    @staticmethod
    @with_context
    def inc_empty_routing(
        from_pool: Optional[str],
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase empty routing result metric by 1.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :param from_pool: name of the originating pool.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, ProvisioningMetrics._KEY_EMPTY_ROUTING, from_pool or UNDEFINED_POOL_NAME)
        return Ok(None)

    @staticmethod
    @with_context
    def inc_failover(
        from_pool: str,
        to_pool: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase pool failover metric by 1.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :param from_pool: name of the originating pool.
        :param to_pool: name of the replacement pool.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, ProvisioningMetrics._KEY_FAILOVER, f'{from_pool}:{to_pool}')
        return Ok(None)

    @staticmethod
    @with_context
    def inc_failover_success(
        from_pool: str,
        to_pool: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase successfull pool failover meric by 1.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :param from_pool: name of the originating pool.
        :param to_pool: name of the replacement pool.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, ProvisioningMetrics._KEY_FAILOVER_SUCCESS, f'{from_pool}:{to_pool}')
        return Ok(None)

    @staticmethod
    @with_context
    def inc_provisioning_durations(
        duration: int,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment provisioning duration bucket by one.

        The bucket is determined by the upper bound of the given ``duration``.

        :param logger: logger to use for logging.
        :param duration: how long, in milliseconds, took actor to finish the task.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        bucket = min(threshold for threshold in PROVISION_DURATION_BUCKETS if threshold > duration)

        inc_metric_field(logger, cache, ProvisioningMetrics._KEY_PROVISIONING_DURATIONS, f'{bucket}')

        return Ok(None)

    @staticmethod
    @with_context
    def inc_guest_state_transition(
        poolname: Optional[str],
        current_state: Optional[GuestState],
        new_state: GuestState,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase counter for a given guest state transition by 1.

        :param poolname: pool that executed the command.
        :param current_state: current state of the guest.
        :param new_state: current state of the guest.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        poolname = poolname or UNDEFINED_POOL_NAME
        current_state_label = current_state.value if current_state is not None else "none"

        inc_metric_field(
            logger,
            cache,
            ProvisioningMetrics._KEY_GUEST_STATE_TRANSITIONS,
            f'{poolname}:{current_state_label}:{new_state.value}'
        )

        return Ok(None)

    @with_context
    def do_sync(
        self,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis,
        session: sqlalchemy.orm.session.Session
    ) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        :param cache: cache instance to use for cache access.
        """

        super().do_sync()

        now = datetime.datetime.utcnow()

        current_record = session.query(
            sqlalchemy.func.count(artemis_db.GuestRequest.guestname)
        )

        self.current = cast(Callable[[], int], current_record.scalar)()
        self.requested = get_metric(logger, cache, self._KEY_PROVISIONING_REQUESTED) or 0
        self.success = {
            poolname: count
            for poolname, count in get_metric_fields(logger, cache, self._KEY_PROVISIONING_SUCCESS).items()
        }
        self.empty_routing = {
            poolname: count
            for poolname, count in get_metric_fields(logger, cache, self._KEY_EMPTY_ROUTING).items()
        }
        # fields are in form `from_pool:to_pool`
        self.failover = {
            cast(Tuple[str, str], tuple(field.split(':', 1))): count
            for field, count in get_metric_fields(logger, cache, self._KEY_FAILOVER).items()
        }
        # fields are in form `from_pool:to_pool`
        self.failover_success = {
            cast(Tuple[str, str], tuple(field.split(':', 1))): count
            for field, count in get_metric_fields(logger, cache, self._KEY_FAILOVER_SUCCESS).items()
        }
        # Using `query` directly, because we need just limited set of fields, and we need our `Query`
        # and `SafeQuery` to support this functionality (it should be just a matter of correct types).
        self.guest_ages = [
            (record[0], record[1], now - record[2])
            for record in cast(
                List[Tuple[GuestState, Optional[str], datetime.datetime]],
                session.query(
                    artemis_db.GuestRequest.state,
                    artemis_db.GuestRequest.poolname,
                    artemis_db.GuestRequest.ctime
                ).all()
            )
        ]
        self.provisioning_durations = {
            field: count
            for field, count in get_metric_fields(logger, cache, self._KEY_PROVISIONING_DURATIONS).items()
        }

        # pool:current-state:new-state => count
        self.guest_state_transitions = {
            cast(Tuple[str, str, str], tuple(field.split(':', 2))): count
            for field, count in get_metric_fields(
                logger,
                cache,
                self._KEY_GUEST_STATE_TRANSITIONS
            ).items()
        }

    def do_register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super().do_register_with_prometheus(registry)

        self.CURRENT_GUEST_REQUEST_COUNT_TOTAL = Gauge(
            'current_guest_request_count_total',
            'Current total number of guest requests being provisioned.',
            registry=registry
        )

        self.OVERALL_PROVISIONING_COUNT = Counter(
            'overall_provisioning_count',
            'Overall total number of all requested guest requests.',
            registry=registry
        )

        self.OVERALL_SUCCESSFULL_PROVISIONING_COUNT = Counter(
            'overall_successfull_provisioning_count',
            'Overall total number of all successfully provisioned guest requests by pool.',
            ['pool'],
            registry=registry
        )

        self.OVERALL_EMPTY_ROUTING_COUNT = Counter(
            'overall_empty_routing_count',
            'Overall total number of all empty routing outcomes by previous pool.',
            ['pool'],
            registry=registry
        )

        self.OVERALL_FAILOVER_COUNT = Counter(
            'overall_failover_count',
            'Overall total number of failovers to another pool by source and destination pool.',
            ['from_pool', 'to_pool'],
            registry=registry
        )

        self.OVERALL_SUCCESSFULL_FAILOVER_COUNT = Counter(
            'overall_successfull_failover_count',
            'Overall total number of successful failovers to another pool by source and destination pool.',
            ['from_pool', 'to_pool'],
            registry=registry
        )

        self.GUEST_AGES = Gauge(
            'guest_request_age',
            'Guest request ages by pool and state.',
            ['pool', 'state', 'age_threshold'],
            registry=registry
        )

        self.PROVISION_DURATIONS = Histogram(
            'provisioning_duration_seconds',
            'The time spent provisioning a machine.',
            [],
            buckets=PROVISION_DURATION_BUCKETS,
            registry=registry,
        )

        self.GUEST_STATE_TRANSITIONS = Counter(
            'guest_request_state_transitions',
            'Overall total number of guest request state transitions, per pool, current state and new state.',
            ['pool', 'current_state', 'new_state'],
            registry=registry
        )

    def do_update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        super().do_update_prometheus()

        reset_counters(self.OVERALL_EMPTY_ROUTING_COUNT)
        reset_counters(self.GUEST_STATE_TRANSITIONS)

        self.CURRENT_GUEST_REQUEST_COUNT_TOTAL.set(self.current)
        self.OVERALL_PROVISIONING_COUNT._value.set(self.requested)

        for pool, count in self.success.items():
            self.OVERALL_SUCCESSFULL_PROVISIONING_COUNT.labels(pool=pool)._value.set(count)

        for pool, count in self.empty_routing.items():
            self.OVERALL_EMPTY_ROUTING_COUNT.labels(pool=pool)._value.set(count)

        for (from_pool, to_pool), count in self.failover.items():
            self.OVERALL_FAILOVER_COUNT.labels(from_pool=from_pool, to_pool=to_pool)._value.set(count)

        for (from_pool, to_pool), count in self.failover_success.items():
            self.OVERALL_SUCCESSFULL_FAILOVER_COUNT.labels(from_pool=from_pool, to_pool=to_pool)._value.set(count)

        reset_counters(self.GUEST_AGES)

        for state, poolname, age in self.guest_ages:
            # Pick the smallest larger bucket threshold (e.g. age == 250 => 300, age == 3599 => 3600, ...)
            # There's always the last threshold, infinity, so the list should never be empty.
            age_threshold = min(threshold for threshold in GUEST_AGE_BUCKETS if threshold > age.total_seconds())

            self.GUEST_AGES.labels(state=state, pool=poolname, age_threshold=age_threshold).inc()

        # Set each bucket to number of observations, and each sum to (observations * bucket threshold)
        # since we don't track the exact duration, just what bucket it falls into.
        reset_histogram(self.PROVISION_DURATIONS)

        for bucket_threshold, count in self.provisioning_durations.items():
            bucket_index = PROVISION_DURATION_BUCKETS.index(
                prometheus_client.utils.INF if bucket_threshold == 'inf' else int(bucket_threshold)
            )
            self.PROVISION_DURATIONS._buckets[bucket_index].set(count)
            self.PROVISION_DURATIONS._sum.inc(float(bucket_threshold) * count)

        for (poolname, current_state, new_state), count in self.guest_state_transitions.items():
            self.GUEST_STATE_TRANSITIONS \
                .labels(pool=poolname, current_state=current_state, new_state=new_state) \
                ._value.set(count)


@dataclasses.dataclass
class RoutingMetrics(MetricsBase):
    """
    Routing metrics.
    """

    _KEY_CALLS = 'metrics.routing.policy.calls'
    _KEY_CANCELLATIONS = 'metrics.routing.policy.cancellations'
    _KEY_RULINGS = 'metrics.routing.policy.rulings'

    policy_calls: Dict[str, int] = dataclasses.field(default_factory=dict)
    policy_cancellations: Dict[str, int] = dataclasses.field(default_factory=dict)
    policy_rulings: Dict[Tuple[str, str, str], int] = dataclasses.field(default_factory=dict)

    @staticmethod
    @with_context
    def inc_policy_called(
        policy_name: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase "policy called to make ruling" metric by 1.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :param policy_name: policy that was called to make ruling.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, RoutingMetrics._KEY_CALLS, policy_name)
        return Ok(None)

    @staticmethod
    @with_context
    def inc_policy_canceled(
        policy_name: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase "policy canceled a guest request" metric by 1.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :param policy_name: policy that made the decision.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, RoutingMetrics._KEY_CANCELLATIONS, policy_name)
        return Ok(None)

    @staticmethod
    @with_context
    def inc_pool_allowed(
        policy_name: str,
        pool_name: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase "pool allowed by policy" metric by 1.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :param policy_name: policy that made the decision.
        :param pool_name: pool that was allowed.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, RoutingMetrics._KEY_RULINGS, f'{policy_name}:{pool_name}:yes')
        return Ok(None)

    @staticmethod
    @with_context
    def inc_pool_excluded(
        policy_name: str,
        pool_name: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase "pool excluded by policy" metric by 1.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :param policy_name: policy that made the decision.
        :param pool_name: pool that was excluded.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, RoutingMetrics._KEY_RULINGS, f'{policy_name}:{pool_name}:no')
        return Ok(None)

    @with_context
    def do_sync(
        self,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        """

        super().do_sync()

        self.policy_calls = {
            field: count
            for field, count in get_metric_fields(logger, cache, self._KEY_CALLS).items()
        }
        self.policy_cancellations = {
            field: count
            for field, count in get_metric_fields(logger, cache, self._KEY_CANCELLATIONS).items()
        }
        # fields are in form `policy:pool:allowed`
        self.policy_rulings = {
            cast(Tuple[str, str, str], tuple(field.split(':', 2))): count
            for field, count in get_metric_fields(logger, cache, self._KEY_RULINGS).items()
        }

    def do_register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super().do_register_with_prometheus(registry)

        self.OVERALL_POLICY_CALLS_COUNT = Counter(
            'overall_policy_calls_count',
            'Overall total number of policy call by policy name.',
            ['policy'],
            registry=registry
        )

        self.OVERALL_POLICY_CANCELLATIONS_COUNT = Counter(
            'overall_policy_cancellations_count',
            'Overall total number of policy canceling a guest request by policy name.',
            ['policy'],
            registry=registry
        )

        self.OVERALL_POLICY_RULINGS_COUNT = Counter(
            'overall_policy_rulings_count',
            'Overall total number of policy rulings by policy name, pool name and whether the pool was allowed.',
            ['policy', 'pool', 'allowed'],
            registry=registry
        )

    def do_update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        super().do_update_prometheus()

        for policy_name, count in self.policy_calls.items():
            self.OVERALL_POLICY_CALLS_COUNT.labels(policy=policy_name)._value.set(count)

        for policy_name, count in self.policy_cancellations.items():
            self.OVERALL_POLICY_CANCELLATIONS_COUNT.labels(policy=policy_name)._value.set(count)

        for (policy_name, pool_name, allowed), count in self.policy_rulings.items():
            self.OVERALL_POLICY_RULINGS_COUNT \
                .labels(policy=policy_name, pool=pool_name, allowed=allowed) \
                ._value.set(count)


@dataclasses.dataclass
class ShelfMetrics(MetricsBase):
    """
    Metrics of a particular shelf.
    """

    _KEY_HITS = 'metrics.shelf.{shelfname}.hits'  # noqa: FS003
    _KEY_MISSES = 'metrics.shelf.{shelfname}.misses'  # noqa: FS003
    _KEY_REMOVALS = 'metrics.shelf.{shelfname}.removals'  # noqa: FS003
    _KEY_FORCED_REMOVALS = 'metrics.shelf.{shelfname}.forced-removals'  # noqa: FS003
    _KEY_DEAD = 'metrics.shelf.{shelfname}.dead'  # noqa: FS003

    shelfname: str

    current_guest_count: int
    size: int
    hit_count: Optional[float]
    miss_count: Optional[float]
    removals: Optional[float]
    forced_removals: Optional[float]
    dead_guest_count: Optional[float]

    def __init__(self, shelfname: str) -> None:
        """
        Metrics of a particular shelf.

        :param shelfname: name of the shelf for which metrics are being tracked.
        """

        self.key_hits = self._KEY_HITS.format(shelfname=shelfname)  # noqa: FS002
        self.key_misses = self._KEY_MISSES.format(shelfname=shelfname)  # noqa: FS002
        self.key_removals = self._KEY_REMOVALS.format(shelfname=shelfname)  # noqa: FS002
        self.key_forced_removals = self._KEY_FORCED_REMOVALS.format(shelfname=shelfname)  # noqa: FS002
        self.key_dead = self._KEY_DEAD.format(shelfname=shelfname)  # noqa: FS002

        self.shelfname = shelfname

        self.current_guest_count = 0
        self.size = 0
        self.hit_count = None
        self.miss_count = None
        self.removals = None
        self.forced_removals = None
        self.dead_guest_count = None

        self.__post_init__()

    @classmethod
    @with_context
    def inc_hits(
        cls,
        shelfname: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase the counter for the given shelf hits by 1.

        :param shelfname: name of the shelf.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric(logger, cache, cls._KEY_HITS.format(shelfname=shelfname))  # noqa: FS002
        return Ok(None)

    @classmethod
    @with_context
    def inc_misses(
        cls,
        shelfname: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase the counter for the given shelf misses by 1.

        :param shelfname: name of the shelf.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric(logger, cache, cls._KEY_MISSES.format(shelfname=shelfname))  # noqa: FS002
        return Ok(None)

    @classmethod
    @with_context
    def inc_removals(
        cls,
        shelfname: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase the counter for the number of guests removed from the given shelf by 1.

        :param shelfname: name of the shelf.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric(logger, cache, cls._KEY_REMOVALS.format(shelfname=shelfname))  # noqa: FS002
        return Ok(None)

    @classmethod
    @with_context
    def inc_forced_removals(
        cls,
        shelfname: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase the counter for the number of guests forcefully released from the given shelf by 1.

        :param shelfname: name of the shelf.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric(logger, cache, cls._KEY_FORCED_REMOVALS.format(shelfname=shelfname))  # noqa: FS002
        return Ok(None)

    @classmethod
    @with_context
    def inc_dead(
        cls,
        shelfname: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase the counter for dead guests in the given shelf by 1.

        :param shelfname: name of the shelf.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric(logger, cache, cls._KEY_DEAD.format(shelfname=shelfname))  # noqa: FS002
        return Ok(None)

    @with_context
    def do_sync(
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

        super().do_sync()

        r_shelf_size = KNOB_SHELF_MAX_GUESTS.get_value(session=session, entityname=self.shelfname)

        if r_shelf_size.is_error:
            r_shelf_size.unwrap_error().handle(logger)
            return

        r_current_guest_count = artemis_db.SafeQuery.from_session(session, artemis_db.GuestRequest) \
            .filter(artemis_db.GuestRequest.shelfname == self.shelfname) \
            .count()

        if r_current_guest_count.is_error:
            r_current_guest_count.unwrap_error().handle(logger)
            return

        self.current_guest_count = r_current_guest_count.unwrap()

        hits = cast(
            Callable[[str], Optional[bytes]],
            cache.get
        )(self.key_hits)

        self.hits = hits if hits is None else float(hits)

        misses = cast(
            Callable[[str], Optional[bytes]],
            cache.get
        )(self.key_misses)

        self.misses = misses if misses is None else float(misses)

        removals = cast(
            Callable[[str], Optional[bytes]],
            cache.get
        )(self.key_removals)

        self.removals = removals if removals is None else float(removals)

        forced_removals = cast(
            Callable[[str], Optional[bytes]],
            cache.get
        )(self.key_forced_removals)

        self.forced_removals = forced_removals if forced_removals is None else float(forced_removals)

        dead = cast(
            Callable[[str], Optional[bytes]],
            cache.get
        )(self.key_dead)

        self.dead_guest_count = dead if dead is None else float(dead)


@dataclasses.dataclass
class ShelvesMetrics(MetricsBase):
    """
    General metrics shared by shelves, and per-shelf metrics.
    """

    shelves: Dict[str, ShelfMetrics] = dataclasses.field(default_factory=dict)

    @with_context
    def do_sync(self, logger: gluetool.log.ContextAdapter, session: sqlalchemy.orm.session.Session) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param session: DB session to use for DB access.
        """

        super().do_sync()

        r_shelves = artemis_db.SafeQuery \
            .from_session(session, artemis_db.GuestShelf) \
            .all()

        if r_shelves.is_error:
            r_shelves.unwrap_error().handle(logger)

            self.shelves = {}

        else:
            self.shelves = {
                shelf.shelfname: ShelfMetrics(shelf.shelfname)
                for shelf in r_shelves.unwrap()
            }

        for metrics in self.shelves.values():
            metrics.sync()

    def do_register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super().do_register_with_prometheus(registry)

        self.CURRENT_GUEST_REQUEST_COUNT = Gauge(
            'shelf_current_guest_request_count',
            'Current number of guest requests being stored, per shelf.',
            ['shelfname'],
            registry=registry
        )

        self.SIZE = Gauge(
            'shelf_size',
            'Size of shelves, per shelf.',
            ['shelfname'],
            registry=registry
        )

        self.HIT_COUNT = Counter(
            'shelf_hit_count',
            'Number of guests retrieved from a shelf, per shelf.',
            ['shelfname'],
            registry=registry
        )

        self.MISS_COUNT = Counter(
            'miss_count',
            'Number of guests not retrieved from a shelf, per shelf.',
            ['shelfname'],
            registry=registry
        )

        self.REMOVALS = Counter(
            'shelf_removals',
            'Number of guests removed a shelf, per shelf.',
            ['shelfname'],
            registry=registry
        )

        self.FORCED_REMOVALS = Counter(
            'shelf_forced_removals',
            'Number of guests forcefully removed from a shelf, per shelf.',
            ['shelfname'],
            registry=registry
        )

        self.DEAD_GUEST_COUNT = Counter(
            'shelf_dead_guest_request_count',
            'Number of dead guests removed from a shelf, per shelf.',
            ['shelfname'],
            registry=registry
        )

    def do_update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        super().do_update_prometheus()

        reset_counters(self.CURRENT_GUEST_REQUEST_COUNT)
        reset_counters(self.SIZE)

        for shelfname, shelf_metrics in self.shelves.items():
            self.CURRENT_GUEST_REQUEST_COUNT.labels(shelfname=shelfname).set(shelf_metrics.current_guest_count)
            self.SIZE.labels(shelfname=shelfname).set(shelf_metrics.size)

            self.HIT_COUNT \
                .labels(shelfname=shelfname) \
                ._value.set(shelf_metrics.hit_count if shelf_metrics.hit_count is not None else float('NaN'))

            self.MISS_COUNT \
                .labels(shelfname=shelfname) \
                ._value.set(shelf_metrics.miss_count if shelf_metrics.miss_count is not None else float('NaN'))

            self.REMOVALS \
                .labels(shelfname=shelfname) \
                ._value.set(shelf_metrics.removals if shelf_metrics.removals is not None else float('NaN'))

            self.FORCED_REMOVALS \
                .labels(shelfname=shelfname) \
                ._value \
                .set(shelf_metrics.forced_removals if shelf_metrics.forced_removals is not None else float('NaN'))

            self.DEAD_GUEST_COUNT \
                .labels(shelfname=shelfname) \
                ._value \
                .set(shelf_metrics.dead_guest_count if shelf_metrics.dead_guest_count is not None else float('NaN'))


@dataclasses.dataclass
class TaskMetrics(MetricsBase):
    """
    Task and actor metrics.
    """

    overall_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    overall_errored_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    overall_retried_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    overall_rejected_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    current_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    current_delayed_message_count: Dict[Tuple[str, str], int] = dataclasses.field(default_factory=dict)
    message_durations: Dict[Tuple[str, str, str, str], int] = dataclasses.field(default_factory=dict)
    current_task_request_count: Dict[str, int] = dataclasses.field(default_factory=dict)

    _KEY_OVERALL_MESSAGES = 'metrics.tasks.messages.overall'
    _KEY_OVERALL_ERRORED_MESSAGES = 'metrics.tasks.messages.overall.errored'
    _KEY_OVERALL_RETRIED_MESSAGES = 'metrics.tasks.messages.overall.retried'
    _KEY_OVERALL_REJECTED_MESSAGES = 'metrics.tasks.messages.overall.rejected'
    _KEY_CURRENT_MESSAGES = 'metrics.tasks.messages.current'
    _KEY_CURRENT_DELAYED_MESSAGES = 'metrics.tasks.messages.current.delayed'
    _KEY_MESSAGE_DURATIONS = 'metrics.tasks.messages.durations'

    @staticmethod
    @with_context
    def inc_overall_messages(
        queue: str,
        actor: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of all encountered messages.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, TaskMetrics._KEY_OVERALL_MESSAGES, f'{queue}:{actor}')
        return Ok(None)

    @staticmethod
    @with_context
    def inc_overall_errored_messages(
        queue: str,
        actor: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of all errored messages.

        :param queue: name of the queue the message belongs to.
        :param actor: name of the actor requested by the message.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, TaskMetrics._KEY_OVERALL_ERRORED_MESSAGES, f'{queue}:{actor}')
        return Ok(None)

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

        inc_metric_field(logger, cache, TaskMetrics._KEY_OVERALL_RETRIED_MESSAGES, f'{queue}:{actor}')
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

        inc_metric_field(logger, cache, TaskMetrics._KEY_OVERALL_REJECTED_MESSAGES, f'{queue}:{actor}')
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

        inc_metric_field(logger, cache, TaskMetrics._KEY_CURRENT_MESSAGES, f'{queue}:{actor}')
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

        dec_metric_field(logger, cache, TaskMetrics._KEY_CURRENT_MESSAGES, f'{queue}:{actor}')
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

        inc_metric_field(logger, cache, TaskMetrics._KEY_CURRENT_DELAYED_MESSAGES, f'{queue}:{actor}')
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

        dec_metric_field(logger, cache, TaskMetrics._KEY_CURRENT_DELAYED_MESSAGES, f'{queue}:{actor}')
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

        bucket = min(threshold for threshold in MESSAGE_DURATION_BUCKETS if threshold > duration)

        inc_metric_field(
            logger,
            cache,
            TaskMetrics._KEY_MESSAGE_DURATIONS,
            f'{queue}:{actor}:{bucket}:{poolname or "undefined"}'
        )

        return Ok(None)

    @with_context
    def do_sync(
        self,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis,
        session: sqlalchemy.orm.session.Session
    ) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :param session: DB session to use for DB access.
        """

        super().do_sync()

        # TODO: find a better way how to make broker aware of all tasks. We rely on `resolve_actor` importing
        # all subpackages, but that's hard to update.
        from .tasks import BROKER, resolve_actor
        resolve_actor('worker_ping')

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

        self.current_task_request_count = {
            actorname: 0
            for actorname in BROKER.actors
        }

        self.current_task_request_count.update({
            record[0]: record[1]
            for record in cast(
                List[Tuple[str, int]],
                session.query(
                    artemis_db.TaskRequest.taskname,
                    sqlalchemy.func.count(artemis_db.TaskRequest.taskname)
                )
                .group_by(artemis_db.TaskRequest.taskname)
                .all()
            )
        })

        # queue:actor:bucket:poolname => count
        # deal with older version which had only three dimensions (no poolname)
        self.message_durations = {}

        for field, count in get_metric_fields(logger, cache, self._KEY_MESSAGE_DURATIONS).items():
            field_split = tuple(field.split(':', 3))

            if len(field_split) == 3:
                field_split = field_split + (UNDEFINED_POOL_NAME,)

            self.message_durations[cast(Tuple[str, str, str, str], field_split)] = count

    def do_register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super().do_register_with_prometheus(registry)

        self.OVERALL_MESSAGE_COUNT = Counter(
            'overall_message_count',
            'Overall total number of messages processed by queue and actor.',
            ['queue_name', 'actor_name'],
            registry=registry
        )

        self.OVERALL_ERRORED_MESSAGE_COUNT = Counter(
            'overall_errored_message_count',
            'Overall total number of errored messages by queue and actor.',
            ['queue_name', 'actor_name'],
            registry=registry
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

        self.CURRENT_TASK_REQUEST_COUNT = Gauge(
            'current_task_request_count',
            'Current number of task requests per actor.',
            ['actor_name'],
            registry=registry
        )

        self.MESSAGE_DURATIONS = Histogram(
            'message_duration_milliseconds',
            'The time spent processing messages by queue and actor.',
            ['queue_name', 'actor_name', 'pool'],
            buckets=MESSAGE_DURATION_BUCKETS,
            registry=registry,
        )

    @with_context
    def do_update_prometheus(self, logger: gluetool.log.ContextAdapter, cache: redis.Redis) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        """

        super().do_update_prometheus()

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

        reset_counters(self.CURRENT_TASK_REQUEST_COUNT)

        for actor_name, count in self.current_task_request_count.items():
            self.CURRENT_TASK_REQUEST_COUNT.labels(actor_name=actor_name)._value.set(count)

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

        bucket = min(threshold for threshold in HTTP_REQUEST_DURATION_BUCKETS if threshold > duration)

        inc_metric_field(
            logger,
            cache,
            APIMetrics._KEY_REQUEST_DURATIONS,
            f'{method}:{bucket}:{path}'
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

        inc_metric_field(logger, cache, APIMetrics._KEY_REQUEST_COUNT, f'{method}:{status}:{path}')
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

        inc_metric_field(logger, cache, APIMetrics._KEY_REQUEST_INPROGRESS_COUNT, f'{method}:{path}')
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

        dec_metric_field(logger, cache, APIMetrics._KEY_REQUEST_INPROGRESS_COUNT, f'{method}:{path}')
        return Ok(None)

    def do_register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super().do_register_with_prometheus(registry)

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
    def do_sync(self, logger: gluetool.log.ContextAdapter, cache: redis.Redis) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        """

        super().do_sync()

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

    def do_update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        super().do_update_prometheus()

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

    worker_ping: Optional[float] = None

    worker_process_count: Dict[str, Optional[int]] = dataclasses.field(default_factory=dict)
    worker_thread_count: Dict[str, Optional[int]] = dataclasses.field(default_factory=dict)
    worker_process_restart_count: Dict[str, Optional[int]] = dataclasses.field(default_factory=dict)
    worker_updated_timestamp: Dict[str, Optional[int]] = dataclasses.field(default_factory=dict)

    _KEY_WORKER_PING = 'metrics.workers.ping'

    _KEY_WORKER_PROCESS_COUNT = 'metrics.workers.{worker}.processes'  # noqa: FS003
    _KEY_WORKER_THREAD_COUNT = 'metrics.workers.{worker}.threads'  # noqa: FS003
    _KEY_WORKER_PROCESS_RESTART_COUNT = 'metrics.workers.{worker}.processes.restarts'  # noqa: FS003
    _KEY_UPDATED_TIMESTAMP = 'metrics.workers.{worker}.updated_timestamp'  # noqa: FS003

    @staticmethod
    @with_context
    def update_worker_ping(
        *,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Update worker ping timestamp.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        set_metric(
            logger,
            cache,
            WorkerMetrics._KEY_WORKER_PING,
            int(datetime.datetime.timestamp(datetime.datetime.utcnow()))
        )

        return Ok(None)

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
            WorkerMetrics._KEY_WORKER_PROCESS_COUNT.format(worker=worker),  # noqa: FS002
            processes,
            ttl=KNOB_WORKER_PROCESS_METRICS_TTL.value
        )

        set_metric(
            logger,
            cache,
            WorkerMetrics._KEY_WORKER_THREAD_COUNT.format(worker=worker),  # noqa: FS002
            threads,
            ttl=KNOB_WORKER_PROCESS_METRICS_TTL.value
        )

        set_metric(
            logger,
            cache,
            WorkerMetrics._KEY_UPDATED_TIMESTAMP.format(worker=worker),  # noqa: FS002
            int(datetime.datetime.timestamp(datetime.datetime.utcnow())),
            ttl=KNOB_WORKER_PROCESS_METRICS_TTL.value
        )

        return Ok(None)

    @staticmethod
    @with_context
    def inc_worker_process_restart_count(
        worker: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increase the worker process counter by 1.

        :param worker: name of the worker.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric(
            logger,
            cache,
            WorkerMetrics._KEY_WORKER_PROCESS_RESTART_COUNT.format(worker=worker)  # noqa: FS002
        )

        return Ok(None)

    def do_register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super().do_register_with_prometheus(registry)

        self.WORKER_PING = Gauge(
            'worker_ping',
            'Last time worker ping task has been executed.',
            registry=registry
        )

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

        self.WORKER_PROCESS_RESTART_COUNT = Counter(
            'worker_process_restart_count',
            'Number of worker process restarts, by worker.',
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
    def do_sync(self, logger: gluetool.log.ContextAdapter, cache: redis.Redis) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        """

        super().do_sync()

        worker_ping: Optional[float] = get_metric(logger, cache, self._KEY_WORKER_PING)
        self.worker_ping = worker_ping if worker_ping is None else float(worker_ping)

        self.worker_process_count = {
            metric.decode().split('.')[2]: get_metric(logger, cache, metric.decode())
            for metric in iter_cache_keys(logger, cache, 'metrics.workers.*.processes')
        }

        self.worker_thread_count = {
            metric.decode().split('.')[2]: get_metric(logger, cache, metric.decode())
            for metric in iter_cache_keys(logger, cache, 'metrics.workers.*.threads')
        }

        self.worker_process_restart_count = {
            metric.decode().split('.')[2]: get_metric(logger, cache, metric.decode())
            for metric in iter_cache_keys(logger, cache, 'metrics.workers.*.processes.restarts')
        }

        self.worker_updated_timestamp = {
            metric.decode().split('.')[2]: get_metric(logger, cache, metric.decode())
            for metric in iter_cache_keys(logger, cache, 'metrics.workers.*.updated_timestamp')
        }

    def do_update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        super().do_update_prometheus()

        self.WORKER_PING.set(self.worker_ping or float('Nan'))

        reset_counters(self.WORKER_PROCESS_COUNT)
        reset_counters(self.WORKER_THREAD_COUNT)
        reset_counters(self.WORKER_PROCESS_RESTART_COUNT)
        reset_counters(self.WORKER_UPDATED_TIMESTAMP)

        # TODO: move these into `reset_counters` - these should be more reliable, and we wouldn't have to
        # do the work on our own.
        self.WORKER_PROCESS_COUNT.clear()
        self.WORKER_THREAD_COUNT.clear()
        self.WORKER_PROCESS_RESTART_COUNT.clear()
        self.WORKER_UPDATED_TIMESTAMP.clear()

        for worker, processes in self.worker_process_count.items():
            self.WORKER_PROCESS_COUNT \
                .labels(worker=worker) \
                .set(processes)

        for worker, threads in self.worker_thread_count.items():
            self.WORKER_THREAD_COUNT \
                .labels(worker=worker) \
                .set(threads)

        for worker, restarts in self.worker_process_restart_count.items():
            self.WORKER_PROCESS_RESTART_COUNT \
                .labels(worker=worker) \
                ._value.set(restarts)

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
class DispatcherMetrics(MetricsBase):
    """
    Dispatcher metrics.
    """

    dispatched_task_invocations_count: int = 0
    dispatched_task_success_count: Dict[str, int] = dataclasses.field(default_factory=dict)
    dispatched_task_failure_count: int = 0
    dispatched_task_sequence_invocations_count: int = 0
    dispatched_task_sequence_success_count: Dict[str, int] = dataclasses.field(default_factory=dict)
    dispatched_task_sequence_failure_count: int = 0

    _KEY_DISPATCHED_TASK_INVOCATIONS = 'metrics.dispatcher.task.invocations'
    _KEY_DISPATCHED_TASK_SUCCESS = 'metrics.dispatcher.task.success'
    _KEY_DISPATCHED_TASK_FAILURE = 'metrics.dispatcher.task.failure'
    _KEY_DISPATCHED_TASK_SEQUENCE_INVOCATIONS = 'metrics.dispatcher.task-sequence.invocations'
    _KEY_DISPATCHED_TASK_SEQUENCE_SUCCESS = 'metrics.dispatcher.task-sequence.success'
    _KEY_DISPATCHED_TASK_SEQUENCE_FAILURE = 'metrics.dispatcher.task-sequence.failure'

    @staticmethod
    @with_context
    def inc_dispatched_task_invocations(
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of task dispatcher invocations.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric(logger, cache, DispatcherMetrics._KEY_DISPATCHED_TASK_INVOCATIONS)
        return Ok(None)

    @staticmethod
    @with_context
    def inc_successful_dispatched_tasks(
        actor_name: str,
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of successfull task dispatches.

        :param actor_name: Name of the dispatched task.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, DispatcherMetrics._KEY_DISPATCHED_TASK_SUCCESS, actor_name)

        return Ok(None)

    @staticmethod
    @with_context
    def inc_failed_dispatched_tasks(
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of task sequence dispatcher invocations.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric(logger, cache, DispatcherMetrics._KEY_DISPATCHED_TASK_FAILURE)
        return Ok(None)

    @staticmethod
    @with_context
    def inc_dispatched_task_sequence_invocations(
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of failed task sequence dispatches.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric(logger, cache, DispatcherMetrics._KEY_DISPATCHED_TASK_SEQUENCE_INVOCATIONS)
        return Ok(None)

    @staticmethod
    @with_context
    def inc_successful_dispatched_task_sequence(
        actor_names: List[str],
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of successfull task sequences dispatches.

        :param actor_names: Names of tasks in the sequence.
        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric_field(logger, cache, DispatcherMetrics._KEY_DISPATCHED_TASK_SEQUENCE_SUCCESS, ':'.join(actor_names))

        return Ok(None)

    @staticmethod
    @with_context
    def inc_failed_dispatched_task_sequences(
        logger: gluetool.log.ContextAdapter,
        cache: redis.Redis
    ) -> Result[None, Failure]:
        """
        Increment number of failed task sequences dispatches.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        :returns: ``None`` on success, :py:class:`Failure` instance otherwise.
        """

        inc_metric(logger, cache, DispatcherMetrics._KEY_DISPATCHED_TASK_SEQUENCE_FAILURE)
        return Ok(None)

    def do_register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super().do_register_with_prometheus(registry)

        self.DISPATCHED_TASK_INVOCATIONS_COUNT = Counter(
            'dispatched_task_invocations_count',
            'Count of dispatched tasks by task name.',
            registry=registry
        )

        self.DISPATCHED_TASK_SUCCESS_COUNT = Counter(
            'dispatched_task_success_count',
            'Count of dispatched tasks by task name.',
            ['actor_name'],
            registry=registry
        )

        self.DISPATCHED_TASK_FAILURE_COUNT = Counter(
            'dispatched_task_failed_count',
            'Count of dispatched tasks by task name.',
            registry=registry
        )

        self.DISPATCHED_TASK_SEQUENCE_INVOCATIONS_COUNT = Counter(
            'dispatched_task_sequence_invocations_count',
            'Count of dispatched tasks by task name.',
            registry=registry
        )

        self.DISPATCHED_TASK_SEQUENCE_SUCCESS_COUNT = Counter(
            'dispatched_task_sequence_success_count',
            'Count of dispatched tasks by task name.',
            ['actor_names'],
            registry=registry
        )

        self.DISPATCHED_TASK_SEQUENCE_FAILURE_COUNT = Counter(
            'dispatched_task_sequence_failed_count',
            'Count of dispatched tasks by task name.',
            registry=registry
        )

    @with_context
    def do_sync(self, logger: gluetool.log.ContextAdapter, cache: redis.Redis) -> None:
        """
        Load values from the storage and update this container with up-to-date values.

        :param logger: logger to use for logging.
        :param cache: cache instance to use for cache access.
        """

        super().do_sync()

        self.dispatched_task_invocations_count = get_metric(logger, cache, self._KEY_DISPATCHED_TASK_INVOCATIONS) or 0

        # actor_name => count
        self.dispatched_task_success_count = {
            field: count
            for field, count in get_metric_fields(logger, cache, self._KEY_DISPATCHED_TASK_SUCCESS).items()
        }

        self.dispatched_task_failure_count = get_metric(logger, cache, self._KEY_DISPATCHED_TASK_FAILURE) or 0

        self.dispatched_task_sequence_invocations_count = get_metric(
            logger,
            cache,
            self._KEY_DISPATCHED_TASK_SEQUENCE_INVOCATIONS
        ) or 0

        # actor_names => count
        self.dispatched_task_sequence_success_count = {
            field: count
            for field, count in get_metric_fields(logger, cache, self._KEY_DISPATCHED_TASK_SEQUENCE_SUCCESS).items()
        }

        self.dispatched_task_sequence_failure_count = get_metric(
            logger,
            cache,
            self._KEY_DISPATCHED_TASK_SEQUENCE_FAILURE
        ) or 0

    def do_update_prometheus(self) -> None:
        """
        Update values of Prometheus metric instances with the data in this container.
        """

        super().do_update_prometheus()

        # Reset all duration buckets and sums first
        reset_counters(self.DISPATCHED_TASK_SUCCESS_COUNT)
        reset_counters(self.DISPATCHED_TASK_SEQUENCE_SUCCESS_COUNT)

        self.DISPATCHED_TASK_INVOCATIONS_COUNT._value.set(self.dispatched_task_invocations_count)

        for actor_name, count in self.dispatched_task_success_count.items():
            self.DISPATCHED_TASK_SUCCESS_COUNT \
                .labels(actor_name=actor_name) \
                ._value.set(count)

        self.DISPATCHED_TASK_FAILURE_COUNT._value.set(self.dispatched_task_failure_count)

        self.DISPATCHED_TASK_SEQUENCE_INVOCATIONS_COUNT._value.set(self.dispatched_task_sequence_invocations_count)

        for actor_names, count in self.dispatched_task_sequence_success_count.items():
            self.DISPATCHED_TASK_SEQUENCE_SUCCESS_COUNT \
                .labels(actor_names=actor_names) \
                ._value.set(count)

        self.DISPATCHED_TASK_SEQUENCE_FAILURE_COUNT._value.set(self.dispatched_task_sequence_failure_count)


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
    shelves: ShelvesMetrics = ShelvesMetrics()
    api: APIMetrics = APIMetrics()
    workers: WorkerMetrics = WorkerMetrics()
    dispatcher: DispatcherMetrics = DispatcherMetrics()

    # Registry this tree of metrics containers is tied to.
    _registry: Optional[CollectorRegistry] = None

    def do_register_with_prometheus(self, registry: CollectorRegistry) -> None:
        """
        Register instances of Prometheus metrics with the given registry.

        :param registry: Prometheus registry to attach metrics to.
        """

        super().do_register_with_prometheus(registry)

        self._registry = registry

        self.PACKAGE_INFO = Info(
            'artemis_package',
            'Artemis packaging info. Labels provide information about package versions.',
            registry=registry
        )

        self.IDENTITY_INFO = Info(
            'artemis_identity',
            'Artemis identity info. Labels provide information about identity aspects.',
            registry=registry
        )

        # Since these values won't ever change, we can already set metrics and be done with it.
        self.PACKAGE_INFO.info({
            'package_version': __VERSION__,
            'image_digest': os.getenv('ARTEMIS_IMAGE_DIGEST', '<undefined>'),
            'image_url': os.getenv('ARTEMIS_IMAGE_URL', '<undefined>')
        })

        self.IDENTITY_INFO.info({
            'api_node': platform.node(),
            'artemis_deployment': os.getenv('ARTEMIS_DEPLOYMENT', '<undefined>')
        })

    @with_context
    def render_prometheus_metrics(
        self,
        logger: gluetool.log.ContextAdapter,
        db: artemis_db.DB
    ) -> Result[bytes, Failure]:
        """
        Render plaintext output of Prometheus metrics representing values in this tree of metrics.

        .. note::

           **Requires** the context variables defined in :py:mod:`tft.artemis` to be set properly.

        :param logger: logger to use for logging.
        :param db: DB instance to use for DB access.
        :returns: plaintext represenation of Prometheus metrics, encoded as ``bytes``.
        """

        def _render() -> bytes:
            with db.transaction(logger, read_only=True) as (session, t):
                SESSION.set(session)

                with Sentry.start_span(TracingOp.FUNCTION, description='metrics.sync'):
                    self.sync()

            with Sentry.start_span(TracingOp.FUNCTION, description='metrics.update'):
                self.update_prometheus()

            with Sentry.start_span(TracingOp.FUNCTION, description='metrics.generate'):
                return cast(bytes, generate_latest(registry=self._registry))

        return safe_call(_render)


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

    with Sentry.start_span(
        TracingOp.FUNCTION,
        description='inc_metric',
        tags={
            'metric': metric
        }
    ):
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

    with Sentry.start_span(
        TracingOp.FUNCTION,
        description='dec_metric',
        tags={
            'metric': metric
        }
    ):
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

    with Sentry.start_span(
        TracingOp.FUNCTION,
        description='inc_metric_field',
        tags={
            'metric': metric
        }
    ):
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

    with Sentry.start_span(
        TracingOp.FUNCTION,
        description='dec_metric_field',
        tags={
            'metric': metric
        }
    ):
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

    with Sentry.start_span(
        TracingOp.FUNCTION,
        description='get_metric',
        tags={
            'metric': metric
        }
    ):
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

    with Sentry.start_span(
        TracingOp.FUNCTION,
        description='set_metric',
        tags={
            'metric': metric
        }
    ):
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

    with Sentry.start_span(
        TracingOp.FUNCTION,
        description='get_metric_fields',
        tags={
            'metric': metric
        }
    ):
        return {
            field.decode(): int(value)
            for field, value in iter_cache_fields(logger, cache, metric)
        }
