# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import dataclasses
import functools
from collections.abc import Sequence
from typing import TYPE_CHECKING, Any, Callable, Generic, Optional, Protocol, TypeVar, cast

import gluetool.log
import sqlalchemy
from gluetool.result import Error, Ok, Result
from typing_extensions import Self, TypeAlias

from .. import Failure, log_dict_yaml
from ..db import GuestRequest
from ..environment import Flavor

if TYPE_CHECKING:
    from . import FlavorBasedPoolDriver, PoolImageInfo


FlavorT = TypeVar('FlavorT', bound=Flavor)
PoolImageInfoT = TypeVar('PoolImageInfoT', bound='PoolImageInfo')
PoolT = TypeVar('PoolT', bound='FlavorBasedPoolDriver[Any, Any, Any, Any, Any]', contravariant=True)  # noqa: PLC0105


@dataclasses.dataclass(repr=False)
class PairRuling(Generic[FlavorT]):
    image: 'PoolImageInfo'
    flavor: FlavorT
    match: bool

    note: Optional[str] = None

    def __repr__(self) -> str:
        return f'<PairRuling: image={self.image.name} flavor={self.flavor.name} match={self.match} note={self.note}>'


@dataclasses.dataclass(repr=False)
class FilterRuling(Generic[FlavorT]):
    rulings: list[PairRuling[FlavorT]] = dataclasses.field(default_factory=list)

    @property
    def matched_rulings(self) -> list[PairRuling[FlavorT]]:
        return [pair_ruling for pair_ruling in self.rulings if pair_ruling.match]

    @property
    def matched_flavors(self) -> list[FlavorT]:
        return [pair_ruling.flavor for pair_ruling in self.rulings if pair_ruling.match]

    @classmethod
    def from_flavors(
        cls,
        image: 'PoolImageInfo',
        flavors: Sequence[FlavorT],
        matcher: Optional[Callable[[FlavorT], bool]] = None,
    ) -> Self:
        if matcher is None:

            def matcher(flavor: FlavorT) -> bool:
                return True

        return cls(rulings=[PairRuling(image=image, flavor=flavor, match=matcher(flavor)) for flavor in flavors])


FilterReturnType: TypeAlias = Result[FilterRuling[FlavorT], Failure]

Filter: TypeAlias = Callable[
    [
        gluetool.log.ContextAdapter,
        sqlalchemy.orm.session.Session,
        PoolT,
        GuestRequest,
        PoolImageInfoT,
        Sequence[FlavorT],
    ],
    FilterReturnType[FlavorT],
]


class FilterWrapperType(Protocol):
    filter_name: str


class FilterLogger(gluetool.log.ContextAdapter):
    def __init__(self, logger: gluetool.log.ContextAdapter, filter_name: str) -> None:
        super().__init__(logger, {'ctx_policy_name': (60, filter_name)})

    @property
    def filtername(self) -> str:
        return cast(str, self._contexts['filter_name'][1])


def image_flavor_filter(fn: Filter[PoolT, PoolImageInfoT, FlavorT]) -> Filter[PoolT, PoolImageInfoT, FlavorT]:
    filter_name = fn.__name__.lower().replace('filter_', '').replace('_', '-')

    @functools.wraps(fn)
    def wrapper(
        logger: gluetool.log.ContextAdapter,
        session: sqlalchemy.orm.session.Session,
        pool: PoolT,
        guest_request: GuestRequest,
        image: PoolImageInfoT,
        flavors: Sequence[FlavorT],
    ) -> FilterReturnType[FlavorT]:
        try:
            filter_logger = FilterLogger(logger, filter_name)

            r = fn(filter_logger, session, pool, guest_request, image, flavors)

            if r.is_error:
                return r

        except Exception as exc:
            return Error(Failure.from_exc('image/flavor filter crashed', exc, filter_name=filter_name))

        else:
            return r

    cast(FilterWrapperType, wrapper).filter_name = filter_name

    return wrapper


@image_flavor_filter
def filter_flavors_image_arch(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pool: 'FlavorBasedPoolDriver[Any, Any, FlavorT, Any, Any]',
    guest_request: GuestRequest,
    image: 'PoolImageInfo',
    flavors: Sequence[FlavorT],
) -> FilterReturnType[FlavorT]:
    if image.arch is None:
        return Ok(FilterRuling.from_flavors(image, flavors))

    return Ok(FilterRuling.from_flavors(image, flavors, matcher=lambda flavor: flavor.arch == image.arch))


@image_flavor_filter
def filter_flavors_image_compatible(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pool: 'FlavorBasedPoolDriver[Any, Any, FlavorT, Any, Any]',
    guest_request: GuestRequest,
    image: 'PoolImageInfo',
    flavors: Sequence[FlavorT],
) -> FilterReturnType[FlavorT]:
    image_distros = set(image.compatible.distro)

    if not image_distros:
        return Ok(FilterRuling.from_flavors(image, flavors))

    return Ok(
        FilterRuling.from_flavors(
            image,
            flavors,
            matcher=lambda flavor: not flavor.compatible.distro
            or bool(image_distros.intersection(flavor.compatible.distro)),
        )
    )


@image_flavor_filter
def filter_flavors_prefer_default_flavor(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pool: 'FlavorBasedPoolDriver[Any, Any, FlavorT, Any, Any]',
    guest_request: GuestRequest,
    image: 'PoolImageInfo',
    flavors: Sequence[FlavorT],
) -> FilterReturnType[FlavorT]:
    if not flavors:
        return Ok(FilterRuling.from_flavors(image, flavors))

    if not any(flavor.name == pool.pool_config['default-flavor'] for flavor in flavors):
        return Ok(FilterRuling.from_flavors(image, flavors))

    return Ok(
        FilterRuling.from_flavors(
            image, flavors, matcher=lambda flavor: flavor.name == pool.pool_config['default-flavor']
        )
    )


@image_flavor_filter
def filter_flavors_default_fallback(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pool: 'FlavorBasedPoolDriver[Any, Any, FlavorT, Any, Any]',
    guest_request: GuestRequest,
    image: 'PoolImageInfo',
    flavors: Sequence[FlavorT],
) -> FilterReturnType[FlavorT]:
    if flavors:
        return Ok(FilterRuling.from_flavors(image, flavors))

    if not pool.pool_config.get('use-default-flavor-when-no-suitable', True):
        return Ok(FilterRuling.from_flavors(image, flavors))

    r_default_flavor = pool._map_environment_to_flavor_info_by_cache_by_name_or_none(
        logger, pool.pool_config['default-flavor']
    )

    if r_default_flavor.is_error:
        return Error(r_default_flavor.unwrap_error())

    flavor = r_default_flavor.unwrap()

    if flavor is None:
        return Ok(FilterRuling(rulings=[]))

    return Ok(FilterRuling(rulings=[PairRuling(image=image, flavor=flavor, match=True)]))


def run_image_flavor_filters(
    logger: gluetool.log.ContextAdapter,
    session: sqlalchemy.orm.session.Session,
    pool: PoolT,
    guest_request: GuestRequest,
    image: PoolImageInfoT,
    flavors: Sequence[FlavorT],
    filters: Sequence[Filter[PoolT, PoolImageInfoT, FlavorT]],
) -> FilterReturnType[FlavorT]:
    final_ruling = FilterRuling(rulings=[PairRuling(image=image, flavor=flavor, match=True) for flavor in flavors])

    for filter_ in filters:
        r = filter_(
            logger, session, pool, guest_request, image, [pair_ruling.flavor for pair_ruling in final_ruling.rulings]
        )

        if r.is_error:
            return Error(
                Failure.from_failure(
                    'failed to filter image/flavor pairs',
                    r.unwrap_error(),
                    environment=guest_request.environment,
                )
            )

        current_filter_ruling = r.unwrap()

        log_dict_yaml(
            logger.debug,
            f'{filter_.filter_name} outcome',  # type: ignore[attr-defined]
            [
                {
                    'image': pair_ruling.image.name,
                    'flavor': pair_ruling.flavor.name,
                    'match': pair_ruling.match,
                    'note': pair_ruling.note,
                }
                for pair_ruling in current_filter_ruling.rulings
            ],
        )

        final_ruling.rulings = [pair_ruling for pair_ruling in current_filter_ruling.rulings if pair_ruling.match]

    return Ok(final_ruling)
