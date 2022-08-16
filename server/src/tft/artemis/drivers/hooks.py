# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

"""
Helpers for driver hooks. Common, often-used actions and primitives.
"""

import os
import threading
from typing import Dict, Optional, Tuple

import gluetool.log
import gluetool.utils
from gluetool.result import Error, Ok, Result

from .. import Failure, log_dict_yaml, render_template
from ..environment import Environment
from ..knobs import KNOB_CONFIG_DIRPATH, Knob
from . import ImageInfoMapperOptionalResultType, PoolDriver, PoolImageInfo

KNOB_CACHE_PATTERN_MAPS: Knob[bool] = Knob(
    'pool.cache-pattern-maps',
    'If enabled, pattern maps loaded by pools would be cached.',
    has_db=False,
    per_pool=True,
    envvar='ARTEMIS_CACHE_PATTERN_MAPS',
    default=True,
    cast_from_str=gluetool.utils.normalize_bool_option
)


_PATTERN_MAP_CACHE: Dict[str, Tuple[float, gluetool.utils.PatternMap]] = {}
_PATTERN_MAP_CACHE_LOCK = threading.Lock()


def get_pattern_map(
    logger: gluetool.log.ContextAdapter,
    filepath: str,
    use_cache: bool = True
) -> Result[gluetool.utils.PatternMap, Failure]:
    if not use_cache:
        try:
            return Ok(gluetool.utils.PatternMap(filepath, allow_variables=True, logger=logger))

        except Exception as exc:
            return Error(Failure.from_exc('cannot load mapping file', exc, filepath=filepath))

    def _refresh_cache() -> Result[gluetool.utils.PatternMap, Failure]:
        try:
            stat = os.stat(filepath)
            pattern_map = gluetool.utils.PatternMap(filepath, allow_variables=True, logger=logger)

        except Exception as exc:
            return Error(Failure.from_exc('cannot load mapping file', exc, filepath=filepath))

        logger.info(f'pattern-map-cache: {filepath} - refreshing')

        _PATTERN_MAP_CACHE[filepath] = (stat.st_mtime, pattern_map)

        return Ok(pattern_map)

    with _PATTERN_MAP_CACHE_LOCK:
        if filepath not in _PATTERN_MAP_CACHE:
            logger.debug(f'pattern-map-cache: {filepath} - not in cache')

            return _refresh_cache()

        stamp, pattern_map = _PATTERN_MAP_CACHE[filepath]
        stat = os.stat(filepath)

        if stat.st_mtime > stamp:
            logger.warning(f'pattern-map-cache: {filepath} - outdated')

            return _refresh_cache()

        logger.debug(f'pattern-map-cache: {filepath} - using cached')

        return Ok(pattern_map)


def map_environment_to_imagename_by_pattern_map(
    logger: gluetool.log.ContextAdapter,
    pool: PoolDriver,
    environment: Environment,
    needle_template: str,
    mapping_filename: Optional[str] = None,
    mapping_filepath: Optional[str] = None
) -> Result[Optional[str], Failure]:
    """
    Using a given pattern mapping file, try to map an environment to its corresponding image name.

    Pattern mapping files are described
    `here <https://gluetool.readthedocs.io/en/latest/gluetool.utils.html#gluetool.utils.PatternMap>`_.

    :param environment: environment to map to an image name.
    :param needle_template: a template to render the string to look for in the pattern map. ``environment``
        is passed to template when rendering.
    :param mapping_filename: if set, pattern mapping file of this name is searched in Artemis' configuration directory.
    :param mapping_filepath: if set, this pattern mapping file is searched.
    :returns: either a image name, or :py:class:`tft.artemis.Failure` if the mapping was unsuccessfull.
    """

    if mapping_filepath:
        pass

    elif mapping_filename:
        mapping_filepath = os.path.join(KNOB_CONFIG_DIRPATH.value, mapping_filename)

    else:
        return Error(Failure('no compose/image mapping file specified', environment=environment))

    r_needle = render_template(needle_template, **environment.serialize())

    if r_needle.is_error:
        return Error(r_needle.unwrap_error())

    logger.debug(f'using pattern map {mapping_filepath}')

    r_cache_enabled = KNOB_CACHE_PATTERN_MAPS.get_value(poolname=pool.poolname)

    if r_cache_enabled.is_error:
        return Error(r_cache_enabled.unwrap_error().update(environment=environment))

    r_pattern_map = get_pattern_map(logger, mapping_filepath, use_cache=r_cache_enabled.unwrap())

    if r_pattern_map.is_error:
        return Error(r_pattern_map.unwrap_error().update(environment=environment))

    pattern_map = r_pattern_map.unwrap()

    try:
        imagename = pattern_map.match(r_needle.unwrap())

    except gluetool.glue.GlueError:
        return Ok(None)

    return Ok(imagename[0] if isinstance(imagename, list) else imagename)


def map_environment_to_image_info(
    logger: gluetool.log.ContextAdapter,
    pool: PoolDriver,
    environment: Environment,
    needle_template: str,
    mapping_filename: Optional[str] = None,
    mapping_filepath: Optional[str] = None
) -> ImageInfoMapperOptionalResultType[PoolImageInfo]:
    """
    Using a given pattern mapping file, try to map a compose, as specified by a given environment, to the corresponding
    cloud-specific image info.

    First, the compose is mapped to a human-readable image *name*, using pattern mapping file.
    See :py:func:`map_compose_to_imagename_by_pattern_map` for details.

    Then, this name is looked up in the pool, and if it does exist, its description is returned.

    :param environment: environment to map to an image info.
    :param needle_template: a template to render the string to look for in the pattern map. ``environment``
        is passed to template when rendering.
    :param mapping_filename: if set, pattern mapping file of this name is searched in Artemis' configuration directory.
    :param mapping_filepath: if set, this pattern mapping file is searched.
    :returns: either cloud-specific image information, or :py:class:`tft.artemis.Failure` if the mapping was
        unsuccessfull.
    """

    log_dict_yaml(logger.info, 'deciding image name for environment', environment.serialize())

    try:
        r_image_name = map_environment_to_imagename_by_pattern_map(
            logger,
            pool,
            environment,
            needle_template,
            mapping_filename=mapping_filename,
            mapping_filepath=mapping_filepath
        )

        if r_image_name.is_error:
            return Error(r_image_name.unwrap_error())

        imagename = r_image_name.unwrap()

        if imagename is None:
            log_dict_yaml(logger.info, 'compose not mapped to image name', {
                'environment': environment.serialize(),
                'image-name': imagename
            })

            return Ok(None)

        log_dict_yaml(logger.info, 'compose mapped to image name', {
            'environment': environment.serialize(),
            'image-name': imagename
        })

        r_image = pool.map_image_name_to_image_info(logger, imagename)

        if r_image.is_error:
            return Error(r_image.unwrap_error())

        log_dict_yaml(logger.info, 'compose mapped to image', {
            'environment': environment.serialize(),
            'image': r_image.unwrap().serialize()
        })

        return Ok(r_image.unwrap())

    except Exception as exc:
        return Error(Failure.from_exc(
            'crashed while mapping environment to image',
            exc,
            environment=environment
        ))
