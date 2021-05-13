"""
Helpers for driver hooks. Common, often-used actions and primitives.
"""

import os
from typing import Optional

import gluetool.log
import gluetool.utils
from gluetool.result import Error, Ok, Result

from .. import KNOB_CONFIG_DIRPATH, Failure
from ..environment import Environment
from . import PoolDriver, PoolImageInfo


def map_compose_to_imagename_by_pattern_map(
    logger: gluetool.log.ContextAdapter,
    compose_id: str,
    mapping_filename: Optional[str] = None,
    mapping_filepath: Optional[str] = None
) -> Result[str, Failure]:
    """
    Using a given pattern mapping file, try to map a compose to its corresponding image name.

    Pattern mapping files are described
    `here <https://gluetool.readthedocs.io/en/latest/gluetool.utils.html#gluetool.utils.PatternMap>`_.

    :param compose_id: compose ID to translate.
    :param mapping_filename: if set, pattern mapping file of this name is searched in Artemis' configuration directory.
    :param mapping_filepath: if set, this pattern mapping file is searched.
    :returns: either a image name, or :py:class:`tft.artemis.Failure` if the mapping was unsuccessfull.
    """

    if mapping_filepath:
        pass

    elif mapping_filename:
        mapping_filepath = os.path.join(KNOB_CONFIG_DIRPATH.value, mapping_filename)

    else:
        return Error(Failure('no compose/image mapping file specified', compose=compose_id))

    logger.debug(f'using pattern map {mapping_filepath}')

    try:
        pattern_map = gluetool.utils.PatternMap(mapping_filepath, allow_variables=True, logger=logger)

    except Exception as exc:
        return Error(Failure.from_exc('cannot open compose/image mapping', exc, compose=compose_id))

    try:
        imagename = pattern_map.match(compose_id)

    except gluetool.glue.GlueError:
        return Error(Failure(
            'cannot map compose to image',
            compose=compose_id,
            recoverable=False
        ))

    return Ok(imagename[0] if isinstance(imagename, list) else imagename)


def map_environment_to_image_info(
    logger: gluetool.log.ContextAdapter,
    pool: PoolDriver,
    environment: Environment,
    mapping_filename: Optional[str] = None,
    mapping_filepath: Optional[str] = None
) -> Result[PoolImageInfo, Failure]:
    """
    Using a given pattern mapping file, try to map a compose, as specified by a given environment, to the corresponding
    cloud-specific image info.

    First, the compose is mapped to a human-readable image *name*, using pattern mapping file.
    See :py:func:`map_compose_to_imagename_by_pattern_map` for details.

    Then, this name is looked up in the pool, and if it does exist, its description is returned.

    :param mapping_filename: if set, pattern mapping file of this name is searched in Artemis' configuration directory.
    :param mapping_filepath: if set, this pattern mapping file is searched.
    :returns: either cloud-specific image information, or :py:class:`tft.artemis.Failure` if the mapping was
        unsuccessfull.
    """

    logger.info(f'deciding image name for {environment}')

    try:
        r_image_name = map_compose_to_imagename_by_pattern_map(
            logger,
            environment.os.compose,
            mapping_filename=mapping_filename,
            mapping_filepath=mapping_filepath
        )

        if r_image_name.is_error:
            return Error(r_image_name.unwrap_error())

        imagename = r_image_name.unwrap()

        logger.info(f'mapped {environment} to image name {imagename}')

        return pool.map_image_name_to_image_info(logger, imagename)

    except Exception as exc:
        return Error(Failure.from_exc(
            'crashed while mapping environment to image',
            exc,
            environment=environment
        ))
