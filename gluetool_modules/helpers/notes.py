import collections
import logging

import gluetool

# Type annotations
from typing import Any


#: A note.
#:
#: :param str text: text of the note.
#: :param int level: level of the note. Using well-known levels of ``logging``.
#: :param str level_name: if set, it is a string representation of the level. Available when ``level``
#:     is one of levels provided by :py:mod:`logging`, for other, custom, levels, consumer of the note has
#:     to provide its own names when rendering each note.
Note = collections.namedtuple('Note', ['text', 'level', 'level_name'])


class Notes(gluetool.Module):
    """
    Store various notes and warnings, gathered by other modules. The notes are than available
    in the evaluation context under ``NOTES`` key.

    Each note has a string text and a integer representing its `level`. Any integer can be used,
    using levels defined by :py:mod:`logging` module, e.g. ``logging.INFO`` or ``logging.WARN``,
    is recommended.
    """

    name = 'notes'
    description = 'Store various notes and warnings, gahthered by other modules.'

    supported_dryrun_level = gluetool.glue.DryRunLevels.ISOLATED

    shared_functions = ('add_note',)

    def __init__(self, *args, **kwargs):
        # type: (*Any, **Any) -> None

        super(Notes, self).__init__(*args, **kwargs)

        self._notes = []

    def add_note(self, text, level=logging.INFO):
        # type: (str, int) -> None
        """
        Add new note.

        :param str text: Text of the note.
        :param level: Level of the note. Any integer is acceptable, using levels defined by :py:mod:`logging`
            module, e.g. ``logging.DEBUG`` or ``logging.INFO``, is recommended. If ``level`` is a string, module
            attempts to convert it to levels of ``logging`` module.
        """

        if isinstance(level, str):
            level_name = level.upper()

            if level_name not in logging._levelNames:
                raise gluetool.GlueError("Cannot deduce note level from '{}'".format(level))

            level = logging._levelNames[level_name]

        note = Note(text=text, level=level, level_name=logging._levelNames.get(level, None))

        if note in self._notes:
            gluetool.log.log_dict(self.debug, 'already noted', note)
            return

        self._notes.append(note)

        gluetool.log.log_dict(self.debug, 'note recorded', note)

    @property
    def eval_context(self):
        __content__ = {  # noqa
            'NOTES': """
                     List of all gathered notes, sorted by their levels from the more important levels
                     (higher values, e.g. ``logging.ERROR``) down to the lesser important ones (lower values,
                     e.g. ``logging.DEBUG``). Each note has ``text`` and ``level`` properties.
                     """
        }

        # sort by level and for same level, sort aplhabetically
        return {
            'NOTES': sorted(self._notes, key=lambda x: (x.level, x.text), reverse=True)
        }
