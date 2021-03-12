import pytest
from mock import MagicMock
import logging

from gluetool import GlueError
from gluetool_modules.helpers.notes import Notes, Note
from . import create_module, check_loadable


@pytest.fixture(name='module')
def fixture_module():
    return create_module(Notes)[1]


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/helpers/notes.py', 'Notes')


def test_default_level(module):
    module.add_note('dummy-text')

    note = Note(text='dummy-text', level=logging.INFO, level_name='INFO')

    assert module._notes == [note]
    assert 'NOTES' in module.eval_context and module.eval_context['NOTES'] == [note]


@pytest.mark.parametrize('level_name, level', [
    ('info', logging.INFO),
    ('debug', logging.DEBUG),
    ('error', logging.ERROR),
    ('warning', logging.WARNING)
])
def test_str_level(module, level_name, level):
    module.add_note('dummy-text', level=level_name)

    note = Note(text='dummy-text', level=level, level_name=level_name.upper())

    assert module._notes == [note]
    assert 'NOTES' in module.eval_context and module.eval_context['NOTES'] == [note]


@pytest.mark.parametrize('level_int, level', [
    (20, logging.INFO),
    (10, logging.DEBUG),
    (40, logging.ERROR),
    (30, logging.WARNING),
    (42, None)
])
def test_int_level(module, level_int, level):
    module.add_note('dummy-text', level=level_int)

    note = Note(text='dummy-text',
                level=level if level else level_int,
                level_name=logging._levelNames.get(level, None))

    assert module._notes == [note]
    assert 'NOTES' in module.eval_context and module.eval_context['NOTES'] == [note]


def test_str_level_error(module):
    with pytest.raises(GlueError, match="Cannot deduce note level from 'dummy-level'"):
        module.add_note('dummy-text', level='dummy-level')


def test_duplicates(module):
    assert len(module.eval_context['NOTES']) == 0
    module.add_note('dummy-test', level=79)
    assert len(module.eval_context['NOTES']) == 1
    module.add_note('dummy-test', level=79)
    assert len(module.eval_context['NOTES']) == 1
