import pytest

from mock import call, MagicMock

import gluetool
import gluetool_modules.helpers.guess_environment

from . import create_module, patch_shared, assert_shared, check_loadable


@pytest.fixture(name='module')
def fixture_module():
    module = create_module(gluetool_modules.helpers.guess_environment.GuessEnvironment)[1]
    module._compose = {
        'type': 'compose',
        'specification': 'foo',
        'method': 'foo',
        'pattern-map': {},
        'result': None
    }
    module._distro = {
        'type': 'distro',
        'specification': 'foo',
        'method': 'foo',
        'pattern-map': {},
        'result': None
    }
    module._image = {
        'type': 'image',
        'specification': 'foo',
        'method': 'foo',
        'pattern-map': {},
        'result': None
    }
    module._product = {
        'type': 'product',
        'specification': 'foo',
        'method': 'foo',
        'pattern-map': {},
        'result': None
    }
    module._wow_relevancy_distro = {
        'type': 'wow_relevancy_distro',
        'specification': 'foo',
        'method': 'foo',
        'pattern-map': {},
        'result': None
    }
    return module


@pytest.fixture(name='module_for_recent')
def fixture_module_for_recent(module, monkeypatch):
    # `name` is an argument to the Mock constructor...
    def _image(name):
        mock_image = MagicMock()
        mock_image.name = name

        return mock_image

    images = [
        _image('image-20160107'),
        _image('image-20160109'),
        _image('image-foo'),
        _image('image-20160103')
    ]

    patch_shared(monkeypatch, module, {
        'openstack': MagicMock(images=MagicMock(list=MagicMock(return_value=images)))
    })

    module._image = {
        'type': 'image',
        'specification': r'image-(\d+)',
        'method': 'recent',
        'pattern-map': {},
        'result': None
    }
    return module


def test_loadable(module):
    check_loadable(module.glue, 'gluetool_modules/helpers/guess_environment.py', 'GuessEnvironment')


@pytest.mark.parametrize('method, image, raises_exc, use', [
    ('recent', None, True, 'required'),
    ('recent', 'foo', False, None),
    ('force', None, True, 'required'),
    ('force', 'foo', False, None),
    ('target-autodetection', None, False, None),
    ('target-autodetection', 'foo', True, 'ignored')
])
def test_method_image_match(module, method, image, raises_exc, use):
    module._config['image-method'] = method
    module._config['image'] = image
    module._config['image-pattern-map'] = 'foo'

    if raises_exc:
        with pytest.raises(gluetool.GlueError, match=r"^--image option is %s with method '%s'$" % (use, method)):
            module.sanity()

    else:
        module.sanity()


@pytest.mark.parametrize('method, distro, raises_exc, use', [
    ('nightly', None, True, 'required'),
    ('nightly', 'foo', False, None),
    ('buc', None, True, 'required'),
    ('buc', 'foo', False, None),
    ('force', None, True, 'required'),
    ('force', 'foo', False, None),
    ('target-autodetection', None, False, None),
    ('target-autodetection', 'foo', True, 'ignored')
])
def test_method_distro_match(module, method, distro, raises_exc, use):
    module._config['distro-method'] = method
    module._config['distro'] = distro
    module._config['distro-pattern-map'] = 'foo'

    if raises_exc:
        with pytest.raises(gluetool.GlueError, match=r"^--distro option is %s with method '%s'$" % (use, method)):
            module.sanity()

    else:
        module.sanity()


@pytest.mark.parametrize('method, product, raises_exc, use', [
    ('force', None, True, 'required'),
    ('force', 'foo', False, None),
    ('target-autodetection', None, False, None),
    ('target-autodetection', 'foo', True, 'ignored')
])
def test_method_product_match(module, method, product, raises_exc, use):
    module._config['product-method'] = method
    module._config['product'] = product
    module._config['product-pattern-map'] = 'foo'

    if raises_exc:
        with pytest.raises(gluetool.GlueError, match=r"^--product option is %s with method '%s'$" % (use, method)):
            module.sanity()

    else:
        module.sanity()


@pytest.mark.parametrize('pattern_map, raises_exc', [
    (None, True),
    ('foo', False)
])
def test_image_method_pattern_map_match(module, pattern_map, raises_exc):
    module._config['image-method'] = 'target-autodetection'
    module._config['image-pattern-map'] = pattern_map

    if raises_exc:
        with pytest.raises(gluetool.GlueError, match=r"^--image-pattern-map option is required with method 'target-autodetection'$"):
            module.sanity()

    else:
        module.sanity()


@pytest.mark.parametrize('pattern_map, raises_exc', [
    (None, True),
    ('foo', False)
])
def test_distro_method_pattern_map_match(module, pattern_map, raises_exc):
    module._config['distro-method'] = 'target-autodetection'
    module._config['distro-pattern-map'] = pattern_map

    if raises_exc:
        with pytest.raises(gluetool.GlueError, match=r"^--distro-pattern-map option is required with method 'target-autodetection'$"):
            module.sanity()

    else:
        module.sanity()


@pytest.mark.parametrize('pattern_map, raises_exc', [
    (None, True),
    ('foo', False)
])
def test_product_method_pattern_map_match(module, pattern_map, raises_exc):
    module._config['product-method'] = 'target-autodetection'
    module._config['product-pattern-map'] = pattern_map

    if raises_exc:
        with pytest.raises(gluetool.GlueError, match=r"^--product-pattern-map option is required with method 'target-autodetection'$"):
            module.sanity()

    else:
        module.sanity()


def test_shared_image(module):
    module._image['result'] = MagicMock()

    assert module.image() == module._image['result']


def test_shared_distro(module):
    module._distro['result'] = MagicMock()

    assert module.distro() == module._distro['result']


def test_shared_product(module):
    module._product['result'] = MagicMock()

    assert module.product() == module._product['result']


def test_shared_wow_relevancy_distro(module):
    # pylint: disable=protected-access
    module._wow_relevancy_distro['result'] = MagicMock()

    assert module.wow_relevancy_distro('dummy-distro') == module._wow_relevancy_distro['result']


def test_image_pattern_map(module, monkeypatch):
    map_instance = MagicMock()
    map_class = MagicMock(return_value=map_instance)

    monkeypatch.setattr(gluetool_modules.helpers.guess_environment, 'PatternMap', map_class)

    module._image['pattern-map'] = {
        'build_target': 'dummy-map.yml'
    }

    assert module.pattern_map(module._image, 'build_target') == map_instance
    map_class.assert_called_once_with('dummy-map.yml', allow_variables=True,
                                      spices=None, logger=module.logger)


def test_distro_pattern_map(module, monkeypatch):
    map_instance = MagicMock()
    map_class = MagicMock(return_value=map_instance)

    monkeypatch.setattr(gluetool_modules.helpers.guess_environment, 'PatternMap', map_class)

    module._distro['pattern-map'] = 'dummy-map.yml'


def test_product_pattern_map(module, monkeypatch):
    map_instance = MagicMock()
    map_class = MagicMock(return_value=map_instance)

    monkeypatch.setattr(gluetool_modules.helpers.guess_environment, 'PatternMap', map_class)

    module._product['pattern-map'] = {
        'build_target': 'dummy-map.yml'
    }

    assert module.pattern_map(module._product, 'build_target') == map_instance
    map_class.assert_called_once_with('dummy-map.yml', allow_variables=True,
                                      spices=None, logger=module.logger)


def test_image_force(module):
    image = 'dummy-image'

    module._image['specification'] = image

    module._guess_force(module._image)

    assert module._image['result'] == image


def test_distro_force(module):
    distro = 'dummy-distro'

    module._distro['specification'] = [distro]

    module._guess_force(module._distro)

    assert module._distro['result'] == [distro]


def test_product_force(module):
    product = 'dummy-product'

    module._product['specification'] = product

    module._guess_force(module._product)

    assert module._product['result'] == product


def test_wow_relevancy_distro_force(module):
    wow_relevancy_distro = 'dummy-wow_relevancy_distro'

    # pylint: disable=protected-access
    module._wow_relevancy_distro['specification'] = wow_relevancy_distro

    module._guess_force(module._wow_relevancy_distro)

    assert module._wow_relevancy_distro['result'] == wow_relevancy_distro


def test_image_autodetection(module, monkeypatch):
    target = 'dummy-target'
    image = 'dummy-image'

    module._image['method'] = 'target-autodetection'

    patch_shared(monkeypatch, module, {}, callables={
        'primary_task': MagicMock(return_value=MagicMock(target=target))
    })

    # monkeypatching of @cached_property does not work, the property's __get__() gets called...
    module.pattern_map = MagicMock(return_value=MagicMock(match=MagicMock(return_value=image)))

    module._guess_target_autodetect(module._image)

    assert module._image['result'] == image


def test_distro_autodetection(module, monkeypatch):
    target = 'dummy-target'
    distro = 'dummy-distro'

    module._distro['method'] = 'target-autodetection'

    patch_shared(monkeypatch, module, {}, callables={
        'primary_task': MagicMock(return_value=MagicMock(target=target))
        })

    # monkeypatching of @cached_property does not work, the property's __get__() gets called...
    module.pattern_map = MagicMock(return_value=MagicMock(match=MagicMock(return_value=distro)))

    module._guess_target_autodetect(module._distro)

    assert module._distro['result'] == distro


def test_product_autodetection(module, monkeypatch):
    target = 'dummy-target'
    product = 'dummy-product'

    module._product['method'] = 'target-autodetection'

    patch_shared(monkeypatch, module, {}, callables={
        'primary_task': MagicMock(return_value=MagicMock(target=target))
    })

    # monkeypatching of @cached_property does not work, the property's __get__() gets called...
    module.pattern_map = MagicMock(return_value=MagicMock(match=MagicMock(return_value=product)))

    module._guess_target_autodetect(module._product)

    assert module._product['result'] == product


def test_wow_relevancy_autodetection(module, monkeypatch):
    target = 'dummy-target'
    distro = 'dummy-distro'
    destination_tag = 'dummy-destination-tag'
    wow_relevancy_distro = 'dummy-wow_relevancy_distro'

    # pylint: disable=protected-access
    module._wow_relevancy_distro['method'] = 'target-autodetection'

    patch_shared(monkeypatch, module, {}, callables={
        'primary_task': MagicMock(return_value=MagicMock(target=target, destination_tag=destination_tag))
    })

    # monkeypatching of @cached_property does not work, the property's __get__() gets called...
    module.pattern_map = MagicMock(return_value=MagicMock(match=MagicMock(return_value=wow_relevancy_distro)))

    # pylint: disable=protected-access
    module._guess_target_autodetect(module._wow_relevancy_distro, distro)

    assert module._wow_relevancy_distro['result'] == wow_relevancy_distro


def test_autodetection_fallback(module, monkeypatch):
    target = 'dummy-target'
    destination_tag = 'dummy-destination-tag'

    # pylint: disable=protected-access
    module._distro['method'] = 'target-autodetection'

    patch_shared(monkeypatch, module, {}, callables={
        'primary_task': MagicMock(return_value=MagicMock(target=target, destination_tag=destination_tag))
    })

    match_mock = MagicMock(side_effect=gluetool.GlueError('Could not match string'))
    module.pattern_map = MagicMock(return_value=MagicMock(match=match_mock))

    # pylint: disable=protected-access
    with pytest.raises(gluetool.GlueError, match="Failed to autodetect 'distro', no match found"):
        module._guess_target_autodetect(module._distro)

    # check if pattern map's match method twice with fallback to build target
    match_mock.assert_has_calls([
        call(destination_tag, multiple=True),
        call(target, multiple=True)
    ])


def test_autodetection_no_brew(module):
    assert_shared('primary_task', module._guess_target_autodetect, MagicMock())


def test_recent_no_openstack(module):
    assert_shared('openstack', module._guess_recent, MagicMock())


def test_recent_broken_regexp(monkeypatch, module):
    module.has_shared = MagicMock(return_value=True)

    patch_shared(monkeypatch, module, {
        'openstack': None
    })

    module._image['specification'] = '[foo'
    module._image['method'] = 'recent'

    with pytest.raises(gluetool.GlueError, match=r"cannot compile hint pattern '\^\[foo\$': unexpected end of regular expression"):
        module._guess_recent(module._image)


def test_recent(module_for_recent):
    module_for_recent._guess_recent(module_for_recent._image)

    assert module_for_recent._image['result'] == 'image-20160109'


def test_recent_no_match(module_for_recent):
    module_for_recent._image['specification'] = r'foo-(\d+)'

    with pytest.raises(gluetool.GlueError, match=r"No image found for hint '\^foo-\(\\d\+\)\$'"):
        module_for_recent._guess_recent(module_for_recent._image)


def test_recent_no_key(module_for_recent):
    module_for_recent._image['specification'] = r'image-foo'

    with pytest.raises(gluetool.GlueError, match=r" key from image name 'image-foo'"):
        module_for_recent._guess_recent(module_for_recent._image)


def test_execute_unknown_method(module):
    with pytest.raises(gluetool.GlueError, match=r"Unknown 'guessing' method 'foo'"):
        module.execute_method(module._image)


def test_execute(module, log):
    def _guess_foo(self, source):
        source['result'] = 'dummy'

    guess_foo = MagicMock(side_effect=_guess_foo)

    module._methods['foo'] = guess_foo

    module.distro()
    module.image()
    module.product()

    assert module._distro['result'] == 'dummy'
    assert log.records[-3].message == "Using distro:\n\"dummy\""
    assert module._image['result'] == 'dummy'
    assert log.records[-2].message == "Using image:\n\"dummy\""
    assert module._product['result'] == 'dummy'
    assert log.records[-1].message == "Using product:\n\"dummy\""


def test_test_guessing(module, log):
    def _guess_foo(self, source):
        source['result'] = 'dummy'

    guess_foo = MagicMock(side_effect=_guess_foo)

    module._methods['foo'] = guess_foo
    module._config['test-guessing'] = True

    module.execute()

    assert log.records[4].message.split('\n') == [
        'Guessed environment:', '{',
        '    "compose": "dummy",',
        '    "distro": "dummy",',
        '    "image": "dummy",',
        '    "product": "dummy"',
        '}'
    ]
