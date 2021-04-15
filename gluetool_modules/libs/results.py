# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import os

import gluetool
from gluetool.utils import new_xml_element

# Type annotations
# pylint: disable=unused-import,wrong-import-order
from typing import cast, Any, Callable, Dict, List, Optional, Tuple, Type, Union  # noqa


class TestResult(object):
    """
    This class represents results of testing performed by a module.

    Meaning of most of the fields depends on the result type, there are only
    few "points of contact" between two different result types.

    :param gluetool.glue.Glue glue: Glue instance the results belongs to - the results was either created
        by this instance, or loaded by it.
    :param str test_type: Type of testing. Makes sense to producers and consumers,
      ``Result`` class does not care of its actual value.
    :param str overall_result: Overall result of the test, e.g. ``PASS``, ``FAIL`` or ``ERROR``.
      The actual value depends on producer's view of the testing process and its results.
    :param dict ids: producer may want to attach arbitrary IDs to the result, e.g.
      test run ID (default: empty)
    :param dict url: producer may want to attach arbitrary URLs to the result, e.g.
      address of 3rd party service website presenting the details of performed tests.
    :param payload: producer may want to attach arbitratry data to the result, e.g.
      list of individual tests and their results performed.

    :ivar str test_type: Type of the test.
    :ivar str overall_result: Overall result of the testing process, e.g. ``PASS``, ``FAIL``
      or ``ERROR``.
    :ivar dict ids: IDs producer think might interest the result consumer.
    :ivar dict urls: URLs producer think might interest the result consumer.
    :ivar payload: Data producer think might interest the result consumer.
    """

    # pylint: disable=too-many-arguments,too-few-public-methods

    def __init__(self,
                 glue,  # type: gluetool.Glue
                 test_type,  # type: str
                 overall_result,  # type: str
                 ids=None,  # type: Optional[Dict[str, Any]]
                 urls=None,  # type: Optional[Dict[str, str]]
                 payload=None  # type: Any
                ):  # noqa
        # type: (...) -> None

        self.glue = glue

        self.test_type = test_type
        self.result_class = '{}.{}'.format(self.__module__, self.__class__.__name__)
        self.overall_result = overall_result
        self.ids = ids or {}
        self.urls = urls or {}
        self.payload = payload or []

        if 'jenkins_build' not in self.urls and 'BUILD_URL' in os.environ:
            self.urls['jenkins_build'] = os.environ['BUILD_URL']

    def __repr__(self):
        # type: () -> str

        return gluetool.log.format_dict(self._serialize_to_json())

    def _serialize_to_json(self):
        # type: () -> Dict[str, Any]
        """
        Return JSON representation of the result.
        """

        return {
            'test_type': self.test_type,
            'result_class': self.result_class,
            'overall_result': self.overall_result,
            'ids': self.ids,
            'urls': self.urls,
            'payload': self.payload
        }

    @classmethod
    def _unserialize_from_json(cls, glue, input_data):
        # type: (gluetool.Glue, Dict[str, Any]) -> TestResult

        return cls(glue, input_data['test_type'], input_data['overall_result'],
                   ids=input_data['ids'], urls=input_data['urls'], payload=input_data['payload'])

    def _serialize_to_xunit_property_dict(self, parent, properties, names):
        # type: (Any, Dict[str, Any], Dict[str, str]) -> None
        """
        Serialize ``key: value`` properties. Method serializes only known properties,
        and raises a warning when there are unknown properties left when it's done.

        :param element parent: Parent <properties/> element.
        :param dict properties: Properties to serialize.
        :param dict names: Mapping between known properties and their xUnit names. E.g. ``testing-thread-id``
            maps to ``baseosci.id.testing-thread``.
        """

        for property_name, xunit_name in names.iteritems():
            if property_name not in properties:
                continue

            value = properties.pop(property_name)

            new_xml_element('property', _parent=parent, name=xunit_name, value=value)

        if properties:
            self.glue.warn('Unconsumed properties:\n{}'.format(gluetool.log.format_dict(properties)), sentry=True)

    def _serialize_to_xunit(self):
        # type: () -> Any

        test_suite = new_xml_element('testsuite', name=self.test_type)
        test_suite_properties = new_xml_element('properties', _parent=test_suite)

        def _add_property(name, value):
            # type: (str, str) -> None

            new_xml_element('property', _parent=test_suite_properties, name='baseosci.{}'.format(name), value=value)

        primary_task = self.glue.shared('primary_task')
        if primary_task:
            _add_property('artifact-id', str(primary_task.id))
            _add_property('artifact-namespace', primary_task.ARTIFACT_NAMESPACE)

        _add_property('test-type', self.test_type)
        _add_property('result-class', self.result_class)
        _add_property('overall-result', self.overall_result)

        # serialize result's IDs into properties
        self._serialize_to_xunit_property_dict(test_suite_properties, self.ids.copy(), {
            'testing-thread-id': 'baseosci.id.testing-thread'
        })

        # serialize result's URLs into properties
        self._serialize_to_xunit_property_dict(test_suite_properties, self.urls.copy(), {
            'jenkins_build': 'baseosci.url.jenkins-build'
        })

        return test_suite

    def can_serialize(self, output_format):
        # type: (str) -> bool
        """
        Returns ``True`` if the class supports serialization into a given format.
        """

        return hasattr(self, '_serialize_to_{}'.format(output_format))

    @classmethod
    def can_unserialize(cls, input_format):
        # type: (str) -> bool
        """
        Returns ``True`` if the class supports unserialization from a given format.
        """

        return hasattr(cls, '_unserialize_from_{}'.format(input_format))

    def serialize(self, output_format):
        # type: (str) -> Any
        """
        Return representation of the result in given format.

        :param str output_format: Output data format.
        :raises gluetool.glue.GlueError: when result class does not support the output format.
        """

        serializer = getattr(self, '_serialize_to_{}'.format(output_format), None)

        if not serializer:
            raise gluetool.GlueError("Cannot serialize into output format '{}'".format(output_format))

        # pylint: disable=not-callable
        return serializer()

    @classmethod
    def unserialize(cls, glue, input_format, input_data):
        # type: (gluetool.Glue, str, Any) -> TestResult
        """
        Return instance of the result class, containing information provided in ``input_data``.

        :param str input_format: Input data format name.
        :param input_data: Input data in given format.
        :raises gluetool.glue.GlueError: when result class does not support the input format.
        """

        unserializer = cast(Callable[[gluetool.Glue, Any], TestResult],
                            getattr(cls, '_unserialize_from_{}'.format(input_format), None))

        if not unserializer:
            raise gluetool.GlueError("Cannot unserialize from input format '{}'".format(input_format))

        # pylint: disable=not-callable
        return unserializer(glue, input_data)


def publish_result(module, result_class, *args, **kwargs):
    # type: (gluetool.Module, Type[TestResult], *Any, **Any) -> None
    """
    Helper function for publishing test results. It creates a result instance,
    and makes it available for other modules.

    Requires shared function named ``results`` that returns list of results
    gathered so far.

    :param gluetool.glue.Module module: Module publishing the result.
    :param Result result_class: Class of the result.
    :param tuple args: arguments passed to result class constructor.
    :param dict kwargs: keyword arguments passed to result class constructor.
    """

    if not module.require_shared('results', warn_only=True):  # type: ignore  # warn_only is passed in kwargs
        return

    result = result_class(module.glue, *args, **kwargs)
    gluetool.log.log_dict(module.debug, 'result', result.serialize('json'))

    module.shared('results').append(result)
