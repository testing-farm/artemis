# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import gluetool
from gluetool.log import log_dict

import requests

# Type annotations
from typing import Any, List, Union  # noqa


class Semaphore(gluetool.Module):
    """
    Checks state of services monitored by Semaphore instance, and when given a list of instructions
    (via ``--instructions-map``), it follows them.

    Example instructions map:

    .. code-block:: yaml

       ---

       # when all components are operational ("status" == "1"), log the good message
       - rule: not [component for component in COMPONENTS if component['status'] != '1']
         log-info: "All components are reported as operational"

       # each component with non-operational status causes Jenkins to switch to quiet mode
       - rule: COMPONENT['status'] != '1'
         log-warn: "Component {{ COMPONENT['name'] }} has status {{ COMPONENT['status_name'] }}, do something"
         action: MODULE.shared('...')

    Each instruction is guarded by a rule, evaluated by ``evaluate_rules`` shared function. Each instruction
    is re-evaluated for every monitored component. Other supported commands are:

        * ``log-info``, ``log-warn``: log given message. Message is treated as a template to render.
        * ``action``: run given `action` - anything the ``evaluate_rules`` function can run.

    Context for both rules and commands contains following extra variables:

        * ``MODULE``: references the ``semaphore`` module itself. Allows access to shared function
          and other ``gluetool`` functionality.
        * ``COMPONENTS``: list of dictionaries describing state of each component monitored by Semaphore.
        * ``COMPONENT``: current component the instruction is inspecting. Instatruction gets to visit
          every component, therefore this variable changes over the iteration over the component states.

    For structure of component state, see https://docs.cachethq.io/reference#get-components.
    """

    name = 'semaphore'
    description = 'Checks state of services monitored by Semaphore, and apply necessary actions.'

    options = [
        ('Common options', {
            'instructions-map': {
                'help': 'List of rules and actions to take (default: none)',
                'action': 'append',
                'default': []
            }
        }),
        ('API settings', {
            'api-url': {
                'help': 'Root of Semaphore API',
                'type': str
            }
        }),
        ('Local API responses', {
            'local-response-components': {
                'help': "JSON file with response to 'state of components' query",
                'type': str
            }
        })
    ]

    required_options = ('api-url',)

    shared_functions = ['semaphore_component_states']

    @gluetool.utils.cached_property
    def instructions_map(self):
        # type: () -> Union[List[Any], Any]
        if not self.option('instructions-map'):
            return []

        return sum([
            gluetool.utils.load_yaml(path, logger=self.logger)
            for path in gluetool.utils.normalize_path_option(self.option('instructions-map'))
        ], [])

    @gluetool.utils.cached_property
    def component_states(self):
        # type: () -> Any
        # caching, for now - suppose the pipeline finishes quickly enough so that states wouldn't change

        local_source = self.option('local-response-components')

        if local_source:
            response = gluetool.utils.load_json(gluetool.utils.normalize_path(local_source), logger=self.logger)

        else:
            response = requests.get('{}/components'.format(self.option('api-url'))).json()

        if 'data' not in response:
            raise gluetool.GlueError("No 'data' key in API response")

        return response['data']

    def semaphore_component_states(self):
        # type: () -> Any
        """
        Returns a list of states of monitored components.

        For fields provided, see https://docs.cachethq.io/reference#get-components.

        :rtype: list(dict)
        """

        return self.component_states

    def execute(self):
        # type: () -> None
        self.require_shared('evaluate_rules')

        # For each component, each instruction is checked whether it applies
        for instruction in self.instructions_map:
            log_dict(self.debug, 'instruction', instruction)

            for component in self.component_states:
                log_dict(self.debug, 'component', component)

                context = gluetool.utils.dict_update(self.shared('eval_context'), {
                    'MODULE': self,
                    'COMPONENT': component,
                    'COMPONENTS': self.component_states
                })

                if not self.shared('evaluate_rules', instruction.get('rule', 'True'), context=context):
                    self.debug('rule does not match, moving on')
                    continue

                if 'log-warn' in instruction:
                    self.warn(gluetool.utils.render_template(instruction['log-warn'], logger=self.logger, **context))

                if 'log-info' in instruction:
                    self.info(gluetool.utils.render_template(instruction['log-info'], logger=self.logger, **context))

                if 'action' in instruction:
                    self.shared('evaluate_rules', instruction['action'], context=context)
