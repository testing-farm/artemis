import imp
import os
from typing import Any, Callable, Dict

import gluetool.utils
from gluetool.result import Error, Ok, Result

from . import Failure


class ScriptEngine:
    def __init__(self) -> None:
        super(ScriptEngine, self).__init__()

        self.functions: Dict[str, Callable[..., Result[Any, Failure]]] = {}
        self.variables: Dict[str, Callable[..., Result[Any, Failure]]] = {}

    def load_script_file(self, filepath: str) -> None:
        filepath = os.path.expanduser(filepath)

        try:
            code = imp.load_source(filepath.replace('/', '_'), filepath)

        except Exception as exc:
            raise Exception('Failed to load script from {}: {}'.format(filepath, exc))

        for member_name in dir(code):
            if member_name.startswith('_'):
                continue

            fn = getattr(code, member_name)

            if not callable(fn):
                continue

            self.functions[member_name] = fn

    def load_variables_file(self, filepath: str) -> None:
        variables = gluetool.utils.load_yaml(filepath)

        if not isinstance(variables, dict):
            raise Exception('Cannot add variables from {}, not a key: value format'.format(filepath))

        self.variables.update(variables)

    def run(self, name: str, **kwargs: Any) -> Result[Any, Failure]:
        kwargs = gluetool.utils.dict_update(
            {},
            self.variables,
            kwargs or {}
        )

        return self.functions[name](**kwargs)

    def run_hook(self, name: str, **kwargs: Any) -> Result[Any, Failure]:
        return self.run('hook_{}'.format(name.upper()), **kwargs)


def hook_engine(hook_name: str) -> Result[ScriptEngine, Failure]:
    script_filepath = os.getenv('ARTEMIS_HOOK_{}'.format(hook_name.upper()), None)
    hook_callback_name = 'hook_{}'.format(hook_name.upper())

    if not script_filepath:
        return Error(Failure('Hook {} is not defined'.format(hook_name)))

    script_filepath = os.path.expanduser(script_filepath)

    if not os.path.exists(script_filepath):
        return Error(Failure('Script file {} does not exist'.format(script_filepath)))

    engine = ScriptEngine()
    engine.load_script_file(script_filepath)

    if hook_callback_name not in engine.functions:
        return Error(Failure('Hook callback {} is not present in {}'.format(hook_callback_name, script_filepath)))

    return Ok(engine)
