# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import imp
import os
from typing import Any, Callable, Dict

import gluetool.utils
from gluetool.result import Error, Ok, Result

from . import Failure


class ScriptEngine:
    def __init__(self) -> None:
        super().__init__()

        self.functions: Dict[str, Callable[..., Result[Any, Failure]]] = {}
        self.variables: Dict[str, Callable[..., Result[Any, Failure]]] = {}

    def load_script_file(self, filepath: str) -> Result[None, Failure]:
        filepath = os.path.expanduser(filepath)

        try:
            code = imp.load_source(filepath.replace('/', '_'), filepath)

        except Exception as exc:
            return Error(Failure.from_exc(
                'failed to load script',
                exc,
                script_filepath=filepath
            ))

        for member_name in dir(code):
            if member_name.startswith('_'):
                continue

            fn = getattr(code, member_name)

            if not callable(fn):
                continue

            self.functions[member_name] = fn

        return Ok(None)

    def load_variables_file(self, filepath: str) -> None:
        variables = gluetool.utils.load_yaml(filepath)

        if not isinstance(variables, dict):
            raise Exception(f'Cannot add variables from {filepath}, not a key: value format')

        self.variables.update(variables)

    def run(self, name: str, **kwargs: Any) -> Result[Any, Failure]:
        kwargs = gluetool.utils.dict_update(
            {},
            self.variables,
            kwargs or {}
        )

        return self.functions[name](**kwargs)

    def run_hook(self, name: str, **kwargs: Any) -> Result[Any, Failure]:
        return self.run(f'hook_{name.upper()}', **kwargs)


def hook_engine(hook_name: str) -> Result[ScriptEngine, Failure]:
    script_filepath = os.getenv(f'ARTEMIS_HOOK_{hook_name.upper()}', None)
    hook_callback_name = f'hook_{hook_name.upper()}'

    if not script_filepath:
        return Error(Failure(
            'hook filepath not defined',
            hook_name=hook_name,
            script_filepath=script_filepath
        ))

    script_filepath = os.path.expanduser(script_filepath)

    if not os.path.exists(script_filepath):
        return Error(Failure(
            'hook filepath not defined',
            hook_name=hook_name,
            script_filepath=script_filepath
        ))

    engine = ScriptEngine()
    r_load = engine.load_script_file(script_filepath)

    if r_load.is_error:
        return Error(r_load.unwrap_error())

    if hook_callback_name not in engine.functions:
        return Error(Failure(
            'hook callable not found',
            hook_name=hook_name,
            script_filepath=script_filepath,
            callable_name=hook_callback_name
        ))

    return Ok(engine)
