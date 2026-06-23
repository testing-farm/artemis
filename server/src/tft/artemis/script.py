# Copyright Contributors to the Testing Farm project.
# SPDX-License-Identifier: Apache-2.0

import importlib.machinery
import importlib.util
import os
from types import ModuleType
from typing import Any, Callable

import gluetool.utils
from gluetool.result import Error, Ok, Result

from . import Failure, Sentry, TracingOp


def load_source(modname: str, filename: str) -> Result[ModuleType, Failure]:
    loader = importlib.machinery.SourceFileLoader(modname, filename)
    spec = importlib.util.spec_from_file_location(modname, filename, loader=loader)

    if spec is None:
        return Error(Failure('failed to load module source', modname=modname, filename=filename))

    module = importlib.util.module_from_spec(spec)

    # The module is always executed and not cached in sys.modules.
    # Uncomment the following line to cache the module.
    # sys.modules[module.__name__] = module  # noqa: ERA001
    loader.exec_module(module)

    return Ok(module)


class ScriptEngine:
    def __init__(self) -> None:
        super().__init__()

        self.functions: dict[str, Callable[..., Result[Any, Failure]]] = {}
        self.variables: dict[str, Callable[..., Result[Any, Failure]]] = {}

    def load_script_file(self, filepath: str) -> Result[None, Failure]:
        filepath = os.path.expanduser(filepath)

        try:
            r_code = load_source(filepath.replace('/', '_'), filepath)

        except Exception as exc:
            return Error(Failure.from_exc('failed to load script', exc, script_filepath=filepath))

        if r_code.is_error:
            return Error(r_code.unwrap_error())

        code = r_code.unwrap()

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
            raise TypeError(f'Cannot add variables from {filepath}, not a key: value format')

        self.variables.update(variables)

    def run(self, name: str, **kwargs: Any) -> Result[Any, Failure]:
        kwargs = gluetool.utils.dict_update({}, self.variables, kwargs or {})

        return self.functions[name](**kwargs)

    def run_hook(self, name: str, **kwargs: Any) -> Result[Any, Failure]:
        with Sentry.start_span(TracingOp.FUNCTION, description='ScriptEngine.run_hook') as tracing_span:
            tracing_span.set_tag('hookname', name)

            return self.run(f'hook_{name.upper()}', **kwargs)


def hook_engine(hook_name: str) -> Result[ScriptEngine, Failure]:
    script_filepath = os.getenv(f'ARTEMIS_HOOK_{hook_name.upper()}', None)
    hook_callback_name = f'hook_{hook_name.upper()}'

    if not script_filepath:
        return Error(Failure('hook filepath not defined', hook_name=hook_name, script_filepath=script_filepath))

    script_filepath = os.path.expanduser(script_filepath)

    if not os.path.exists(script_filepath):
        return Error(Failure('hook filepath not defined', hook_name=hook_name, script_filepath=script_filepath))

    engine = ScriptEngine()
    r_load = engine.load_script_file(script_filepath)

    if r_load.is_error:
        return Error(r_load.unwrap_error())

    if hook_callback_name not in engine.functions:
        return Error(
            Failure(
                'hook callable not found',
                hook_name=hook_name,
                script_filepath=script_filepath,
                callable_name=hook_callback_name,
            )
        )

    return Ok(engine)
