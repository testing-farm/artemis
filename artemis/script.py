import imp
import os.path

import gluetool.utils

from typing import Any, Dict, Optional


class ScriptEngine:
    def __init__(self) -> None:
        super(ScriptEngine, self).__init__()

        self._scripts: Dict[str, Any] = {}
        self._variables: Dict[str, Any] = {}

    def _load_script_file(self, name: str, filepath: str) -> None:
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

            self._scripts[member_name] = fn

    def _load_variables_file(self, filepath: str) -> None:
        variables = gluetool.utils.load_yaml(filepath)

        if not isinstance(variables, dict):
            raise Exception('Cannot add variables from {}, not a key: value format'.format(filepath))

        self._variables.update(variables)

    def run_script(self, name: str, variables: Optional[Dict[str, Any]] = None) -> Any:
        variables = variables or {}

        kwargs = gluetool.utils.dict_update(
            {},
            self._variables,
            variables
        )

        return self._scripts[name](**kwargs)
