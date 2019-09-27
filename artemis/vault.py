import ansible_vault

from typing import Any


class Vault:
    def __init__(self, password):
        # type: (str) -> None

        self._vault = ansible_vault.Vault(password)

    def load(self, filepath):
        # type: (str) -> Any

        with open(filepath, 'rb') as f:
            return self._vault.load(f)
