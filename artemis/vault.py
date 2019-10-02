import ansible_vault

from typing import Any


class Vault:
    """
    Provides access to encrypted data - SSH keys, passwords, etc.
    """

    def __init__(self, password):
        # type: (str) -> None

        self._vault = ansible_vault.Vault(password.strip())

    def load(self, filepath):
        # type: (str) -> Any

        with open(filepath, 'rb') as f:
            return self._vault.load(f.read())
