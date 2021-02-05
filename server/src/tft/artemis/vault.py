from typing import Any

import ansible_vault


# Workaround a nasty issue in ansible-vault package: compares Ansible versions
# by comparing floats, and `2.4` is just bigger than `2.10`...
#
# https://github.com/tomoh1r/ansible-vault/pull/34
class CustomVault(ansible_vault.Vault):  # type: ignore
    def _make_secrets(self, secret: str) -> Any:
        from ansible.constants import DEFAULT_VAULT_ID_MATCH  # type: ignore
        from ansible.parsing.vault import VaultSecret  # type: ignore

        return [(DEFAULT_VAULT_ID_MATCH, VaultSecret(secret))]


class Vault:
    """
    Provides access to encrypted data - SSH keys, passwords, etc.
    """

    def __init__(self, password: str) -> None:
        self._vault = CustomVault(password.strip())

    def load(self, filepath: str) -> Any:
        with open(filepath, 'rb') as f:
            return self._vault.load(f.read())
