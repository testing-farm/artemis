import os.path

from typing import cast, Dict
from .vault import Vault


def _key_filepath(config_root, owner, name):
    # type: (str, str, str) -> str

    return os.path.join(config_root, owner, '{}.yaml'.format(name))


class Key:
    def __init__(self, store, owner, name):
        # type: (KeyStore, str, str) -> None

        self.store = store

        self.owner = owner
        self.name = name

    @property
    def _data(self):
        # type: () -> Dict[str, str]

        return cast(
            Dict[str, str],
            self.store.vault.load(_key_filepath('', self.owner, self.name))
        )

    @property
    def private(self):
        # type: () -> str

        return self._data['private']

    @property
    def public(self):
        # type: () -> str

        return self._data['public']


class KeyStore:
    def __init__(self, vault):
        # type: (Vault) -> None

        self.vault = vault

    def get_key(self, owner, name):
        # type: (str, str) -> Key

        return Key(self, owner, name)
