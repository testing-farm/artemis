import os.path

import dataclasses

from typing import cast, Dict
from .vault import Vault


def _key_filepath(store_dirpath, owner, name):
    # type: (str, str, str) -> str

    return os.path.join(store_dirpath, owner, '{}.yaml'.format(name))


class KeyStore:
    def __init__(self, vault, store_dirpath):
        # type: (Vault, str) -> None

        self.vault = vault
        self.store_dirpath = store_dirpath

    def get_key(self, owner, name):
        # type: (str, str) -> Key

        return Key(self, owner, name)


@dataclasses.dataclass
class Key:
    store: KeyStore
    owner: str
    name: str

    def __repr__(self):
        # type: () -> str

        return '<Key: owner={}, name={}>'.format(
            self.owner,
            self.name
        )

    @property
    def _data(self):
        # type: () -> Dict[str, str]

        return cast(
            Dict[str, str],
            self.store.vault.load(_key_filepath(self.store.store_dirpath, self.owner, self.name))
        )

    @property
    def private(self):
        # type: () -> str

        return self._data['private']

    @property
    def public(self):
        # type: () -> str

        return self._data['public']
