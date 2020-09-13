#!/bin/bash

VAULT_PASSWORD_FILE='.vault_pass'
VENV_DIR='venv'

virtualenv -p /usr/bin/python3 "$VENV_DIR"
source "$VENV_DIR/bin/activate"

pip3 install -U pip setuptools
pip3 install -U pyyaml j2cli ansible-vault

# generate configs
"$VENV_DIR/bin/j2" server.yml.j2 env.yml > server.yml
"$VENV_DIR/bin/j2" master-key.yaml.j2 env.yml > master-key.yaml

# enter vault password
read -p 'Vault password (will be saved in .vault_pass file): ' vault_password
echo "$vault_password" > "$VAULT_PASSWORD_FILE"
ansible-vault encrypt master-key.yaml --vault-password-file "$VAULT_PASSWORD_FILE"

# cleanup
rm -r "$VENV_DIR"
