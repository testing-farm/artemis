#!/bin/bash

VAULT_PASSWORD_FILE='.vault_pass'
VENV_DIR='venv'

virtualenv "$VENV_DIR"
source "$VENV_DIR/bin/activate" && pip3 install pyyaml j2cli

# generate configs
"$VENV_DIR/bin/j2" server.yml.j2 env.yml > server.yml
"$VENV_DIR/bin/j2" master-key.yaml.j2 env.yml > master-key.yaml

# enter vault password
read -p 'Vault password (will be saved in .vault_pass file): ' vault_password
echo "$vault_password" > "$VAULT_PASSWORD_FILE"
ansible-vault encrypt master-key.yaml --vault-password-file "$VAULT_PASSWORD_FILE"

# cleanup
rm -r "$VENV_DIR"
