#! /bin/bash
#
# setup_plugin.sh
# Copyright (C) 2019 zivx <pupupu0701@gmail.com>
#
# Distributed under terms of the MIT license.
#

set -ue -o pipefail

VAULT_PATH="athenz"
BIN_NAME="vault-plugin-auth-athenz"
SHA256_PREFIX="sha256sum"
PLUGIN_DIR="/private/tmp/vault/plugin/"
CONFIG_FILE_PATH="/private/tmp/vault/plugin/athenz_plugin.yaml"

unameOut=$(uname -s)
case "${unameOut}" in
  Linux*)
    SHA256_PREFIX="sha256sum";;

  Darwin*)
    SHA256_PREFIX="shasum -a 256";;
esac

# build
echo "[+] prepare ----"
if [ ! -e $PLUGIN_DIR ]; then
  mkdir -p $PLUGIN_DIR
fi

if [ -e "$PLUGIN_DIR/$BIN_NAME" ]; then
  rm $PLUGIN_DIR/$BIN_NAME
fi

if [ ! -e "../cmd/$BIN_NAME" ]; then
  make build
fi

cp ../target/"${unameOut,,}"/$BIN_NAME $PLUGIN_DIR/$BIN_NAME
cp /Users/katyamag/Documents/vault_sandbox/athenz_plugin.yaml $CONFIG_FILE_PATH


# disable and delete plugin
echo "[+] disable and delete ----"
vault auth disable $VAULT_PATH
vault delete /sys/plugins/catalog/auth/$VAULT_PATH

# register plugin
echo "[+] register -----"
SHA256=$(${SHA256_PREFIX} "${PLUGIN_DIR}/${BIN_NAME}"| cut -d' ' -f1);
vault write sys/plugins/catalog/auth/$VAULT_PATH sha_256="$SHA256" args="$CONFIG_FILE_PATH" command="$BIN_NAME"

# enable plugin
echo "[+] enable plugin -----"
vault auth enable -path="$VAULT_PATH" -plugin-name="$VAULT_PATH" -options="--config-file=${CONFIG_FILE_PATH}" plugin
