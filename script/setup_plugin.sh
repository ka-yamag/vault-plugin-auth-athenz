#!/bin/sh

set -ue -o pipefail

VAULT_PATH="athenz"
BIN_NAME="vault-plugin-auth-athenz"

if [ "$1" = "build" ]; then
  SHA256_PREFIX="sha256sum"
  PLUGIN_DIR="/tmp/vault/plugin/"
  CONFIG_FILE_PATH="/tmp/vault/plugin/athenz_plugin.yaml"
  go build $GOPATH/src/github.com/katyamag/${BIN_NAME}/cmd/${BIN_NAME}
  mv vault-plugin-auth-athenz $PLUGIN_DIR
fi

# unameOut=$(uname -s)
# case "${unameOut}" in
#   Linux*)
#     SHA256_PREFIX="sha256sum"
#     PLUGIN_DIR="${GOBIN}"
#     CONFIG_FILE_PATH="/tmp/vault/plugin/athenz_plugin.yaml"
#     go get github.com/katyamag/vault-plugin-auth-athenz/cmd/vault-plugin-auth-athenz;;

#   Darwin*)
#     SHA256_PREFIX="shasum -a 256"
#     PLUGIN_DIR="/private/tmp/vault/plugin"
#     CONFIG_FILE_PATH="${GOPATH}/src/ghe.corp.yahoo.co.jp/katyamag/vault-plugin-auth-athenz/athenz_plugin.yaml"

#     if [ ! -e $PLUGIN_DIR ]; then
#       mkdir -p $PLUGIN_DIR
#     fi

#     if [ -e $PLUGIN_DIR/$BIN_NAME ]; then
#       rm $PLUGIN_DIR/$BIN_NAME
#     fi

#     echo "[+] build go binary ----"
#     cd ../cmd/$BIN_NAME
#     go build
#     mv $BIN_NAME $PLUGIN_DIR;;
# esac

# disable and delete plugin
echo "[+] disable and delete ----"
vault auth disable $VAULT_PATH
vault delete /sys/plugins/catalog/auth/$VAULT_PATH

# kill plugin process
# echo "[+] kill vault-plugin -----"
# pkill -9 $BIN_NAME

# cp $PLUGIN_DIR/$BIN_NAME ../vault/plugin/

# register plugin
echo "[+] register -----"
# SHA256=$(${SHA256_PREFIX} "${PLUGIN_DIR}/${BIN_NAME}"| cut -d' ' -f1);
# LOCAL
SHA256=$(${SHA256_PREFIX} "${PLUGIN_DIR}/${BIN_NAME}"| cut -d' ' -f1);
vault write sys/plugins/catalog/auth/$VAULT_PATH sha_256=$SHA256 args=$CONFIG_FILE_PATH command=$BIN_NAME

# enable plugin
echo "[+] enable -----"
vault auth enable -path=$VAULT_PATH -plugin-name=$VAULT_PATH -options="--config-file=${CONFIG_FILE_PATH}" plugin
