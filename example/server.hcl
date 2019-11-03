log_level = "DEBUG"
api_addr = "http://127.0.0.1:8200"
plugin_directory = "/tmp/vault/plugin"
disable_mlock = true

storage "inmem" {}

listener "tcp" {
  address       = "0.0.0.0:8200"
  tls_disable = 1
}
