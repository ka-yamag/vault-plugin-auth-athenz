log_level = "DEBUG"
api_addr = "http://127.0.0.1:8200"
plugin_directory = "/private/tmp/vault/plugin"
disable_mlock = true

storage "file" {
  path = "/var/vault"
}

listener "tcp" {
  address       = "127.0.0.1:8200"
  tls_disable = 1
}

telemetry {
  dogstatsd_addr = "localhost:9125"
  disable_hostname = true
}
