# Example vault plugin on docker

```
$ docker-compose up -d
$ export VAULT_ADDR='http://127.0.0.1:8200'
```

```
$ vault operator init -key-shares=1 -key-threshold=1
```
