# Build dev athenz

    $ export HOSTNAME=localhost

    $ docker run -itd -h localhost -p 9443:9443 -p 4443:4443 -p 8443:8443 -e ZMS_SERVER=localhost -e UI_SERVER=localhost --name athenz-server athenz/athenz

Get ca.pem form athenz-server container because the cacert is self certification and there is the cacert in container. Copy the ca.pem to local space.

    $ docker exec -it affectionate_jepsen cat /opt/athenz/athenz-ui-1.7.29/keys/zms_cert.pem
    -----BEGIN CERTIFICATE-----

    <snip>

    -----END CERTIFICATE-----

Add policy for vault authorization.

    $ ./zms-cli -d user.vault -i user.athenz -c ./ca.pem add-policy vault-access grant access to user.athenz on 'vault'
