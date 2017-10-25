# cfssl_refresh_cert #

Get new certificate, key, and bundle from cfssl server.

Suitable for cron:

    0 * * * * cfssl_refresh_cert --config /etc/cfssl_refresh_cert/config.json

