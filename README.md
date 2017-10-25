# cfssl_refresh_cert #

Get new certificate and key from cfssl server.

Suitable for cron:

    0 * * * * cfssl_refresh_cert --config /etc/cfssl_refresh_cert/config.json

Example config.json:

    {
      "cfssl": {
        "url": "http://127.0.0.1:8888",
        "request": {
          "names": [
            {
              "C": "Canada",
              "ST": "Ontario",
              "L": "Toronto",
              "O": "Fake org."
            }
          ],
          "CN": "testpost",
          "hosts": [
            "testpost.com"
          ],
          "expiry": "876000h"
        }
      },
      "output": {
        "cert": "server.pem",
        "key": "server-key.pem"
      }
    }
