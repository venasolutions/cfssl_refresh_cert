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

Signing profile can be added to the `cfssl` entry:

    {
      "cfssl": {
        "url": "http://127.0.0.1:8888",
        "request": {
            ...
        },
        "profile": "non-default"
      },
      ...
    }

Add the "auth" entry in cfssl to use HTTP basic auth:

    "auth": {
        "user": "test",
        "password": "passwd"
    },

To post to a Slack channel when cfssl fails to refresh, add a
"onfailure" section with a "post_to_slack" subsection:

    {
      "cfssl": {
        ...
      },
      "onfailure": {
          "post_to_slack": {
              "token": "TOKEN",
              "channel": "alerts"
          }
      },
      "output": {
        ...
      }
    }

To execute a command following a successful certificate refresh, add a
"onsuccess" section with a "execute_command" key:

    {
      "cfssl": {
        ...
      },
      "onfailure": {
          "post_to_slack": {
              "token": "TOKEN",
              "channel": "alerts"
          }
      },
      "onsuccess": {
          "execute_command": "true"
      },
      "output": {
        ...
      }
    }

If onfailure.post_to_slack and onsuccess.execute_command are defined,
then a message will also be posted to Slack if that command fails.

