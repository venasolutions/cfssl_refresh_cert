#!/usr/bin/env python

import json
import requests
import click

@click.command()
@click.option("--config",
              help="json configuration file",
              required=True)
def cfssl_refresh_cert(config):
    """Get new certificate and key from cfssl server."""
    with open(config) as fp:
        config = json.load(fp)

    d = {
        "request": config["cfssl"]["request"]
    }

    url = "{}/api/v1/cfssl/newcert".format(config["cfssl"]["url"])

    resp = requests.post(url, json=d)
    resp.raise_for_status()

    r = resp.json()

    with open(config["output"]["cert"], "w") as fp:
        fp.write(r["result"]["certificate"])

    with open(config["output"]["key"], "w") as fp:
        fp.write(r["result"]["private_key"])

