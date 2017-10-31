#!/usr/bin/env python

import json
import os
import requests
import click


class CFSSLRefreshCert(object):
    """Automate refreshing SSL certificates from a CFSSL server."""
    def __init__(self):
        self.config = None

    def read_config_from_file(self, config_filename):
        """Configure class object using JSON configuration file."""
        with open(config_filename) as filep:
            self.config = json.load(filep)

    def refresh_cert_and_key(self):
        """
        Ask CFSSL server for new cert and key, write to configured paths.

        POSTs to a CFSSL server to retrieve a new certificate and private key.
        Writes those to paths specified in the configuration file.

        Returns true if successful, false if not.
        """
        d = {
            "request": self.config["cfssl"]["request"]
        }

        url = "{}/api/v1/cfssl/newcert".format(self.config["cfssl"]["url"])

        kwargs = {}

        if "auth" in self.config["cfssl"]:
            kwargs["auth"] = (self.config["cfssl"]["auth"]["user"],
                              self.config["cfssl"]["auth"]["password"])

        try:
            resp = requests.post(url, json=d, **kwargs)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            print "cfssl refresh failed! {}".format(e)
            return False

        r = resp.json()

        self._write_out_cert_files(r["result"]["certificate"],
                                   r["result"]["private_key"])

        return True

    def _write_out_cert_files(self, certificate, private_key):
        with open(self.config["output"]["cert"], "w") as fp:
            fp.write(certificate)

        with open(self.config["output"]["key"], "w") as fp:
            fp.write(private_key)

        os.chmod(self.config["output"]["key"], 0600)


@click.command()
@click.option("--config",
              help="json configuration file",
              required=True)
def cfssl_refresh_cert_cli(config):
    """Get new certificate and key from cfssl server."""
    refresher = CFSSLRefreshCert()
    refresher.read_config_from_file(config)
    if not refresher.refresh_cert_and_key():
        exit(1)
