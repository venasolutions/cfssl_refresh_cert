#!/usr/bin/env python

import json
import os
import socket
import requests
import click
import subprocess
import shlex


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
        d = None

        if "post_body" in self.config["cfssl"]:
            d = self.config["cfssl"]["post_body"]
        else:
            d = {
                "request": self.config["cfssl"]["request"]
            }

        url = "{}/api/v1/cfssl/newcert".format(self.config["cfssl"]["url"])

        kwargs = {}

        if "auth" in self.config["cfssl"]:
            kwargs["auth"] = (self.config["cfssl"]["auth"]["user"],
                              self.config["cfssl"]["auth"]["password"])

        if "ca_bundle" in self.config["cfssl"]:
            kwargs["verify"] = self.config["cfssl"]["ca_bundle"]

        try:
            resp = requests.post(url, json=d, **kwargs)
            resp.raise_for_status()
        except requests.exceptions.RequestException as e:
            print "cfssl refresh failed! {}".format(e)

            if "onfailure" in self.config:
                if "post_to_slack" in self.config["onfailure"]:

                    msg_lines = [
                        "exception: `{}`".format(e),
                        "request:",
                        "```",
                        "{}".format(
                            json.dumps(self.config["cfssl"]["request"],
                                       indent=2)),
                        "```"
                        ]

                    self._post_to_slack("cfssl refresh failed!", msg_lines)

            return False

        r = resp.json()

        self._write_out_cert_files(r["result"])

        if "onsuccess" in self.config:
            if "execute_command" in self.config["onsuccess"]:
                args = shlex.split(
                    self.config["onsuccess"]["execute_command"]
                )

                child = subprocess.Popen(args, stdout=subprocess.PIPE,
                                         stderr=subprocess.PIPE)
                stdout, stderr = child.communicate()

                if child.returncode != 0:
                    if "onfailure" in self.config:
                        if "post_to_slack" in self.config["onfailure"]:
                            msg_lines = [
                                "args: `{}`".format(args),
                                "rc: {}".format(child.returncode),
                                "stdout: `{}`".format(stdout.strip()),
                                "stderr: `{}`".format(stderr.strip()),
                                ]

                            self._post_to_slack(
                                "post cfssl refresh execute command failed!",
                                msg_lines)

                    return False

        return True

    def _write_out_cert_files(self, result):
        if "bundle" in self.config["output"]:
            with open(self.config["output"]["bundle"], "w") as fp:
                fp.write(result["bundle"])

        with open(self.config["output"]["cert"], "w") as fp:
            fp.write(result["certificate"])

        with open(self.config["output"]["key"], "w") as fp:
            fp.write(result["private_key"])

        os.chmod(self.config["output"]["key"], 0600)

    def _get_machine_info(self):
        """Return hostname, private IP, and public IP."""
        hostname = socket.gethostname()

        # Grab the IP used to connect to 8.8.8.8
        #
        # Use this instead of `socket.gethostbyname(socket.getfqdn())`, because
        # that can be affected by entries in /etc/hosts.
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        private_ip_addr = s.getsockname()[0]
        s.close()

        # Ask a public entity what IP is connecting to it.
        public_ip_addr = None
        resp = requests.get("https://api.ipify.org")
        if resp.status_code == 200:
            public_ip_addr = resp.text

        return hostname, private_ip_addr, public_ip_addr

    def _post_to_slack(self, title, message_lines):
        """Assuming Slack is in our configuration, post a message there."""
        slack_config = self.config["onfailure"]["post_to_slack"]
        url = "https://hooks.slack.com/services/{}"
        url = url.format(slack_config["token"])

        hostname, private_ip, public_ip = self._get_machine_info()

        standard_info = [
            "*{}*".format(title),
            "hostname: {}".format(hostname),
            "private ip: {}".format(private_ip),
            "public ip: {}".format(public_ip),
            ]

        message_text = "\n".join(standard_info + message_lines)

        post_body = {
            "channel": slack_config["channel"],
            "text": message_text,
        }

        headers = {
            "Content-Type": "application/json",
        }

        resp = requests.post(url, json=post_body, headers=headers)
        resp.raise_for_status()


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
