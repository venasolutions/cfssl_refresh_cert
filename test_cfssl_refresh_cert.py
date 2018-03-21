#!/usr/bin/env python


import json
import base64

import mock
import requests
import requests_mock
from click.testing import CliRunner

from cfssl_refresh_cert import CFSSLRefreshCert, cfssl_refresh_cert_cli


def test_cfssl_config_read():
    """Test reading json configuration from a file."""
    refresher = CFSSLRefreshCert()
    d = {
        "cfssl": {
            "url": "http://127.0.0.1:8888",
            "request": {
                "CN": "testpost",
            }
        },
        "output": {
            "cert": "server.pem",
            "key": "server-key.pem"
        }
    }

    m = mock.mock_open(read_data=json.dumps(d))
    with mock.patch("cfssl_refresh_cert.open", m, create=True):
        refresher.read_config_from_file("fake.json")

    assert refresher.config == d


def test_cfssl_ok():
    """Test successful certificate refresh."""
    refresher = CFSSLRefreshCert()
    refresher.config = {
        "cfssl": {
            "url": "http://127.0.0.1:8888",
            "request": {
                "CN": "testpost",
            }
        },
        "output": {
            "cert": "server.pem",
            "key": "server-key.pem"
        }
    }

    with requests_mock.mock() as m:
        json_response = {
            "result": {
                "certificate": "cfssl cert",
                "private_key": "cfssl key",
            }
        }
        m.post("http://127.0.0.1:8888/api/v1/cfssl/newcert",
               json=json_response)

        refresher._write_out_cert_files = mock.MagicMock()

        result = refresher.refresh_cert_and_key()
        assert result

        # assert POST body is correct
        assert len(m.request_history) == 1
        assert m.request_history[0].method == 'POST'
        assert m.request_history[0].url == \
            "http://127.0.0.1:8888/api/v1/cfssl/newcert"
        assert m.request_history[0].text == \
            json.dumps({"request": {"CN": "testpost"}})

        # assert data is correctly written
        refresher._write_out_cert_files.assert_called_with("cfssl cert",
                                                           "cfssl key")


def test_cfssl_ok_with_profile():
    """Test successful certificate refresh (non-standard profile)."""
    refresher = CFSSLRefreshCert()
    refresher.config = {
        "cfssl": {
            "url": "http://127.0.0.1:8888",
            "request": {
                "CN": "testpost",
            },
            "profile": "non-standard",
        },
        "output": {
            "cert": "server.pem",
            "key": "server-key.pem"
        }
    }

    with requests_mock.mock() as m:
        json_response = {
            "result": {
                "certificate": "cfssl cert",
                "private_key": "cfssl key",
            }
        }
        m.post("http://127.0.0.1:8888/api/v1/cfssl/newcert",
               json=json_response)

        refresher._write_out_cert_files = mock.MagicMock()

        result = refresher.refresh_cert_and_key()
        assert result

        # assert POST body is correct
        assert len(m.request_history) == 1
        assert m.request_history[0].text == \
            json.dumps({"request": {"CN": "testpost"}, "profile":
                    "non-standard"})


def test_cfssl_bad_post():
    """Test unsuccessful certificate refresh."""
    refresher = CFSSLRefreshCert()
    refresher.config = {
        "cfssl": {
            "url": "http://127.0.0.1:8888",
            "request": {
                "CN": "testpost",
            }
        },
        "output": {
            "cert": "server.pem",
            "key": "server-key.pem"
        }
    }

    with requests_mock.mock() as m:
        m.post("http://127.0.0.1:8888/api/v1/cfssl/newcert",
               exc=requests.exceptions.ConnectTimeout)

        refresher._write_out_cert_files = mock.MagicMock()

        result = refresher.refresh_cert_and_key()
        assert not result

        # assert POST body is correct
        assert len(m.request_history) == 1
        assert m.request_history[0].method == 'POST'
        assert m.request_history[0].url == \
            "http://127.0.0.1:8888/api/v1/cfssl/newcert"
        assert m.request_history[0].text == \
            json.dumps({"request": {"CN": "testpost"}})

        # assert data is never written
        assert not refresher._write_out_cert_files.called


def test_cfssl_ok_with_auth():
    """Test using HTTP auth when refreshing certificate."""
    refresher = CFSSLRefreshCert()
    refresher.config = {
        "cfssl": {
            "url": "http://127.0.0.1:8888",
            "auth": {
                "user": "cfssluser",
                "password": "cfsslpasswd"
            },
            "request": {
                "CN": "testpost",
            }
        },
        "output": {
            "cert": "server.pem",
            "key": "server-key.pem"
        }
    }

    with requests_mock.mock() as m:
        json_response = {
            "result": {
                "certificate": "cfssl cert",
                "private_key": "cfssl key",
            }
        }
        m.post("http://127.0.0.1:8888/api/v1/cfssl/newcert",
               json=json_response)

        refresher._write_out_cert_files = mock.MagicMock()

        result = refresher.refresh_cert_and_key()
        assert result

        # assert POST body is correct
        assert len(m.request_history) == 1
        assert m.request_history[0].method == 'POST'
        assert m.request_history[0].url == \
            "http://127.0.0.1:8888/api/v1/cfssl/newcert"
        assert m.request_history[0].text == \
            json.dumps({"request": {"CN": "testpost"}})
        assert "authorization" in m.request_history[0]._request.headers
        basic_auth = "Basic {}".format(
            base64.b64encode("{}:{}".format("cfssluser", "cfsslpasswd")))
        assert m.request_history[0]._request.headers["authorization"] == \
            basic_auth

        # assert data is correctly written
        refresher._write_out_cert_files.assert_called_with("cfssl cert",
                                                           "cfssl key")


def test_cfssl_writes():
    """Test that CFSSLRefreshCert writes out the proper files."""
    refresher = CFSSLRefreshCert()
    refresher.config = {
        "output": {
            "cert": "server.pem",
            "key": "server-key.pem"
        }
    }

    mocked_open = mock.mock_open()
    mocked_os = mock.MagicMock()

    with mock.patch("cfssl_refresh_cert.open", mocked_open, create=True), \
            mock.patch("cfssl_refresh_cert.os", mocked_os):
        refresher._write_out_cert_files("cert", "key")

    mocked_open.assert_has_calls([mock.call("server.pem", "w"),
                                  mock.call().write("cert"),
                                  mock.call().__exit__(None, None, None),
                                  mock.call("server-key.pem", "w"),
                                  mock.call().write("key"),
                                  mock.call().__exit__(None, None, None)],
                                 any_order=True)

    mocked_os.assert_has_calls([mock.call.chmod("server-key.pem", 0600)])


def test_get_machine_info_ok():
    """Test grabbing machine info from socket package and ipify."""
    refresher = CFSSLRefreshCert()

    with mock.patch("cfssl_refresh_cert.socket") as mock_socket:
        mock_socket_obj = mock.Mock()
        mock_socket.socket.return_value = mock_socket_obj

        mock_socket.gethostname.return_value = "host1"
        mock_socket_obj.getsockname.return_value = ["private"]

        with requests_mock.mock() as m:
            m.get("https://api.ipify.org", text="public")

            machine_info = refresher._get_machine_info()

            assert machine_info == ("host1", "private", "public")


def test_post_to_slack():
    """Validate the JSON POST to Slack."""
    refresher = CFSSLRefreshCert()
    refresher.config = {
        "onfailure": {
            "post_to_slack": {
                "token": "abcd",
                "channel": "alerts",
            },
        },
    }

    with requests_mock.mock() as m:
        m.post("https://hooks.slack.com/services/abcd")

        refresher._get_machine_info = \
            mock.Mock(return_value=["host", "private", "public"])

        refresher._post_to_slack("testpost", ["line1", "line2"])

        # assert POST body is correct
        assert len(m.request_history) == 1

        assert m.request_history[0].method == 'POST'
        assert m.request_history[0].url == \
            "https://hooks.slack.com/services/abcd"

        request_json_body = json.loads(m.request_history[0].text)

        assert request_json_body["channel"] == "alerts"
        assert request_json_body["text"] == "\n".join([
            "*testpost*",
            "hostname: host",
            "private ip: private",
            "public ip: public",
            "line1",
            "line2"
        ])


def test_post_to_slack_on_refresh_fail():
    """Test that a Slack message is sent when configured and refresh fails."""
    refresher = CFSSLRefreshCert()
    refresher.config = {
        "cfssl": {
            "url": "http://127.0.0.1:8888",
            "request": {
                "CN": "testpost",
            }
        },
        "onfailure": {
            "post_to_slack": {
                "token": "abcd",
                "channel": "alerts",
            },
        },
        "output": {
            "cert": "server.pem",
            "key": "server-key.pem"
        }
    }

    with requests_mock.mock() as m:
        m.post("http://127.0.0.1:8888/api/v1/cfssl/newcert",
               exc=requests.exceptions.ConnectTimeout)

        refresher._write_out_cert_files = mock.MagicMock()
        refresher._post_to_slack = mock.MagicMock()

        result = refresher.refresh_cert_and_key()
        assert not result

        # assert POST body is correct
        assert len(m.request_history) == 1

        assert m.request_history[0].method == 'POST'
        assert m.request_history[0].url == \
            "http://127.0.0.1:8888/api/v1/cfssl/newcert"
        assert m.request_history[0].text == \
            json.dumps({"request": {"CN": "testpost"}})

        refresher._post_to_slack.assert_called_with(
            "cfssl refresh failed!", mock.ANY
        )


def test_post_to_slack_on_execute_command_fail():
    """Test that a Slack message is sent when configured and command fails."""
    refresher = CFSSLRefreshCert()
    refresher.config = {
        "cfssl": {
            "url": "http://127.0.0.1:8888",
            "request": {
                "CN": "testpost",
            }
        },
        "onfailure": {
            "post_to_slack": {
                "token": "abcd",
                "channel": "alerts",
            },
        },
        "onsuccess": {
            "execute_command": "dmesg",
        },
        "output": {
            "cert": "server.pem",
            "key": "server-key.pem"
        }
    }

    with requests_mock.mock() as m:
        json_response = {
            "result": {
                "certificate": "cfssl cert",
                "private_key": "cfssl key",
            }
        }
        m.post("http://127.0.0.1:8888/api/v1/cfssl/newcert",
               json=json_response)

        refresher._write_out_cert_files = mock.MagicMock()
        refresher._post_to_slack = mock.MagicMock()

        with mock.patch("subprocess.Popen") as mock_subprocess:
            mock_child = mock.Mock()
            mock_subprocess.return_value = mock_child
            mock_child.communicate = mock.Mock(return_value=["out", "err"])
            mock_child.returncode = 1

            result = refresher.refresh_cert_and_key()
            assert not result

        # assert POST body is correct
        assert len(m.request_history) == 1

        assert m.request_history[0].method == 'POST'
        assert m.request_history[0].url == \
            "http://127.0.0.1:8888/api/v1/cfssl/newcert"
        assert m.request_history[0].text == \
            json.dumps({"request": {"CN": "testpost"}})

        refresher._post_to_slack.assert_called_with(
            "post cfssl refresh execute command failed!",
            mock.ANY
        )

def test_ca_bundle():
    """Test successful certificate refresh."""
    refresher = CFSSLRefreshCert()
    refresher.config = {
        "cfssl": {
            "url": "http://127.0.0.1:8888",
            "request": {
                "CN": "testpost",
            },
            "ca_bundle" : "/etc/ssl/certs/ca-certificates.crt"
        },
        "output": {
            "cert": "server.pem",
            "key": "server-key.pem"
        }
    }

    with requests_mock.mock() as m:
        json_response = {
            "result": {
                "certificate": "cfssl cert",
                "private_key": "cfssl key",
            }
        }
        m.post("http://127.0.0.1:8888/api/v1/cfssl/newcert",
               json=json_response)

        refresher._write_out_cert_files = mock.MagicMock()

        result = refresher.refresh_cert_and_key()
        assert result

        # assert POST body is correct
        assert len(m.request_history) == 1
        assert m.request_history[0].method == 'POST'
        assert m.request_history[0].url == \
            "http://127.0.0.1:8888/api/v1/cfssl/newcert"
        assert m.request_history[0].text == \
            json.dumps({"request": {"CN": "testpost"}})

        # assert data is correctly written
        refresher._write_out_cert_files.assert_called_with("cfssl cert",
                                                           "cfssl key")
        req = m.request_history[0]
        assert req.verify == "/etc/ssl/certs/ca-certificates.crt"

def test_cfssl_cli_ok():
    """Test click functionality with successful refresh."""
    with mock.patch("cfssl_refresh_cert.CFSSLRefreshCert") as m:
        runner = CliRunner()
        result = runner.invoke(cfssl_refresh_cert_cli,
                               ["--config", "fake.json"])
        assert result.exit_code == 0

        m.assert_has_calls([mock.call().read_config_from_file("fake.json"),
                            mock.call().refresh_cert_and_key()],
                           any_order=False)


def test_cfssl_cli_bad():
    """Test click functionality with unsuccessful refresh."""
    with mock.patch("cfssl_refresh_cert.CFSSLRefreshCert") as m:
        runner = CliRunner()

        mock_object = m.return_value
        mock_object.refresh_cert_and_key.return_value = False

        result = runner.invoke(cfssl_refresh_cert_cli,
                               ["--config", "fake.json"])
        assert result.exit_code != 0

        m.assert_has_calls([mock.call().read_config_from_file("fake.json"),
                            mock.call().refresh_cert_and_key()],
                           any_order=False)
