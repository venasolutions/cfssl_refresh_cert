#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name = "cfssl_refresh_cert",
    version = "0.1.20171025",
    packages = find_packages(),
    install_requires = [
        "requests",
        "click"
    ],
    description = "Get new certificate, key, and bundle from cfssl server",
    url = "http://github.com/jmpesp/cfssl_refresh_cert",
    py_modules=['cfssl_refresh_cert'],
    entry_points = {
        'console_scripts': [
            "cfssl_refresh_cert = cfssl_refresh_cert:cfssl_refresh_cert"
        ]
    }
)
