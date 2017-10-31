#!/usr/bin/env python

from setuptools import setup, find_packages

setup(
    name="cfssl_refresh_cert",
    version="0.2.20171031",
    packages=find_packages(),
    install_requires=[
        "requests",
        "click",
        "pytest",
        "pytest-cov",
        "mock",
        "requests-mock"
    ],
    description="Get new certificate, key, and bundle from cfssl server",
    url="http://github.com/venasolutions/cfssl_refresh_cert",
    py_modules=['cfssl_refresh_cert'],
    entry_points={
        'console_scripts': [
            "cfssl_refresh_cert = cfssl_refresh_cert:cfssl_refresh_cert_cli"
        ]
    }
)
