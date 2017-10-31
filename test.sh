#!/bin/bash
set -e
py.test -s \
    --cov=cfssl_refresh_cert --cov-report term-missing
