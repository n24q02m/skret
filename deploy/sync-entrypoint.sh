#!/bin/sh
set -eu

exec /usr/local/bin/skret sync plan-server \
    --listen 0.0.0.0:8080 \
    --max-body-bytes 1048576
