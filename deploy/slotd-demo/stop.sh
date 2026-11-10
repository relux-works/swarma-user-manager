#!/bin/sh
# Stop admission/expiry service only; existing slot units and state are retained.
set -eu
exec /usr/bin/systemctl --system --no-ask-password stop -- swarma-slotd-demo.service
