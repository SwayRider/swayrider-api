#!/bin/sh
set -e

CREDS_FILE="/credentials/swayrider-api.env"
if [ -f "$CREDS_FILE" ]; then
    # shellcheck disable=SC2046
    export $(grep -v '^#' "$CREDS_FILE" | xargs)
else
    echo "ERROR: credentials file not found at $CREDS_FILE" >&2
    exit 1
fi

exec /app/swayrider-api "$@"
