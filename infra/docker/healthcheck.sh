#!/bin/sh
# Liveness probe for the gateway image.
#
# Targets GET /health (C-022), the documented liveness endpoint, on the port the gateway reads
# from AEGIS_GATEWAY_PORT. The scheme follows the listener: TLS is on when AEGIS_TLS_ENABLED says
# so, or, matching the gateway's own default, when a keystore path is supplied (NFR-021). The
# certificate is not verified because the probe talks to its own loopback listener; it proves the
# process serves requests, not the identity of the peer.
#
# Exit status: 0 when the endpoint answers 2xx, 1 otherwise.

set -u

port="${AEGIS_GATEWAY_PORT:-8443}"
scheme="http"

case "${AEGIS_TLS_ENABLED:-}" in
    true|TRUE|True|1|yes|YES)
        scheme="https"
        ;;
    false|FALSE|False|0|no|NO)
        scheme="http"
        ;;
    *)
        if [ -n "${AEGIS_TLS_KEYSTORE_PATH:-}" ]; then
            scheme="https"
        fi
        ;;
esac

if [ "$scheme" = "https" ]; then
    wget -q -O /dev/null --no-check-certificate "https://127.0.0.1:${port}/health"
else
    wget -q -O /dev/null "http://127.0.0.1:${port}/health"
fi
