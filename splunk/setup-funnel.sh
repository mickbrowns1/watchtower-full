#!/bin/sh
# Re-applies the Funnel config for the local Splunk HEC endpoint.
# Idempotent - safe to run any time, e.g. after ts-splunk loses its
# Tailscale state (fresh tailscale-data volume, new node identity, etc).
#
# Splunk's HEC on :8088 requires TLS (enableSSL=1), so the backend proxy
# target must be https+insecure (self-signed cert) - plain http:// here
# causes every Funnel request to fail with a 502.

set -e

docker exec ts-splunk tailscale funnel --bg --https=443 https+insecure://localhost:8088

echo
docker exec ts-splunk tailscale funnel status
