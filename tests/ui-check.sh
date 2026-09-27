#!/usr/bin/env bash
# Render key Kibana pages as a real user in headless Chromium; fails on error callouts.
set -euo pipefail
cd "$(dirname "$0")/.."
set -a
# shellcheck disable=SC1091  # .env is generated per install
source .env
set +a
user=${1:-analyst}
url="https://$HOST_IP:$KIBANA_PORT" script=ui_check.py
case $user in
  analyst) pass=$ANALYST_PASSWORD ;;
  elastic) pass=$ELASTIC_PASSWORD ;;
  iris) user=administrator pass=$IRIS_ADM_PASSWORD url="https://$HOST_IP:${IRIS_PORT:-8443}" script=iris_check.py ;;
  *) echo "usage: $0 [analyst|elastic|iris]" >&2; exit 2 ;;
esac
mkdir -p tests/out
# Password goes in via an env file (not argv) so it doesn't show in ps.
envf=$(mktemp); trap 'rm -f "$envf"' EXIT; chmod 600 "$envf"
printf 'KB=%s\nKU=%s\nKP=%s\n' "$url" "$user" "$pass" > "$envf"
docker run --rm --net=host --env-file "$envf" -v "$PWD/tests:/tests:ro" -v "$PWD/tests/out:/out" \
  mcr.microsoft.com/playwright/python:v1.63.0-noble \
  sh -c 'pip install -q --disable-pip-version-check playwright==1.63.0 >/dev/null 2>&1; python /tests/$0' "$script"
