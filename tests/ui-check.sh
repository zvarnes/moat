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

# Viewing isn't enough: analysts must be able to change alert status (close/acknowledge).
# Status changes write to the concrete .internal.alerts-* index, which the role must cover.
# No-op update (open -> open) so the check never changes data.
if [[ $user == analyst ]]; then
  res=$(printf 'user = "analyst:%s"\n' "$pass" | docker compose --env-file .env exec -T kibana \
    curl -sS --cacert /certs/ca/ca.crt -K - -H kbn-xsrf:moat -H elastic-api-version:2023-10-31 \
    -H Content-Type:application/json -X POST https://localhost:5601/api/detection_engine/signals/status \
    -d '{"status":"open","conflicts":"proceed","query":{"term":{"kibana.alert.workflow_status":"open"}}}')
  if grep -q '"failures":\[\]' <<<"$res" && ! grep -q security_exception <<<"$res"; then
    echo "ok   alert status update allowed for analyst"
  else
    echo "FAIL analyst cannot update alert status: ${res:0:200}"; exit 1
  fi
fi
