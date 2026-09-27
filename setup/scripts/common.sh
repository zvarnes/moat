#!/usr/bin/env bash
# Shared helpers for moat setup containers.
set -euo pipefail

CA=/certs/ca/ca.crt
ES_URL=${ES_URL:-https://es01:9200}
KIBANA_URL=${KIBANA_URL:-https://kibana:5601}

log() { printf '[moat:%s] %s\n' "${STEP:-setup}" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

# Credentials and request bodies never go on curl's command line: container processes
# are visible in the host's `ps`. Credentials come from a curl config on a file
# descriptor (-K <(...)), bodies from stdin (--data-binary @-).
auth_cfg() { printf 'user = "elastic:%s"\n' "$ELASTIC_PASSWORD"; }

# es METHOD PATH [JSON]  -> prints body, fails on HTTP >= 400
es() {
  local method=$1 path=$2 body=${3:-}
  local args=(-sS --fail-with-body --cacert "$CA" -X "$method"
              -H 'Content-Type: application/json' "${ES_URL}${path}")
  # -K <(...) must sit on the curl command itself: a process substitution only lives
  # for the command it's attached to, so putting it in the array leaves a closed fd.
  if [[ -n $body ]]; then curl -K <(auth_cfg) "${args[@]}" --data-binary @- <<<"$body"
  else curl -K <(auth_cfg) "${args[@]}"; fi
}

# kb METHOD PATH [JSON]  -> Kibana API call as elastic
kb() {
  local method=$1 path=$2 body=${3:-}
  local args=(-sS --fail-with-body --cacert "$CA" -X "$method"
              -H 'Content-Type: application/json' -H 'kbn-xsrf: moat'
              -H 'elastic-api-version: 2023-10-31' "${KIBANA_URL}${path}")
  if [[ -n $body ]]; then curl -K <(auth_cfg) "${args[@]}" --data-binary @- <<<"$body"
  else curl -K <(auth_cfg) "${args[@]}"; fi
}

wait_for() { # wait_for DESCRIPTION CMD...
  local desc=$1; shift
  log "waiting for ${desc}..."
  for _ in $(seq 1 120); do
    if "$@" >/dev/null 2>&1; then log "${desc} is up"; return 0; fi
    sleep 5
  done
  die "timed out waiting for ${desc}"
}
