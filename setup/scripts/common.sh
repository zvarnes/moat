#!/usr/bin/env bash
# Shared helpers for moat setup containers.
set -euo pipefail

CA=/certs/ca/ca.crt
ES_URL=${ES_URL:-https://es01:9200}
KIBANA_URL=${KIBANA_URL:-https://kibana:5601}

log() { printf '[moat:%s] %s\n' "${STEP:-setup}" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }

# es METHOD PATH [JSON]  -> prints body, fails on HTTP >= 400
es() {
  local method=$1 path=$2 body=${3:-}
  local args=(-sS --fail-with-body --cacert "$CA" -u "elastic:${ELASTIC_PASSWORD}" -X "$method"
              -H 'Content-Type: application/json' "${ES_URL}${path}")
  [[ -n $body ]] && args+=(-d "$body")
  curl "${args[@]}"
}

# kb METHOD PATH [JSON]  -> Kibana API call as elastic
kb() {
  local method=$1 path=$2 body=${3:-}
  local args=(-sS --fail-with-body --cacert "$CA" -u "elastic:${ELASTIC_PASSWORD}" -X "$method"
              -H 'Content-Type: application/json' -H 'kbn-xsrf: moat'
              -H 'elastic-api-version: 2023-10-31' "${KIBANA_URL}${path}")
  [[ -n $body ]] && args+=(-d "$body")
  curl "${args[@]}"
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
