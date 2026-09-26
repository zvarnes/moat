#!/usr/bin/env bash
# Step 1 (before Elasticsearch starts): local CA, service certs, rendered kibana.yml.
# Idempotent: existing CA and certs are kept so enrolled agents keep trusting the box.
export STEP=certs
# shellcheck source=common.sh
source /setup/common.sh

: "${HOST_IP:?HOST_IP must be set (run ./socinabox init)}"
HOST_NAME=${HOST_NAME:-socinabox.local}

mkdir -p /certs/ca /certs/public /config

if [[ ! -f /certs/ca/ca.key ]]; then
  log "creating local CA"
  openssl req -x509 -new -nodes -newkey rsa:4096 -sha256 -days 3650 \
    -subj "/O=socinabox/CN=socinabox local CA" \
    -keyout /certs/ca/ca.key -out /certs/ca/ca.crt 2>/dev/null
fi

issue() { # issue NAME DNS1,DNS2,...
  local name=$1 dns=$2 dir=/certs/$1
  [[ -f $dir/$name.crt ]] && { log "cert for $name exists"; return; }
  mkdir -p "$dir"
  local san="IP:${HOST_IP},IP:127.0.0.1"
  IFS=, read -ra names <<<"$dns"
  for n in "${names[@]}"; do san+=",DNS:$n"; done
  log "issuing cert for $name ($san)"
  openssl req -new -nodes -newkey rsa:2048 -subj "/O=socinabox/CN=$name" \
    -keyout "$dir/$name.key" -out "$dir/$name.csr" 2>/dev/null
  openssl x509 -req -in "$dir/$name.csr" -CA /certs/ca/ca.crt -CAkey /certs/ca/ca.key \
    -CAcreateserial -days 825 -sha256 -out "$dir/$name.crt" \
    -extfile <(printf 'subjectAltName=%s\nextendedKeyUsage=serverAuth,clientAuth\n' "$san") 2>/dev/null
  rm -f "$dir/$name.csr"
}

issue es01         "es01,localhost,${HOST_NAME}"
issue kibana       "kibana,localhost,${HOST_NAME}"
issue fleet-server "fleet-server,localhost,${HOST_NAME}"

# Public copy of the CA cert, served by Caddy for agent enrollment. Never the key.
cp /certs/ca/ca.crt /certs/public/ca.crt

CA_FINGERPRINT=$(openssl x509 -in /certs/ca/ca.crt -noout -fingerprint -sha256 \
  | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
echo "$CA_FINGERPRINT" > /certs/public/ca.sha256
export CA_FINGERPRINT HOST_IP HOST_NAME
export FLEET_PORT=${FLEET_PORT:-8220} ES_PORT=${ES_PORT:-9200}
PUBLIC_URL="https://${HOST_IP}"
[[ ${KIBANA_PORT:-443} == 443 ]] || PUBLIC_URL+=":${KIBANA_PORT}"
export PUBLIC_URL

# shellcheck disable=SC2016  # literal var names for envsubst
# Only substitute our variables; ${SECRET} references stay for Kibana to resolve from its env.
envsubst '${CA_FINGERPRINT} ${HOST_IP} ${FLEET_PORT} ${ES_PORT} ${PUBLIC_URL}' \
  < /setup/templates/kibana.yml > /config/kibana.yml

# Services run as uid 1000; keys readable by them, CA key root-only.
chown -R 1000:0 /certs /config
chown 0:0 /certs/ca/ca.key
chmod 600 /certs/ca/ca.key
find /certs -name '*.key' ! -path '/certs/ca/*' -exec chmod 640 {} +
log "done (CA sha256 ${CA_FINGERPRINT})"
