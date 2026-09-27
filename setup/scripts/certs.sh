#!/usr/bin/env bash
# Step 1 (before Elasticsearch starts): local CA, service certs, rendered kibana.yml.
# Idempotent: existing CA and certs are kept so enrolled agents keep trusting the box.
export STEP=certs
# shellcheck source=common.sh
source /setup/common.sh

: "${HOST_IP:?HOST_IP must be set (run ./moat init)}"
HOST_NAME=${HOST_NAME:-moat.local}

mkdir -p /certs/ca /certs/public /config

# keyUsage is required on a CA by strict RFC 5280 verifiers (Python 3.13+, among others).
CA_SUBJ="/O=moat/CN=moat local CA"
CA_KU="keyUsage=critical,keyCertSign,cRLSign"
if [[ ! -f /certs/ca/ca.key ]]; then
  log "creating local CA"
  openssl req -x509 -new -nodes -newkey rsa:4096 -sha256 -days 3650 -subj "$CA_SUBJ" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "$CA_KU" \
    -keyout /certs/ca/ca.key -out /certs/ca/ca.crt 2>/dev/null
elif ! openssl x509 -in /certs/ca/ca.crt -noout -ext keyUsage 2>/dev/null | grep -q 'Certificate Sign'; then
  # Older moat CAs lack keyUsage. Re-issue the CA *certificate* with the same key and
  # subject: every cert it signed, and every agent that trusts it, keeps working. Only
  # the fingerprint changes, and it is re-rendered into kibana.yml below.
  log "re-issuing CA certificate with keyUsage (same key; existing trust is kept)"
  cp /certs/ca/ca.crt /certs/ca/ca.crt.pre-keyusage
  openssl req -x509 -new -key /certs/ca/ca.key -sha256 -days 3650 -subj "$CA_SUBJ" \
    -addext "basicConstraints=critical,CA:TRUE" -addext "$CA_KU" -out /certs/ca/ca.crt 2>/dev/null
fi

issue() { # issue NAME DNS1,DNS2,...
  local name=$1 dns=$2 dir=/certs/$1
  [[ -f $dir/$name.crt ]] && { log "cert for $name exists"; return; }
  mkdir -p "$dir"
  local san="IP:${HOST_IP},IP:127.0.0.1"
  IFS=, read -ra names <<<"$dns"
  for n in "${names[@]}"; do san+=",DNS:$n"; done
  log "issuing cert for $name ($san)"
  openssl req -new -nodes -newkey rsa:2048 -subj "/O=moat/CN=$name" \
    -keyout "$dir/$name.key" -out "$dir/$name.csr" 2>/dev/null
  openssl x509 -req -in "$dir/$name.csr" -CA /certs/ca/ca.crt -CAkey /certs/ca/ca.key \
    -CAcreateserial -days 825 -sha256 -out "$dir/$name.crt" \
    -extfile <(printf 'subjectAltName=%s\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,clientAuth\n' "$san") 2>/dev/null
  rm -f "$dir/$name.csr"
}

issue es01         "es01,localhost,${HOST_NAME}"
issue kibana       "kibana,localhost,${HOST_NAME}"
issue fleet-server "fleet-server,localhost,${HOST_NAME}"

# ES must present leaf + CA: agents trust it via the output's ca_trusted_fingerprint,
# which only matches certificates the server actually sends. Rebuilt every run so
# existing installs pick it up.
cat /certs/es01/es01.crt /certs/ca/ca.crt > /certs/es01/es01.chain.crt

# Public copy of the CA cert, served by Caddy for agent enrollment. Never the key.
cp /certs/ca/ca.crt /certs/public/ca.crt

CA_FINGERPRINT=$(openssl x509 -in /certs/ca/ca.crt -noout -fingerprint -sha256 \
  | cut -d= -f2 | tr -d ':' | tr 'A-F' 'a-f')
echo "$CA_FINGERPRINT" > /certs/public/ca.sha256
export CA_FINGERPRINT HOST_IP HOST_NAME
export FLEET_PORT=${FLEET_PORT:-8220} ES_PORT=${ES_PORT:-9200}
# The address people use to reach Kibana (links in Kibana, IRIS alerts, ...). Set
# KIBANA_PUBLIC_URL in .env when that's not the LAN IP, e.g. a Tailscale name.
PUBLIC_URL="https://${HOST_IP}"
[[ ${KIBANA_PORT:-443} == 443 ]] || PUBLIC_URL+=":${KIBANA_PORT}"
[[ -n ${KIBANA_PUBLIC_URL:-} ]] && PUBLIC_URL=${KIBANA_PUBLIC_URL%/}
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
