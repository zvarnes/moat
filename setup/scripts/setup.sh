#!/usr/bin/env bash
# Step 2 (Elasticsearch up, before Kibana): built-in passwords and Fleet Server token.
export STEP=setup
# shellcheck source=common.sh
source /setup/common.sh

wait_for "Elasticsearch" es GET /_cluster/health

log "setting kibana_system password"
es POST /_security/user/kibana_system/_password \
  "{\"password\":\"${KIBANA_SYSTEM_PASSWORD}\"}" >/dev/null

TOKEN_FILE=/tokens/fleet-server.token
if [[ -s $TOKEN_FILE ]] && curl -sf --cacert "$CA" \
     -H "Authorization: Bearer $(cat "$TOKEN_FILE")" "${ES_URL}/_security/_authenticate" >/dev/null; then
  log "fleet-server service token still valid"
else
  log "creating fleet-server service token"
  name="socinabox-$(date +%s)"
  es POST "/_security/service/elastic/fleet-server/credential/token/${name}" \
    | jq -r '.token.value' > "$TOKEN_FILE"
  [[ -s $TOKEN_FILE ]] || die "failed to create service token"
fi
chown 1000:0 "$TOKEN_FILE"
chmod 640 "$TOKEN_FILE"
log "done"
