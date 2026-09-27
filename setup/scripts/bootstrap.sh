#!/usr/bin/env bash
# Step 3 (Kibana up): Fleet setup, Elastic Defend, analyst account, detection rules.
# Safe to re-run: every step checks before creating.
export STEP=bootstrap
# shellcheck source=common.sh
source /setup/common.sh

kibana_ready() { kb GET /api/status | jq -e '.status.overall.level == "available"'; }
wait_for "Kibana" kibana_ready

# --- Single-node replicas ---
# Fleet data streams default to 1 replica, which a single node can't place (cluster
# goes yellow). The *@custom hooks are composed into every logs/metrics/traces
# template, including Elastic Defend's. Don't clobber a user's own @custom template.
for t in logs metrics traces; do
  if es GET "/_component_template/${t}@custom" >/dev/null 2>&1; then
    log "${t}@custom exists, leaving it alone"
  else
    log "creating ${t}@custom (auto_expand_replicas 0-1)"
    es PUT "/_component_template/${t}@custom" \
      '{"template":{"settings":{"index":{"auto_expand_replicas":"0-1"}}},"_meta":{"managed_by":"moat"}}' >/dev/null
  fi
done
# Indices created before the templates existed (upgrades from earlier moat runs).
es PUT "/logs-*,metrics-*,traces-*,.logs-*/_settings?expand_wildcards=all&allow_no_indices=true" \
  '{"index":{"auto_expand_replicas":"0-1"}}' >/dev/null

log "initializing Fleet"
# Preconfiguration problems (e.g. a license-gated setting) come back as nonFatalErrors
# and Kibana then silently skips the affected policy, so treat them as fatal.
errs=$(kb POST /api/fleet/setup | jq -c '.nonFatalErrors // []')
[[ $errs == "[]" ]] || die "Fleet setup reported errors: $errs"
kb GET /api/fleet/agent_policies/fleet-server-policy >/dev/null \
  || die "fleet-server-policy missing after Fleet setup; check kibana.yml preconfiguration"

# --- Elastic Defend on the Endpoints policy ---
if kb GET "/api/fleet/package_policies?perPage=100&kuery=ingest-package-policies.name:defend-endpoints" \
    | jq -e '.total > 0' >/dev/null; then
  log "Elastic Defend already on Endpoints policy"
else
  ver=$(kb GET /api/fleet/epm/packages/endpoint | jq -r '.item.version // .response.version')
  [[ -n $ver && $ver != null ]] || die "could not resolve endpoint package version"
  log "adding Elastic Defend ${ver} (EDR Complete) to Endpoints policy"
  kb POST /api/fleet/package_policies "$(jq -n --arg v "$ver" '{
    name: "defend-endpoints",
    description: "Elastic Defend, EDR Complete preset",
    namespace: "default",
    policy_ids: ["moat-endpoints"],
    enabled: true,
    package: {name: "endpoint", version: $v},
    inputs: [{
      type: "ENDPOINT_INTEGRATION_CONFIG", enabled: true, streams: [],
      config: {_config: {value: {type: "endpoint", endpointConfig: {preset: "EDRComplete"}}}}
    }]}')" >/dev/null
fi

# --- Network retention (Zeek, Suricata, UDM syslog via CEF) ---
# Before the packages are installed, so their first data streams pick it up. The
# <package>@custom hook is composed into every one of the package's index templates.
days=${RETENTION_NETWORK_DAYS:-7}
log "network data retention: ${days} days (ILM policy moat-network)"
es PUT /_ilm/policy/moat-network "$(jq -n --arg d "${days}d" '{policy: {
  phases: {
    hot: {actions: {rollover: {max_age: "1d", max_primary_shard_size: "10gb"}}},
    delete: {min_age: $d, actions: {delete: {}}}
  },
  _meta: {managed_by: "moat"}}}')" >/dev/null
for t in zeek suricata cef; do
  if cur=$(es GET "/_component_template/${t}@custom" 2>/dev/null); then
    owner=$(jq -r '.component_templates[0].component_template._meta.managed_by // "user"' <<<"$cur")
  else
    owner=none
  fi
  if [[ $owner != moat && $owner != none ]]; then
    log "${t}@custom was not created by moat, leaving it alone"
    continue
  fi
  es PUT "/_component_template/${t}@custom" \
    '{"template":{"settings":{"index":{"lifecycle":{"name":"moat-network"}}}},"_meta":{"managed_by":"moat"}}' >/dev/null
done
es PUT "/logs-zeek.*,logs-suricata.*,logs-cef.*/_settings?expand_wildcards=all&allow_no_indices=true" \
  '{"index":{"lifecycle":{"name":"moat-network"}}}' >/dev/null

# --- Sensor policy: Zeek + Suricata, read by the sensor-agent container ---
if kb GET /api/fleet/agent_policies/moat-sensor >/dev/null 2>&1; then
  log "Sensor policy exists"
else
  log "creating Sensor agent policy"
  kb POST /api/fleet/agent_policies '{"id":"moat-sensor","name":"Sensor","namespace":"default",
    "description":"Zeek + Suricata on the mirror port (sensor-agent container)",
    "monitoring_enabled":["logs","metrics"]}' >/dev/null
fi
# name, package, simplified-API inputs (paths are inside the sensor-agent container)
add_sensor_integration() {
  local name=$1 pkg=$2 inputs=$3 ver
  if kb GET "/api/fleet/package_policies?perPage=100&kuery=ingest-package-policies.name:${name}" \
      | jq -e '.total > 0' >/dev/null; then
    log "${pkg} already on Sensor policy"; return
  fi
  kb POST "/api/fleet/epm/packages/${pkg}" >/dev/null
  ver=$(kb GET "/api/fleet/epm/packages/${pkg}" | jq -r '.item.version')
  log "adding ${pkg} ${ver} to Sensor policy"
  kb POST /api/fleet/package_policies "$(jq -n --arg n "$name" --arg p "$pkg" --arg v "$ver" \
    --argjson i "$inputs" '{name: $n, namespace: "default", policy_ids: ["moat-sensor"],
    package: {name: $p, version: $v}, inputs: $i}')" >/dev/null
}
add_sensor_integration zeek-sensor zeek \
  '{"zeek-logfile":{"enabled":true,"vars":{"base_paths":["/sensor/zeek/current"]}}}'
add_sensor_integration suricata-sensor suricata \
  '{"suricata-logfile":{"enabled":true,"streams":{"suricata.eve":{"enabled":true,"vars":{"paths":["/sensor/suricata/eve-*.json"]}}}}}'
# UDM Pro / UniFi "SIEM Server" sends CEF over syslog. The sensor-agent listens on UDP
# 5514; compose publishes it on BIND_IP:${SYSLOG_PORT}.
add_sensor_integration udm-cef cef \
  '{"cef-logfile":{"enabled":false},"cef-tcp":{"enabled":false},
    "cef-udp":{"enabled":true,"streams":{"cef.log":{"enabled":true,"vars":{"syslog_host":"0.0.0.0","syslog_port":5514}}}}}'

# UniFi syslog fixes, run by Fleet's cef pipeline as its final @custom hook:
# - UniFi Network/Protect stamp CEF with console-local time and no zone, so events land
#   hours off. Network carries the true time in UNIFIutcTime; for events without it
#   (Protect), use arrival time (live UDP, ~1s). UniFi OS console events are correct.
# - Protect puts a UUID in the numeric CEF eventId field; the event still parses, so
#   drop that one error instead of flagging every Protect event as broken.
if cur=$(es GET /_ingest/pipeline/logs-cef.log@custom 2>/dev/null); then
  owner=$(jq -r '.["logs-cef.log@custom"]._meta.managed_by // "user"' <<<"$cur")
else
  owner=none
fi
if [[ $owner == moat || $owner == none ]]; then
  log "ensuring logs-cef.log@custom (UniFi timestamp fixes)"
  es PUT /_ingest/pipeline/logs-cef.log@custom '{
    "description": "moat: UniFi syslog timestamp and Protect eventId fixes",
    "_meta": {"managed_by": "moat"},
    "processors": [
      {"date": {"if": "ctx.cef?.extensions?.UNIFIutcTime != null",
                "field": "cef.extensions.UNIFIutcTime", "target_field": "@timestamp",
                "formats": ["ISO8601"], "ignore_failure": true}},
      {"set": {"if": "ctx.observer?.vendor == \"Ubiquiti\" && ctx.observer?.product != \"UniFi OS\" && ctx.cef?.extensions?.UNIFIutcTime == null",
               "field": "@timestamp", "value": "{{{_ingest.timestamp}}}"}},
      {"remove": {"if": "ctx.observer?.vendor == \"Ubiquiti\" && ctx.error?.message instanceof String && ctx.error.message.contains(\"field '"'"'eventId'"'"'\")",
                  "field": "error.message", "ignore_missing": true}}
    ]}' >/dev/null
else
  log "logs-cef.log@custom was not created by moat, leaving it alone"
fi

# Enrollment token for the sensor-agent container (only used on its first start).
tok=$(kb GET "/api/fleet/enrollment_api_keys?perPage=100&kuery=policy_id:moat-sensor" \
  | jq -r '[.items[] | select(.active)][0].api_key // empty')
[[ -n $tok ]] || die "no enrollment token for the Sensor policy"
printf '%s' "$tok" > /tokens/sensor.enroll
chown 1000:0 /tokens/sensor.enroll
chmod 640 /tokens/sensor.enroll

# --- Analyst role + user (daily driver; elastic stays for admin) ---
log "ensuring moat_analyst role and analyst user"
kb PUT /api/security/role/moat_analyst "$(jq -n '{
  elasticsearch: {
    cluster: ["monitor"],
    indices: [{names: ["logs-*", "metrics-*", ".alerts-security*", ".siem-signals*",
                       ".lists*", ".items*", "zeek*", "suricata*"],
               privileges: ["read", "view_index_metadata"]},
              {names: [".alerts-security*", ".siem-signals*", ".lists*", ".items*"],
               privileges: ["write", "maintenance"]}]
  },
  kibana: [{base: ["all"], feature: {}, spaces: ["*"]}]
}')" >/dev/null
es POST /_security/user/analyst "$(jq -n --arg p "$ANALYST_PASSWORD" '{
  password: $p, roles: ["moat_analyst"], full_name: "moat analyst"}')" >/dev/null

# --- Detection rules ---
log "installing prebuilt detection rules (this can take a minute)"
kb POST /api/detection_engine/index >/dev/null 2>&1 || true
kb PUT /api/detection_engine/rules/prepackaged | jq -c '{rules_installed, rules_updated}' || \
  log "WARN: prebuilt rule install failed; retry with ./moat bootstrap"

IFS='|' read -ra tags <<<"${ENABLE_RULE_TAGS:-}"
for tag in "${tags[@]}"; do
  [[ -z $tag ]] && continue
  log "enabling prebuilt rules tagged: ${tag}"
  kb POST /api/detection_engine/rules/_bulk_action "$(jq -n --arg t "$tag" '{
    action: "enable",
    query: ("alert.attributes.tags: \"" + $t + "\" AND alert.attributes.params.immutable: true")}')" \
    | jq -c '.attributes.summary // .' || log "WARN: enabling '${tag}' failed"
done

IFS='|' read -ra ids <<<"${ENABLE_RULE_IDS:-}"
for id in "${ids[@]}"; do
  [[ -z $id ]] && continue
  log "enabling prebuilt rule ${id}"
  kb POST /api/detection_engine/rules/_bulk_action "$(jq -n --arg i "$id" '{
    action: "enable", query: ("alert.attributes.params.ruleId: \"" + $i + "\"")}')" \
    | jq -c '.attributes.summary // .' || log "WARN: enabling rule '${id}' failed"
done

log "done"
