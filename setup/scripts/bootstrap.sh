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

# --- Threat intel feeds (free keys; each is added only once its key is in .env) ---
# Indicators land in logs-ti_*; the packages' own transforms expire old IOCs.
ti=0
if [[ -n ${ABUSECH_AUTH_KEY:-} ]]; then
  add_sensor_integration ti-abusech ti_abusech "$(jq -nc --arg k "$ABUSECH_AUTH_KEY" \
    '{"ti_abusech-cel": {enabled: true, vars: {auth_key: $k}}}')"
  ti=1
fi
if [[ -n ${OTX_API_KEY:-} ]]; then
  add_sensor_integration ti-otx ti_otx "$(jq -nc --arg k "$OTX_API_KEY" \
    '{"ti_otx-httpjson": {enabled: false},
      "ti_otx-cel": {enabled: true, streams: {"ti_otx.pulses_subscribed": {enabled: true, vars: {api_key: $k}}}}}')"
  ti=1
fi
(( ti )) || log "no threat-intel keys in .env (ABUSECH_AUTH_KEY / OTX_API_KEY); feeds skipped. See docs/threat-intel.md"
# The policy started as sensor-only; it now also carries syslog and intel.
kb PUT /api/fleet/agent_policies/moat-sensor '{"name":"moat collector","namespace":"default",
  "description":"Router syslog, threat-intel feeds, and Zeek + Suricata (sensor profile)"}' >/dev/null

# Enrollment token for the sensor-agent container (only used on its first start).
tok=$(kb GET "/api/fleet/enrollment_api_keys?perPage=100&kuery=policy_id:moat-sensor" \
  | jq -r '[.items[] | select(.active)][0].api_key // empty')
[[ -n $tok ]] || die "no enrollment token for the Sensor policy"
printf '%s' "$tok" > /tokens/sensor.enroll
chown 1000:0 /tokens/sensor.enroll
chmod 640 /tokens/sensor.enroll

# --- Analyst role + user (daily driver; elastic stays for admin) ---
# Least privilege: SOC work (alerts, rules, cases, Timeline, hunting, dashboards) but no
# Stack Management, Fleet changes, Osquery or ML. Feature ids are Kibana 9.5's current
# (non-deprecated) ones: list them with GET /api/features on upgrades.
log "ensuring moat_analyst role and analyst user"
kb PUT /api/security/role/moat_analyst "$(jq -n '{
  elasticsearch: {
    cluster: ["monitor"],
    indices: [{names: ["logs-*", "metrics-*", ".alerts-security*", ".siem-signals*",
                       ".lists*", ".items*", "zeek*", "suricata*"],
               privileges: ["read", "view_index_metadata"]},
              # manage: required by Security for alert/value-list workflows (the Alerts
              # page shows "Insufficient privileges" without it).
              # .internal.alerts-*: the concrete index behind the .alerts-security.*
              # alias. Reads work via the alias, but status changes (close, acknowledge)
              # are written to the concrete index, so without it analysts cannot close alerts.
              {names: [".alerts-security*", ".internal.alerts-security*", ".siem-signals*",
                       ".lists*", ".items*"],
               privileges: ["read", "write", "maintenance", "manage", "view_index_metadata"]}]
  },
  kibana: [{base: [], spaces: ["*"], feature: {
    siemV5: ["all"], securitySolutionAlertsV1: ["all"], securitySolutionRulesV4: ["all"],
    securitySolutionCasesV3: ["all"], securitySolutionTimeline: ["all"], securitySolutionNotes: ["all"],
    discover_v2: ["all"], dashboard_v2: ["all"], visualize_v2: ["all"], maps_v2: ["all"],
    savedQueryManagement: ["all"], savedObjectsTagging: ["all"], indexPatterns: ["all"],
    dev_tools: ["all"], filesManagement: ["all"],
    fleet: ["read"], fleetv2: ["read"]
  }}]
}')" >/dev/null
es POST /_security/user/analyst "$(jq -n --arg p "$ANALYST_PASSWORD" '{
  password: $p, roles: ["moat_analyst"], full_name: "moat analyst"}')" >/dev/null

# --- moat_bridge: read-only ES user for the IRIS bridge (profile "iris") ---
# Reads open alerts and DHCP hostnames (to name devices in IRIS). Nothing else.
if [[ -n ${BRIDGE_ES_PASSWORD:-} ]]; then
  log "ensuring moat_bridge role and user"
  es PUT /_security/role/moat_bridge '{"indices":[
    {"names":[".alerts-security.alerts-*","logs-zeek.dhcp-*"],"privileges":["read"]}]}' >/dev/null
  es POST /_security/user/moat_bridge "$(jq -n --arg p "$BRIDGE_ES_PASSWORD" '{
    password: $p, roles: ["moat_bridge"], full_name: "moat IRIS bridge"}')" >/dev/null
fi

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

# Prebuilt indicator-match rules (IP, hash, URL) only once a feed is configured.
ti_rules=""
(( ti )) && ti_rules="0c41e478-5263-4c69-8f9e-7dfd2c22da64|aab184d3-72b3-4639-b242-6597c99d8bca|f3e22c8b-ea47-45d1-b502-b57b6de950b3"
IFS='|' read -ra ids <<<"${ENABLE_RULE_IDS:-}${ti_rules:+|$ti_rules}"
for id in "${ids[@]}"; do
  [[ -z $id ]] && continue
  log "enabling prebuilt rule ${id}"
  kb POST /api/detection_engine/rules/_bulk_action "$(jq -n --arg i "$id" '{
    action: "enable", query: ("alert.attributes.params.ruleId: \"" + $i + "\"")}')" \
    | jq -c '.attributes.summary // .' || log "WARN: enabling rule '${id}' failed"
done

# --- moat rule pack (rules/*.json, mounted at /rules) ---
# Files are the source of truth: create missing rules, update existing ones to match.
for f in /rules/*.json; do
  [[ -e $f ]] || continue
  id=$(jq -r .rule_id "$f")
  if kb GET "/api/detection_engine/rules?rule_id=${id}" >/dev/null 2>&1; then
    kb PUT /api/detection_engine/rules "$(cat "$f")" >/dev/null && log "updated rule ${id}"
  else
    kb POST /api/detection_engine/rules "$(cat "$f")" >/dev/null && log "created rule ${id}"
  fi
done

# --- Sigma rules: sigma/moat (ours) + optional pinned SigmaHQ network pack ---
# sigma_convert.py maps fields (ecs_zeek_beats + sigma/pipelines/moat.yml), skips rules
# moat has no data for or that would reference unmapped fields, and keeps whatever
# enabled/disabled state a user already chose in Kibana.
sigma_import() { # sigma_import SOURCE [--disabled] PATH...
  local src=$1; shift
  local keep ndj res dir
  # Kibana's import wants a *.ndjson filename; BusyBox mktemp has no --suffix.
  dir=$(mktemp -d); keep=$dir/enabled.json; ndj=$dir/sigma.ndjson
  kb GET "/api/detection_engine/rules/_find?per_page=1000&filter=alert.attributes.tags:%22Sigma%3A%20${src}%22" \
    | jq '[.data[] | {(.rule_id): .enabled}] | add // {}' > "$keep"
  /opt/sigma/bin/python /setup/sigma_convert.py --source "$src" --keep-enabled "$keep" "$@" > "$ndj" \
    2> >(while IFS= read -r l; do log "  $l" >&2; done)  # >&2: this subshell's stdout is $ndj
  if [[ -s $ndj ]]; then
    res=$(curl -sS --cacert "$CA" -K <(auth_cfg) -H 'kbn-xsrf: moat' \
          -X POST "${KIBANA_URL}/api/detection_engine/rules/_import?overwrite=true" -F "file=@${ndj}")
    log "sigma[${src}]: imported $(jq -r '.success_count // 0' <<<"$res") rule(s)"
    jq -r '.errors[]? | "  import error \(.rule_id): \(.error.message)"' <<<"$res" | while IFS= read -r l; do log "$l"; done
  fi
  rm -rf "$dir"
}
sigma_import moat /sigma/moat

if [[ ${SIGMA_COMMUNITY:-network} == network ]]; then
  rel=${SIGMA_RELEASE:-r2026-07-01}
  tmp=$(mktemp -d)
  if curl -fsSL "https://github.com/SigmaHQ/sigma/archive/refs/tags/${rel}.tar.gz" -o "$tmp/s.tgz" \
     && echo "${SIGMA_RELEASE_SHA256:-}  $tmp/s.tgz" | sha256sum -c -s; then
    tar xzf "$tmp/s.tgz" -C "$tmp" --strip-components=1 \
      "sigma-${rel}/rules/network/zeek" "sigma-${rel}/rules/network/dns" 2>/dev/null
    log "SigmaHQ ${rel} (DRL 1.1): community rules install disabled; enable them in Security > Rules"
    sigma_import sigmahq --disabled "$tmp/rules/network"
  else
    log "WARN: SigmaHQ ${rel} download failed or checksum mismatch; community Sigma rules skipped"
  fi
  rm -rf "$tmp"
fi

# --- Single-node housekeeping (last, after everything that creates indices) ---
# Security's value-list data streams use Kibana-managed templates with no @custom hook
# and default to 1 replica. Patch the templates (re-applied every run, in case a Kibana
# upgrade rewrites them), then fix any existing index that still wants a replica.
for t in .lists-default .items-default; do
  tpl=$(es GET "/_index_template/${t}" 2>/dev/null | jq -c '.index_templates[0].index_template // empty') || continue
  [[ -n $tpl ]] || continue
  if [[ $(jq -r '.template.settings.index.auto_expand_replicas // empty' <<<"$tpl") != 0-1 ]]; then
    # GET returns system-managed timestamps that PUT rejects; strip them.
    body=$(jq -c 'del(.created_date_millis, .modified_date_millis)
                  | .template.settings.index.auto_expand_replicas = "0-1"' <<<"$tpl")
    if es PUT "/_index_template/${t}" "$body" >/dev/null; then log "patched ${t} template for single node"
    else log "WARN: could not patch ${t} template (cluster may go yellow on its next rollover)"; fi
  fi
done
mapfile -t want_replicas < <(es GET "/_cat/indices?h=index,rep&expand_wildcards=all" | awk '$2 > 0 {print $1}')
if (( ${#want_replicas[@]} )); then
  es PUT "/$(IFS=,; echo "${want_replicas[*]}")/_settings?expand_wildcards=all" \
    '{"index":{"auto_expand_replicas":"0-1"}}' >/dev/null
  log "set auto_expand_replicas on ${#want_replicas[@]} index(es): ${want_replicas[*]}"
fi

# --- moat dashboards (dashboards/*.ndjson, mounted at /dashboards) ---
# Generated by dashboards/build_*.py. overwrite=true: the files are the source of truth.
for f in /dashboards/*.ndjson; do
  [[ -e $f ]] || continue
  res=$(curl -sS --fail-with-body --cacert "$CA" -K <(auth_cfg) -H 'kbn-xsrf: moat' \
        -X POST "${KIBANA_URL}/api/saved_objects/_import?overwrite=true" -F "file=@${f}")
  jq -e '.success' <<<"$res" >/dev/null || die "dashboard import failed for ${f##*/}: $res"
  log "imported ${f##*/} ($(jq -r .successCount <<<"$res") objects)"
done

log "done"
