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

log "done"
