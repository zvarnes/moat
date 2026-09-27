# CLAUDE.md — moat

moat is a free, single-host home SOC for threat hunting: Elastic Security (SIEM) + Fleet + Zeek + Suricata network sensing. Target user: anyone with a Linux box (16 GB standard, 8 GB lite profile) who wants real SOC tooling at home. The previous working name was "socinabox".

## Hard constraints

- **Free only.** Everything must work on the Elastic Basic license, with no trial or Platinum features. Verify license requirements before designing around an Elastic feature. Known Platinum-only: per-policy Fleet outputs (`data_output_id`/`monitoring_output_id`). On Basic, Kibana silently drops a preconfigured policy that uses them.
- **Network-first.** The primary data source is a switch port mirror into Zeek + Suricata on the moat host. Endpoint agents (Elastic Defend) are optional, for users who want them later.

## Current state

- Phase 1 (core SIEM) **runs live** on the test laptop (Elastic 9.5.4). A clean `./moat destroy` then `./moat up` reaches a green cluster with Fleet Server online in about 5 minutes and needs no manual steps.
- Phase 2 (network sensing) **runs live** as of 2026-09-27: Zeek + Suricata on the mirror, shipped through the `moat-sensor` agent. There are 0 ingest errors across 16 datasets, and Suricata alerts reach Security alerts via the External Alerts rule.
- Not yet exercised: enrolling an external endpoint via `./moat enroll`.
- UDM Pro syslog: the `cef` integration on the Sensor policy listens on UDP 5514 (published on `BIND_IP:${SYSLOG_PORT}`). Verified live 2026-09-27: UniFi OS 5.1.33 sends CEF (`observer.product: UniFi OS`, UniFi fields under `cef.extensions.UNIFI*`) with 0 parse errors. UniFi's syslog setting is a single Mode (internal/external), so it's either/or. Firewall events only arrive for rules with logging enabled.
  - Network app → CyberSecure → Traffic Logging → Activity Logging (Syslog) = SIEM Server, pointed at the same `:5514`. It's separate from the UniFi OS console's System Logging / SIEM, which only covers OS + Protect.
  - UniFi Network/Protect stamp CEF with console-local time and no zone (4h off here). Bootstrap's `logs-cef.log@custom` pipeline takes `@timestamp` from `UNIFIutcTime` (Network), uses arrival time for other non-"UniFi OS" Ubiquiti events, and drops Protect's harmless `eventId` UUID parse error.
  - UDM IPS detections arrive as CEF with `event.kind: event`, so External Alerts does **not** promote them. They need a custom rule (Phase 3).
- **Next:** measure GB/day after a full day, tune Suricata noise, and check that firewall/threat CEF events parse once some arrive.

## Architecture (compose.yml, project name `moat`)

Startup chain, each gated on the previous one:

1. `certs`: alpine setup image; openssl local CA + certs for es01/kibana/fleet-server with SAN = HOST_IP; renders `setup/templates/kibana.yml` via envsubst (only non-secret vars; `${SECRET}` refs are left for Kibana to resolve from its env).
2. `es01`: single node, HTTP TLS, transport TLS off, ML off, Basic license.
3. `setup`: sets the kibana_system password; creates the fleet-server service token → `tokens` volume.
4. `kibana`: started with `--config` pointing at the rendered file; Fleet is declared as code (outputs with `ca_trusted_fingerprint`, Fleet Server host, `fleet-server-policy`, `moat-endpoints` policy).
5. `bootstrap`:
   - creates `logs|metrics|traces@custom` component templates with `auto_expand_replicas: 0-1` (single-node stays green);
   - calls `/api/fleet/setup` and fails on any `nonFatalErrors`;
   - adds Elastic Defend (EDRComplete) to `moat-endpoints`;
   - creates the `moat_analyst` role and `analyst` user;
   - installs prebuilt rules and enables them by `ENABLE_RULE_TAGS`.
6. `fleet-server`: elastic-agent container, `FLEET_SERVER_SERVICE_TOKEN_PATH`; it has a healthcheck, and `./moat up` fails unless it is healthy.
7. `caddy`: :443 → kibana; serves `/moat-ca.crt` for agent enrollment. It mounts only the kibana/ and public/ subpaths of the certs volume, never the CA key.

Case management uses compose profile `iris` (`IRIS_ENABLED=true` by default in standard, false in lite):
- `iris-db`, `iris-rabbitmq` (3.13.7-alpine; IRIS 2.4 pins RabbitMQ 3.x and 3.13 is EOL upstream, revisit when IRIS moves), `iris-app`, `iris-worker`, all DFIR-IRIS **v2.4.29** (v3 is beta).
- Explicit env only, no `env_file` (verified: 0 Elastic secrets in these containers). Caddy serves IRIS on `IRIS_PORT` (8443), and IRIS trusts X-Forwarded-Proto via ProxyFix.
- The worker runs Celery directly with `--concurrency ${IRIS_WORKER_CONCURRENCY:-2}`. IRIS's entrypoint forks one process per CPU (765 MB on 8 cores).
- `bridge` (`bridge/bridge.py`, stdlib only, non-root, read-only):
  - polls open Security alerts ≥ `BRIDGE_MIN_SEVERITY` every 60 s and creates IRIS alerts via `POST /alerts/add`, with IOCs (external IPs, domains, URLs rebuilt from `url.domain`+`url.original`, hashes) and assets (internal IPs named from `logs-zeek.dhcp-*`);
  - creates the IRIS customer "moat home";
  - sets the VirusTotal module's `api_key` param when `VT_API_KEY` is set;
  - keeps state in `/state/state.json` (no duplicates across restarts, verified);
  - reads ES as `moat_bridge` (read on alerts + zeek.dhcp only; bootstrap creates it).
- New secrets come via `./moat init --add-missing` (appends keys new in `.env.example`, generates secrets, never changes existing values).
- Threat intel (M4): `ti_abusech` / `ti_otx` are added to the collector policy only when `ABUSECH_AUTH_KEY` / `OTX_API_KEY` are set, and then the prebuilt IP/hash/URL indicator-match rules are enabled too.
  - `rules/moat-ti-domain-match.json` covers DNS names (no prebuilt equivalent).
  - `sensor-agent` is always on now (policy display name "moat collector", id still `moat-sensor`).
  - Verified with a synthetic indicator in `logs-ti_moattest.indicator-default` (deleted afterwards): DNS lookup → 6 high alerts → IRIS with a domain IOC.
  - Real feeds are not yet exercised; they need the user's free keys.
- Tailscale: `tailscale serve --https=8443 https+insecure://<HOST_IP>:8443` makes IRIS reachable at https://<tailnet-host>:8443.
- IRIS renders alert descriptions as HTML: `&times…` in a URL shows as "×", so put `timestamp=` first in the Kibana link.

Sensor services use compose profile `sensor`. `./moat`'s `compose()` enables it when `SENSOR_IFACE` is set, and `destroy` always includes it.
- `zeek` (`zeek/zeek`, host network): `sensors/zeek/run.sh` + `moat.zeek`. JSON logs go to `zeeklogs:/zeek/current`, rotated hourly to `/zeek/archive`, and pruned after `SENSOR_LOG_HOURS`. `Site::local_nets` comes from `LOCAL_NETS` (default RFC1918). No zeekctl.
- `suricata` (`jasonish/suricata`, host network, PUID/PGID 1000): `sensors/suricata/run.sh` runs `suricata-update` (ET Open, with `sensors/suricata/disable.conf`) at start and daily, then reloads with SIGUSR2. EVE is `eve-%Y%m%d-%H.json`, rotated hourly. Suricata disables NIC offloads itself.
- `sensor-agent` (elastic-agent, uid 1000): enrolls into the `moat-sensor` policy with `/tokens/sensor.enroll` (written by bootstrap) and reads both log volumes read-only. It also receives UDM syslog/CEF on UDP 5514.
- Bootstrap also:
  - creates the `moat-sensor` policy with the zeek (`base_paths`) and suricata (`paths`) integrations via the simplified package-policy API;
  - creates the ILM policy `moat-network` (`RETENTION_NETWORK_DAYS`), attached via `zeek@custom`/`suricata@custom`/`cef@custom`, and only overwritten when `_meta.managed_by == moat`;
  - enables prebuilt rules by `ENABLE_RULE_TAGS` (Zeek|Suricata) plus `ENABLE_RULE_IDS` (empty by default). It only ever *enables* rules; changing these does not disable old ones.
  - converts and imports Sigma: `sigma/moat/*.yml` (enabled by level ≥ medium) and, with `SIGMA_COMMUNITY=network`, the pinned + sha256-verified SigmaHQ release's `rules/network/{zeek,dns}` (installed disabled). `setup/scripts/sigma_convert.py` maps fields (`ecs_zeek_beats` + `sigma/pipelines/moat.yml`), rewrites `zeek.conn`→`zeek.connection`, rejects unknown datasets and unmapped fields, and keeps the user's enabled/disabled choices. The Sigma toolchain is hash-pinned (`setup/requirements-sigma.txt`).
  - installs the moat rule pack from `rules/*.json` (mounted at `/rules`): POST if missing, PUT to match the file otherwise. The files are the source of truth, and bootstrap re-enables a moat rule disabled in the UI.

Ports 443 / 8220 / 9200 bind to `BIND_IP` (= HOST_IP). Secrets live only in `.env` (mode 600, git-ignored), generated by `./moat init`.

## Test rig

- This laptop: Wi-Fi `wlp114s0` = management, `HOST_IP=<HOST_IP>` via a UniFi fixed-IP reservation (Wi-Fi power save off). Built-in Ethernet `enp0s31f6` = sensor (`SENSOR_IFACE`), NetworkManager profile with IPv4/IPv6 disabled, fed by a UniFi mirror of the switch↔UDM Pro uplink.
- The mirror sees two subnets: the main LAN and a second VLAN/subnet. Treat both as local (Zeek `Site::local_nets`, Suricata `HOME_NET`). It's pre-NAT, so internal IPs are visible. It can't see WAN-side traffic, devices on the UDM's own ports, or intra-switch east-west traffic. Plan UDM syslog to cover some of that.
- Measured 2026-09-26/27: ~6,200–7,400 pkt/s on the mirror, ~29 LAN hosts. Suricata steady-state kernel drops were 0% (1.6% only during startup/rule load).
- Remote access: Tailscale (`<tailnet-host>`, <tailscale-ip>). `tailscale serve` proxies https://<tailnet-host> → https+insecure://<HOST_IP>:443, and must be repointed if `HOST_IP` changes. OpenSSH is key-only, with keys from the owner's GitHub account. The tailnet is shared with another user.
- Setup guides: `docs/laptop-test.md` and `docs/sensors/unifi-port-mirror.md`.

## Lessons from the first live run (don't regress these)

- The service token file must have **no trailing newline**. Fleet Server sends the raw bytes as the header, so write it with `jq -j`.
- Fleet Server caches its enrollment and token in the `fleetdata` volume. After fixing a token or enrollment problem, remove that volume or the old values stick.
- ES serves `es01.chain.crt` (leaf + CA). Agents trust ES via `ca_trusted_fingerprint`, which only matches certs the server actually sends.
- A few seconds of yellow right after new data streams appear is expected: `auto_expand_replicas` drops the replica asynchronously. Only persistent yellow is a problem.
- Credentials never go on a process command line; container processes show in the host's `ps`. Use curl `-K` config: host helpers pipe it on stdin, and container helpers use `-K <(auth_cfg)` placed **on the curl command itself** (a process substitution inside an array assignment is a closed fd by the time curl runs). Secret bodies go via `--data-binary @-`. Verify with a `/proc/*/cmdline` scan plus a canary positive control.
- Before bumping `STACK_VERSION`, check the image registry (docker.elastic.co tags). artifacts-api lists versions before their images are published (9.5.5 wasn't pullable on 2026-09-27).
- Re-PUTting a GET'd index template needs `created_date_millis`/`modified_date_millis` removed.
- `.lists-default`/`.items-default` (Security value lists) have no `@custom` hook. Bootstrap patches their templates and fixes any index with replicas > 0 at the end of every run.
- The analyst role needs `manage` on `.alerts-security*`, `.lists*`, `.items*`, or Security shows an "Insufficient privileges" *info* callout. `tests/ui-check.sh [analyst|elastic]` renders key pages in Playwright and fails on error or privilege callouts. Check the screenshots in `tests/out/` too.
- **UniFi mirror VLAN asymmetry:** the mirror tags client→server with VLAN 1 and leaves replies untagged. Suricata must run with `vlan.use-for-tracking=false` (run.sh), or every TCP session splits into two one-way flows: no HTTP/TLS parsing, no app-layer alerts, and a flood of STREAM anomalies. Zeek is unaffected. Found by replaying a mirror pcap offline (`suricata -r`) and seeing two flows with different `vlan` fields.
- `suricata-update` treats rule-shaped *comments* in local.rules as disabled rules; a duplicate sid there silently replaces the real rule. `./moat rules test` and CI fail on duplicate sids.
- Suricata's `-T -S file` check ignores comments, and a SIGUSR2 reload of ~53k rules takes a while. Wait for "rule reload complete" before testing a new rule.
- moat CA certs need `keyUsage` (strict verifiers such as Python 3.13+ reject a CA without it). certs.sh re-issues an old CA cert with the same key; `./moat up` restarts Kibana automatically when the rendered kibana.yml changes.
- Host-side helpers that exec into containers must pass curl config on **stdin** (`-K -`). A host `<(...)` fd doesn't exist inside the container.
- `./moat logs` follows forever. In scripts, use `docker compose --env-file .env logs --no-color <svc>`.

## Open issues

- `certs.sh` never reissues an existing cert, so a `HOST_IP` change needs a rebuild (`destroy` + `init --force`) or manual cert rotation.
- Alert policy (2026-09-27): prebuilt "External Alerts" is **off**, because it promoted every Suricata/Zeek alert (~2,500 per 2h). Replaced by `rules/`:
  - `moat-suricata-alert`: severity ≤ 2 only; severity 3 stays searchable.
  - `moat-zeek-notice`: excludes `SSL::Invalid_Server_Cert`.
  - `moat-unifi-ips`: UDM IDS/IPS via CEF, severity from `UNIFIrisk`.
  - Expected volume ~15 per 2h. The remaining chatter is ET DNS/INFO TLD rules (.to/.life/.world); revisit after a day.
- `disable.conf`: ethertype-unknown, QUIC errors, STUN, `group:stream-events.rules` (mirror artifacts, ~75% of the noise), and SSDP 2019102 (LAN UPnP discovery to the router).
- Dashboards as code: edit `dashboards/build_home_network.py`, run it to regenerate `moat-home-network.ndjson`, and bootstrap imports every `dashboards/*.ndjson` with overwrite (UI edits to those objects get replaced, so users should "Save as" to keep their own). Panels are Lens by value, and the ndjson format was copied from Fleet's own Zeek dashboard (dashboard typeMigrationVersion 10.3.0). Verify rendering with a headless browser (Playwright container logging in as `analyst`), because the import API accepts panels that fail to render.
- Rule pack is JSON (Kibana rule API shape), not the TOML detection-rules format the roadmap mentions. Revisit if `make test-rules` needs TOML.
- Caddy volume `subpath` needs Docker Engine 26+ / Compose 2.23+.

## Workflow

- Run: `./moat preflight`, `./moat init`, `./moat up`, then `./moat status` and `./moat enroll`.
- Debug: `./moat logs <service>`. Re-run bootstrap: `./moat bootstrap`. Wipe and retry: `./moat destroy`, then `./moat init --force`.
- Before committing: `shellcheck -x -P setup/scripts moat setup/scripts/*.sh` and `docker compose --env-file .env config -q`.
- Keep scripts idempotent: check before create; never regenerate the CA if it exists.
- Record measured RAM (`docker stats`) and GB/day in the plan doc so the profile defaults can be tuned.
  - 2026-09-27 with sensors: ES 5.4/6 GB, Kibana 1.6/2 GB (the old 1.5 GB cap starved it), Fleet Server 180/768 MB, Suricata 550 MB/3 GB (53k rules), sensor-agent 220 MB/1 GB, Zeek 110 MB/2 GB, Caddy 17 MB.
  - 2026-09-27 with IRIS: iris-app 184 MB, iris-worker 258 MB (after the concurrency fix), iris-rabbitmq 135 MB, iris-db 49 MB, bridge 14 MB. Host total ~13/30 GB used.
  - GB/day: not measured yet (needs a full day).

## Roadmap

- **Phase 2:** done: Zeek + Suricata + sensor agent, network rule defaults, 7-day ILM.
  - Remaining: endpoint ILM (30d) once endpoints exist, and GB/day measurement.
- **Phase 3:** started: `rules/` (3 rules) and `dashboards/` (moat: Home Network). Still to do: more rules, guided labs with Atomic Red Team and PCAPs, `make test-rules`.
- **Phase 4:** lite-profile polish, backup/restore, docs site, v1.0.

Plan doc (claude.ai): https://claude.ai/code/artifact/67029afa-f1bc-4508-9d3f-695881a61eae
