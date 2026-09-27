#!/usr/bin/env bash
# Suricata on the mirrored interface, ET Open rules (free), EVE JSON rotated hourly.
# Suricata itself disables NIC offloading while running and restores it on exit.
set -euo pipefail

: "${SENSOR_IFACE:?SENSOR_IFACE is not set}"
nets=${LOCAL_NETS:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}
keep_min=$(( ${SENSOR_LOG_HOURS:-24} * 60 ))

# Rules: refresh at start (keep the previous set if offline), then daily with a live
# reload (SIGUSR2). suricata-update defaults to the ET Open ruleset.
suricata-update --no-test --no-reload -q --disable-conf /sensor/disable.conf || echo "[moat:suricata] rule update failed; using existing rules"
[[ -s /var/lib/suricata/rules/suricata.rules ]] || { echo "[moat:suricata] no rules available" >&2; exit 1; }
(while sleep 86400; do suricata-update --no-test --no-reload -q --disable-conf /sensor/disable.conf && kill -USR2 1; done) &
(while sleep 3600; do find /var/log/suricata -name 'eve-*.json' -mmin "+$keep_min" -delete; done) &

echo "[moat:suricata] capturing on $SENSOR_IFACE, HOME_NET: [$nets]"
# The image entrypoint drops to the suricata user (PUID/PGID) and execs suricata as PID 1.
# outputs.0 = fast.log (off, EVE has the same alerts), outputs.1 = eve-log.
exec /docker-entrypoint.sh --af-packet="$SENSOR_IFACE" \
  --set "vars.address-groups.HOME_NET=[${nets}]" \
  --set outputs.0.fast.enabled=no \
  --set outputs.1.eve-log.filename=eve-%Y%m%d-%H.json \
  --set outputs.1.eve-log.rotate-interval=hour \
  --set outputs.1.eve-log.community-id=true
