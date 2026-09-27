#!/usr/bin/env bash
# Zeek on the mirrored interface. Live JSON logs in /zeek/current, rotated hourly to
# /zeek/archive; archives older than SENSOR_LOG_HOURS are deleted (ES holds the history).
set -euo pipefail

: "${SENSOR_IFACE:?SENSOR_IFACE is not set}"
nets=${LOCAL_NETS:-10.0.0.0/8,172.16.0.0/12,192.168.0.0/16}
keep_min=$(( ${SENSOR_LOG_HOURS:-24} * 60 ))

mkdir -p /zeek/current /zeek/archive
cd /zeek/current

(while sleep 3600; do find /zeek/archive -type f -mmin "+$keep_min" -delete; done) &

echo "[moat:zeek] capturing on $SENSOR_IFACE, local nets: $nets"
exec zeek -i "af_packet::${SENSOR_IFACE}" /sensor/moat.zeek "Site::local_nets += { ${nets//,/, } };"
