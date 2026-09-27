# moat

**moat** is a free, one-box home SOC for threat hunting, built on the tools real SOCs use:

- **Elastic Security** (SIEM): detections, alerts, Timeline, Cases, dashboards
- **Zeek + Suricata** on a switch mirror port: every connection, DNS query, TLS/HTTP detail and IDS alert on your network
- **Router syslog** (UniFi/UDM via CEF): firewall blocks and the router's own IPS detections
- **Fleet + Elastic Defend** (optional): endpoint telemetry from laptops and servers

Everything runs in Docker on one Linux box, uses only free licenses (Elastic Basic, open-source sensors), and is configured as code, so `./moat destroy && ./moat up` rebuilds it identically.

## Quick start

```bash
git clone https://github.com/<you>/moat && cd moat
./moat preflight     # RAM, disk, Docker, vm.max_map_count, ports, NICs
./moat init          # picks profile, detects LAN IP, generates secrets into .env
./moat up            # builds and bootstraps everything (~5 min; first run pulls images)
./moat status        # health, agents, event counts
```

Browse to `https://<HOST_IP>` and log in as `analyst` (`./moat creds`). Open **Dashboards → "moat: Home Network"** for the overview, or **Security → Alerts** for detections.

For network sensing, mirror your router↔switch uplink to a spare NIC and set `SENSOR_IFACE` in `.env`. See [UniFi port mirroring](docs/sensors/unifi-port-mirror.md).

## What `up` builds

```
certs ─► es01 ─► setup ─► kibana ─► bootstrap ─► fleet-server ─► sensor-agent
                                       │                              ▲
                                       │            zeek ─────────────┤ (mirror NIC)
                                       │            suricata ─────────┤
                                       │            router syslog ────┘ (udp/5514)
                                       └─► caddy :443 ─► kibana
```

`bootstrap` declares everything as code: Fleet policies, integrations, retention, the least-privilege `analyst` user, prebuilt + moat detection rules (`rules/`), and dashboards (`dashboards/`).

| Port | Service | Who connects |
| --- | --- | --- |
| 443/tcp | Caddy → Kibana | You (browser); agents fetch the CA cert here |
| 8220/tcp | Fleet Server | Elastic Agents (enroll + check-in) |
| 9200/tcp | Elasticsearch | Elastic Agents (data) |
| 5514/udp | Syslog (CEF) | Your router's SIEM/syslog export |

All ports bind only to `HOST_IP`. Don't port-forward them; use Tailscale or WireGuard for remote access.

## Profiles

| Profile | RAM | ES heap | Use |
| --- | --- | --- | --- |
| `standard` | 16 GB+ | 4 GB | Default |
| `lite` | 8 GB | 2 GB | Small labs, fewer sources |

## Commands

Run `./moat help`. Highlights:

- `status`: health, agents, event counts
- `bootstrap`: re-apply policies, rules and dashboards
- `enroll`: agent install commands
- `creds`: logins
- `destroy`: wipe everything, the only command that deletes data

## Docs

- [Laptop test rig](docs/laptop-test.md): running moat on a laptop (sleep, lid, Wi-Fi)
- [UniFi port mirroring](docs/sensors/unifi-port-mirror.md): feeding the sensor NIC

## Security notes

- **Secrets:** generated per install into `.env` (mode 600, git-ignored). Nothing is hardcoded, and credentials are never passed on process command lines.
- **CA key:** a local CA signs all service certs. Its private key stays in the `certs` volume, root-only; Caddy mounts only the Kibana cert and the public CA cert.
- **Accounts:** `analyst` is least privilege (SOC work only, no Stack Management or Fleet changes). `elastic` is the superuser for admin tasks.
- **Elastic Defend** uses the EDR Complete preset with Elastic's default protections, which **prevent** (e.g. quarantine malware). Switch protections to detect-only in Kibana if you'd rather only alert.
- **Supply chain:** images are pinned by version in `.env`; CI actions are pinned by commit SHA.

## License

TBD (MIT suggested). Elastic components are used under the free Elastic license tier.
