# moat

**moat** is a free, one-box home SOC for threat hunting, built on the tools real SOCs use:

- **Elastic Security** (SIEM): detections, alerts, Timeline, Cases, dashboards
- **Zeek + Suricata** on a switch mirror port: every connection, DNS query, TLS/HTTP detail and IDS alert on your network
- **Router syslog** (UniFi/UDM via CEF): firewall blocks and the router's own IPS detections
- **Detections as code**: Sigma rules (yours + SigmaHQ's), Suricata/Snort-style rules, and Elastic rules, tested and installed with one command
- **Threat intel**: free abuse.ch and AlienVault OTX feeds, matched against every DNS lookup, connection, URL and hash
- **DFIR-IRIS case management**: alerts flow in automatically with IOCs and device names; VirusTotal enrichment
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

Browse to `https://<HOST_IP>` and log in as `analyst` (`./moat creds`). Open **Dashboards → "moat: Home Network"** for the overview, or **Security → Alerts** for detections. Cases live in DFIR-IRIS at `https://<HOST_IP>:8443`.

**New here? Start with [Getting started](docs/getting-started.md).**

For network sensing, mirror your router↔switch uplink to a spare NIC and set `SENSOR_IFACE` in `.env`. See [UniFi port mirroring](docs/sensors/unifi-port-mirror.md).

## What `up` builds

```
certs ─► es01 ─► setup ─► kibana ─► bootstrap ─► fleet-server ─► sensor-agent (collector)
                             │                                    ▲
                             │               zeek, suricata ──────┤ mirror NIC (profile: sensor)
                             │               router syslog ───────┤ udp/5514
                             │               threat-intel feeds ──┘ (free keys)
                             │
                             ├─► caddy :443 ─► Kibana          alerts ─► bridge ─► DFIR-IRIS
                             └─► caddy :8443 ─────────────────────────────────────► (profile: iris)
```

`bootstrap` declares everything as code: Fleet policies, integrations, retention, the least-privilege `analyst` user, prebuilt + moat detection rules (`rules/`), and dashboards (`dashboards/`).

| Port | Service | Who connects |
| --- | --- | --- |
| 443/tcp | Caddy → Kibana | You (browser); agents fetch the CA cert here |
| 8220/tcp | Fleet Server | Elastic Agents (enroll + check-in) |
| 9200/tcp | Elasticsearch | Elastic Agents (data) |
| 5514/udp | Syslog (CEF) | Your router's SIEM/syslog export |
| 8443/tcp | Caddy → DFIR-IRIS | You (browser) |

All ports bind only to `HOST_IP`. Don't port-forward them; use Tailscale or WireGuard for remote access.

## Profiles

| Profile | RAM | ES heap | Use |
| --- | --- | --- | --- |
| `standard` | 16 GB+ | 4 GB | Default |
| `lite` | 8 GB | 2 GB | Small labs, fewer sources |

## Commands

Run `./moat help`. Highlights:

- `status`: health, agents, IRIS + bridge, event counts
- `rules test [path]` / `rules apply`: check, then install Sigma, Suricata and Elastic rules
- `bootstrap`: re-apply policies, rules and dashboards
- `init --add-missing`: add settings new in an upgrade to your existing `.env`
- `enroll`: agent install commands
- `creds`: logins
- `destroy`: wipe everything, the only command that deletes data

## Docs

- [Getting started](docs/getting-started.md): your first hour, from login to a triaged alert and an IRIS case
- [Hunting 101](docs/hunting-101.md): the data you have and queries to find what rules miss
- [Writing detections](docs/writing-detections.md): Sigma, Suricata/Snort-style and Elastic rules; tuning noise
- [Case management](docs/case-management.md): Elastic Cases vs DFIR-IRIS, the alert bridge, enrichment
- [Threat intel](docs/threat-intel.md): free feeds and keys
- [UniFi port mirroring](docs/sensors/unifi-port-mirror.md): feeding the sensor NIC
- [Laptop test rig](docs/laptop-test.md): running moat on a laptop (sleep, lid, Wi-Fi)

## moat vs Security Onion

[Security Onion](https://securityonionsolutions.com/) is the mature, free, all-in-one NSM/SOC platform, and it covers far more than moat. Pick it if you have dedicated hardware and want everything: full packet capture, file analysis, distributed sensors, years of production use.

moat is the lightweight, learn-by-owning option:
- **Install:** runs as Docker Compose on a Linux box you already have (8–16 GB).
- **Interface:** uses Elastic's native Security app, the one many enterprise SOCs run.
- **Size:** small enough that you can read, understand and change every piece.

## Security notes

- **Secrets:** generated per install into `.env` (mode 600, git-ignored). Nothing is hardcoded, and credentials are never passed on process command lines.
- **CA key:** a local CA signs all service certs. Its private key stays in the `certs` volume, root-only; Caddy mounts only the Kibana cert and the public CA cert.
- **Accounts:** `analyst` is least privilege (SOC work only, no Stack Management or Fleet changes). `elastic` is the superuser for admin tasks.
- **Elastic Defend** uses the EDR Complete preset with Elastic's default protections, which **prevent** (e.g. quarantine malware). Switch protections to detect-only in Kibana if you'd rather only alert.
- **Least privilege for the bridge:** it reads Elasticsearch as a dedicated account (alerts and DHCP only). IRIS containers never receive Elastic secrets.
- **Supply chain:** images are pinned by version in `.env`; CI actions are pinned by commit SHA; the Sigma toolchain is hash-pinned; the SigmaHQ rule download is checksum-verified.

## License

TBD (MIT suggested). Elastic components are used under the free Elastic license tier.
