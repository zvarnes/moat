# moat

**moat** is a free, one-box home SOC for threat hunting with the same tools real SOCs use: **Elastic Security** (SIEM, detections, Timeline, Cases), **Fleet + Elastic Defend** (EDR telemetry), and soon **Zeek + Suricata** for network visibility.

> Status: **Phase 1 (core SIEM)**. Network sensing lands in Phase 2.

## Quick start

```bash
git clone https://github.com/<you>/moat && cd moat
./moat preflight     # RAM, disk, Docker, vm.max_map_count, ports, NICs
./moat init          # picks profile, detects LAN IP, generates secrets into .env
./moat up            # ES + Kibana + Fleet Server + Caddy, bootstraps Defend + rules
./moat enroll        # one-line agent installs for Linux / Windows / macOS
```

Then browse to `https://<HOST_IP>` and log in as `analyst` (`./moat creds`).

## What `up` builds

```
certs ──► es01 ──► setup ──► kibana ──► bootstrap ──► fleet-server
 (CA,      (TLS,     (kibana_system   (Fleet as    (Fleet setup, Defend,
 certs,    single    pw, fleet svc    code in      analyst user, prebuilt
 kibana.yml) node)   token)           kibana.yml)  rules)          caddy :443 ─► kibana
```

| Port | Service | Who connects |
| --- | --- | --- |
| 443 | Caddy → Kibana | You (browser); agents fetch the CA cert here |
| 8220 | Fleet Server | Elastic Agents (enroll + check-in) |
| 9200 | Elasticsearch | Elastic Agents (data) |

All ports bind only to `HOST_IP`. Don't port-forward them; use Tailscale/WireGuard for remote access.

## Profiles

| Profile | RAM | ES heap | Use |
| --- | --- | --- | --- |
| `standard` | 16 GB+ | 4 GB | Default |
| `lite` | 8 GB | 2 GB | Small labs, fewer endpoints |

## Commands

Run `./moat help`. Highlights: `status` (health, agents, event counts), `bootstrap` (re-run Fleet/Defend/rules setup), `sensor-prep <iface>` (capture-mode NIC), `destroy` (wipe everything).

## Docs

- [Laptop test rig](docs/laptop-test.md)
- [UniFi port mirroring to the sensor NIC](docs/sensors/unifi-port-mirror.md)

## Security notes

- Secrets are generated per install into `.env` (mode 600, git-ignored). Nothing is hardcoded.
- A local CA signs all service certs. Its private key stays in the `certs` volume, root-only; Caddy only mounts the Kibana cert and the public CA cert.
- `analyst` is for daily use; `elastic` is the superuser for admin tasks.
- Elastic Defend uses the EDR Complete preset with Elastic's default protections, which **prevent** (e.g. quarantine malware). Switch individual protections to detect in Kibana if you'd rather only alert.
- Images are pinned by version in `.env`. Pinning by digest is on the roadmap.

## License

TBD (MIT suggested). Elastic components are used under the free Elastic license tier.
