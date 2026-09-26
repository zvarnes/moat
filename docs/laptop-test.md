# Testing moat on a laptop

A laptop with 16 GB+ RAM, a built-in Ethernet port, and a USB Ethernet adapter is a good Phase 1–2 test rig:

| Interface | Role | Config |
| --- | --- | --- |
| Built-in Ethernet | Management: Kibana, Fleet, agent data | Normal LAN DHCP; give it a **DHCP reservation** in UniFi so `HOST_IP` never changes |
| USB-C Ethernet | Sensor: mirrored traffic | No IP, promiscuous (see `docs/sensors/unifi-port-mirror.md`) |
| Wi-Fi | Leave off | Avoids a second default route confusing `init` |

Prefer wired management over Wi-Fi: agents and Fleet need a stable address, and certificates are issued for `HOST_IP`.

## 1. Base OS

Ubuntu 24.04 (Server or Desktop) or Debian 12. Then:

```bash
sudo apt update && sudo apt install -y git curl ethtool tcpdump
# Docker Engine + compose plugin (official repo)
curl -fsSL https://get.docker.com -o get-docker.sh && less get-docker.sh   # read it first
sudo sh get-docker.sh
sudo usermod -aG docker "$USER" && newgrp docker

# Elasticsearch kernel requirement
echo 'vm.max_map_count=262144' | sudo tee /etc/sysctl.d/99-moat.conf
sudo sysctl --system
```

## 2. Keep the laptop awake with the lid closed

```bash
sudo mkdir -p /etc/systemd/logind.conf.d
printf '[Login]\nHandleLidSwitch=ignore\nHandleLidSwitchExternalPower=ignore\nHandleLidSwitchDocked=ignore\n' \
  | sudo tee /etc/systemd/logind.conf.d/moat.conf
sudo systemctl restart systemd-logind
# Desktop only: stop idle suspend
sudo systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target
```

Keep it on AC power; Elasticsearch doesn't like surprise shutdowns.

## 3. Bring up Phase 1

```bash
git clone <your repo> moat && cd moat
./moat preflight
./moat init            # accept the detected IP if it's the built-in NIC's address
./moat up              # first run: ~5–10 min
./moat status
./moat creds
```

Open `https://<HOST_IP>` and log in as `analyst`. The browser warns about the certificate because it's signed by the box's own CA. To trust it, import `https://<HOST_IP>/moat-ca.crt` into your OS/browser trust store after checking its fingerprint matches `./moat enroll`.

## 4. Enroll a first endpoint

Run `./moat enroll` and paste the Linux or Windows commands on another machine (or the laptop itself). Within a couple of minutes:

- **Fleet → Agents** shows it Healthy.
- **Security → Explore → Hosts** shows events.
- `./moat status` shows non-zero `logs-*` counts.

## 5. Phase 1 exit test

Trigger a known-benign Defend detection on a Linux endpoint:

```bash
# EICAR test string: harmless, flagged by every AV/EDR
echo 'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' > /tmp/eicar.com
```

Defend will quarantine the file and an alert should appear under **Security → Alerts** within a minute or two. Record in the plan doc:

- `docker stats --no-stream` RAM per container at idle and after 1 hour
- `du -sh` of the `moat_esdata` volume after 24 hours (GB/day)

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `es01` restarts | `./moat logs es01`; usually `vm.max_map_count` or heap > `ES_MEM_LIMIT` |
| `bootstrap` failed | `./moat logs bootstrap`, fix, then `./moat bootstrap` |
| Agent stuck "Enrolling" | Endpoint can reach `https://HOST_IP:8220`? Firewall (`ufw allow 8220,9200,443/tcp`)? |
| Agent healthy but no data | Endpoint can reach `https://HOST_IP:9200`? CA fingerprint in Fleet output matches? |
| Changed `HOST_IP` | Certs embed the IP: `./moat destroy`, `init --force`, `up`, re-enroll agents |
