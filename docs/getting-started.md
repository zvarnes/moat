# Getting started: your first hour with moat

This walks you from a fresh `./moat up` to triaging a real alert and opening a case. No prior SOC experience needed.

## 1. Log in

```bash
./moat creds
```

| What | Where | Log in as |
| --- | --- | --- |
| Kibana (SIEM, hunting, dashboards) | `https://<HOST_IP>` | `analyst` for daily work, `elastic` for admin |
| DFIR-IRIS (cases, tickets) | `https://<HOST_IP>:8443` | `administrator` |

Your browser will warn about the certificate. moat uses its own local certificate authority. Either accept the warning, or install `https://<HOST_IP>/moat-ca.crt` as a trusted CA on your machine. (Over Tailscale, `tailscale serve` gives you a real certificate; see the README.)

## 2. Check it's healthy

```bash
./moat status
```

You want:
- a **green** cluster;
- agents **online**;
- IRIS **healthy**;
- a recent **bridge last poll**;
- event counts that aren't zero.

To prove the whole detection chain works end to end, run this from any device on the mirrored network:

```bash
curl http://example.com/moat-test-canary
```

Within about 5 minutes, a **high**-severity alert called *"moat TEST sensor canary"* appears in Kibana → Security → Alerts, and a minute later in IRIS → Alerts. That single request exercised the whole chain: mirror → Suricata → Elasticsearch → detection rule → bridge → IRIS.

## 3. Tour the dashboard

Kibana → **Dashboards → "moat: Home Network"**:

- **Headline numbers:** open alerts, active devices, DNS lookups, what your router blocked.
- **Top talkers / Device names:** which IP is which device (names come from DHCP).
- **Top DNS domains / HTTPS sites / organizations / countries:** where your traffic goes.
- **Suricata alerts:** *every* IDS hit, including low-severity ones that don't raise an alert.
- **UDM blocks and IPS:** what the router stopped.
- **Threat intel:** indicators loaded, and any device that touched one.

Click any value (an IP, a domain) and choose **Filter for value**, and the whole dashboard narrows to it. That's the fastest way to start investigating.

## 4. Triage an alert

Kibana → **Security → Alerts**. For each alert, ask four questions:

1. **Who?** `source.ip`. Match it to a device name in the dashboard's DHCP table.
2. **What?** The rule name and `reason`. Open the alert (the ⤢ icon) for the full event.
3. **Where?** `destination.ip` or domain. Is it a company you'd expect this device to talk to?
4. **Normal?** Click **Investigate in timeline** and look at what else that device did around the same time.

Then decide:
- **Benign:** close it. If it will keep happening, add a rule exception (alert menu → *Add rule exception*).
- **Suspicious:** escalate to a case (next step).

## 5. Work the case in IRIS

Every medium-or-higher alert is already waiting in **IRIS → Alerts**. The bridge put it there with the IPs, domains and URLs as IOCs, and the device as an asset.

- **Similar alerts** (on the alert page) shows other alerts sharing an IOC. It's your quickest "is this a pattern?" check.
- **Escalate** turns one or more alerts into a **case**. There you get:
  - a timeline;
  - tasks you can assign;
  - notes and evidence;
  - IOCs and assets cross-referenced across all your cases.
- **Enrichment:** with a free VirusTotal key, IOCs get VirusTotal reputation data. See [threat-intel.md](threat-intel.md).

## Next

- [Hunting 101](hunting-101.md): find things no rule told you about.
- [Writing detections](writing-detections.md): turn what you found into a rule.
- [Case management](case-management.md): how Elastic Cases and IRIS fit together.
