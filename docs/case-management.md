# Case management: Elastic Cases and DFIR-IRIS

moat has two places to track an investigation. They serve different needs.

| | Elastic Cases (Kibana → Security → Cases) | DFIR-IRIS (`https://<HOST_IP>:8443`) |
| --- | --- | --- |
| Best for | Quick notes on an alert, solo work | Real incident handling: triage queue, cases, tasks, evidence, IOC tracking |
| Assign to people | ❌ paid Elastic tiers only | ✅ |
| Alert inbox with triage workflow | Alerts page | ✅ IRIS Alerts (fed automatically) |
| IOC cross-referencing across cases | ❌ | ✅ "similar alerts", case IOC links |
| Enrichment (VirusTotal, MISP) | ❌ | ✅ modules |
| Cost | Free (Basic) | Free (LGPL-3.0) |

**Rule of thumb:** triage in Kibana, investigate in IRIS.

## How alerts get into IRIS

The `bridge` service checks Kibana every minute for **open** alerts at or above `BRIDGE_MIN_SEVERITY` (default `medium`; set it in `.env`). It creates one IRIS alert each, with:
- **title and severity** from the detection rule;
- **a link back** to the exact alert in Kibana;
- **IOCs:** external IPs, domains, URLs and file hashes from the alert;
- **assets:** internal IPs, named from DHCP where known ("living-room-tv" rather than "192.168.1.50");
- **the full alert document**, for reference.

The bridge remembers what it sent, so restarts never create duplicates. Closing an alert in Kibana doesn't change IRIS; triage it there too, or just work from IRIS.

```bash
./moat status        # "bridge last poll" shows it's alive
./moat logs bridge   # what it forwarded
```

## Working an alert in IRIS

1. **Alerts:** new alerts arrive with status *New*. Check **Similar alerts** for others that share an IOC or asset.
2. **Escalate** one or more alerts into a **case**. Their IOCs and assets carry over.
3. In the case:
   - **Timeline:** what happened, in order.
   - **Tasks:** what to check, assigned to people.
   - **Notes:** findings.
   - **Evidence:** files and screenshots.
4. **Close** the case with a resolution. IOCs stay searchable, so the next time one appears, IRIS links it to this case.

## Enrichment

- **VirusTotal:** put a free key in `.env` as `VT_API_KEY`, then `./moat up`. The bridge configures IRIS's VirusTotal module for you. The free public API allows about 500 lookups a day, which is plenty for a home SOC.
- **MISP:** IRIS's MISP module is installed. Configure it in IRIS → Advanced → Modules if you run a MISP instance.

## Users

The `administrator` account is created at first start (`./moat creds`). For day-to-day use, create personal accounts in IRIS → Advanced → Access control, and keep `administrator` for admin work.
