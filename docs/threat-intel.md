# Threat intel: free feeds and enrichment

Threat intel tells you *who is known-bad*. moat uses it in two ways:

1. **Matching (Elastic):** every DNS lookup, connection, URL and file hash is compared against indicator feeds. A hit becomes a **high** alert (*"moat: DNS lookup of a threat-intel domain"*, *"Threat Intel IP Address Indicator Match"*, …).
2. **Enrichment (IRIS):** when you investigate an IOC, VirusTotal adds reputation data.

Each source needs a free account. Put the keys in `.env`, run `./moat up`, and moat wires everything up. Sources without a key are skipped.

| `.env` key | Source | What you get | Sign up |
| --- | --- | --- | --- |
| `ABUSECH_AUTH_KEY` | abuse.ch | ThreatFox (IOCs), URLhaus (malicious URLs), MalwareBazaar (malware hashes), SSLBL (bad certificates) | https://auth.abuse.ch/ → sign in → *Auth-Key* |
| `OTX_API_KEY` | AlienVault OTX | Indicators from the "pulses" you subscribe to | https://otx.alienvault.com/ → Settings → *OTX Key* |
| `VT_API_KEY` | VirusTotal | IOC reputation inside IRIS (public API: ~500 lookups/day) | https://www.virustotal.com/ → profile → *API key* |

After adding keys:

```bash
./moat up
./moat status    # the dashboard's "Threat intel indicators loaded" should climb within ~30 min
```

## How matching works

- **Feed storage:** feeds land in `logs-ti_*`. Each integration expires old indicators automatically, so the index doesn't grow forever.
- **Enabled rules:** once any feed key is set, bootstrap enables Elastic's prebuilt indicator-match rules for **IPs, URLs and file hashes**, plus moat's own **domain** rule (DNS lookups vs listed domains).
- **Historical look-back:** indicator-match rules look back over recent data. A newly listed domain matches a lookup your network made *before* it was listed, if the lookup is still within the rule's look-back window.
- **Where hits show up:** Security → Alerts, the dashboard's *Threat intel matches* table, and IRIS (via the bridge).

## Tips

- **Subscribe to OTX pulses selectively.** Pulses for everything drown you in low-quality indicators.
- **A match is a lead, not a verdict.** Shared hosting and CDNs mean a listed IP can also serve legitimate sites. Check the domain, the time and the device before calling it an incident.
