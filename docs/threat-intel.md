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
| `CENSYS_API_KEY` | Censys | Context on external IPs in IRIS: owner (ASN), open ports and services, reverse DNS, labels (free-tier limits vary: check your account) | https://platform.censys.io/ → account → *Personal Access Tokens* |

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

## Censys: who is this IP?

With `CENSYS_API_KEY` set, the bridge looks up each **external IP** in an alert and writes a one-line summary into IRIS, on the IOC's description and in the alert text. For example: `AS64500 Example Hosting (US); open: 22/SSH, 443/HTTP; labels: scanner`. That answers "what is on the other end?" without leaving IRIS.

The free Censys tier allows 100 lookups a month, so the bridge is frugal by default:
- one lookup per IP, cached for 30 days, and only one request at a time;
- a monthly cap, `CENSYS_MONTHLY_LIMIT` (default 100, the free tier). Raise it on a paid plan, or set `0` to remove the cap. Once the month's budget is used, alerts still reach IRIS, just without the Censys line;
- a 10-minute pause if Censys ever answers "too many requests" (HTTP 429);
- only IPs in alerts that reach IRIS are looked up, so quiet rules also mean fewer lookups.

Two things to know. The IP address you look up is sent to Censys, so leave the key blank if you don't want that. And a failed or over-budget lookup never delays an alert; it just arrives without the summary. The bridge log (`./moat logs bridge`) shows lookups used this month at startup.

## Tips

- **Subscribe to OTX pulses selectively.** Pulses for everything drown you in low-quality indicators.
- **A match is a lead, not a verdict.** Shared hosting and CDNs mean a listed IP can also serve legitimate sites. Check the domain, the time and the device before calling it an incident.
