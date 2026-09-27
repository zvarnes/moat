# 4. Threat intel

**Goal:** see how a threat-intel feed turns an ordinary DNS lookup into a high-severity alert, and learn to judge whether a match matters. About 20 minutes.

Requires at least one feed key in `.env`. See [threat-intel.md](../threat-intel.md) (free abuse.ch / OTX / VirusTotal accounts).

## Are feeds loaded?

Dashboard → **Threat intel indicators loaded** should be in the thousands. You can also check in Discover:

```
event.kind : "enrichment" and threat.indicator.type : *
```

Click `threat.indicator.type` (domain-name, url, ipv4-addr, file…) and `data_stream.dataset` (which feed).

## Trigger a match

```bash
./moat lab threat-intel
```

This adds one **harmless test indicator**, a made-up `moat-lab-….example.com` "listed" in a lab feed, then looks it up. In about 5 minutes: **"moat: DNS lookup of a threat-intel domain: moat-lab-….example.com"**, severity **high**.

## Read the match

Open the alert in Kibana:
- the **Threat intelligence** section / tab: *what* matched (`matched.atomic`), *on which field* (`dns.question.name`), and *from which feed* (the provider);
- `source.ip`: which device looked it up.

You'll likely see **several alerts for one lookup**. Your device asks for IPv4 and IPv6 addresses separately, and your router or DNS forwarder repeats the question upstream. The device that actually matters is the one that's *not* your router or DNS server.

In IRIS the alert title already includes the domain, and the domain is an IOC. With a VirusTotal key, open the IOC and run the VirusTotal module to see its reputation.

## Judging a real match

A match is a **lead, not a verdict**. Before calling it an incident:

1. **What kind of indicator?** A listed *domain* (`domain-name`) is strong. A listed *URL* usually points at one bad file on a big site (github.com, discord's CDN). moat's domain rule deliberately ignores those, or everyone who uses GitHub would "match".
2. **Which device, and does it make sense?** A lookup from a PC is more interesting than from your DNS server repeating it.
3. **Did it connect?** A lookup isn't a download. Check Zeek for a connection or TLS session to the answer:
   ```
   data_stream.dataset : ("zeek.connection" or "zeek.ssl") and source.ip : "<device>"
   ```
   around the alert's time.
4. **How fresh is the indicator?** Feeds age out. An old listing for a domain that's since been cleaned up is weak.

## Clean up

```bash
./moat lab cleanup
```

Then close the lab alerts in Kibana and IRIS (resolution: *not applicable / test*).

## What you just learned

- Feeds are lists; rules compare every lookup, connection, URL and hash against them.
- **Domain-type** indicators make good alerts. URL-type ones need the full URL, not just the host.
- Confirm with evidence: *which device, did it connect, how fresh*.

Next: [5. Your first detection →](05-first-detection.md)
