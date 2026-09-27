# Hunting 101

Alerts tell you what a rule already knew to look for. Hunting is looking for what it didn't. All of this happens in Kibana → **Discover**, with the `logs-*` data view and a sensible time range such as "Last 24 hours".

## The data you have

| Dataset (`data_stream.dataset`) | What it is | Key fields |
| --- | --- | --- |
| `zeek.connection` | Every network connection | `source.ip`, `destination.ip`, `destination.port`, `network.bytes`, `event.duration` |
| `zeek.dns` | Every DNS lookup | `dns.question.name`, `dns.question.registered_domain`, `source.ip` |
| `zeek.ssl` | Every TLS handshake | `zeek.ssl.server.name` (the site name), `tls.version` |
| `zeek.http` | Plain-HTTP requests | `url.original`, `user_agent.original`, `http.response.status_code` |
| `zeek.dhcp` | Which device got which IP | `zeek.dhcp.hostname`, `client.address` |
| `zeek.files`, `zeek.x509`, `zeek.notice`, … | Files, certificates, Zeek's own notices | |
| `suricata.eve` | IDS alerts + protocol events | `rule.name`, `event.severity` (1 = high), `event.kind: alert` |
| `cef.log` | Your router (UniFi) | `cef.name`, `cef.extensions.UNIFI*` |

Everything related to one connection shares a `network.community_id`, across Zeek *and* Suricata.

## Starter queries (paste into Discover's search bar)

**What does one device talk to?**
```
data_stream.dataset : "zeek.connection" and source.ip : "192.168.1.50"
```
In the left sidebar, click `destination.as.organization.name`, then `destination.geo.country_name`. Anything surprising for that device (a TV talking to a VPS provider, a camera talking to another country)?

**Every lookup of a domain, and who asked**
```
data_stream.dataset : "zeek.dns" and dns.question.registered_domain : "telegram.org"
```

**Rare domains** (things only one device looks up are more interesting than google.com):
Query `data_stream.dataset : "zeek.dns"`, then click `dns.question.registered_domain` in the sidebar → *Visualize* → sort ascending by count.

**Beaconing** (malware often checks in on a fixed interval):
```
data_stream.dataset : "zeek.connection" and destination.ip : "<suspicious IP>"
```
Switch the histogram to 1-minute buckets. Evenly spaced bars at night, when nobody's using the device, are a classic sign.

**Suricata hits that didn't become alerts** (severity 3, informational):
```
data_stream.dataset : "suricata.eve" and event.kind : "alert" and event.severity : 3
```

**Pivot from an alert to the raw connection:**
Copy `network.community_id` from any Suricata alert, then:
```
network.community_id : "1:Qj4biCowcBfc6cBEpgXwAG2qGoo="
```
You get Zeek's connection record (bytes, duration) next to Suricata's view.

**What did the router block?**
```
data_stream.dataset : "cef.log" and cef.name : "Blocked by Firewall"
```

## Habits that make hunting work

- **Start from a question** ("does anything talk to the internet at 3 a.m.?"), not from the data.
- **Know normal first.** Spend a week just looking, and the abnormal starts standing out.
- **Write down what you find**, even "this is normal." A note in an IRIS case works.
- **Turn repeat findings into rules.** See [writing-detections.md](writing-detections.md).
