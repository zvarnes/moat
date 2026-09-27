# 3. Hunting 101

**Goal:** answer "what is this device doing?" from raw evidence, without any alert telling you where to look. About 30 minutes.

Everything here happens in **Discover** (Kibana main menu). Set the data view (top left) to **`logs-*`** and the time picker to **Last 24 hours**.

## Discover in 60 seconds

- **The search bar** takes KQL (Kibana Query Language): `field : "value"`, combined with `and`, `or`, `not`.
- **The left sidebar** lists fields. Click one to see its **top 5 values**. That's often the whole answer.
- **Hover a field → ⊕** to add it as a column, so the table becomes readable.
- **The histogram** shows *when* things happened. Drag across it to zoom in.

## Exercise 1: what does one device talk to?

Pick a device from the dashboard's *Top talkers* or *Device names* table.

```
data_stream.dataset : "zeek.connection" and source.ip : "<device IP>"
```

Click these fields in the sidebar, one at a time:
- `destination.as.organization.name`: which companies it talks to.
- `destination.geo.country_name`: which countries.
- `destination.port`: 443 (HTTPS) and 53 (DNS) are normal; anything unusual stands out.

**Ask:** does this fit what the device *is*? A smart plug talking to one vendor cloud is normal. A smart plug talking to 40 organizations isn't.

## Exercise 2: what did it look up?

```
data_stream.dataset : "zeek.dns" and source.ip : "<device IP>"
```

Click `dns.question.registered_domain`. Then switch the query to **all devices** (remove the `source.ip` part) and compare.

**Ask:** are there domains only *one* device looks up? Rare is more interesting than common.

## Exercise 3: which sites (even over HTTPS)?

Most traffic is encrypted, but the site name is visible in the TLS handshake:

```
data_stream.dataset : "zeek.ssl" and source.ip : "<device IP>"
```

Click `zeek.ssl.server.name`. This is how you know *which* site a device reached without decrypting anything.

## Exercise 4: is something checking in on a timer?

Malware often "beacons": it contacts its server at regular intervals. Pick a destination from exercise 1 that you don't recognize:

```
data_stream.dataset : "zeek.connection" and destination.ip : "<that IP>"
```

In the histogram, choose a **1-minute** interval. Evenly spaced bars, especially overnight when nobody's using the device, are worth a closer look. Most of the time it's an app syncing, and that's fine. You're learning what normal looks like.

## Exercise 5: what's new on the network?

```
data_stream.dataset : "zeek.dhcp"
```

Add `zeek.dhcp.hostname` and `client.address` as columns. Every device that joined, with its name. A new, unnamed device is something to identify.

## Save your work

When a query is useful, **Save** it (top right) with a clear name ("Device X: connections"). Saved searches can go onto a dashboard, or become a detection rule later (chapter 5).

## What you just learned

- Zeek logs are your ground truth: **connections, DNS, TLS names, DHCP**.
- The loop is: **start from a question → narrow with KQL → read the sidebar → pivot**.
- Rare beats common. Timing tells stories.

More queries: [hunting-101 reference](../hunting-101.md). Next: [4. Threat intel →](04-threat-intel.md)
