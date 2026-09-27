# Writing detections

moat supports the three rule formats you'll meet in real SOCs. Pick by *what you're matching*:

| You want to match… | Use | Lives in | Language |
| --- | --- | --- | --- |
| Log records (DNS lookups, connections, HTTP, router events) | **Sigma** | `sigma/moat/*.yml` | Sigma YAML → converted to Elastic |
| Packet contents on the wire | **Suricata rules** (Snort-style) | `sensors/suricata/local.rules` | Suricata/Snort signature |
| Sequences, thresholds, "first time seen", threat-intel matching | **Elastic native** | `rules/*.json` | Kibana rule JSON (KQL / EQL / ES\|QL) |

Sigma and Suricata/Snort rules are portable: what you write here works in other SIEMs and IDSes. Elastic-native rules are for things only Elastic can do.

**YARA** is the other big name. It matches *file contents* (malware), not logs or packets, so it doesn't fit here yet. It's a planned add-on: Zeek extracts files from traffic, and YARA scans them.

## The loop

```bash
./moat rules test                 # converts Sigma (prints the Elastic query), checks Suricata + JSON rules
./moat rules test sigma/moat/my_rule.yml   # just one file
./moat rules apply                # installs everything and live-reloads Suricata
```

`rules test` installs nothing. Use it as you write. `rules apply` takes about a minute.

## Sigma

Start by copying a starter rule. They're commented line by line:
- `sigma/moat/dns_dynamic_dns_provider.yml`: DNS lookups (the most useful home data)
- `sigma/moat/zeek_conn_smb_to_internet.yml`: connections, with CIDR matching
- `sigma/moat/zeek_http_scripting_user_agent.yml`: HTTP, and a `level: low` rule that installs **disabled**

How moat converts your rule:
- **Logsource:** use `product: zeek` + `service: dns|conn|http|ssl|files|…`, or `category: dns`. moat only has data for these, so other logsources are skipped with a message.
- **Field names:** use Zeek's names (`query`, `id.orig_h`, `id.resp_p`, `user_agent`). They're mapped to Elastic's fields automatically (`dns.question.name`, `source.ip`, …) via the `ecs_zeek_beats` pipeline plus `sigma/pipelines/moat.yml`. `./moat rules test` prints the resulting query, so you can check it.
- **Safety check:** if a field can't be mapped, the rule is **rejected, not installed**, because a rule that can never match is worse than none. Add the mapping to `sigma/pipelines/moat.yml`.
- **Level:** `medium` and above install **enabled**. `informational`/`low` install disabled (enable in Kibana → Security → Rules when you want to hunt with them).
- **ID:** each rule's `id` becomes rule id `moat-sigma-<id>`. Keep it unique and never change it.
- **Your choices stick:** if you enable or disable a Sigma rule in Kibana, re-applying keeps your choice.

**Community rules:** with `SIGMA_COMMUNITY=network` (the default), moat installs SigmaHQ's Zeek and DNS rules from a pinned, checksum-verified release, **disabled**. Browse them in Security → Rules (filter by tag `Sigma: sigmahq`) and enable what fits your network. They're licensed under the [Detection Rule License 1.1](https://github.com/SigmaHQ/Detection-Rule-License).

Sigma reference: https://sigmahq.io/docs/basics/rules.html

## Suricata (Snort-style) rules

Edit `sensors/suricata/local.rules`. It contains:
- **a test canary:** `curl http://example.com/moat-test-canary` triggers it;
- **a dynamic-DNS TLS rule;**
- **commented templates.**

Rules:
- **Use SIDs 9000000–9999999**, and bump `rev:` when you edit.
- **`priority:1` or `2` raises a moat alert.** `3` stays searchable only.
- **Don't write rule-shaped comments with a real SID.** `suricata-update` treats a commented rule as a *disabled rule*, and a duplicate SID silently replaces your real one. `rules test` catches this.
- **After `rules apply`, give Suricata a minute to reload** about 53k rules before testing.

Suricata reads most Snort rules as-is, so Snort tutorials apply. Reference: https://docs.suricata.io/en/latest/rules/

## Elastic-native rules

Files in `rules/` are Kibana detection-rule JSON, created or updated by bootstrap (the file wins over UI edits). Examples:
- `moat-suricata-alert.json`: promotes Suricata severity 1–2 to alerts
- `moat-ti-domain-match.json`: an **indicator match** rule (DNS vs threat intel)
- `moat-unifi-ips.json`: router IPS events, with severity mapped from a field

The easy way to write one: build it in Kibana → Security → Rules → **Create new rule**, test it, then export it and trim it into `rules/`.

## Tuning noise

- **Suricata signature that's always benign:** add its SID to `sensors/suricata/disable.conf` with a comment explaining why, then `./moat rules apply`.
- **One device or domain that's always fine:** add a rule *exception* in Kibana (alert menu → Add rule exception).
- **Before disabling anything, ask whether it's really noise.** Every entry in `disable.conf` is a blind spot. The first day's "SSDP amplification" noise turned out to be UPnP discovery, and the "STREAM" noise turned out to be a mirror VLAN bug.
