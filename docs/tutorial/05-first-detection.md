# 5. Your first detection

**Goal:** turn something you care about into a rule: write it in Sigma, test it, deploy it and watch it fire. About 30 minutes.

The scenario: you want to know whenever any device looks up a particular domain. Maybe one from a news report about a campaign, or a service you've banned at home. We'll use a harmless placeholder: `moat-tutorial.example.org`.

## 1. Copy a starter rule

```bash
cp sigma/moat/dns_dynamic_dns_provider.yml sigma/moat/dns_watched_domain.yml
```

## 2. Edit it

Open `sigma/moat/dns_watched_domain.yml` and change it to:

```yaml
title: DNS lookup of a watched domain
id: <generate one: python3 -c "import uuid; print(uuid.uuid4())">
status: experimental
description: A device looked up a domain on my watch list.
author: <you>
date: 2026-01-01
logsource:
  product: zeek
  service: dns
detection:
  selection:
    query|endswith:
      - 'moat-tutorial.example.org'
  condition: selection
falsepositives:
  - None expected
level: medium
```

The four parts:
- **`logsource`:** *where* to look (Zeek's DNS log);
- **`detection`:** *what* to match. `query` is Zeek's name for the looked-up domain, and `|endswith` also catches subdomains;
- **`level`:** medium and above install **enabled**; low installs disabled (hunting only);
- **`id`:** permanent and unique. moat installs the rule as `moat-sigma-<id>`.

## 3. Test it

```bash
./moat rules test sigma/moat/dns_watched_domain.yml
```

You'll see the Elastic query it becomes:

```
event.dataset:zeek.dns AND dns.question.name:*moat\-tutorial.example.org
```

If a field can't be mapped to moat's data, the test **fails** and tells you why. moat won't install a rule that could never fire.

## 4. Deploy it

```bash
./moat rules apply
```

In Kibana → **Security → Rules**, search "watched domain". It's there, enabled, tagged `Sigma: moat`.

## 5. Make it fire

From any device on the mirrored network:

```bash
nslookup moat-tutorial.example.org
```

About 5 minutes later: **"Sigma: DNS lookup of a watched domain"** in Security → Alerts, and in IRIS with the domain in the title.

## Bonus: the same idea on the wire (Suricata)

Sigma matches **logs**. Suricata rules match **packets** and use the classic Snort syntax. Add to `sensors/suricata/local.rules`:

```
alert dns $HOME_NET any -> any any (msg:"moat watched domain (DNS)"; dns.query; content:"moat-tutorial.example.org"; nocase; endswith; priority:2; sid:9000200; rev:1;)
```

```bash
./moat rules test && ./moat rules apply
```

Give Suricata a minute to reload, then look the domain up again. You'll get a second alert, from the network side.

**When to use which:** Sigma for anything Zeek or your router *logs*, which covers most things. Suricata when you need **packet contents**: a string in an HTTP request, a TLS certificate detail, a byte pattern. More in [writing-detections](../writing-detections.md).

## Clean up (or keep it)

Keep the rule if it's useful. To remove it, delete the file, run `./moat rules apply`, then delete the rule in Kibana → Rules. Commit rules you keep to git: they're code.

## What you just learned

- Detections are **files you version**, test and deploy, not clicks in a UI.
- `./moat rules test` shows exactly what a rule becomes, and rejects rules that can't work.
- Sigma for logs, Suricata for packets.

Next: [6. Tuning noise →](06-tuning.md)
