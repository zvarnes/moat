# 6. Tuning noise

**Goal:** make alerts rare enough that you read every one, without blinding yourself. About 20 minutes, then a few minutes a week.

Every home network has its own noise: game clients, video calls, smart-home chatter. An alert queue you ignore is worse than none, but every rule you disable is a blind spot. Tuning means removing noise *precisely*.

## Step 1: measure before you touch anything

Which rules fire most? In **Security → Alerts**, open the **Counts** or **Treemap** view, grouped by rule name, over the last 7 days. For raw IDS hits (including the ones that don't raise alerts), the dashboard's **Informational IDS hits** panel shows the busiest signatures.

For the top offender, look at 3–5 examples. Are they all the same benign thing?

## Step 2: pick the narrowest fix

| The noise is… | Fix | Where |
| --- | --- | --- |
| **One device or domain** that's always fine (your NAS talking to its vendor) | a **rule exception** (only that case is ignored; the rule still fires for everything else) | Kibana: open the alert → **Take action → Add rule exception** |
| **One signature** that's never useful here | **disable that signature** by SID, with a comment saying why | `sensors/suricata/disable.conf`, then `./moat rules apply` |
| **A whole rule** that doesn't fit your network | **disable the rule** | Kibana → Security → Rules (moat keeps your choice across re-applies for Sigma rules) |
| **Informational** hits cluttering views | nothing: severity-3 hits never alert | use the dashboard's split panels |

Always prefer the row higher in the table: it hides less.

## Step 3: don't disable by pattern without checking

It's tempting to silence a whole family ("all *Observed … in TLS SNI* rules"). Check what else the pattern matches first:

```bash
docker compose --env-file .env --profile sensor exec suricata grep -cE '<your pattern>' /var/lib/suricata/rules/suricata.rules
```

On a real moat install, one such pattern matched ~3,100 rules, including ones for known threat-actor domains and credential theft. That trade isn't worth it.

## Real examples from moat's own tuning

These are in `sensors/suricata/disable.conf`, each with its reason:

- **"DNS query to .to / .cc / .life TLD" rules:** they judge a lookup only by its ending. They fired on link shorteners and app backends. Threat-intel feeds judge the actual domain, which is far better.
- **STUN, Telegram, Discord, Tailscale "observed" signatures:** these log that a service was used, not an attack, and Zeek already records every DNS name and TLS site.
- **SSDP "amplification scan":** it was ordinary UPnP discovery to the router.
- **Suricata "STREAM" anomalies:** mostly capture artifacts. (Part of that was a mirror-port VLAN issue, now fixed in moat.)

Note what's **not** there: anything disabled "just in case". Each entry was investigated first.

## Step 4: write it down

Every tuning change gets a one-line reason (a comment in `disable.conf`, or the exception's description). Six months from now, "why is this off?" should have an answer.

## What you just learned

- Measure → look at examples → apply the **narrowest** fix → document it.
- Exceptions beat disables. Specific SIDs beat patterns.
- Quiet is the goal, blind is the risk.

Next: [7. A routine that sticks →](07-routine.md)
