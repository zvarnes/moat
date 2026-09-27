# 1. A first look

**Goal:** log in, confirm everything is healthy, and understand what the dashboard is telling you. About 15 minutes.

## Log in

```bash
./moat creds
```

- **Kibana** (where you'll spend most of your time): `https://<HOST_IP>`, as **`analyst`**. Use `elastic` only for admin tasks.
- **IRIS** (cases): `https://<HOST_IP>:8443`, as **`administrator`**.

> **Tip:** pick *one* address for Kibana and stick with it (the LAN IP, or your Tailscale name if you use one). Browsers keep a separate login per address. If you use another name, set `KIBANA_PUBLIC_URL` in `.env` so links in IRIS match it.

Your browser will warn about the certificate. moat uses its own local certificate authority, so accept the warning, or install `https://<HOST_IP>/moat-ca.crt` as a trusted CA.

## Check health

```bash
./moat status
```

| Line | Healthy looks like | If not |
| --- | --- | --- |
| cluster status | `green` | yellow for a few seconds after changes is normal; see `./moat logs es01` |
| Fleet agents | `online` | `degraded` for ~10 minutes after a fresh install is normal |
| IRIS | `healthy` | `./moat logs iris-app` |
| bridge last poll | a time within the last minute or two | `./moat logs bridge` |
| Events in the last 15 minutes | thousands of `logs-*` | 0 means the sensor sees nothing; check the mirror port |

## Tour the dashboard

In Kibana: **Dashboards → "moat: Home Network"**. Set the time picker (top right) to **Last 24 hours**.

Read it top to bottom and answer these for your own network. Jot the answers down, because they're your *baseline*: what normal looks like.

1. **Active devices:** how many? Does that match the number of things you own?
2. **Device names (from DHCP):** anything you don't recognize?
3. **Top talkers to the internet:** which device moves the most data? Does it make sense (a TV streaming, a PC updating)?
4. **Top DNS domains / Top HTTPS sites / Traffic by organization:** your network's "normal". Most of it will be Google, Apple, Microsoft, Amazon, Cloudflare and CDNs.
5. **Countries contacted:** mostly your own country plus big cloud regions is typical.
6. **IDS alerts (high/medium)** and **UDM firewall blocks:** usually short lists. The router blocks inbound probes all day, which is normal internet background.

**Try this:** click a device IP in *Top talkers* → **Filter for value**. The whole dashboard now shows only that device. Remove the filter pill at the top when you're done.

## What you just learned

- Everything on the dashboard comes from three sources: **Zeek** (connections, DNS, TLS…), **Suricata** (signature hits) and your **router's logs**.
- A dashboard answers "what's normal?" Alerts (next chapter) answer "what's worth a look right now?"

Next: [2. Your first alert →](02-first-alert.md)
