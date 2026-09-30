#!/usr/bin/env python3
"""moat bridge: Elastic Security alerts -> DFIR-IRIS alerts.

Every POLL_SECONDS, reads open Security alerts at or above BRIDGE_MIN_SEVERITY and
creates one IRIS alert each: title, severity, a link back to the Kibana alert, the
alert document, IOCs (IPs, domains, URLs, hashes) and assets (internal IPs, named
from Zeek's DHCP log). IRIS then links alerts that share IOCs ("similar alerts"),
and its VirusTotal module enriches IOCs when VT_API_KEY is set. External IPs are also
looked up in Censys when CENSYS_API_KEY is set (cached, with a monthly budget).

Python standard library only. Reads ES as the least-privilege moat_bridge user.
State (forwarded alert ids + high-water mark) lives in /state so restarts never
duplicate.
"""
import base64
import ipaddress
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from urllib.parse import quote

ES_URL = os.environ["ES_URL"]
ES_AUTH = "Basic " + base64.b64encode(f"moat_bridge:{os.environ['BRIDGE_ES_PASSWORD']}".encode()).decode()
IRIS_URL = os.environ["IRIS_URL"].rstrip("/")
IRIS_KEY = os.environ["IRIS_API_KEY"]
KIBANA = os.environ.get("KIBANA_PUBLIC_URL", "").rstrip("/")
VT_KEY = os.environ.get("VT_API_KEY", "").strip()
CENSYS_KEY = os.environ.get("CENSYS_API_KEY", "").strip()
CENSYS_ORG = os.environ.get("CENSYS_ORG_ID", "").strip()
CENSYS_LIMIT = int(os.environ.get("CENSYS_MONTHLY_LIMIT", "100"))
CENSYS_URL = "https://api.platform.censys.io/v3/global/asset/host/"
CENSYS_TTL = timedelta(days=30)
MIN_SEV = os.environ.get("BRIDGE_MIN_SEVERITY", "medium").lower()
POLL_SECONDS = int(os.environ.get("POLL_SECONDS", "60"))
STATE_FILE = "/state/state.json"
CUSTOMER = "moat home"
SEVERITIES = ["low", "medium", "high", "critical"]
ES_CTX = ssl.create_default_context(cafile="/certs/public/ca.crt")


def log(msg):
    print(f"[moat:bridge] {msg}", flush=True)


# ---------------------------------------------------------------- HTTP
def request(method, url, body=None, headers=None, ctx=None, timeout=30):
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(url, data=data, method=method, headers={
        "Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(req, context=ctx, timeout=timeout) as r:
        raw = r.read()
    return json.loads(raw) if raw else {}


def es(method, path, body=None):
    return request(method, ES_URL + path, body, {"Authorization": ES_AUTH}, ES_CTX)


def iris(method, path, body=None):
    res = request(method, IRIS_URL + path, body, {"Authorization": f"Bearer {IRIS_KEY}"})
    if res.get("status") != "success":
        raise RuntimeError(f"IRIS {path}: {res.get('message')} {res.get('data')}")
    return res.get("data")


# ---------------------------------------------------------------- field access
def flatten(doc, prefix=""):
    """Alert docs mix flat dotted keys ("kibana.alert.severity") and nested objects
    ("source": {"ip": ...}). Flatten once so every field is one dotted key."""
    out = {}
    for k, v in doc.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(flatten(v, key + "."))
        else:
            out[key] = v
    return out


def first(value):
    return value[0] if isinstance(value, list) and value else value


def is_private(ip):
    try:
        a = ipaddress.ip_address(ip)
        return a.is_private or a.is_link_local
    except ValueError:
        return False


# ---------------------------------------------------------------- IRIS setup
class Lookups:
    def __init__(self):
        def by_name(path, id_key, name_key):
            return {str(i[name_key]).lower(): i[id_key] for i in iris("GET", path)}
        self.severity = by_name("/manage/severities/list", "severity_id", "severity_name")
        self.status = by_name("/manage/alert-status/list", "status_id", "status_name")
        self.ioc_type = by_name("/manage/ioc-types/list", "type_id", "type_name")
        self.tlp = by_name("/manage/tlp/list", "tlp_id", "tlp_name")
        self.asset_type = by_name("/manage/asset-type/list", "asset_id", "asset_name")
        self.customer = self._customer()
        self.asset_default = next((v for k, v in self.asset_type.items() if "other" in k),
                                  next(iter(self.asset_type.values())))

    @staticmethod
    def _customer():
        for c in iris("GET", "/manage/customers/list"):
            if c.get("customer_name") == CUSTOMER:
                return c["customer_id"]
        c = iris("POST", "/manage/customers/add", {
            "customer_name": CUSTOMER, "customer_description": "Home network monitored by moat",
            "customer_sla": ""})
        log(f"created IRIS customer '{CUSTOMER}'")
        return c["customer_id"]


def configure_virustotal():
    if not VT_KEY:
        log("VT_API_KEY not set; VirusTotal enrichment off (add a free key to .env)")
        return
    mods = iris("GET", "/manage/modules/list")
    # IRIS 2.4 lists it as module_human_name "IrisVT" (no "VirusTotal" anywhere).
    mod = next((m for m in mods if m.get("module_human_name", "").lower() in ("irisvt", "iris vt")
                or "virustotal" in m.get("module_human_name", "").lower()), None)
    if not mod:
        log(f"WARN: IRIS VirusTotal module not found; modules: {[m.get('module_human_name') for m in mods]}")
        return
    mid = mod["id"]
    # Parameter names come from the module's own config, not guesses.
    params = mod.get("module_config") or []
    name = next((p["param_name"] for p in params if p.get("param_name", "").endswith("api_key")), None)
    if not name:
        log(f"WARN: no api_key parameter on VirusTotal module; params={[p.get('param_name') for p in params]}")
        return
    ref = base64.b64encode(f"{mid}##{name}".encode()).decode()
    iris("POST", f"/manage/modules/set-parameter/{ref}", {"parameter_value": VT_KEY})
    if not mod.get("is_active"):
        iris("POST", f"/manage/modules/enable/{mid}")
    log("VirusTotal module configured and enabled")


# ---------------------------------------------------------------- Censys
def censys_summary(res):
    """One line about a host: who owns it, what it exposes. Defensive: every field optional."""
    r = res.get("result") or res
    r = r.get("resource") or r
    asn = r.get("autonomous_system") or {}
    loc = r.get("location") or {}
    parts = []
    owner = " ".join(str(x) for x in (f"AS{asn['asn']}" if asn.get("asn") else "", asn.get("name") or "") if x)
    country = loc.get("country_code") or loc.get("country")
    if owner:
        parts.append(owner + (f" ({country})" if country else ""))
    ports = {}  # one entry per port; "UNKNOWN" only when nothing better is known
    for sv in r.get("services") or []:
        if isinstance(sv, dict) and sv.get("port"):
            name = sv.get("protocol") or sv.get("service_name") or sv.get("extended_service_name") or ""
            names_for = ports.setdefault(sv["port"], [])
            if name and name.upper() != "UNKNOWN" and name not in names_for:
                names_for.append(name)
    svcs = [f"{p}/{'+'.join(n)}" if n else str(p) for p, n in sorted(ports.items())]
    if svcs:
        more = f" (+{len(svcs) - 8} more)" if len(svcs) > 8 else ""
        parts.append("open: " + ", ".join(svcs[:8]) + more)
    names = ((r.get("dns") or {}).get("reverse_dns") or {}).get("names")
    if names:
        parts.append("rDNS: " + ", ".join(names[:3]))
    labels = [x.get("value") or x.get("name") if isinstance(x, dict) else x for x in r.get("labels") or []]
    labels = [str(x) for x in labels if x]
    if labels:
        parts.append("labels: " + ", ".join(labels[:6]))
    return "; ".join(parts).replace("&", "and")[:400] or "known to Censys, no details"


class Censys:
    """One lookup per IP per 30 days (cached in the bridge state), an optional monthly cap
    (CENSYS_MONTHLY_LIMIT, default 100 = the free tier, 0 = none) and a back-off on
    HTTP 429. Requests are sequential (accounts may allow 1 concurrent action). Failures
    never block forwarding alerts."""

    def __init__(self, state):
        self.enabled = bool(CENSYS_KEY)
        self.cache = state.setdefault("censys", {})
        self.usage = state.setdefault("censys_usage", {"month": "", "n": 0})
        now = datetime.now(timezone.utc)
        for ip in [k for k, v in self.cache.items() if now - datetime.fromisoformat(v["ts"]) > CENSYS_TTL]:
            del self.cache[ip]
        self.capped = False
        self.pause_until = now
        if self.enabled:
            self._roll(now)
            cap = f"/{CENSYS_LIMIT}" if CENSYS_LIMIT else " (no cap)"
            log(f"Censys enrichment on: {self.usage['n']}{cap} lookups used this month, "
                f"{len(self.cache)} IPs cached")
        else:
            log("CENSYS_API_KEY not set; Censys enrichment off")

    def _roll(self, now):
        month = now.strftime("%Y-%m")
        if self.usage["month"] != month:
            self.usage.update(month=month, n=0)
            self.capped = False

    def lookup(self, ip):
        if not self.enabled:
            return None
        now = datetime.now(timezone.utc)
        hit = self.cache.get(ip)
        if hit:
            return hit["text"]
        self._roll(now)
        if now < self.pause_until:
            return None
        if CENSYS_LIMIT and self.usage["n"] >= CENSYS_LIMIT:
            if not self.capped:
                log(f"Censys monthly budget reached ({CENSYS_LIMIT}); skipping until next month")
                self.capped = True
            return None
        url = CENSYS_URL + quote(ip, safe="")
        if CENSYS_ORG:
            url += "?organization_id=" + quote(CENSYS_ORG, safe="")
        try:
            self.usage["n"] += 1
            text = censys_summary(request("GET", url, headers={
                "Authorization": f"Bearer {CENSYS_KEY}", "Accept": "application/json"}, timeout=15))
        except urllib.error.HTTPError as e:
            if e.code == 404:
                text = "no Censys record"
            elif e.code in (401, 403):
                log(f"Censys rejected the key (HTTP {e.code}); enrichment off until restart")
                self.enabled = False
                return None
            elif e.code == 429:
                log("Censys rate limit hit (HTTP 429); pausing lookups for 10 minutes")
                self.pause_until = now + timedelta(minutes=10)
                return None
            else:
                log(f"Censys lookup of {ip} failed: HTTP {e.code}")
                return None
        except Exception as e:  # noqa: BLE001 - enrichment is best-effort
            log(f"Censys lookup of {ip} failed: {type(e).__name__}: {e}")
            return None
        self.cache[ip] = {"ts": now.isoformat(), "text": text}
        return text


# ---------------------------------------------------------------- mapping
def device_name(ip, cache):
    if ip in cache:
        return cache[ip]
    name = None
    try:
        res = es("POST", "/logs-zeek.dhcp-*/_search", {
            "size": 1, "sort": [{"@timestamp": "desc"}], "_source": ["zeek.dhcp.hostname"],
            "query": {"bool": {"filter": [{"term": {"client.address": ip}},
                                          {"exists": {"field": "zeek.dhcp.hostname"}}]}}})
        hits = res["hits"]["hits"]
        name = flatten(hits[0]["_source"]).get("zeek.dhcp.hostname") if hits else None
    except urllib.error.HTTPError:
        pass
    cache[ip] = name
    return name


def to_iris(hit, lk, names, cz):
    src = hit["_source"]
    f = flatten(src)

    def get(key, default=None):
        return f.get(key, default)
    ts = get("kibana.alert.original_time") or src["@timestamp"]
    sev = str(get("kibana.alert.severity", "medium")).lower()
    rule = get("kibana.alert.rule.name", "Security alert")
    tlp = lk.tlp.get("amber", next(iter(lk.tlp.values())))

    iocs, seen = [], set()

    def ioc(value, kind, desc, tags="moat"):
        tid = lk.ioc_type.get(kind)
        if value and tid and (value, kind) not in seen:
            seen.add((value, kind))
            iocs.append({"ioc_value": str(value), "ioc_type_id": tid, "ioc_tlp_id": tlp,
                         "ioc_description": desc, "ioc_tags": tags})

    enriched = []

    assets = []
    for field, kind in (("source.ip", "ip-src"), ("destination.ip", "ip-dst")):
        ip = first(get(field))
        if not ip:
            continue
        if is_private(ip):
            name = device_name(ip, names)
            assets.append({"asset_name": name or ip, "asset_type_id": lk.asset_default,
                           "asset_ip": ip, "asset_description": f"{field} in '{rule}'",
                           "asset_tags": "moat"})
        else:
            info = cz.lookup(ip)
            if info:
                enriched.append(f"{ip}: {info}")
            ioc(ip, kind, f"{field} in '{rule}'" + (f" | Censys: {info}" if info else ""),
                "moat,censys" if info else "moat")
    ioc(first(get("dns.question.name")), "domain", "DNS query")
    # Suricata/Zeek HTTP put the host and path in separate fields; rebuild the URL.
    host, path = first(get("url.domain")), first(get("url.original"))
    url = first(get("url.full")) or (f"http://{host}{path}" if host and path and path.startswith("/") else None)
    ioc(url, "url", "URL")
    for field in ("url.domain", "destination.domain", "tls.client.server_name", "zeek.ssl.server.name"):
        ioc(first(get(field)), "domain", field)
    for h in ("sha256", "sha1", "md5"):
        ioc(first(get(f"file.hash.{h}")), h, f"file {h}")

    # timestamp first: IRIS renders descriptions as HTML, and "&times" (in "&timestamp")
    # is a legacy HTML entity that displays as "×".
    link = (f"{KIBANA}/app/security/alerts/redirect/{hit['_id']}"
            f"?timestamp={ts}&index=.alerts-security.alerts-default") if KIBANA else ""
    tags = get("kibana.alert.rule.tags", []) or []
    # Put the thing that matched in the title, so the queue is readable without
    # opening each alert: the threat-intel value, else the DNS name.
    enrich = src.get("threat", {}).get("enrichments") if isinstance(src.get("threat"), dict) else None
    matched = next((e.get("matched", {}).get("atomic") for e in (enrich or []) if isinstance(e, dict)), None)
    key = matched or first(get("dns.question.name"))
    title = f"{rule}: {key}" if key and str(key) not in rule else rule

    return {
        "alert_title": title,
        "alert_description": (f"{get('kibana.alert.reason', '')}\n\nKibana: {link}"
                              + "".join(f"\n\nCensys {e}" for e in enriched)).strip(),
        "alert_source": "moat / Elastic Security",
        "alert_source_ref": hit["_id"],
        "alert_source_link": link,
        "alert_source_event_time": ts[:19],
        "alert_source_content": src,
        "alert_severity_id": lk.severity.get(sev, lk.severity.get("medium")),
        "alert_status_id": lk.status.get("new", next(iter(lk.status.values()))),
        "alert_customer_id": lk.customer,
        "alert_tags": ",".join(["moat"] + [t for t in tags if t != "moat"][:8]),
        "alert_iocs": iocs,
        "alert_assets": assets,
    }


# ---------------------------------------------------------------- main loop
def load_state():
    try:
        with open(STATE_FILE) as f:
            return json.load(f)
    except (OSError, ValueError):
        # First run: forward the last hour, not the whole history.
        return {"last_ts": (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(), "sent": []}


def save_state(state):
    state["sent"] = state["sent"][-5000:]
    state["heartbeat"] = datetime.now(timezone.utc).isoformat()
    tmp = STATE_FILE + ".tmp"
    with open(tmp, "w") as f:
        json.dump(state, f)
    os.replace(tmp, STATE_FILE)


def poll(lk, state, cz):
    wanted = SEVERITIES[SEVERITIES.index(MIN_SEV):] if MIN_SEV in SEVERITIES else SEVERITIES[1:]
    since = (datetime.fromisoformat(state["last_ts"]) - timedelta(minutes=5)).isoformat()
    res = es("POST", "/.alerts-security.alerts-*/_search", {
        "size": 200, "sort": [{"@timestamp": "asc"}],
        "query": {"bool": {"filter": [
            {"term": {"kibana.alert.workflow_status": "open"}},
            {"terms": {"kibana.alert.severity": wanted}},
            {"range": {"@timestamp": {"gt": since}}}]}}})
    sent, names, n = set(state["sent"]), {}, 0
    for hit in res["hits"]["hits"]:
        state["last_ts"] = max(state["last_ts"], hit["_source"]["@timestamp"])
        if hit["_id"] in sent:
            continue
        a = iris("POST", "/alerts/add", to_iris(hit, lk, names, cz))
        state["sent"].append(hit["_id"])
        sent.add(hit["_id"])
        n += 1
        log(f"-> IRIS alert #{a.get('alert_id')}: {a.get('alert_title')}")
    save_state(state)
    return n


def main():
    log(f"starting: forwarding open alerts >= {MIN_SEV} every {POLL_SECONDS}s")
    while True:  # IRIS and ES may still be starting
        try:
            lk = Lookups()
            configure_virustotal()
            break
        except Exception as e:  # noqa: BLE001 - keep retrying until the stack is up
            log(f"waiting for IRIS/ES: {e}")
            time.sleep(15)
    state = load_state()
    cz = Censys(state)
    while True:
        try:
            poll(lk, state, cz)
        except urllib.error.HTTPError as e:
            log(f"HTTP {e.code} from {e.url}: {e.read()[:300]!r}")
        except Exception as e:  # noqa: BLE001 - one bad poll must not stop the bridge
            log(f"poll failed: {type(e).__name__}: {e}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    sys.exit(main())
