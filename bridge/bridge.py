#!/usr/bin/env python3
"""moat bridge: Elastic Security alerts -> DFIR-IRIS alerts.

Every POLL_SECONDS, reads open Security alerts at or above BRIDGE_MIN_SEVERITY and
creates one IRIS alert each: title, severity, a link back to the Kibana alert, the
alert document, IOCs (IPs, domains, URLs, hashes) and assets (internal IPs, named
from Zeek's DHCP log). IRIS then links alerts that share IOCs ("similar alerts"),
and its VirusTotal module enriches IOCs when VT_API_KEY is set.

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

ES_URL = os.environ["ES_URL"]
ES_AUTH = "Basic " + base64.b64encode(f"moat_bridge:{os.environ['BRIDGE_ES_PASSWORD']}".encode()).decode()
IRIS_URL = os.environ["IRIS_URL"].rstrip("/")
IRIS_KEY = os.environ["IRIS_API_KEY"]
KIBANA = os.environ.get("KIBANA_PUBLIC_URL", "").rstrip("/")
VT_KEY = os.environ.get("VT_API_KEY", "").strip()
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
    mod = next((m for m in mods if "virustotal" in (m.get("module_human_name", "") +
                                                   m.get("interface_module_name", "")).lower()), None)
    if not mod:
        log("WARN: IRIS VirusTotal module not found")
        return
    mid = mod["id"]
    # Parameter names come from the module's own config, not guesses.
    cfg = iris("GET", f"/manage/modules/export-config/{mid}")
    params = cfg.get("module_configuration", cfg) if isinstance(cfg, dict) else cfg
    name = next((p["param_name"] for p in params if "api_key" in p.get("param_name", "")), None)
    if not name:
        log(f"WARN: no api_key parameter on VirusTotal module; params={[p.get('param_name') for p in params]}")
        return
    ref = base64.b64encode(f"{mid}##{name}".encode()).decode()
    iris("POST", f"/manage/modules/set-parameter/{ref}", {"parameter_value": VT_KEY})
    if not mod.get("is_active"):
        iris("POST", f"/manage/modules/enable/{mid}")
    log("VirusTotal module configured and enabled")


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


def to_iris(hit, lk, names):
    src = hit["_source"]
    f = flatten(src)

    def get(key, default=None):
        return f.get(key, default)
    ts = get("kibana.alert.original_time") or src["@timestamp"]
    sev = str(get("kibana.alert.severity", "medium")).lower()
    rule = get("kibana.alert.rule.name", "Security alert")
    tlp = lk.tlp.get("amber", next(iter(lk.tlp.values())))

    iocs, seen = [], set()

    def ioc(value, kind, desc):
        tid = lk.ioc_type.get(kind)
        if value and tid and (value, kind) not in seen:
            seen.add((value, kind))
            iocs.append({"ioc_value": str(value), "ioc_type_id": tid, "ioc_tlp_id": tlp,
                         "ioc_description": desc, "ioc_tags": "moat"})

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
            ioc(ip, kind, f"{field} in '{rule}'")
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
    return {
        "alert_title": rule,
        "alert_description": f"{get('kibana.alert.reason', '')}\n\nKibana: {link}".strip(),
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


def poll(lk, state):
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
        a = iris("POST", "/alerts/add", to_iris(hit, lk, names))
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
    while True:
        try:
            poll(lk, state)
        except urllib.error.HTTPError as e:
            log(f"HTTP {e.code} from {e.url}: {e.read()[:300]!r}")
        except Exception as e:  # noqa: BLE001 - one bad poll must not stop the bridge
            log(f"poll failed: {type(e).__name__}: {e}")
        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    sys.exit(main())
