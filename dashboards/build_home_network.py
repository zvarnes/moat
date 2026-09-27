#!/usr/bin/env python3
"""Generate dashboards/moat-home-network.ndjson (Kibana saved objects).

Edit the PANELS list below, then run:  python3 dashboards/build_home_network.py
bootstrap imports every dashboards/*.ndjson with overwrite, so changes made in the
Kibana UI to these objects are replaced on the next bootstrap. Save a copy under a
new name in the UI if you want to keep your own edits.
"""
import json
import uuid
from pathlib import Path

NS = uuid.UUID("5b0c7f3e-6d1a-4e2b-9c55-6d6f61740001")  # stable ids across rebuilds
DASHBOARD_ID = "moat-home-network"
LOGS = "logs-*"  # data view created by Fleet
ALERTS = "moat-alerts"  # data view created below

# Zeek sets local_orig/local_resp from Site::local_nets (LOCAL_NETS) plus private and
# link-local space. Multicast/broadcast destinations count as "not local" to Zeek, so
# exclude them (and IPv6 link-local sources), or LAN discovery chatter looks like internet.
NOT_LAN_CHATTER = ('not destination.ip:"224.0.0.0/4" and not destination.ip:"255.255.255.255" '
                   'and not destination.ip:"ff00::/8" and not source.ip:"fe80::/10"')
INTERNET = ('data_stream.dataset:"zeek.connection" and zeek.connection.local_orig:true '
            'and zeek.connection.local_resp:false and ' + NOT_LAN_CHATTER)
# Count devices by their IPv4 address; IPv6 gives each device several addresses.
LAN_V4 = '(source.ip:"10.0.0.0/8" or source.ip:"172.16.0.0/12" or source.ip:"192.168.0.0/16")'
BYTES = {"id": "bytes", "params": {"decimals": 1}}


def uid(*parts):
    return str(uuid.uuid5(NS, "/".join(parts)))


# ---- column builders --------------------------------------------------------------
def count(label="Count"):
    return {"label": label, "customLabel": True, "dataType": "number", "operationType": "count",
            "isBucketed": False, "scale": "ratio", "sourceField": "___records___",
            "params": {"emptyAsNull": True}}


def metric(op, field, label, dtype="number", fmt=None):
    col = {"label": label, "customLabel": True, "dataType": dtype, "operationType": op,
           "isBucketed": False, "scale": "ratio", "sourceField": field, "params": {}}
    if op in ("sum", "unique_count"):
        col["params"]["emptyAsNull"] = True
    if fmt:
        col["params"]["format"] = fmt
    return col


def terms(field, label, size, order_by, dtype="string"):
    return {"label": label, "customLabel": True, "dataType": dtype, "operationType": "terms",
            "isBucketed": True, "scale": "ordinal", "sourceField": field,
            "params": {"size": size, "orderBy": {"type": "column", "columnId": order_by},
                       "orderDirection": "desc", "otherBucket": False, "missingBucket": False,
                       "parentFormat": {"id": "terms"}, "include": [], "exclude": [],
                       "includeIsRegex": False, "excludeIsRegex": False}}


def date_histogram():
    return {"label": "@timestamp", "dataType": "date", "operationType": "date_histogram",
            "isBucketed": True, "scale": "interval", "sourceField": "@timestamp",
            "params": {"interval": "auto", "includeEmptyRows": True, "dropPartials": False}}


# ---- panel builders ---------------------------------------------------------------
# Each returns (title, visualizationType, data view id, columns[(id, col)], visualization, query)
def p_metric(key, title, dv, col, query):
    c = uid(key, "m")
    vis = {"layerId": None, "layerType": "data", "metricAccessor": c}
    return title, "lnsMetric", dv, [(c, col)], vis, query


def p_table(key, title, dv, cols, query):
    ids = [(uid(key, str(i)), col) for i, col in enumerate(cols)]
    vis = {"layerId": None, "layerType": "data", "columns": [{"columnId": i} for i, _ in ids]}
    return title, "lnsDatatable", dv, ids, vis, query


def p_xy(key, title, dv, x, ys, query, series="bar_stacked", split=None):
    xid = uid(key, "x")
    yids = [(uid(key, f"y{i}"), y) for i, y in enumerate(ys)]
    cols = [(xid, x)] + yids
    layer = {"layerId": None, "layerType": "data", "seriesType": series, "xAccessor": xid,
             "accessors": [i for i, _ in yids], "position": "top", "showGridlines": False}
    if split:
        sid = uid(key, "split")
        cols.insert(1, (sid, split))
        layer["splitAccessor"] = sid
    vis = {"legend": {"isVisible": True, "position": "right"}, "valueLabels": "hide",
           "preferredSeriesType": series, "fittingFunction": "None", "layers": [layer]}
    return title, "lnsXY", dv, cols, vis, query


def p_donut(key, title, dv, group, value, query):
    gid, vid = uid(key, "g"), uid(key, "v")
    vis = {"shape": "donut", "layers": [{
        "layerId": None, "layerType": "data", "primaryGroups": [gid], "metrics": [vid],
        "numberDisplay": "percent", "categoryDisplay": "default", "legendDisplay": "default",
        "nestedLegend": False, "legendPosition": "right"}]}
    return title, "lnsPie", dv, [(gid, group), (vid, value)], vis, query


# ---- the dashboard ----------------------------------------------------------------
def panels():
    k = "talkers"
    talk_bytes = uid(k, "1")  # column 1 = Traffic (p_table ids columns by position)
    k2 = "orgs"
    org_bytes = uid(k2, "y0")
    k3 = "countries"
    ctry_ips = uid(k3, "y0")
    return [
        # row 1: headline numbers (x, y, w, h)
        ((0, 0, 12, 6), p_metric("m_alerts", "Open security alerts", ALERTS,
                                 count("Open alerts"), 'kibana.alert.workflow_status:"open"')),
        ((12, 0, 12, 6), p_metric("m_devices", "Active devices", LOGS,
                                  metric("unique_count", "source.ip", "Devices"),
                                  'data_stream.dataset:"zeek.connection" and ' + LAN_V4)),
        ((24, 0, 12, 6), p_metric("m_dns", "DNS lookups", LOGS, count("Lookups"),
                                  'data_stream.dataset:"zeek.dns" and dns.question.name:*')),
        ((36, 0, 12, 6), p_metric("m_blocks", "Blocked by the UDM", LOGS, count("Blocks"),
                                  'data_stream.dataset:"cef.log" and (cef.name:"Blocked by Firewall" '
                                  'or cef.extensions.UNIFIpolicyType:"IDS/IPS")')),
        # row 2: over time
        ((0, 6, 24, 12), p_xy("alerts_time", "Alerts over time by severity", ALERTS,
                              date_histogram(), [count("Alerts")], "",
                              split=terms("kibana.alert.severity", "Severity", 5, uid("alerts_time", "y0")))),
        ((24, 6, 24, 12), p_xy("traffic_time", "Internet traffic: download vs upload", LOGS,
                               date_histogram(),
                               [metric("sum", "destination.bytes", "Download", fmt=BYTES),
                                metric("sum", "source.bytes", "Upload", fmt=BYTES)],
                               INTERNET, series="area")),
        # row 3: devices
        ((0, 18, 24, 14), p_table(k, "Top talkers to the internet", LOGS, [
            terms("source.ip", "Device IP", 15, talk_bytes, dtype="ip"),
            metric("sum", "network.bytes", "Traffic", fmt=BYTES),
            count("Connections"),
            metric("unique_count", "destination.ip", "Distinct destinations"),
        ], INTERNET)),
        ((24, 18, 24, 14), p_table("dhcp", "Device names (from DHCP)", LOGS, [
            terms("zeek.dhcp.hostname", "Hostname", 50, uid("dhcp", "2")),
            terms("client.address", "IP", 3, uid("dhcp", "2")),
            metric("max", "@timestamp", "Last seen", dtype="date"),
        ], 'data_stream.dataset:"zeek.dhcp" and zeek.dhcp.hostname:*')),
        # row 4: where traffic goes
        ((0, 32, 16, 14), p_table("dns", "Top DNS domains", LOGS, [
            terms("dns.question.registered_domain", "Domain", 20, uid("dns", "1")),
            count("Lookups"),
            metric("unique_count", "source.ip", "Devices"),
        ], 'data_stream.dataset:"zeek.dns" and not dns.question.registered_domain:*.arpa')),
        ((16, 32, 16, 14), p_table("sni", "Top HTTPS sites (TLS SNI)", LOGS, [
            terms("zeek.ssl.server.name", "Site", 20, uid("sni", "1")),
            count("Connections"),
            metric("unique_count", "source.ip", "Devices"),
        ], 'data_stream.dataset:"zeek.ssl"')),
        ((32, 32, 16, 14), p_xy(k2, "Traffic by destination organization", LOGS,
                                terms("destination.as.organization.name", "Organization", 12, org_bytes),
                                [metric("sum", "network.bytes", "Traffic", fmt=BYTES)],
                                INTERNET, series="bar_horizontal")),
        # row 5: detections
        ((0, 46, 24, 14), p_table("suri", "Suricata alerts (all severities, 1 = high)", LOGS, [
            terms("rule.name", "Signature", 25, uid("suri", "2")),
            metric("min", "event.severity", "Severity"),
            count("Hits"),
            metric("unique_count", "source.ip", "Sources"),
            metric("max", "@timestamp", "Last seen", dtype="date"),
        ], 'data_stream.dataset:"suricata.eve" and event.kind:"alert"')),
        ((24, 46, 24, 14), p_table("udm", "UDM firewall blocks and IPS", LOGS, [
            terms("cef.name", "Event", 5, uid("udm", "3")),
            terms("cef.extensions.UNIFIsrcClientAlias", "Device", 10, uid("udm", "3")),
            terms("destination.ip", "Destination", 10, uid("udm", "3"), dtype="ip"),
            count("Count"),
        ], 'data_stream.dataset:"cef.log" and (cef.name:"Blocked by Firewall" '
           'or cef.extensions.UNIFIpolicyType:"IDS/IPS")')),
        # row 6: context
        ((0, 60, 16, 12), p_xy(k3, "Countries contacted (distinct IPs)", LOGS,
                               terms("destination.geo.country_name", "Country", 12, ctry_ips),
                               [metric("unique_count", "destination.ip", "Distinct IPs")],
                               INTERNET, series="bar_horizontal")),
        ((16, 60, 16, 12), p_donut("proto", "Protocols", LOGS,
                                   terms("network.protocol", "Protocol", 8, uid("proto", "v")),
                                   count("Connections"),
                                   'data_stream.dataset:"zeek.connection" and network.protocol:*')),
        ((32, 60, 16, 12), p_table("notice", "Zeek notices", LOGS, [
            terms("zeek.notice.note", "Notice", 15, uid("notice", "1")),
            count("Count"),
            metric("max", "@timestamp", "Last seen", dtype="date"),
        ], 'data_stream.dataset:"zeek.notice"')),
    ]


def build():
    panels_json, refs = [], []
    for n, ((x, y, w, h), (title, vtype, dv, cols, vis, query)) in enumerate(panels(), start=1):
        idx = str(n)
        layer = uid(DASHBOARD_ID, idx, "layer")
        # point the visualization at this layer
        if vtype in ("lnsXY", "lnsPie"):
            for lyr in vis["layers"]:
                lyr["layerId"] = layer
        else:
            vis["layerId"] = layer
        ref_name = f"indexpattern-datasource-layer-{layer}"
        attrs = {
            "title": title, "type": "lens", "visualizationType": vtype,
            "references": [{"type": "index-pattern", "id": dv, "name": ref_name}],
            "state": {
                "datasourceStates": {
                    "formBased": {"layers": {layer: {
                        "columns": dict(cols), "columnOrder": [c for c, _ in cols],
                        "incompleteColumns": {}}}},
                    "textBased": {"layers": {}}},
                "visualization": vis,
                "query": {"language": "kuery", "query": query},
                "filters": [], "internalReferences": [], "adHocDataViews": {}},
        }
        panels_json.append({
            "type": "lens", "panelIndex": idx, "title": title,
            "gridData": {"x": x, "y": y, "w": w, "h": h, "i": idx},
            "embeddableConfig": {"attributes": attrs, "enhancements": {}}})
        refs.append({"type": "index-pattern", "id": dv, "name": f"{idx}:{ref_name}"})

    alerts_view = {
        "type": "index-pattern", "id": ALERTS, "managed": False,
        "attributes": {"title": ".alerts-security.alerts-default", "timeFieldName": "@timestamp",
                       "name": "moat: Security alerts"},
        "references": []}
    dashboard = {
        "type": "dashboard", "id": DASHBOARD_ID, "managed": False,
        "coreMigrationVersion": "8.8.0", "typeMigrationVersion": "10.3.0",
        "attributes": {
            "title": "moat: Home Network",
            "description": "Devices, traffic, DNS, sites, detections and UDM blocks for the home "
                           "network. Built from dashboards/build_home_network.py.",
            "timeRestore": True, "timeFrom": "now-24h", "timeTo": "now",
            "refreshInterval": {"pause": False, "value": 300000},
            "optionsJSON": json.dumps({"hidePanelTitles": False, "syncColors": False,
                                       "syncCursor": True, "syncTooltips": False,
                                       "useMargins": True}),
            "panelsJSON": json.dumps(panels_json),
            "kibanaSavedObjectMeta": {"searchSourceJSON": json.dumps(
                {"filter": [], "query": {"language": "kuery", "query": ""}})},
            "version": 1},
        "references": refs}

    out = Path(__file__).with_name("moat-home-network.ndjson")
    out.write_text("".join(json.dumps(o, sort_keys=True) + "\n" for o in (alerts_view, dashboard)))
    print(f"wrote {out} ({len(panels_json)} panels)")


if __name__ == "__main__":
    build()
