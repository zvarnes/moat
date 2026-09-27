#!/usr/bin/env python3
"""Convert Sigma rules into Kibana detection rules (NDJSON on stdout, report on stderr).

    sigma_convert.py [--strict] [--source NAME] [--keep-enabled FILE] [--show] PATH...

PATH may be files or directories (searched recursively for *.yml).
--strict        exit 1 if any rule is skipped or fails (use for your own rules)
--source NAME   tag the rules with "Sigma: NAME" (e.g. moat, sigmahq)
--keep-enabled  JSON {rule_id: bool}: keep the enabled state already set in Kibana
--show          print each rule's Elastic query instead of NDJSON (for learning/testing)
--disabled      install new rules disabled (community packs: browse, then enable)

moat feeds Sigma from Zeek (product: zeek) and DNS (category: dns). Field names are
mapped with the upstream `ecs_zeek_beats` pipeline plus sigma/pipelines/moat.yml.
Rules that still reference unmapped fields are skipped with a reason, because an
installed rule that can never match is worse than a missing one.
"""
import argparse
import json
import re
import sys
import uuid
from pathlib import Path

from sigma.backends.elasticsearch import LuceneBackend
from sigma.collection import SigmaCollection
from sigma.pipelines.elasticsearch.zeek import ecs_zeek_beats
from sigma.processing.pipeline import ProcessingPipeline

# In the setup containers the repo's sigma/ is mounted at /sigma; from a checkout, use it directly.
_here = Path(__file__).resolve()
_candidates = [Path("/sigma/pipelines/moat.yml")]
if len(_here.parents) > 2:
    _candidates.append(_here.parents[2] / "sigma/pipelines/moat.yml")
MOAT_PIPELINE = next((p for p in _candidates if p.exists()), _candidates[0])

# Field names the Elastic zeek integration never produces: wildcards left by the
# upstream pipeline, or raw Zeek names that should have become ECS fields.
UNMAPPED = re.compile(r"(^|[\s(])(zeek\.\\\*|[a-z_]*\\\*|id\.(orig|resp)_[hp])")
# Datasets of the Elastic zeek integration. Sigma's Zeek service names mostly match;
# "conn" is the exception. A rule filtering on any other dataset could never match.
ZEEK_DATASETS = set("""capture_loss connection dce_rpc dhcp dnp3 dns dpd files ftp http intel
    irc kerberos known_certs known_hosts known_services modbus mysql notice ntlm ntp ocsp pe
    radius rdp rfb signature sip smb_cmd smb_files smb_mapping smtp snmp socks software ssh
    ssl stats syslog traceroute tunnel weird x509""".split())
DATASET_RENAMES = {"conn": "connection"}
DATASET_RE = re.compile(r"event\.dataset:zeek\.([a-z_0-9]+)")
SEVERITY = {"informational": ("low", 21), "low": ("low", 21), "medium": ("medium", 47),
            "high": ("high", 73), "critical": ("critical", 99)}
ENABLE_LEVELS = {"medium", "high", "critical"}
NS = uuid.UUID("5b0c7f3e-6d1a-4e2b-9c55-6d6f61740002")


def supported(logsource):
    if logsource.product == "zeek":
        return True
    return logsource.category == "dns" and logsource.product in (None, "zeek")


def attack_tags(rule):
    out = []
    for t in rule.tags or []:
        s = str(t)
        if s.startswith("attack.t"):
            out.append("MITRE ATT&CK: " + s.split(".", 1)[1].upper())
        elif s.startswith("attack."):
            out.append("Tactic: " + s.split(".", 1)[1].replace("_", " ").title())
    return out


def to_kibana(rule, query, source, keep, default_off=False):
    sid = str(rule.id) if rule.id else str(uuid.uuid5(NS, rule.title))
    level = str(rule.level.name).lower() if rule.level else "medium"
    sev, risk = SEVERITY.get(level, ("medium", 47))
    rule_id = f"moat-sigma-{sid}"
    return {
        "rule_id": rule_id,
        "name": f"Sigma: {rule.title}",
        "description": (rule.description or rule.title).strip(),
        "type": "query",
        "language": "lucene",
        "index": ["logs-zeek.*"],
        "query": query,
        "severity": sev,
        "risk_score": risk,
        "interval": "5m",
        "from": "now-10m",
        "max_signals": 100,
        "enabled": keep.get(rule_id, (not default_off) and level in ENABLE_LEVELS),
        "author": [rule.author] if rule.author else ["unknown"],
        "references": [str(r) for r in (rule.references or [])],
        "false_positives": [str(f) for f in (rule.falsepositives or [])],
        "license": "DRL-1.1" if source == "sigmahq" else "",
        "tags": ["moat", "Sigma", f"Sigma: {source}", "Domain: Network"] + attack_tags(rule),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("paths", nargs="+")
    ap.add_argument("--strict", action="store_true")
    ap.add_argument("--source", default="moat")
    ap.add_argument("--keep-enabled")
    ap.add_argument("--show", action="store_true")
    ap.add_argument("--disabled", action="store_true")
    a = ap.parse_args()
    keep = json.loads(Path(a.keep_enabled).read_text()) if a.keep_enabled else {}
    backend = LuceneBackend(processing_pipeline=ProcessingPipeline.from_yaml(
        MOAT_PIPELINE.read_text()) + ecs_zeek_beats())

    files = []
    for p in map(Path, a.paths):
        files += sorted(p.rglob("*.yml")) if p.is_dir() else [p]
    ok = skipped = 0
    for f in files:
        try:
            for rule in SigmaCollection.from_yaml(f.read_text()).rules:
                if not supported(rule.logsource):
                    raise ValueError(f"unsupported logsource {rule.logsource} (moat feeds zeek + dns)")
                query = backend.convert(SigmaCollection([rule]))[0]
                query = DATASET_RE.sub(lambda m: "event.dataset:zeek." + DATASET_RENAMES.get(
                    m.group(1), m.group(1)), query)
                bad = [d for d in DATASET_RE.findall(query) if d not in ZEEK_DATASETS]
                if bad:
                    raise ValueError(f"unknown zeek dataset(s) {bad} in query: {query[:120]}")
                if UNMAPPED.search(query):
                    raise ValueError(f"unmapped field in query: {query[:120]}")
                if a.show:
                    print(f"# {f}\n{query}\n")
                else:
                    print(json.dumps(to_kibana(rule, query, a.source, keep, a.disabled), sort_keys=True))
                ok += 1
        except Exception as e:  # one bad rule never stops the rest
            skipped += 1
            print(f"skip {f}: {type(e).__name__}: {e}", file=sys.stderr)
    print(f"sigma[{a.source}]: {ok} converted, {skipped} skipped", file=sys.stderr)
    sys.exit(1 if a.strict and skipped else 0)


if __name__ == "__main__":
    main()
