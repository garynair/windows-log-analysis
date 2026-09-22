import json, re, sys, pathlib
root = pathlib.Path(sys.argv[1]).expanduser()

# ---- 1. Digest: spike detection needs >=3 days of baseline history ----
p = root / "digest/windows_digest.py"
s = p.read_text()
old_loop = '''    c24, c7 = counts("24h"), counts("7d")
    rows = []
    for (eid, ch), n in sorted(c24.items(), key=lambda kv: -kv[1]):
        avg = c7.get((eid, ch), 0) / 7
        rows.append({"event_id": eid, "channel": ch, "name": EVENT_NAMES.get(eid, "other"),
                     "count_24h": int(n), "avg_per_day_7d": round(avg, 1),
                     "spike": n >= 5 and n > 2 * max(avg, 1)})'''
new_loop = '''    c24, c7 = counts("24h"), counts("7d")
    prior_days = max(history_days() - 1, 0)   # full days of history before the last 24h
    rows = []
    for (eid, ch), n in sorted(c24.items(), key=lambda kv: -kv[1]):
        prior = max(c7.get((eid, ch), 0) - n, 0)
        avg = prior / prior_days if prior_days else 0
        rows.append({"event_id": eid, "channel": ch, "name": EVENT_NAMES.get(eid, "other"),
                     "count_24h": int(n), "baseline_avg_per_day": round(avg, 1),
                     "spike": prior_days >= MIN_BASELINE_DAYS and n >= 5 and n > 2 * max(avg, 1)})'''
old_ret = 'return {"window": "last 24h", "event_counts": rows, "notable_events": notable[:25]}'
new_ret = ('return {"window": "last 24h", "baseline_days": prior_days, '
           '"spike_detection": "active" if prior_days >= MIN_BASELINE_DAYS else "warming up (needs 3 days of history)", '
           '"event_counts": rows, "notable_events": notable[:25]}')
helper = '''

MIN_BASELINE_DAYS = 3


def history_days():
    """Days (up to 7) that contain any Windows events - used to avoid false spikes on a new install."""
    qs = urllib.parse.urlencode({"query": 'sum(count_over_time({job="windows"}[1d]))', "since": "7d", "step": "86400"})
    res = http(f"{LOKI}/loki/api/v1/query_range?" + qs)["data"]["result"]
    return sum(1 for _ts, v in res[0]["values"] if float(v) > 0) if res else 0


def build_facts():'''
if "MIN_BASELINE_DAYS" in s:
    print("digest: already patched")
else:
    for a in (old_loop, old_ret, "\n\ndef build_facts():"):
        if a not in s:
            sys.exit(f"digest: expected text not found, no changes made: {a[:60]!r}")
    s = s.replace(old_loop, new_loop).replace(old_ret, new_ret).replace("\n\ndef build_facts():", helper, 1)
    p.write_text(s)
    print("digest: patched")

# ---- 2. Dashboard: DNS tables sorted by count, readable header, no localhost ----
d = root / "grafana/dashboards/windows-security.json"
dash = json.loads(d.read_text())
n = 0
for panel in dash["panels"]:
    if panel.get("type") == "table" and "DNS" in panel.get("title", ""):
        t = panel["targets"][0]
        if '| qname!="localhost"' not in t["expr"]:
            t["expr"] = t["expr"].replace("[$__range]", '| qname!="localhost" [$__range]')
        panel["transformations"] = [
            {"id": "organize", "options": {"excludeByName": {"Time": True},
                                           "renameByName": {"qname": "Domain", "Value #A": "Queries", "Value": "Queries"}}},
            {"id": "sortBy", "options": {"sort": [{"field": "Queries", "desc": True}]}},
        ]
        n += 1
for panel in dash["panels"]:
    if panel.get("title", "").startswith("Daily AI digest"):
        panel["targets"][0]["expr"] = ('{job="ai_digest"} | json | line_format '
            '"[{{.severity | ToUpper}}] {{.headline}}  (source: {{.source}}, floor: {{.severity_floor}})"')
        n += 1
dash["version"] = dash.get("version", 1) + 1
d.write_text(json.dumps(dash, indent=2))
print(f"dashboard: updated {n} panels")
