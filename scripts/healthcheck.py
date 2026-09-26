#!/usr/bin/env python3
"""Checks that the stack is up and data is flowing. Standard library only. Run from WSL:
    python3 scripts/healthcheck.py
Reads GRAFANA_ADMIN_USER / GRAFANA_ADMIN_PASSWORD from the environment or .env.
Exit code 1 if any required check fails; data-freshness checks only warn.
"""
import base64, json, os, pathlib, sys, time, urllib.parse, urllib.request

LOKI = os.getenv("LOKI_URL", "http://localhost:3100")
GRAFANA = os.getenv("GRAFANA_URL", "http://localhost:3001")
DASHBOARD_TITLE = "Windows Security Overview"


def load_env():
    env = pathlib.Path(__file__).resolve().parent.parent / ".env"
    if env.exists():
        for line in env.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip())


def get(url, auth=None):
    req = urllib.request.Request(url)
    if auth:
        req.add_header("Authorization", "Basic " + base64.b64encode(auth.encode()).decode())
    with urllib.request.urlopen(req, timeout=10) as resp:
        body = resp.read().decode()
    try:
        return json.loads(body)
    except ValueError:
        return body.strip()


def loki_count(query, since):
    qs = urllib.parse.urlencode({"query": f"sum(count_over_time({query}[{since}]))"})
    res = get(f"{LOKI}/loki/api/v1/query?{qs}")["data"]["result"]
    return int(float(res[0]["value"][1])) if res else 0


def main():
    load_env()
    auth = f'{os.getenv("GRAFANA_ADMIN_USER", "admin")}:{os.getenv("GRAFANA_ADMIN_PASSWORD", "")}'
    checks = [
        ("Loki ready", True, lambda: get(f"{LOKI}/ready") == "ready"),
        ("Grafana healthy", True, lambda: get(f"{GRAFANA}/api/health")["database"] == "ok"),
        ("Loki data source provisioned", True,
         lambda: get(f"{GRAFANA}/api/datasources/uid/loki", auth)["type"] == "loki"),
        ("Dashboard provisioned", True,
         lambda: any(d["title"] == DASHBOARD_TITLE for d in
                     get(f"{GRAFANA}/api/search?" + urllib.parse.urlencode({"query": DASHBOARD_TITLE}), auth))),
        ("Windows events in the last hour", False, lambda: loki_count('{job="windows"}', "1h") > 0),
        ("AI digest in the last 26 hours", False, lambda: loki_count('{job="ai_digest"}', "26h") > 0),
    ]
    failed = False
    for name, required, check in checks:
        for attempt in range(3):
            try:
                ok, err = check(), ""
            except Exception as exc:
                ok, err = False, f" ({exc})"
            if ok or not required:
                break
            time.sleep(5)
        status = "PASS" if ok else ("FAIL" if required else "WARN")
        print(f"[{status}] {name}{err}")
        failed |= required and not ok
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
