#!/usr/bin/env bash
# End-to-end check without Windows or a model: push synthetic Windows events into a
# running stack, run the digest (Ollama unreachable -> facts-only path) and confirm
# the rules raised severity and the digest landed in Loki. Used by CI.
set -euo pipefail
LOKI_URL="${LOKI_URL:-http://localhost:3100}"
cd "$(dirname "$0")/.."

for _ in $(seq 60); do [ "$(curl -s "$LOKI_URL/ready")" = "ready" ] && break; sleep 2; done
python3 scripts/healthcheck.py

now=$(date +%s%N)
push() {  # event_id channel count
  local values="" i
  for i in $(seq "$3"); do values+="[\"$((now + i))\",\"{\\\"event_id\\\":\\\"$1\\\",\\\"message\\\":\\\"synthetic $1\\\"}\"],"; done
  curl -sf -H 'Content-Type: application/json' "$LOKI_URL/loki/api/v1/push" \
    -d "{\"streams\":[{\"stream\":{\"job\":\"windows\",\"channel\":\"$2\",\"event_id\":\"$1\"},\"values\":[${values%,}]}]}"
}
push 4624 Security 12
push 1102 Security 1      # log cleared -> investigate
push 7045 System 2        # new service -> watch
sleep 3

LOKI_URL="$LOKI_URL" OLLAMA_URL="http://127.0.0.1:9" python3 digest/windows_digest.py > /tmp/digest.json
python3 - <<'EOF'
import json
d = json.load(open("/tmp/digest.json"))
assert d["severity"] == "investigate", d["severity"]
assert d["headline"] == "Security log cleared (1x in 24h) (+1 more)", d["headline"]
assert d["severity_reasons"] == ["Security log cleared (1x in 24h)", "New service installed (2x in 24h)"], d["severity_reasons"]
print("digest OK:", d["headline"])
EOF

sleep 2
count=$(curl -s -G "$LOKI_URL/loki/api/v1/query" --data-urlencode 'query=sum(count_over_time({job="ai_digest", severity="investigate"}[5m]))' \
  | python3 -c 'import json,sys; r=json.load(sys.stdin)["data"]["result"]; print(int(float(r[0]["value"][1])) if r else 0)')
[ "$count" -ge 1 ] || { echo "digest not found in Loki"; exit 1; }
echo "digest found in Loki"
python3 scripts/healthcheck.py
