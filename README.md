![Windows Log Stack: Alloy → Loki → Grafana (+ optional AI digest)](docs/banner.png)

# Windows Log Stack: Alloy → Loki → Grafana (+ optional AI digest)

```
WINDOWS                        WSL (Docker)                         DIGEST (pick one)
Event Logs ─► Grafana Alloy ─► Loki :3100 ─► Grafana :3001          A) digest/windows_digest.py  (no n8n)
 (service)    (localhost push)     ▲                                B) n8n workflow              (with n8n)
                                   └──── job="ai_digest" ◄── both write the daily digest back to Loki
```

## 1. Windows: enable the right logs (Admin PowerShell, once)
```powershell
powershell -ExecutionPolicy Bypass -File .\windows\enable-auditing.ps1
```

## 2. WSL: start Loki + Grafana
```bash
cp .env.example .env && nano .env          # set a real GRAFANA_ADMIN_PASSWORD
docker compose up -d
curl -s localhost:3100/ready               # -> ready (may take ~15s)
```
Grafana: http://localhost:3001 → Dashboards → Security → **Windows Security Overview**

## 3. Windows: install Grafana Alloy
1. Download `alloy-installer-windows-amd64.exe` from github.com/grafana/alloy/releases (latest) and install.
2. Copy `alloy\config.alloy` over `C:\Program Files\GrafanaLabs\Alloy\config.alloy`.
3. Admin PowerShell: `Restart-Service Alloy`
4. Check http://localhost:12345 — every `loki.source.windowsevent` component should be healthy.
5. Within ~1 minute, panels in Grafana start filling.

## 4a. Digest WITHOUT n8n
```bash
python3 digest/windows_digest.py          # prints the digest and pushes it to Loki
```
Schedule: `crontab -e` → `0 7 * * * /usr/bin/python3 /home/<you>/windows-log-stack/digest/windows_digest.py >> /tmp/digest.log 2>&1`
(cron only runs while WSL is up; alternative is Windows Task Scheduler running
`wsl -d Ubuntu-24.04 -- python3 /home/<you>/windows-log-stack/digest/windows_digest.py`).

## 4b. Digest WITH n8n
1. n8n → ⋯ → Import from File → `n8n/windows_log_digest_workflow.json`
2. Open **Ollama llama3.2:3b** node → select your existing Ollama credential.
3. Execute workflow once manually; then Publish to run daily at 7 AM.

Both paths write to `{job="ai_digest"}` → the **Daily AI digest** panel shows whichever you use.

## Design notes
- **Severity floor:** deterministic rules (log cleared, audit policy changed, Defender disabled → *investigate*;
  account/group changes, new services, detections, spikes → *watch*) can raise the LLM's severity, never lower it.
- **Data stays local:** logs, Loki, and the model are all on this laptop. Don't point the digest at a cloud LLM —
  4688 command lines can contain secrets.
- **Retention:** 30 days (`loki/loki-config.yaml` → `retention_period`).
- **Images are pinned** to known-good versions; update tags once the stack works.

## Known weak spots
- If WSL is stopped, Alloy retries then **drops** events (its bookmark still advances). Keep WSL running while collecting.
- The DNS panels extract names with a regex on the event message; if they're empty but `{channel="dns"}` has logs,
  the message format differs — adjust the regex in the two DNS panels.
- 4624/4672/4688 are high-volume by nature; fine for one laptop, too noisy to ship as-is to a shared SIEM.
