# Changelog

## v1.0.0
First release.
- Alloy → Loki → Grafana stack for Windows Security, System, Defender, PowerShell and DNS events, with the Windows Security Overview dashboard
- Daily AI digest via a Python script or n8n, with a deterministic severity floor, rule reasons and recommended checks
- n8n workflow now matches the script: spike baseline with a 3-day warm-up, rule reasons passed to the model, headline replaced when rules raise severity, rule-based checks
- Loki and Grafana bound to `127.0.0.1`; n8n reaches Loki over the stack's Docker network
- Alloy `channel` labels use the full Windows channel names the dashboard queries expect
- Digest ignores non-list `findings` / `recommended_checks` from the model
- Tests for both digest paths from shared cases, a health check, an end-to-end smoke test and GitHub Actions CI
- Removed one-off patch scripts
