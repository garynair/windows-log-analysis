"""Patch 2: make the digest explain WHY rules raised severity, so headline and severity agree."""
import sys, pathlib
p = pathlib.Path(sys.argv[1]).expanduser() / "digest/windows_digest.py"
s = p.read_text()
if "RULE_CHECKS" in s:
    sys.exit("already patched")

old_floor = '''def severity_floor(facts):
    ids = {r["event_id"] for r in facts["event_counts"]}
    if ids & CRITICAL:
        return "investigate"
    if ids & WATCH or any(r["spike"] for r in facts["event_counts"]):
        return "watch"
    return "info"'''
new_floor = '''RULE_CHECKS = {
    "1102": "Identify who cleared the Security log and why (see the event's Subject account).",
    "104": "Identify who cleared the System log and why.",
    "4719": "Confirm the audit policy change was authorized: check the event's Subject account and run 'auditpol /get /category:*'.",
    "5001": "Re-enable Defender real-time protection and find out who or what disabled it.",
    "7045": "Confirm each newly installed service is expected software.",
    "1116": "Review the Defender detection and confirm it was remediated.",
    "1117": "Review the action Defender took and confirm the threat is resolved.",
    "5007": "Review the Defender configuration change and confirm it was intended.",
}
ACCOUNT_IDS = {"4720", "4722", "4725", "4726", "4728", "4732", "4740", "4756"}


def severity_floor(facts):
    """Returns (level, reasons, checks). Reasons are ordered most serious first."""
    rows = facts["event_counts"]
    reasons, checks = [], []
    for r in rows:
        if r["event_id"] in CRITICAL:
            reasons.append(f'{r["name"]} ({r["count_24h"]}x in 24h)')
            checks.append(RULE_CHECKS[r["event_id"]])
    level = "investigate" if reasons else None
    for r in rows:
        if r["event_id"] in WATCH:
            reasons.append(f'{r["name"]} ({r["count_24h"]}x in 24h)')
            checks.append(RULE_CHECKS.get(r["event_id"], "Verify each account or group change against an approved request."
                                          if r["event_id"] in ACCOUNT_IDS else "Review these events."))
        elif r["spike"]:
            reasons.append(f'Unusual volume: {r["name"]} ({r["count_24h"]} vs ~{r["baseline_avg_per_day"]}/day)')
            checks.append(f'Find the source of the increase in {r["name"]} events.')
    level = level or ("watch" if reasons else "info")
    return level, reasons, list(dict.fromkeys(checks))'''

old_main = '''    facts = build_facts()
    floor = severity_floor(facts)'''
new_main = '''    facts = build_facts()
    floor, reasons, rule_checks = severity_floor(facts)
    facts["severity_floor"], facts["severity_reasons"] = floor, reasons'''

old_sev = '''    severity = RANK[max(RANK.index(llm_sev), RANK.index(floor))]  # rules can raise, never lower'''
new_sev = '''    severity = RANK[max(RANK.index(llm_sev), RANK.index(floor))]  # rules can raise, never lower
    headline = d.get("headline", "")
    if RANK.index(floor) > RANK.index(llm_sev) and reasons:
        headline = reasons[0] + (f" (+{len(reasons) - 1} more)" if len(reasons) > 1 else "")  # rules raised it: say why
    checks = list(dict.fromkeys(rule_checks + list(d.get("recommended_checks", []))))'''

old_fields = '''"llm_severity": d.get("severity"), "headline": d.get("headline", ""),
              "findings": d.get("findings", []), "recommended_checks": d.get("recommended_checks", []),'''
new_fields = '''"llm_severity": d.get("severity"), "headline": headline, "llm_headline": d.get("headline", ""),
              "severity_reasons": reasons,
              "findings": d.get("findings", []), "recommended_checks": checks,'''

old_prompt = "- Keep findings specific: cite event names and counts from the facts."
new_prompt = (old_prompt + "\\n- facts.severity_reasons lists issues detected by rules. If it is not empty, the headline MUST name "
              "the most serious one, severity must be at least facts.severity_floor, and findings must explain each reason.")

for a in (old_floor, old_main, old_sev, old_fields, old_prompt):
    if a not in s:
        sys.exit(f"expected text not found, no changes made: {a[:70]!r}")
s = (s.replace(old_floor, new_floor).replace(old_main, new_main).replace(old_sev, new_sev)
       .replace(old_fields, new_fields).replace(old_prompt, new_prompt))
p.write_text(s)
print("digest: severity reasons added")
