"""Scan operations health: are the scans themselves trustworthy?

A vulnerability count is only as good as the scan behind it. A host where
credentials failed reports a fraction of its real findings, so a clean
result there is a blind spot, not good news. This module checks three
things a vulnerability operations team owns day to day:

1. Credentialed scan coverage, read from Nessus/Tenable plugin output:
   - 19506 "Nessus Scan Information": "Credentialed checks : yes" means authenticated
   - 21745 "Authentication Failure - Local Checks Not Run"
   - 110385 "Authentication Success Insufficient Access"
2. Scan schedule health: scans that missed their window or did not finish
3. Coverage by asset class, so gaps are reported where they matter

Input CSVs:
  plugins.csv    host,plugin_id,plugin_output    (export of the three plugins above)
  schedules.csv  scan,target_tag,frequency_days,last_run,hosts_targeted,hosts_scanned,status
  assets.csv     host,tag                          (same inventory the tracker uses)
"""
from __future__ import annotations

import re
from collections import defaultdict
from datetime import date

SCAN_INFO, AUTH_FAIL, AUTH_INSUFFICIENT = "19506", "21745", "110385"


def credential_status(plugin_rows):
    """Return {host: status} where status is authenticated, failed, insufficient or unauthenticated."""
    seen = defaultdict(set)
    cred_yes = set()
    for r in plugin_rows:
        h, pid = r["host"], str(r["plugin_id"]).strip()
        seen[h].add(pid)
        if pid == SCAN_INFO and re.search(r"credentialed checks\s*:\s*yes", r.get("plugin_output", ""), re.I):
            cred_yes.add(h)
    out = {}
    for h, pids in seen.items():
        if AUTH_FAIL in pids:
            out[h] = "failed"
        elif AUTH_INSUFFICIENT in pids:
            out[h] = "insufficient"
        elif h in cred_yes:
            out[h] = "authenticated"
        else:
            out[h] = "unauthenticated"
    return out


def coverage_by_tag(assets, cred):
    tags = defaultdict(lambda: {"assets": 0, "scanned": 0, "authenticated": 0})
    for a in assets:
        t = tags[a["tag"]]
        t["assets"] += 1
        if a["host"] in cred:
            t["scanned"] += 1
            t["authenticated"] += cred[a["host"]] == "authenticated"
    for t in tags.values():
        t["auth_pct"] = round(100 * t["authenticated"] / t["assets"]) if t["assets"] else 0
    return dict(sorted(tags.items()))


def schedule_health(schedules, today: date, min_completion=0.9):
    issues = []
    for s in schedules:
        last = date.fromisoformat(s["last_run"]) if s.get("last_run") else None
        freq = int(s["frequency_days"])
        if last is None or (today - last).days > freq:
            age = "never run" if last is None else f"last ran {(today - last).days} days ago"
            issues.append({"scan": s["scan"], "issue": "missed schedule", "detail": f"{age}, expected every {freq} days"})
        if s.get("status", "").lower() not in ("completed", "complete"):
            issues.append({"scan": s["scan"], "issue": "did not complete", "detail": f"status {s.get('status')}"})
        tgt, done = int(s.get("hosts_targeted") or 0), int(s.get("hosts_scanned") or 0)
        if tgt and done / tgt < min_completion:
            issues.append({"scan": s["scan"], "issue": "low host completion",
                           "detail": f"{done}/{tgt} hosts ({round(100 * done / tgt)}%)"})
    return issues


def report(assets, plugin_rows, schedules, today: date, target_auth_pct=95):
    cred = credential_status(plugin_rows)
    cov = coverage_by_tag(assets, cred)
    sched = schedule_health(schedules, today)
    failed = sorted(h for h, s in cred.items() if s == "failed")
    insufficient = sorted(h for h, s in cred.items() if s == "insufficient")
    unauth = sorted(h for h, s in cred.items() if s == "unauthenticated")
    inventory = {a["host"] for a in assets}
    total_auth = sum(1 for h in inventory if cred.get(h) == "authenticated")
    actions = []
    for h in failed:
        actions.append(f"{h}: credentials failed, local checks did not run. Fix the scan credential (rotated password, locked account, or blocked SMB/SSH) and rescan; treat current results as incomplete.")
    for h in insufficient:
        actions.append(f"{h}: logged in but lacked privileges. Grant the scan account admin/root (or sudo) rights so patch-level checks run.")
    for h in unauth:
        actions.append(f"{h}: scanned without credentials. Add it to a credentialed scan policy.")
    for tag, t in cov.items():
        if t["auth_pct"] < target_auth_pct:
            actions.append(f"Asset class '{tag}': {t['auth_pct']}% authenticated coverage (target {target_auth_pct}%).")
    for i in sched:
        actions.append(f"Scan '{i['scan']}': {i['issue']} ({i['detail']}).")
    return {
        "authenticated_pct": round(100 * total_auth / len(inventory)) if inventory else 0,
        "credential_status": cred, "failed": failed, "insufficient": insufficient, "unauthenticated": unauth,
        "coverage_by_tag": cov, "schedule_issues": sched, "actions": actions,
    }


def to_markdown(r) -> str:
    lines = ["# Scan operations health", "",
             f"Authenticated coverage across inventory: **{r['authenticated_pct']}%**. "
             f"{len(r['failed'])} credential failures, {len(r['insufficient'])} insufficient-privilege logins, "
             f"{len(r['unauthenticated'])} unauthenticated hosts, {len(r['schedule_issues'])} schedule issues.", "",
             "## Coverage by asset class", "", "| Tag | Assets | Scanned | Authenticated | Auth % |", "|---|---|---|---|---|"]
    for tag, t in r["coverage_by_tag"].items():
        lines.append(f"| {tag} | {t['assets']} | {t['scanned']} | {t['authenticated']} | {t['auth_pct']}% |")
    lines += ["", "## Actions", ""] + [f"- {a}" for a in r["actions"]] or ["- None"]
    return "\n".join(lines) + "\n"
