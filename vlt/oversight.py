"""Independent (second-line) oversight of the findings and exposure lifecycle.

The tracker answers "where is each finding?". Oversight answers "should we believe it?":
- exception challenge: is each risk acceptance justified, approved at the right level, and time-bound?
- closure assurance: is claimed closure backed by a rescan, or is the finding still there?
- data quality: are records complete, owned, and internally consistent?
- patch oversight: is every patch-not-deployed decision explained and approved on time?
- escalation and trends: which owners are missing commitments, and how old is the backlog?
"""
from collections import Counter, defaultdict
from datetime import date, timedelta

# Who may accept residual risk, by severity (configurable).
APPROVAL_AUTHORITY = {"Critical": {"CISO"}, "High": {"CISO", "Deputy CISO"},
                      "Medium": {"CISO", "Deputy CISO", "IT Manager", "Risk Manager"},
                      "Low": {"CISO", "Deputy CISO", "IT Manager", "Risk Manager", "Team Lead"}}
MAX_EXCEPTION_DAYS = {"Critical": 90, "High": 180, "Medium": 365, "Low": 365}
AGING = [(30, "0-30"), (60, "31-60"), (90, "61-90"), (10**6, "90+")]


def _d(s):
    try:
        return date.fromisoformat(s) if s else None
    except ValueError:
        return None


def challenge_exceptions(exceptions, findings, today, warn_days=30):
    sev = {(f["host"].lower(), f["plugin_id"]): f["severity"] for f in findings}
    out = []
    for e in exceptions:
        k = (e["host"].lower(), e["plugin_id"])
        s = sev.get(k, "Unknown")
        issues = []
        if not (e.get("reason") or "").strip():
            issues.append("no rationale")
        if not (e.get("compensating_control") or "").strip():
            issues.append("no compensating control documented")
        if s in APPROVAL_AUTHORITY and e.get("approved_by") not in APPROVAL_AUTHORITY[s]:
            issues.append(f"{e.get('approved_by') or 'nobody'} cannot accept {s} risk")
        exp, start = _d(e.get("expires")), _d(e.get("approved_on"))
        if exp is None:
            issues.append("no valid expiry")
        else:
            if exp < today:
                issues.append("expired")
            elif exp <= today + timedelta(days=warn_days):
                issues.append(f"expires in {(exp - today).days} days; renewal or remediation plan needed")
            if start and s in MAX_EXCEPTION_DAYS and (exp - start).days > MAX_EXCEPTION_DAYS[s]:
                issues.append(f"term {(exp - start).days} days exceeds {MAX_EXCEPTION_DAYS[s]}-day limit for {s}")
        if k not in sev:
            issues.append("finding no longer present; retire the exception")
        if issues:
            out.append({"host": e["host"], "plugin_id": e["plugin_id"], "severity": s, "issues": issues})
    return out


def closure_assurance(claims, findings):
    """claims: rows (host, plugin_id, claimed_by, evidence) from the remediation tracker."""
    status = {(f["host"].lower(), f["plugin_id"]): f["status"] for f in findings}
    out = []
    for c in claims:
        st = status.get((c["host"].lower(), c["plugin_id"]))
        if st == "Verified closed":
            verdict = "accepted (rescan confirms)"
        elif st in ("Open", "Overdue", "Exception"):
            verdict = "REJECTED: still detected in latest scan"
        elif st == "Not rescanned":
            verdict = "PENDING: host not rescanned, no independent evidence"
        else:
            verdict = "PENDING: finding not in scan data"
        if not (c.get("evidence") or "").strip() and verdict.startswith("accepted"):
            verdict = "accepted by rescan; closure evidence missing from record"
        out.append({**c, "verdict": verdict})
    return out


def data_quality(findings, assets, today):
    issues = []
    seen = Counter((f["host"].lower(), f["plugin_id"]) for f in findings)
    inventory = {a["host"].lower() for a in assets}
    for f in findings:
        ref = f"{f['host']} / {f['plugin_id']}"
        if f["owner"] == "UNASSIGNED":
            issues.append((ref, "no accountable owner"))
        if f["host"].lower() not in inventory:
            issues.append((ref, "host missing from asset inventory"))
        if f["severity"] not in APPROVAL_AUTHORITY:
            issues.append((ref, f"unrecognised severity '{f['severity']}'"))
        fs = _d(f["first_seen"])
        if fs is None:
            issues.append((ref, "invalid first_seen"))
        elif fs > today:
            issues.append((ref, "first_seen is in the future"))
    issues += [(f"{h} / {p}", "duplicate record") for (h, p), n in seen.items() if n > 1]
    return [{"record": r, "issue": i} for r, i in issues]


def patch_oversight(patches, today):
    """patches: rows (host, patch, status, rationale, approval_due, approved_by)."""
    out = []
    for p in patches:
        if p.get("status", "").lower() != "not_deployed":
            continue
        issues = []
        if not (p.get("rationale") or "").strip():
            issues.append("patch not deployed with no rationale")
        due = _d(p.get("approval_due"))
        if not (p.get("approved_by") or "").strip():
            issues.append("approval overdue" if due and due < today else "awaiting approval")
        if issues:
            out.append({"host": p["host"], "patch": p["patch"], "issues": issues})
    return out


def escalations(findings, today, central_after_days=30):
    out = []
    for f in findings:
        if f["status"] != "Overdue":
            continue
        late = (today - date.fromisoformat(f["due"])).days
        level = "central escalation" if late > central_after_days or f["severity"] == "Critical" else "owner escalation"
        out.append({"owner": f["owner"], "host": f["host"], "name": f["name"], "severity": f["severity"],
                    "days_late": late, "level": level})
    return sorted(out, key=lambda x: (x["level"] != "central escalation", -x["days_late"]))


def aging(findings):
    table = defaultdict(Counter)
    for f in findings:
        if f["status"] in ("Open", "Overdue", "Exception") and f["days_open"] != "":
            bucket = next(name for limit, name in AGING if f["days_open"] <= limit)
            table[f["severity"]][bucket] += 1
    return {s: dict(c) for s, c in table.items()}


def owner_scorecard(findings):
    sc = defaultdict(lambda: {"open": 0, "overdue": 0, "on_exception": 0, "verified_closed": 0})
    keymap = {"Open": "open", "Overdue": "overdue", "Exception": "on_exception", "Verified closed": "verified_closed"}
    for f in findings:
        if f["status"] in keymap:
            sc[f["owner"]][keymap[f["status"]]] += 1
    return dict(sc)


def render(today, exc, claims, dq, patches, esc, ages, owners):
    L = [f"# Findings & Exposure Oversight Report ({today})", "",
         "## Headline", "",
         f"- {len(esc)} overdue findings ({sum(e['level'] == 'central escalation' for e in esc)} need central escalation)",
         f"- {len(exc)} risk acceptances challenged",
         f"- {sum(c['verdict'].startswith('REJECTED') for c in claims)} closure claims rejected, "
         f"{sum(c['verdict'].startswith('PENDING') for c in claims)} pending evidence",
         f"- {len(dq)} data-quality issues; {len(patches)} patch-not-deployed decisions need action", ""]
    L += ["## Escalations", "", "| Level | Owner | Host | Finding | Severity | Days late |", "|---|---|---|---|---|---|"]
    L += [f"| {e['level']} | {e['owner']} | {e['host']} | {e['name']} | {e['severity']} | {e['days_late']} |" for e in esc]
    L += ["", "## Risk acceptance challenges", ""]
    L += [f"- **{x['host']} / {x['plugin_id']}** ({x['severity']}): {'; '.join(x['issues'])}" for x in exc] or ["- none"]
    L += ["", "## Closure assurance", "", "| Host | Plugin | Claimed by | Verdict |", "|---|---|---|---|"]
    L += [f"| {c['host']} | {c['plugin_id']} | {c.get('claimed_by', '')} | {c['verdict']} |" for c in claims]
    L += ["", "## Patch oversight", ""]
    L += [f"- **{p['host']} {p['patch']}**: {'; '.join(p['issues'])}" for p in patches] or ["- none"]
    L += ["", "## Data quality", ""]
    L += [f"- {d['record']}: {d['issue']}" for d in dq] or ["- none"]
    L += ["", "## Aging (open, overdue, on exception)", "", "| Severity | 0-30 | 31-60 | 61-90 | 90+ |", "|---|---|---|---|---|"]
    for s in ("Critical", "High", "Medium", "Low"):
        if s in ages:
            L.append(f"| {s} | " + " | ".join(str(ages[s].get(b, 0)) for _, b in AGING) + " |")
    L += ["", "## Owner accountability", "", "| Owner | Open | Overdue | On exception | Verified closed |", "|---|---|---|---|---|"]
    L += [f"| {o} | {v['open']} | {v['overdue']} | {v['on_exception']} | {v['verified_closed']} |"
          for o, v in sorted(owners.items(), key=lambda kv: -kv[1]["overdue"])]
    return "\n".join(L) + "\n"
