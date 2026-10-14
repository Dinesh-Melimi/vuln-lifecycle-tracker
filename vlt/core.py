import csv
from datetime import date, timedelta

SLA_DAYS = {"Critical": 15, "High": 30, "Medium": 90, "Low": 180}


def read_csv(path):
    with open(path, newline="") as f:
        return list(csv.DictReader(f))


def key(row):
    return (row["host"].lower(), row["plugin_id"])


def load_owners(rows):
    """asset tag -> owner team."""
    return {r["tag"]: r["owner"] for r in rows}


def load_exceptions(rows, today):
    """Active approved exceptions keyed by (host, plugin_id). Expired ones are ignored."""
    active, expired = {}, []
    for r in rows:
        k = (r["host"].lower(), r["plugin_id"])
        exp = date.fromisoformat(r["expires"])
        (active.__setitem__(k, r) if exp >= today else expired.append({**r, "key": k}))
    return active, expired


def build(prev_scan, curr_scan, assets, owners, exceptions, today):
    """Compare two scans and produce the tracked finding list.

    prev_scan / curr_scan: rows with host, plugin_id, name, severity, first_seen
    assets: rows with host, tag
    """
    tag_of = {a["host"].lower(): a["tag"] for a in assets}
    exc, expired = load_exceptions(exceptions, today)
    prev = {key(r): r for r in prev_scan}
    curr = {key(r): r for r in curr_scan}
    scanned_hosts = {r["host"].lower() for r in curr_scan}
    findings = []

    for k, r in curr.items():
        first = date.fromisoformat(r["first_seen"])
        due = first + timedelta(days=SLA_DAYS.get(r["severity"], 180))
        tag = tag_of.get(k[0], "untagged")
        if k in exc:
            status = "Exception"
        elif due < today:
            status = "Overdue"
        else:
            status = "Open"
        findings.append({
            "host": r["host"], "plugin_id": r["plugin_id"], "name": r["name"], "severity": r["severity"],
            "owner": owners.get(tag, "UNASSIGNED"), "first_seen": r["first_seen"], "due": due.isoformat(),
            "days_open": (today - first).days, "status": status,
            "exception": exc[k]["approved_by"] + " until " + exc[k]["expires"] if k in exc else "",
        })

    for k, r in prev.items():
        if k in curr:
            continue
        # Only call it fixed if the host was actually rescanned; otherwise it is a coverage gap.
        status = "Verified closed" if k[0] in scanned_hosts else "Not rescanned"
        findings.append({
            "host": r["host"], "plugin_id": r["plugin_id"], "name": r["name"], "severity": r["severity"],
            "owner": owners.get(tag_of.get(k[0], "untagged"), "UNASSIGNED"), "first_seen": r["first_seen"],
            "due": "", "days_open": "", "status": status, "exception": "",
        })

    coverage_gaps = sorted({a["host"] for a in assets} - {r["host"] for r in curr_scan})
    return findings, coverage_gaps, expired


def summary(findings, coverage_gaps, expired):
    by = lambda s: [f for f in findings if f["status"] == s]
    return {
        "open": len(by("Open")), "overdue": len(by("Overdue")), "exceptions": len(by("Exception")),
        "verified_closed": len(by("Verified closed")), "not_rescanned": len(by("Not rescanned")),
        "unassigned": len([f for f in findings if f["owner"] == "UNASSIGNED" and f["status"] in ("Open", "Overdue")]),
        "coverage_gaps": coverage_gaps, "expired_exceptions": [e["host"] + " / " + e["plugin_id"] for e in expired],
    }
