"""Import Qualys VMDR exports into the tracker's scan format.

Qualys detection exports (CSV) use columns such as IP, DNS, NetBIOS, QID, Title, Severity (1-5),
CVSS3.1 Base, CVE ID, First Detected, Last Detected, Status, Threat Intel / RTI, and QDS.
This maps them to host, plugin_id, name, severity, first_seen so the same SLA, exception,
verified-closure and oversight logic works on Qualys data, and adds risk fields for prioritization.
"""
import csv
from datetime import datetime

# Qualys severity 1-5 -> tracker severity
QUALYS_SEV = {"5": "Critical", "4": "High", "3": "Medium", "2": "Low", "1": "Low"}


def _date(s):
    s = (s or "").strip()
    for fmt in ("%m/%d/%Y %H:%M:%S", "%m/%d/%Y %H:%M", "%m/%d/%Y", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%d"):
        try:
            return datetime.strptime(s, fmt).date().isoformat()
        except ValueError:
            continue
    raise ValueError(f"unrecognised Qualys date: {s!r}")


def severity(row):
    """Prefer CVSS v3 base score when present; fall back to the Qualys 1-5 severity."""
    cvss = (row.get("CVSS3.1 Base") or row.get("CVSS3 Base") or "").strip()
    if cvss:
        v = float(cvss.split()[0])
        return "Critical" if v >= 9 else "High" if v >= 7 else "Medium" if v >= 4 else "Low"
    return QUALYS_SEV.get((row.get("Severity") or "").strip(), "Low")


def risk_score(row):
    """0-100 risk for ordering within a severity: Qualys QDS when exported, else CVSS + threat intel."""
    qds = (row.get("QDS") or "").strip()
    if qds:
        return int(float(qds))
    cvss = float(((row.get("CVSS3.1 Base") or "0").split() or ["0"])[0])
    rti = (row.get("Threat Intel") or row.get("RTI") or "").lower()
    bonus = 25 if "active attacks" in rti or "cisa known exploited" in rti else 10 if "exploit" in rti else 0
    return min(100, int(cvss * 7.5) + bonus)


def load_qualys(path, include_fixed=False):
    out = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for r in csv.DictReader(fh):
            if not include_fixed and (r.get("Status") or "").strip().lower() == "fixed":
                continue
            host = (r.get("DNS") or r.get("NetBIOS") or r.get("IP") or "").strip().split(".")[0]
            out.append({"host": host, "plugin_id": r["QID"].strip(), "name": r["Title"].strip(),
                        "severity": severity(r), "first_seen": _date(r["First Detected"]),
                        "cve": (r.get("CVE ID") or "").strip(), "risk": risk_score(r),
                        "threat_intel": (r.get("Threat Intel") or r.get("RTI") or "").strip()})
    return out
