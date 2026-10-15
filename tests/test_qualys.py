from datetime import date

from vlt.core import build, load_owners, read_csv
from vlt.qualys import load_qualys, risk_score, severity


def test_maps_qualys_export_and_skips_fixed():
    rows = load_qualys("samples/qualys_curr.csv")
    assert {r["plugin_id"] for r in rows} == {"91345", "42400", "38173", "38140"}
    smb = next(r for r in rows if r["plugin_id"] == "91345")
    assert smb["host"] == "fs01" and smb["first_seen"] == "2026-09-01" and smb["cve"] == "CVE-2017-0144"
    assert len(load_qualys("samples/qualys_curr.csv", include_fixed=True)) == 5


def test_severity_prefers_cvss_then_qualys_level():
    assert severity({"CVSS3.1 Base": "8.1", "Severity": "5"}) == "High"
    assert severity({"CVSS3.1 Base": "", "Severity": "2"}) == "Low"
    assert severity({"CVSS3.1 Base": "10.0"}) == "Critical"


def test_risk_score_uses_qds_or_threat_intel():
    assert risk_score({"QDS": "95"}) == 95
    assert risk_score({"CVSS3.1 Base": "8.0", "Threat Intel": "Active Attacks"}) == 85
    assert risk_score({"CVSS3.1 Base": "8.0", "Threat Intel": ""}) == 60


def test_qualys_rows_flow_through_tracker():
    f, _, _ = build([], load_qualys("samples/qualys_curr.csv"), read_csv("samples/assets.csv"),
                    load_owners(read_csv("samples/owners.csv")), read_csv("samples/exceptions.csv"), date(2026, 10, 14))
    fs = next(x for x in f if x["host"] == "fs01")
    assert fs["status"] == "Overdue" and fs["owner"] == "Infrastructure"
