from datetime import date

from vlt import oversight
from vlt.cli import main
from vlt.core import build, load_owners, read_csv

TODAY = date(2026, 10, 14)
S = "samples/"


def _findings():
    f, _, _ = build(read_csv(S + "scan_prev.csv"), read_csv(S + "scan_curr.csv"), read_csv(S + "assets.csv"),
                    load_owners(read_csv(S + "owners.csv")), read_csv(S + "exceptions.csv"), TODAY)
    return f


def test_exception_challenges():
    f = _findings()
    out = {x["host"]: x["issues"] for x in oversight.challenge_exceptions(read_csv(S + "exceptions.csv"), f, TODAY)}
    assert "db01" not in out  # CISO-approved, time-bound, compensating control: passes
    assert "expired" in out["web01"]
    assert any("exceeds 365-day limit" in i for i in out["web01"])
    assert "no compensating control documented" in out["web01"]


def test_wrong_approver_and_retired_finding():
    f = [{"host": "h1", "plugin_id": "1", "severity": "Critical"}]
    rows = [{"host": "h1", "plugin_id": "1", "approved_by": "IT Manager", "reason": "x", "expires": "2027-01-01",
             "compensating_control": "y"},
            {"host": "h2", "plugin_id": "9", "approved_by": "CISO", "reason": "x", "expires": "2027-01-01",
             "compensating_control": "y"}]
    out = {x["host"]: x["issues"] for x in oversight.challenge_exceptions(rows, f, TODAY)}
    assert "IT Manager cannot accept Critical risk" in out["h1"]
    assert "finding no longer present; retire the exception" in out["h2"]


def test_closure_claims_rejected_when_still_detected():
    v = {c["host"]: c["verdict"] for c in oversight.closure_assurance(read_csv(S + "closure_claims.csv"), _findings())}
    assert v["web01"].startswith("accepted")
    assert v["fs01"].startswith("REJECTED")


def test_patch_oversight():
    out = {p["host"]: p["issues"] for p in oversight.patch_oversight(read_csv(S + "patches.csv"), TODAY)}
    assert out["fs01"] == ["patch not deployed with no rationale", "approval overdue"]
    assert out["db01"] == ["awaiting approval"]
    assert "web02" not in out


def test_data_quality_catches_bad_records():
    f = [{"host": "ghost", "plugin_id": "1", "severity": "Severe", "owner": "UNASSIGNED", "first_seen": "2027-01-01"},
         {"host": "ghost", "plugin_id": "1", "severity": "Severe", "owner": "UNASSIGNED", "first_seen": "bad"}]
    issues = {d["issue"] for d in oversight.data_quality(f, [], TODAY)}
    assert {"no accountable owner", "host missing from asset inventory", "unrecognised severity 'Severe'",
            "first_seen is in the future", "invalid first_seen", "duplicate record"} <= issues


def test_escalation_levels_and_aging():
    esc = oversight.escalations(_findings(), TODAY)
    assert esc[0]["severity"] == "Critical" and esc[0]["level"] == "central escalation"
    assert oversight.aging(_findings())["Medium"]["90+"] == 2


def test_cli_writes_report(tmp_path):
    out = tmp_path / "ov.md"
    main(["--prev", S + "scan_prev.csv", "--curr", S + "scan_curr.csv", "--assets", S + "assets.csv",
          "--owners", S + "owners.csv", "--exceptions", S + "exceptions.csv", "--today", "2026-10-14",
          "--claims", S + "closure_claims.csv", "--patches", S + "patches.csv", "--oversight-report", str(out)])
    text = out.read_text()
    assert "## Escalations" in text and "REJECTED" in text and "## Owner accountability" in text
