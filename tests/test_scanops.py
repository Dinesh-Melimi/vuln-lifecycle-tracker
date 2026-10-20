from datetime import date

from vlt.core import read_csv
from vlt.scanops import credential_status, report, schedule_health
from vlt.scanops_cli import main

T = date(2026, 10, 14)


def run():
    return report(read_csv("samples/assets.csv"), read_csv("samples/scan_plugins.csv"),
                  read_csv("samples/scan_schedules.csv"), T)


def test_credential_status_from_plugins():
    c = credential_status(read_csv("samples/scan_plugins.csv"))
    assert c["web01"] == "authenticated"
    assert c["web02"] == "failed"          # 21745 wins over "Credentialed checks : no"
    assert c["db01"] == "insufficient"     # logged in, but 110385 says no privileges
    assert c["hr-app"] == "unauthenticated"


def test_unscanned_asset_counts_against_coverage():
    r = run()
    assert "atm-gw01" not in r["credential_status"]
    assert r["coverage_by_tag"]["branch"]["auth_pct"] == 0
    assert r["authenticated_pct"] == 33    # web01 and fs01 of 6 inventory hosts


def test_schedule_problems_found():
    issues = {(i["scan"], i["issue"]) for i in schedule_health(read_csv("samples/scan_schedules.csv"), T)}
    assert ("Weekly - Servers", "missed schedule") in issues      # 16 days on a 7-day cadence
    assert ("Monthly - Branch", "did not complete") in issues
    assert ("Monthly - Branch", "low host completion") in issues
    assert not any(s == "Weekly - Web" for s, _ in issues)


def test_actions_are_specific():
    acts = "\n".join(run()["actions"])
    assert "web02: credentials failed" in acts and "db01: logged in but lacked privileges" in acts
    assert "hr-app: scanned without credentials" in acts


def test_cli_exit_code_and_report(tmp_path, capsys):
    out = tmp_path / "s.md"
    rc = main(["--assets", "samples/assets.csv", "--plugins", "samples/scan_plugins.csv",
               "--schedules", "samples/scan_schedules.csv", "--today", "2026-10-14", "--out", str(out)])
    assert rc == 1 and out.read_text().startswith("# Scan operations health")
    assert "Authenticated coverage 33%" in capsys.readouterr().out
