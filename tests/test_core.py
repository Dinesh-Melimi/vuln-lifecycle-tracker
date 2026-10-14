from datetime import date

from vlt.core import build, load_owners, read_csv, summary

T = date(2026, 10, 14)


def run():
    return build(read_csv("samples/scan_prev.csv"), read_csv("samples/scan_curr.csv"),
                 read_csv("samples/assets.csv"), load_owners(read_csv("samples/owners.csv")),
                 read_csv("samples/exceptions.csv"), T)


def get(f, host, pid):
    return next(x for x in f if x["host"] == host and x["plugin_id"] == pid)


def test_critical_past_sla_is_overdue():
    f, *_ = run()
    assert get(f, "fs01", "97833")["status"] == "Overdue"   # 43 days > 15-day SLA


def test_fixed_finding_is_verified_closed():
    f, *_ = run()
    assert get(f, "web01", "156860")["status"] == "Verified closed"


def test_unscanned_host_not_counted_as_fixed():
    f, gaps, _ = run()
    assert get(f, "hr-app", "10114")["status"] == "Not rescanned"
    assert "hr-app" in gaps and "atm-gw01" in gaps


def test_active_and_expired_exceptions():
    f, _, expired = run()
    assert get(f, "db01", "57582")["status"] == "Exception"
    assert get(f, "web01", "42873")["status"] == "Overdue"   # exception expired 2026-09-30
    assert expired[0]["host"] == "web01"


def test_unassigned_owner_flagged():
    f, gaps, exp = run()
    assert get(f, "web02", "187315")["owner"] == "Digital Banking"
    assert summary(f, gaps, exp)["overdue"] == 2
