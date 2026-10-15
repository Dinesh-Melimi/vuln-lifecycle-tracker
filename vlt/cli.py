import argparse
import csv
import sys
from datetime import date

from . import oversight
from .core import build, load_owners, read_csv, summary

ORDER = {"Overdue": 0, "Open": 1, "Exception": 2, "Not rescanned": 3, "Verified closed": 4}
SEV = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}


def main(argv=None):
    ap = argparse.ArgumentParser(description="Track vulnerability findings from scan to verified closure.")
    ap.add_argument("--prev", required=True)
    ap.add_argument("--curr", required=True)
    ap.add_argument("--assets", required=True)
    ap.add_argument("--owners", required=True)
    ap.add_argument("--exceptions", required=True)
    ap.add_argument("--today", default=date.today().isoformat())
    ap.add_argument("--out", help="Write tracked findings CSV (audit evidence)")
    ap.add_argument("--oversight-report", help="Write an independent oversight report (Markdown)")
    ap.add_argument("--claims", help="Closure claims CSV from the remediation tracker (host,plugin_id,claimed_by,evidence)")
    ap.add_argument("--patches", help="Patch status CSV (host,patch,status,rationale,approval_due,approved_by)")
    a = ap.parse_args(argv)
    today = date.fromisoformat(a.today)
    f, gaps, expired = build(read_csv(a.prev), read_csv(a.curr), read_csv(a.assets),
                             load_owners(read_csv(a.owners)), read_csv(a.exceptions), today)
    f.sort(key=lambda x: (ORDER[x["status"]], SEV.get(x["severity"], 9)))
    s = summary(f, gaps, expired)
    print(f"As of {today}: {s['overdue']} overdue, {s['open']} open, {s['exceptions']} on exception, "
          f"{s['verified_closed']} verified closed, {s['not_rescanned']} not rescanned, {s['unassigned']} unassigned")
    if gaps:
        print("Coverage gaps (in inventory, not scanned):", ", ".join(gaps))
    if s["expired_exceptions"]:
        print("Expired exceptions (back in scope):", ", ".join(s["expired_exceptions"]))
    for x in f:
        if x["status"] in ("Overdue", "Open"):
            print(f"  [{x['status']}] {x['severity']:8} {x['host']:12} {x['name'][:40]:40} owner={x['owner']} due={x['due']}")
    if a.out:
        with open(a.out, "w", newline="") as fh:
            w = csv.DictWriter(fh, fieldnames=list(f[0].keys()))
            w.writeheader()
            w.writerows(f)
    if a.oversight_report:
        exc_rows = read_csv(a.exceptions)
        report = oversight.render(
            today,
            oversight.challenge_exceptions(exc_rows, f, today),
            oversight.closure_assurance(read_csv(a.claims) if a.claims else [], f),
            oversight.data_quality(f, read_csv(a.assets), today),
            oversight.patch_oversight(read_csv(a.patches) if a.patches else [], today),
            oversight.escalations(f, today),
            oversight.aging(f),
            oversight.owner_scorecard(f),
        )
        with open(a.oversight_report, "w") as fh:
            fh.write(report)
        print(f"Oversight report written to {a.oversight_report}")
    return 1 if s["overdue"] else 0


if __name__ == "__main__":
    sys.exit(main())
