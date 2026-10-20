"""python -m vlt.scanops_cli --assets samples/assets.csv --plugins samples/scan_plugins.csv \
       --schedules samples/scan_schedules.csv --today 2026-10-14 --out scanops.md"""
import argparse
import sys
from datetime import date

from .core import read_csv
from .scanops import report, to_markdown


def main(argv=None):
    ap = argparse.ArgumentParser(description="Check credentialed coverage and scan schedule health.")
    ap.add_argument("--assets", required=True)
    ap.add_argument("--plugins", required=True, help="Nessus/Tenable export of plugins 19506, 21745, 110385")
    ap.add_argument("--schedules", required=True)
    ap.add_argument("--today", default=date.today().isoformat())
    ap.add_argument("--target", type=int, default=95, help="authenticated coverage target per asset class (%%)")
    ap.add_argument("--out", help="write the Markdown report here")
    a = ap.parse_args(argv)
    r = report(read_csv(a.assets), read_csv(a.plugins), read_csv(a.schedules), date.fromisoformat(a.today), a.target)
    print(f"Authenticated coverage {r['authenticated_pct']}%: {len(r['failed'])} credential failures, "
          f"{len(r['insufficient'])} insufficient privilege, {len(r['unauthenticated'])} unauthenticated, "
          f"{len(r['schedule_issues'])} schedule issues")
    for x in r["actions"]:
        print("  -", x)
    if a.out:
        open(a.out, "w").write(to_markdown(r))
    return 1 if (r["failed"] or r["schedule_issues"]) else 0


if __name__ == "__main__":
    sys.exit(main())
