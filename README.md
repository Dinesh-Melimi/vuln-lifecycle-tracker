# Vulnerability Lifecycle Tracker

Scanners are good at finding things. The hard part is everything after: who owns the finding, when it is due, whether an exception is still valid, and whether "fixed" was actually verified by a rescan. Examiners (NCUA, FFIEC) ask for exactly that trail.

This tool compares the previous and current scan exports (Tenable/Nessus CSV) with your asset inventory and produces a tracked list where every finding has:

- **Owner**, from asset tags (unassigned findings are called out)
- **SLA due date** by severity (Critical 15 / High 30 / Medium 90 / Low 180 days, configurable)
- **Status**: Open, Overdue, Exception, Verified closed, or Not rescanned
- **Exception routing** with approver and expiry; expired exceptions go straight back to Overdue
- **Verified closure** only when the host was actually rescanned; a missing finding on an unscanned host is a coverage gap, not a fix
- **Coverage gaps**: inventory assets that the scan never touched

## Run

```bash
python -m vlt.cli --prev samples/scan_prev.csv --curr samples/scan_curr.csv \
  --assets samples/assets.csv --owners samples/owners.csv --exceptions samples/exceptions.csv \
  --today 2026-10-14 --out tracked.csv
```

```
As of 2026-10-14: 2 overdue, 1 open, 1 on exception, 1 verified closed, 1 not rescanned, 0 unassigned
Coverage gaps (in inventory, not scanned): atm-gw01, hr-app
Expired exceptions (back in scope): web01 / 42873
  [Overdue] Critical fs01   SMBv1 Enabled (MS17-010)  owner=Infrastructure due=2026-09-16
  ...
```

`tracked.csv` is the audit evidence. Exit code 1 when anything is overdue, so it can run after each scan and alert.

## Independent oversight report

The tracker answers "where is each finding?". `--oversight-report` answers "should we believe it?", the second-line review a risk or oversight team runs:

```bash
python -m vlt.cli --prev samples/scan_prev.csv --curr samples/scan_curr.csv --assets samples/assets.csv \
  --owners samples/owners.csv --exceptions samples/exceptions.csv --today 2026-10-14 \
  --claims samples/closure_claims.csv --patches samples/patches.csv --oversight-report oversight.md
```

- **Risk acceptance challenge**: rationale and compensating control present, approved at the right authority for the severity (Critical needs the CISO), term within the limit, not expired or about to expire, and retired once the finding is gone
- **Closure assurance**: each closure claimed in the remediation tracker is accepted only if a rescan confirms it; a claim on a finding still detected is rejected
- **Patch oversight**: every patch-not-deployed decision needs a rationale and an approval before its due date
- **Data quality**: missing owners, hosts not in inventory, unknown severities, impossible dates, duplicate records
- **Escalation**: overdue findings routed to the owner, or to central escalation when Critical or more than 30 days late
- **Trends**: aging by severity (0-30 / 31-60 / 61-90 / 90+) and an owner accountability scorecard for leadership

```
- 2 overdue findings (1 need central escalation)
- 1 risk acceptances challenged
- 1 closure claims rejected, 0 pending evidence
- 1 data-quality issues; 2 patch-not-deployed decisions need action
```
