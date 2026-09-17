"""RAMShift launcher: unpacks the bundled tool and its pure-Python dependencies once
into a per-user cache (botocore reads its service models from files), then runs it."""
import os
import sys
import tempfile
import zipfile
from pathlib import Path

VERSION = "0.0.0"
if sys.version_info < (3, 11):
    sys.exit(f"RAMShift {VERSION} requires Python 3.11 or later; this is {sys.version.split()[0]}")
archive = Path(__file__).resolve().parent
with zipfile.ZipFile(archive) as bundle:
    build = bundle.read("BUILD_ID").decode().strip()
    cache = Path(os.environ.get("RAMSHIFT_CACHE") or Path.home() / ".cache" / "ramshift")
    target = cache / f"{VERSION}-{build}"
    if not (target / ".complete").exists():
        cache.mkdir(parents=True, exist_ok=True)
        staging = Path(tempfile.mkdtemp(prefix=".unpack-", dir=cache))
        for name in bundle.namelist():
            if name.startswith("lib/") and not name.endswith("/"):
                bundle.extract(name, staging)
        (staging / "lib" / ".complete").touch()
        try:
            (staging / "lib").rename(target)
        except OSError:  # another run unpacked it first
            pass
sys.path[:0] = [str(target)]

# Console presentation for the bundled application; monitor owns its reads,
# migration record updates and exit code.
import re
import shlex
import textwrap
import threading
from datetime import datetime

MONITOR_COUNTS = ("original_share_drops", "shares_added", "lost", "degraded", "added", "unobserved")


def _event_fields(message):
    try:
        tokens = shlex.split(message)
    except ValueError:
        return None
    fields = {}
    for token in tokens:
        key, separator, value = token.partition("=")
        if separator and re.fullmatch(r"[a-z_]+", key):
            fields[key] = value
    return fields


class HumanMonitorReporter:
    lock = threading.Lock()

    def __init__(self):
        self.context = None
        self.accounts = []
        self.organizations = {}
        self.account_counts = {}
        self.read_gaps = {}
        self.details = []
        self.reasons = []
        self.route_reason = None
        self.auth_started = False

    @staticmethod
    def _line(message=""):
        print(message, flush=True)

    @staticmethod
    def _counts(fields):
        if not all(re.fullmatch(r"[0-9]+", fields.get(key, "")) for key in MONITOR_COUNTS):
            return None
        return {key: int(fields[key]) for key in MONITOR_COUNTS}

    def emit(self, message):
        with self.lock:
            fields = _event_fields(message)
            if fields is None:
                self._line(message)
                return
            phase, status = fields.get("phase"), fields.get("status")
            if phase == "verification-scope" and status == "EXCLUDED":
                if fields.get("collector") == "tgw_routes":
                    self.route_reason = fields.get("reason")
                else:
                    self._line(message)
                return
            if message == "TGW route health and network reachability are outside this verification scope." and self.route_reason:
                return  # The same limitation appears in the scope below.
            if phase == "monitor" and status == "STARTED":
                self._start(fields)
                return
            if phase == "authentication" and status == "VERIFIED":
                if not self.auth_started:
                    self._line("Checking account access...")
                    self.auth_started = True
                return
            if phase == "progress":
                if fields.get("stage") != "observation:monitor":
                    self._line(message)
                elif status == "STARTED":
                    self._line("Checking baseline access and existing resource bindings...")
                elif re.fullmatch(r"[0-9]+", fields.get("gaps", "")) and fields.get("account"):
                    self.read_gaps[fields["account"]] = int(fields["gaps"])
                else:
                    self._line(message)
                return
            if phase == "monitor" and fields.get("consumer") and "organization_now" in fields:
                self.organizations[fields["consumer"]] = fields
                return
            if phase == "monitor" and fields.get("change"):
                self.details.append((fields, message))
                return
            if phase == "monitor" and fields.get("consumer") and "original_share_drops" in fields and not status:
                counts = self._counts(fields)
                if counts is None:
                    self._line(message)
                else:
                    self.account_counts[fields["consumer"]] = counts
                return
            if phase == "monitor" and status in ("UNCHANGED", "CHANGED", "LOSS", "INCONCLUSIVE"):
                if "exit_code" in fields:
                    if self._counts(fields) is None or not all(re.fullmatch(r"[0-9]+", fields.get(key, "")) for key in ("gaps", "exit_code")):
                        self._line(message)
                    else:
                        self._finish(fields)
                else:
                    self.reasons.append(message.split(f"status={status}", 1)[-1].strip())
                return
            if status == "BLOCKED":
                self._line("Monitor could not run.")
                self._line("Reason: " + message.split("status=BLOCKED", 1)[-1].strip())
                return
            self._line(message)  # Preserve every unrecognized message and diagnostic.

    def _start(self, fields):
        self.accounts = [account for account in fields.get("consumers", "").split(",") if account]
        self._line(f"RAMShift monitor - {fields.get('migration', 'migration')}")
        self._line(f"Accounts: {len(self.accounts)}")
        regions = getattr(self.context, "regions", [])
        if regions:
            self._line("Regions: " + ", ".join(regions))
        baseline = fields.get("baseline_captured_at", "not recorded")
        try:
            baseline = datetime.fromisoformat(baseline).isoformat(sep=" ", timespec="seconds").replace("+00:00", " UTC")
        except ValueError:
            pass
        self._line("Baseline: " + baseline)
        if self.route_reason:
            self._line("TGW route checks excluded: " + self.route_reason)
            self._line("Route health and network reachability are outside this check.")
        self._line()

    def _finish(self, fields):
        status = fields["status"]
        headlines = {
            "UNCHANGED": "No changes detected in the monitored baseline.",
            "CHANGED": "Changes detected; the monitored baseline remains intact.",
            "LOSS": "Baseline items were lost or degraded.",
            "INCONCLUSIVE": "Some checks could not be completed.",
        }
        self._line()
        self._line(f"Result: {status} - {headlines[status]}")
        totals = self._counts(fields)
        self._line(f"Lost: {totals['lost']}   Degraded: {totals['degraded']}   Unobserved: {totals['unobserved']}   Read gaps: {fields['gaps']}")
        accounts = [account for account in fields.get("consumers", "").split(",") if account]
        rows = [("Account", "Current org", "Org change", "Changes", "Lost", "Degraded", "Unobserved")]
        for account in accounts:
            org = self.organizations.get(account, {})
            counts = self.account_counts.get(account)
            if counts is None:
                numbers = ("?", "?", "?", "?")
            else:
                numbers = (str(counts["original_share_drops"] + counts["shares_added"] + counts["added"]),
                           str(counts["lost"]), str(counts["degraded"]), str(counts["unobserved"]))
            rows.append((account, org.get("organization_now", "UNKNOWN"),
                         org.get("organization_change", "UNKNOWN"), *numbers))
        widths = [max(len(row[index]) for row in rows) for index in range(len(rows[0]))]
        self._line()
        for index, row in enumerate(rows):
            self._line("  ".join(value.ljust(width) for value, width in zip(row, widths)).rstrip())
            if index == 0:
                self._line("  ".join("-" * width for width in widths))
        if any(totals[key] for key in ("original_share_drops", "shares_added", "added")):
            self._line(f"Access changes: original grants removed={totals['original_share_drops']}, shares added={totals['shares_added']}, items added={totals['added']}")
        if self.details:
            self._line()
            self._line("Changes and incomplete checks:")
            labels = {"ORIGINAL_SHARE_DROPPED": "Original share access removed", "SHARE_ADDED": "Shared access added", "LOST": "Lost", "DEGRADED": "Degraded", "ADDED": "Added", "UNOBSERVED": "Could not observe"}
            for event, message in self.details:
                label = labels.get(event.get("change"), event.get("change", "Change"))
                # Keep the original evidence for losses and read gaps, including
                # complete reason strings; never truncate error details.
                if event.get("change") in ("ORIGINAL_SHARE_DROPPED", "SHARE_ADDED"):
                    detail = f"{event.get('consumer', 'account')} | {event.get('region', 'region')} | {event.get('resource', 'resource')} | current access={event.get('access', 'UNKNOWN')} | share={event.get('share', 'UNKNOWN')}"
                else:
                    detail = message.replace("phase=monitor ", "", 1).replace(f"change={event.get('change')} ", "", 1)
                self._line(textwrap.fill(f"- {label}: {detail}", width=110, subsequent_indent="  "))
        if self.reasons or any(self.read_gaps.values()):
            self._line()
            self._line("Checks needing attention:")
            for account, count in sorted(self.read_gaps.items()):
                if count:
                    self._line(f"- {account}: {count} read gap(s)")
            for reason in self.reasons:
                self._line(textwrap.fill("- " + reason, width=110, subsequent_indent="  "))
        self._line()
        if fields.get("recorded") == "false":
            self._line("Record: result could not be saved.")
        elif fields.get("revision"):
            record_path = getattr(getattr(self.context, "args", None), "record", "migration record")
            self._line(f"Record: {record_path} (revision {fields['revision']})")
        self._line(f"Exit code: {fields['exit_code']}")
        self._line("One snapshot completed. Run the command again for another snapshot.")
        self._line("Use --raw-output for the full technical event output.")


def _launch(cli, argv):
    parser = cli.build_parser()
    parser.add_argument("--raw-output", action="store_true", help="monitor: show the full technical event output instead of the readable summary")
    parsed = parser.parse_args(argv)
    if parsed.raw_output and parsed.mode != "monitor":
        parser.error("--raw-output is supported only for monitor")
    native_argv = [argument for argument in argv if argument != "--raw-output"]
    if parsed.mode != "monitor" or parsed.raw_output:
        return cli.main(native_argv)
    original_reporter, original_monitor = cli.Reporter, cli.run_monitor

    def monitor(router, opts, report):
        report.context = opts
        return original_monitor(router, opts, report)

    cli.Reporter, cli.run_monitor = HumanMonitorReporter, monitor
    try:
        return cli.main(native_argv)
    finally:
        cli.Reporter, cli.run_monitor = original_reporter, original_monitor

import temporary_migration_ram_shares as cli  # noqa: E402

sys.exit(_launch(cli, sys.argv[1:]))
