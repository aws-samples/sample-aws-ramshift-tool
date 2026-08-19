#!/usr/bin/env python3
"""Interactive orchestration for additive RAM migration shares (Python 3.11+).

Plan is the default and cannot request writable clients. With ``--record`` it
writes a versioned migration record that ``approve``, ``apply`` and ``verify``
consume. Approve binds explicit approvals to exact permission changes and owner
scope. Apply requires a PLANNED record revision whose entitlements still match
live discovery, then opens its write gate only after complete preflight, the
exact ``APPLY <migration-id>`` reply, and a check under the record lock that the
record still holds that reviewed revision. It records each stack's shares as
the stack completes, and its outcome even when it fails or is interrupted.
This tool neither moves accounts nor cleans up shares or Resolver associations.
"""
from __future__ import annotations

import argparse
import copy
import importlib
import json
import os
import random
import re
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from botocore.exceptions import (
    BotoCoreError, ClientError, ConnectionClosedError, ConnectTimeoutError,
    EndpointConnectionError, ReadTimeoutError,
)

from ram_migration_common import (
    Api, Group, MigrationError, Plan, Router, account_id, change_key, check_sdk, digest,
    error_text, pages, timestamp,
)
from ram_migration_discovery import (
    Discovery, LookupCache, describe_difference, external_catalog, failure_text,
    revalidate_change,
)
from ram_migration_record import (
    APPLICABLE, CHANGE_FIELDS, add_drops, approval_for, approve_owner_scope,
    approve_permission_change, approved_owners, drop_id, failure_drops, latest, new_record,
    owner_scope_request, pending_requests, permission_requests, plan_digest, tool_identity,
)
from ram_migration_record import load as load_record
from ram_migration_record import update as update_record
from ram_migration_stacks import Stacks, accept, delete_share, stack_name, verify_group

try:
    import ram_migration_verification as verification
except ImportError:  # pragma: no cover - ships in the same release
    verification = None

RAM_HOME_REGION = "us-east-1"
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d+$")
ROLE = re.compile(r"^arn:[a-z0-9-]+:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$")
TRANSIENT_CODES = {
    "Throttling", "ThrottlingException", "TooManyRequestsException",
    "RequestLimitExceeded", "ServiceUnavailable", "ServiceUnavailableException",
    "InternalError", "InternalFailure", "InternalServerException",
    "ResourceShareInvitationArnNotFoundException", "UnknownResourceException",
}


def bounded_integer(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 64:
        raise argparse.ArgumentTypeError("use an integer between 1 and 64")
    return number


def share_worker_count(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 16:
        raise argparse.ArgumentTypeError("use an integer between 1 and 16")
    return number


def positive_number(value: str) -> float:
    number = float(value)
    if not 0 < number < float("inf"):
        raise argparse.ArgumentTypeError("use a positive finite number")
    return number


def nonnegative_number(value: str) -> float:
    number = float(value)
    if not 0 <= number < float("inf"):
        raise argparse.ArgumentTypeError("use a nonnegative finite number")
    return number


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "Complete the AWS CLI login and explicit account/role selection "
            "first. Profiles are never selected automatically."
        ),
    )
    parser.add_argument("mode", nargs="?",
                        choices=("plan", "approve", "apply", "verify", "complete", "monitor"),
                        default="plan")
    parser.add_argument("--migration-id", help="stable identifier for this migration")
    parser.add_argument("--record", type=Path,
                        help="versioned migration record: written by plan and approve, "
                             "required by apply and verify")
    parser.add_argument("--owners", "--accounts", dest="owners", nargs="+", action="append",
                        default=[], help="explicit owner/inspection account IDs; spaces or commas")
    parser.add_argument("--consumers", nargs="+", action="append", default=[],
                        help="explicit migrating consumer account IDs; spaces or commas")
    parser.add_argument("--regions", nargs="+", action="append", default=[],
                        help="Regions to inspect; RAM global home us-east-1 is always included")
    parser.add_argument("--scan-enabled-regions", "--discover-regions", action="store_true",
                        help="also discover enabled Regions separately for each owner")
    parser.add_argument("--exclude-regions", nargs="+", action="append", default=[],
                        help="enabled Regions explicitly left out of the received-dependency "
                             "audit, the owned-share check and owner discovery, for example "
                             "where an SCP denies RAM reads; requires --exclude-reason. Recorded "
                             "in the record scope and shown in every summary; us-east-1 cannot "
                             "be excluded")
    parser.add_argument("--exclude-reason",
                        help="mandatory reason for --exclude-regions, recorded with them")
    parser.add_argument("--profile", action="append", default=[], help="base profile; repeatable")
    parser.add_argument("--source-profile", help="explicit source base profile")
    parser.add_argument("--destination-profile", help="explicit destination base profile")
    parser.add_argument("--account-map", help="JSON object/file: account ID -> profile or role ARN")
    parser.add_argument("--profile-map", help="JSON object/file: account ID -> profile")
    parser.add_argument("--role-map", help="JSON object/file: account ID -> role ARN")
    parser.add_argument("--role-name", help="explicit fallback role name to assume using base profiles")
    parser.add_argument("--sso-role", help="explicit SSO role for unmapped accounts")
    parser.add_argument("--principal-map",
                        help="JSON object/file: original share ARN -> explicit intended account IDs")
    parser.add_argument("--capabilities",
                        help="JSON object/file: additional capability restrictions; true must "
                             "already be true in the official catalog, false can add a denial")
    parser.add_argument("--account-workers", type=bounded_integer, default=4)
    parser.add_argument("--region-workers", type=bounded_integer, default=4,
                        help="maximum regional workers per active account")
    parser.add_argument("--share-workers", type=share_worker_count, default=4,
                        help="maximum concurrent share inspections per owner Region during "
                             "discovery (1-16); results merge in share-ARN order")
    parser.add_argument("--timeout", type=positive_number, default=1800,
                        help="seconds per stack operation or invitation/verification polling task")
    parser.add_argument("--retry-limit", "--retries", type=bounded_integer, default=20,
                        help="bounded eventual-consistency/transient polling attempts")
    parser.add_argument("--poll-interval", type=positive_number, default=2,
                        help="initial polling delay in seconds, with bounded jitter/backoff")
    parser.add_argument("--settle-seconds", type=nonnegative_number, default=300,
                        help="complete: seconds to keep re-verifying after each temporary share "
                             "deletion before deleting the next one")
    parser.add_argument("--export-plan", type=Path,
                        help="optional local JSON plan export (plan/apply only)")
    parser.add_argument("--monitor-config", help="JSON object/file passed to ram_migration_monitor.monitor")
    parser.add_argument("--interactive", action="store_true",
                        help="prompt for missing inputs even when stdin is not a terminal")
    return parser


def json_object(value: str | None, label: str) -> dict:
    if value is None:
        return {}
    try:
        text = value if value.lstrip().startswith("{") else Path(value).read_text(encoding="utf-8")
        result = json.loads(text)
    except (OSError, ValueError) as exc:
        raise MigrationError(f"{label}: unable to read a JSON object: {error_text(exc)}") from exc
    if not isinstance(result, dict):
        raise MigrationError(f"{label}: expected a JSON object")
    return result


def split_values(values: list[list[str]]) -> list[str]:
    return sorted({item.strip() for row in values for value in row
                   for item in value.split(",") if item.strip()})


def checked_account(value: Any) -> str:
    if not isinstance(value, str) or not re.fullmatch(r"[0-9]{12}", value):
        raise MigrationError("Account IDs must be 12-digit strings, including leading zeros")
    return account_id(value)


@dataclass
class Options:
    args: argparse.Namespace
    owners: list[str]
    consumers: list[str]
    regions: list[str]
    profiles: list[str]
    mappings: dict[str, str]
    principals: dict[str, list[str]]
    capabilities: dict[str, bool] | None
    monitor_config: dict
    known_enabled_regions: dict[str, set[str]] = field(default_factory=dict)
    # Set by apply when its write gate opens: reads back, through a closed gate, the
    # temporary shares the run created and returns the record update for them.
    interrupt_readback: Callable[[], Callable[[dict], Any]] | None = None
    # Regions the operator excluded explicitly, with the mandatory reason.
    excluded_regions: list[str] = field(default_factory=list)
    exclusion_reason: str | None = None
    # Migrating accounts classified as migrating owners because they own RAM shares.
    detected_owners: list[str] = field(default_factory=list)
    # The reviewed plan revision and digest an apply consumed at its write gate.
    applied_plan: dict = field(default_factory=dict)


MIGRATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
MAX_REASON = 500


def exclusion_scope(opts: Options) -> dict | None:
    """The record-scope form of an explicit Region exclusion."""
    if not opts.excluded_regions:
        return None
    return {"regions": sorted(set(opts.excluded_regions)), "reason": opts.exclusion_reason}


def exclusion_text(excluded: dict | None) -> str:
    """Appended to every summary line of a run whose scope excludes Regions."""
    if not excluded:
        return ""
    return (f" excluded_regions={','.join(excluded['regions'])} "
            f"exclusion_reason={json.dumps(excluded['reason'])}")


def aliases_record(export: Path, record: Path) -> bool:
    """Whether writing ``export`` would replace the record, through any path or link,
    or one of the lock and temporary files written next to it."""
    export, record = Path(export), Path(record)
    try:
        if export.exists() and record.exists() and os.path.samefile(export, record):
            return True
    except OSError:
        pass
    target = export.resolve()
    for path in {record.resolve(), record.absolute().parent.resolve() / record.name}:
        if target == path or target.parent == path.parent and (
                target.name == f".{path.name}.lock" or target.name.startswith(f".{path.name}.tmp-")):
            return True
    return False


def excluded_regions(args: argparse.Namespace, regions: list[str]) -> tuple[list[str], str | None]:
    """An explicit, reasoned Region exclusion; never implied by an error."""
    excluded = split_values(args.exclude_regions)
    if not excluded and args.exclude_reason is None:
        return [], None
    if args.mode not in ("plan", "apply", "verify", "complete"):
        raise MigrationError("--exclude-regions is supported only for plan, apply, verify and complete")
    if not excluded:
        raise MigrationError("--exclude-reason requires --exclude-regions")
    if any(not REGION.fullmatch(region) for region in excluded):
        raise MigrationError("Regions must be AWS Region names")
    reason = (args.exclude_reason or "").strip()
    if not reason:
        raise MigrationError("--exclude-regions requires --exclude-reason: a nonempty reason, "
                             "recorded with the excluded Regions and shown in every summary")
    if "\n" in reason or "\r" in reason or len(reason) > MAX_REASON:
        raise MigrationError(f"--exclude-reason must be one line of at most {MAX_REASON} characters")
    if RAM_HOME_REGION in excluded:
        raise MigrationError(f"{RAM_HOME_REGION} is RAM's global home Region and is always "
                             "inspected; it cannot be excluded")
    both = sorted(set(excluded) & set(regions))
    if both:
        raise MigrationError(f"Regions {','.join(both)} are both requested (--regions) and "
                             "excluded (--exclude-regions)")
    return excluded, reason


def options(args: argparse.Namespace, ask: Callable[[str], str]) -> Options:
    if args.mode == "approve":
        # Approval is an offline review of the record; it needs no AWS access.
        if not args.record:
            raise MigrationError("approve requires --record")
        if args.migration_id and not MIGRATION_ID.fullmatch(args.migration_id):
            raise MigrationError("Supply a valid --migration-id or omit it to use the record's")
        excluded_regions(args, [])
        return Options(args, [], [], [], [], {}, {}, None, {})
    if args.mode in ("apply", "verify", "complete") and not args.record:
        raise MigrationError(f"{args.mode} requires --record: the reviewed migration record "
                             "written by plan")
    from_record = args.mode in ("verify", "complete")
    interactive = args.interactive or sys.stdin.isatty()
    if args.mode != "monitor" and interactive:
        if not args.migration_id:
            args.migration_id = ask("Migration identifier: ").strip()
        if not args.owners and not from_record:
            args.owners = [ask("Owner/inspection account IDs (comma or space separated): ").split()]
        if args.mode in ("plan", "apply") and not args.consumers:
            args.consumers = [ask("Migrating consumer account IDs (comma or space separated): ").split()]
        if not args.regions and not args.scan_enabled_regions and not from_record:
            args.regions = [ask("Regions (comma or space separated): ").split()]
    if interactive and not any((args.profile, args.source_profile, args.destination_profile,
                                args.account_map, args.profile_map, args.role_map)):
        args.profile = ask("Configured source/destination profiles (space separated): ").split()

    owners = [checked_account(value) for value in split_values(args.owners)]
    consumers = [checked_account(value) for value in split_values(args.consumers)]
    regions = split_values(args.regions)
    if any(not REGION.fullmatch(region) for region in regions):
        raise MigrationError("Regions must be AWS Region names")
    if args.mode != "monitor":
        if not args.migration_id or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}",
                                                    args.migration_id):
            raise MigrationError("Supply --migration-id (1-128 letters, digits, dots, underscores or hyphens)")
        if not owners and not from_record:
            raise MigrationError("Supply explicit --owners/--accounts")
        if args.mode in ("plan", "apply") and not consumers:
            raise MigrationError("Supply explicit --consumers")
        if not regions and not args.scan_enabled_regions and not from_record:
            raise MigrationError("Supply --regions or --scan-enabled-regions")
    if args.export_plan and args.mode not in ("plan", "apply"):
        raise MigrationError("--export-plan is supported only for plan/apply")
    if args.export_plan and args.record and aliases_record(args.export_plan, args.record):
        raise MigrationError(f"--export-plan {args.export_plan} would overwrite the migration record "
                             f"{args.record} or its lock or temporary file; choose another path")
    excluded, reason = excluded_regions(args, regions)
    if args.monitor_config and args.mode != "monitor":
        raise MigrationError("--monitor-config requires monitor mode")
    if args.mode == "monitor" and not args.monitor_config:
        raise MigrationError("monitor requires --monitor-config JSON or a JSON file")

    mappings: dict[str, str] = {}
    for label in ("account_map", "profile_map", "role_map"):
        for account, value in json_object(getattr(args, label), label.replace("_", "-")).items():
            checked_account(account)
            if not isinstance(value, str) or not value.strip() or value != value.strip():
                raise MigrationError(f"{label}: mapping values must be nonempty profile names or role ARNs")
            if "\n" in value or "\r" in value:
                raise MigrationError(f"{label}: mapping values must be on one line")
            is_role = value.startswith("arn:")
            if label == "role_map" and not is_role or label == "profile_map" and is_role:
                raise MigrationError(f"{label}: incorrect mapping value type")
            if is_role:
                match = ROLE.fullmatch(value)
                if not match or match.group(1) != account:
                    raise MigrationError(f"{account}: role ARN must name the mapped account")
            if account in mappings and mappings[account] != value:
                raise MigrationError(f"{account}: conflicting account/profile/role maps")
            mappings[account] = value
    profiles = list(dict.fromkeys(p for p in
                                  [*args.profile, args.source_profile, args.destination_profile,
                                   *(value for value in mappings.values() if not value.startswith("arn:"))]
                                  if p))
    if not profiles and not mappings:
        raise MigrationError("Supply explicit --profile, source/destination profiles, or account mappings")
    if not profiles and (args.role_name or any(value.startswith("arn:") for value in mappings.values())):
        raise MigrationError("Role assumption requires an explicit base --profile")
    if args.role_name and not re.fullmatch(r"[A-Za-z0-9+=,.@_/-]+", args.role_name):
        raise MigrationError("--role-name must be an IAM role name/path")
    if interactive and not from_record and set(owners + consumers) - set(mappings) and \
            not args.sso_role and not args.role_name:
        args.sso_role = ask(
            "SSO role for unmapped accounts (explicit role name; blank to use account/profile maps): "
        ).strip() or None
        if args.sso_role is None:
            print("For accounts outside the base profiles, supply --sso-role or explicit "
                  "--account-map/--profile-map/--role-map; no SSO role is selected automatically.",
                  flush=True)

    principals = json_object(args.principal_map, "principal-map")
    for arn, accounts in principals.items():
        if not isinstance(arn, str) or not arn.startswith("arn:") or ":resource-share/" not in arn:
            raise MigrationError("principal-map keys must be original RAM share ARNs")
        if not isinstance(accounts, list):
            raise MigrationError("principal-map values must be lists of explicit account ID strings")
        principals[arn] = sorted({checked_account(account) for account in accounts})
    capabilities = None if args.capabilities is None else json_object(args.capabilities, "capabilities")
    if capabilities is not None:
        if not capabilities or any(not isinstance(k, str) or ":" not in k or type(v) is not bool
                                   for k, v in capabilities.items()):
            raise MigrationError("capabilities must map RAM resource type strings to booleans")
        capabilities = {key.lower(): value for key, value in capabilities.items()}
    return Options(args, owners, consumers, sorted(set(regions) | {RAM_HOME_REGION}),
                   profiles, mappings, principals, capabilities,
                   json_object(args.monitor_config, "monitor-config"),
                   excluded_regions=excluded, exclusion_reason=reason)


class WriteGate:
    """Enforce mode/confirmation even if a helper asks for a writable client."""
    def __init__(self, router: Router):
        self.router = router
        self.open = False

    def __getattr__(self, name: str):
        # Do not expose an unguarded session/client through this facade.
        if name == "session":
            raise MigrationError("Use the guarded client API")
        return getattr(self.router, name)

    def client(self, account: str, service: str, region: str, write: bool = False):
        if write and not self.open:
            raise MigrationError(f"{account}/{region}: write gate is closed for {service}")
        client = self.router.client(account, service, region, write=write)
        return Api(client, write=write)


class Reporter:
    lock = threading.Lock()  # one console: every reporter, worker and interrupt notice

    def emit(self, message: str) -> None:
        with self.lock:
            print(message, flush=True)


class Progress:
    """Per-account completion and elapsed time for one long phase."""
    def __init__(self, report: Reporter, stage: str, scopes: dict[str, list[str]]):
        self.report, self.stage = report, stage
        self.totals = {account: len(set(units)) for account, units in scopes.items()}
        self.done: Counter = Counter()
        self.lock = threading.Lock()
        self.started = time.monotonic()
        if self.totals:
            report.emit(f"phase=progress stage={stage} status=STARTED accounts={len(self.totals)} "
                        f"tasks={sum(self.totals.values())}")

    def advance(self, account: str, detail: str = "") -> None:
        with self.lock:
            self.done[account] += 1
            self.report.emit(
                f"phase=progress stage={self.stage} account={account} "
                f"done={self.done[account]}/{self.totals[account]} "
                f"overall={sum(self.done.values())}/{sum(self.totals.values())} "
                f"elapsed_seconds={time.monotonic() - self.started:.1f}{detail}")

    def observed(self, observation: Any) -> None:
        """One collect() call observes every account at once."""
        items, gaps = value(observation, "items"), value(observation, "gaps")
        for account in sorted(self.totals):
            found = sum((item.get("consumer") or item.get("owner")) == account for item in items)
            missing = sum(gap.get("account") == account for gap in gaps)
            self.advance(account, f" items={found} gaps={missing}")


@dataclass
class Outcome:
    account: str
    region: str
    value: Any = None
    error: str | None = None


def fanout(scopes: dict[str, list[str]], callback: Callable[[str, str], Any],
           account_workers: int, region_workers: int,
           progress: Progress | None = None,
           notify: Callable[[str], None] | None = None) -> list[Outcome]:
    """At most account_workers accounts and region_workers tasks per account.

    An interrupt starts no further task; tasks already running finish, and what
    they changed is retained, before the interrupt propagates. Every interrupt,
    repeated ones included, is acknowledged at once with the tasks still running."""
    stop = threading.Event()
    running, lock = [0], threading.Lock()
    notify = notify or Reporter().emit

    def task(account: str, region: str) -> Any:
        if stop.is_set():
            raise MigrationError("not started: the run was interrupted")
        with lock:
            running[0] += 1
        try:
            return callback(account, region)
        except BaseException as exc:
            if not isinstance(exc, Exception):
                stop.set()
            raise
        finally:
            with lock:
                running[0] -= 1
            if progress is not None:
                progress.advance(account)

    def one_account(account: str) -> list[Outcome]:
        output = []
        with ThreadPoolExecutor(max_workers=region_workers) as executor:
            futures = {executor.submit(task, account, region): region
                       for region in sorted(set(scopes[account]))}
            for future in as_completed(futures):
                region = futures[future]
                try:
                    output.append(Outcome(account, region, future.result()))
                except Exception as exc:
                    output.append(Outcome(account, region, error=failure_text(exc)))
        return output

    output: list[Outcome] = []
    with ThreadPoolExecutor(max_workers=account_workers) as executor:
        try:
            futures = [executor.submit(one_account, account) for account in sorted(scopes)]
            for future in as_completed(futures):
                output.extend(future.result())
        except BaseException as exc:
            stop.set()
            interrupt = isinstance(exc, KeyboardInterrupt)
            while True:
                try:
                    if interrupt:
                        with lock:
                            count = running[0]
                        notify(f"status=INTERRUPTING no new tasks start; waiting for {count} "
                               "running tasks to finish; their changes are retained")
                    executor.shutdown(wait=True, cancel_futures=True)
                    break
                except KeyboardInterrupt:
                    interrupt = True
            raise
    return sorted(output, key=lambda row: (row.account, row.region))


def scoped_fanout(scopes, callback, opts: Options, progress: Progress | None = None):
    return fanout(scopes, callback, opts.args.account_workers, opts.args.region_workers,
                  progress)


def authenticate(router: Router, accounts: set[str], opts: Options, report: Reporter) -> list[str]:
    def check(account, _region):
        router.session(account)  # Router validates the actual STS caller, not its profile label.
        report.emit(f"account={account} phase=authentication status=VERIFIED")
    return [f"account={row.account} phase=authentication status=BLOCKED {row.error}"
            for row in scoped_fanout({account: ["identity"] for account in accounts}, check, opts)
            if row.error]


def region_scopes(router: WriteGate, opts: Options, report: Reporter,
                  dependencies: dict[str, set[str]] | None = None, *,
                  exclude: bool = True) -> tuple[dict, list[str]]:
    """Explicit Regions, plus every Region where a migrating account receives
    this owner's resources (consumer-driven), plus all enabled Regions on request.

    A migrating owner is inspected in every Region it has enabled plus RAM's global
    home: a share it holds with stationary consumers in any of them is lost when it
    leaves. Explicitly excluded Regions are never inspected for planning; verify
    passes exclude=False because it reads every Region its recorded shares are in."""
    dependencies = dependencies or {}
    excluded = set(opts.excluded_regions) if exclude else set()
    migrating = set(opts.owners) & set(opts.consumers)

    def implied(owner: str, enabled: set[str]) -> set[str]:
        regions = set(opts.regions) | dependencies.get(owner, set()) | enabled
        if owner in migrating:
            regions |= opts.known_enabled_regions.get(owner, set()) | {RAM_HOME_REGION}
        return regions - excluded
    scopes = {owner: sorted(implied(owner, set())) for owner in opts.owners}
    failures = []
    if opts.args.scan_enabled_regions:
        def scan(owner, _region):
            rows = router.client(owner, "ec2", RAM_HOME_REGION).describe_regions(AllRegions=True)["Regions"]
            enabled = [r["RegionName"] for r in rows
                       if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")]
            if not enabled:
                raise MigrationError("No enabled Regions returned; discovery scope is unresolved")
            return sorted(implied(owner, set(enabled))), set(enabled)
        for row in scoped_fanout({owner: [RAM_HOME_REGION] for owner in opts.owners}, scan, opts):
            if row.error:
                failures.append(f"owner={row.account} phase=regions status=BLOCKED {row.error}")
            else:
                scopes[row.account], opts.known_enabled_regions[row.account] = row.value
    for owner, regions in scopes.items():
        report.emit(f"owner={owner} phase=scope regions={','.join(regions)}")
    return scopes, failures


@dataclass
class ReceivedAudit:
    scopes: dict[str, list[str]] = field(default_factory=dict)
    entries: list[dict] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    # Shares that migrating accounts not given in --owners own themselves (resourceOwner=SELF).
    owned: list[dict] = field(default_factory=list)

    def counts(self) -> dict[str, int]:
        return {
            "received_accounts": len(self.scopes),
            "received_regions": len({region for regions in self.scopes.values() for region in regions}),
            "received_owners": len({entry["owner"] for entry in self.entries}),
            "received_shares": len({entry["share"] for entry in self.entries}),
            "received_resources": len({resource["arn"] for entry in self.entries
                                       for resource in entry["resources"]}),
            "received_share_observations": len(self.entries),
            "received_resource_observations": sum(len(entry["resources"]) for entry in self.entries),
            "owned_shares": len(self.owned),
        }

    def to_dict(self) -> dict:
        entries = [{k: v for k, v in entry.items() if k != "context"} for entry in self.entries]
        return {"scopes": self.scopes, "counts": self.counts(), "entries": entries,
                "owned": self.owned, "blocked": self.blocked, "excluded": self.excluded}


def received_scopes(router: WriteGate, opts: Options,
                    report: Reporter) -> tuple[dict[str, list[str]], list[str]]:
    """Consumer-driven: every enabled Region of every migrating account, plus
    RAM's global home, except Regions the operator excluded explicitly with a
    reason. Stationary owners are not audited: their own received dependencies
    are not affected by the migration."""
    failures = []
    failed_accounts = set()
    excluded = set(opts.excluded_regions)
    unresolved = set(opts.consumers) - set(opts.known_enabled_regions)

    def enabled(account, _region):
        rows = router.client(account, "ec2", RAM_HOME_REGION).describe_regions(AllRegions=True)["Regions"]
        regions = {row["RegionName"] for row in rows
                   if row.get("OptInStatus") in ("opt-in-not-required", "opted-in")}
        if not regions or any(not REGION.fullmatch(region) for region in regions):
            raise MigrationError("Enabled Region scope is unresolved")
        return regions
    for row in scoped_fanout({account: [RAM_HOME_REGION] for account in unresolved}, enabled, opts):
        if row.error:
            failed_accounts.add(row.account)
            failures.append(f"account={row.account} phase=received-regions status=BLOCKED {row.error}")
        else:
            opts.known_enabled_regions[row.account] = row.value
    scopes = {}
    for account in sorted(set(opts.consumers)):
        if account in failed_accounts:
            continue
        known = opts.known_enabled_regions[account]
        for region in sorted(set(opts.regions) - known - {RAM_HOME_REGION}):
            report.emit(f"account={account} region={region} phase=received-regions "
                        "status=EXCLUDED Region is not enabled in this account")
        for region in sorted(known & excluded):
            report.emit(f"account={account} region={region} phase=received-regions "
                        f"status=EXCLUDED_BY_OPERATOR reason={json.dumps(opts.exclusion_reason)} "
                        "received dependencies and owned shares in this enabled Region are not "
                        "inspected")
        scopes[account] = sorted((known | {RAM_HOME_REGION}) - excluded)
    return scopes, failures


def received_inventory(router: WriteGate, opts: Options, report: Reporter) -> ReceivedAudit:
    """Read-only inventory of what the migrating accounts actually receive, and of the
    shares that migrating accounts not given in --owners own themselves."""
    scopes, errors = received_scopes(router, opts, report)
    audit = ReceivedAudit(scopes=scopes, blocked=errors)
    unlisted = set(opts.consumers) - set(opts.owners)

    def owned_shares(account: str, region: str, ram: Any, result: ReceivedAudit) -> None:
        """A migrating account that owns a share is a migrating owner (see detect_owners)."""
        try:
            shares = pages(ram, "get_resource_shares", "resourceShares", resourceOwner="SELF")
        except Exception as exc:
            result.blocked.append(f"account={account} region={region} phase=owned-audit "
                                  f"status=BLOCKED {failure_text(exc)}")
            return
        for share in shares:
            state = share.get("status", "UNKNOWN")
            if state == "DELETED":  # terminal; it shares nothing
                continue
            result.owned.append({"account": account, "region": region,
                                 "share": share.get("resourceShareArn", "unknown"),
                                 "share_status": state})

    def inspect(account, region):
        result = ReceivedAudit()
        ram = router.client(account, "ram", region)
        if account in unlisted:
            owned_shares(account, region, ram, result)
        shares = pages(ram, "get_resource_shares", "resourceShares", resourceOwner="OTHER-ACCOUNTS")
        for share in shares:
            arn = share.get("resourceShareArn", "unknown")
            context = f"account={account} region={region} share={arn} phase=received-audit"
            try:
                owner = checked_account(share.get("owningAccountId"))
                context = f"account={account} owner={owner} region={region} share={arn} phase=received-audit"
                parts = arn.split(":")
                if len(parts) < 6 or parts[0] != "arn" or parts[2:5] != ["ram", region, owner]:
                    raise MigrationError("Received share ARN does not match its owner/service/Region")
                resources = pages(ram, "list_resources", "resources", resourceOwner="OTHER-ACCOUNTS",
                                  resourceShareArns=[arn])
                items = []
                seen = set()
                for resource in resources:
                    resource_arn = resource.get("arn")
                    resource_parts = resource_arn.split(":") if isinstance(resource_arn, str) else []
                    if len(resource_parts) < 6 or resource_parts[0] != "arn" or \
                            resource_parts[1] != parts[1] or \
                            resource_parts[4] != owner or \
                            resource_parts[3] not in ("", region):
                        raise MigrationError("Received resource ARN does not match its owner/Region")
                    if resource.get("resourceShareArn", arn) != arn:
                        raise MigrationError("Received resource belongs to another share")
                    if not isinstance(resource.get("type"), str) or not resource["type"]:
                        raise MigrationError("Received resource type is missing")
                    if resource_arn in seen:
                        raise MigrationError("Received resource inventory contains duplicate ARNs")
                    seen.add(resource_arn)
                    items.append({"arn": resource_arn, "type": resource["type"],
                                  "status": resource.get("status", "UNKNOWN")})
                state = share.get("status", "UNKNOWN")
                if state not in ("ACTIVE", "PENDING", "FAILED", "DELETING", "DELETED"):
                    raise MigrationError(f"Received share status is missing or unsupported: {state}")
                result.entries.append({"account": account, "owner": owner, "region": region,
                                       "share": arn, "share_status": state, "resources": items,
                                       "status": "OBSERVED", "context": context})
            except Exception as exc:
                result.blocked.append(f"{context} status=BLOCKED {failure_text(exc)}")
        return result

    for row in scoped_fanout(scopes, inspect, opts, Progress(report, "received-inventory", scopes)):
        if row.error:
            audit.blocked.append(f"account={row.account} region={row.region} "
                                 f"phase=received-audit status=BLOCKED {row.error}")
        else:
            audit.entries.extend(row.value.entries)
            audit.owned.extend(row.value.owned)
            audit.blocked.extend(row.value.blocked)
    audit.owned.sort(key=lambda entry: (entry["account"], entry["region"], entry["share"]))
    return audit


def detect_owners(audit: ReceivedAudit, opts: Options, report: Reporter) -> list[str]:
    """A migrating account that owns RAM shares is a migrating owner whether or not
    --owners names it: it is inspected as an owner in every audited Region, recorded
    as a migrating owner, and blocked if it shares with any stationary consumer."""
    owned: dict[str, list[dict]] = defaultdict(list)
    for entry in audit.owned:
        owned[entry["account"]].append(entry)
    for account, entries in sorted(owned.items()):
        report.emit(f"account={account} phase=owned-audit status=MIGRATING_OWNER "
                    f"owned_shares={len(entries)} "
                    f"regions={','.join(sorted({entry['region'] for entry in entries}))} this "
                    "migrating account owns RAM shares: it is inspected as a migrating owner in "
                    "every audited Region, and a share with any stationary consumer blocks")
    detected = sorted(owned)
    opts.owners = sorted(set(opts.owners) | set(detected))
    opts.detected_owners = sorted(set(opts.detected_owners) | set(detected))
    return detected


def dependency_regions(audit: ReceivedAudit | None) -> dict[str, set[str]]:
    """Owner Regions implied by what migrating accounts actually receive."""
    regions: dict[str, set[str]] = defaultdict(set)
    for entry in (audit.entries if audit else []):
        if entry["share_status"] in ("ACTIVE", "PENDING"):
            regions[entry["owner"]].add(entry["region"])
    return regions


def received_provenance(stacks: Stacks, persisted: dict[tuple[str, str], list[Group]],
                        opts: Options) -> tuple[dict[tuple[str, str, str], Group], list[str]]:
    proven: dict[tuple[str, str, str], Group] = {}
    blocked = []
    persisted_scopes = grouped_scopes([group for groups in persisted.values() for group in groups])[1]
    for row in scoped_fanout(persisted_scopes, stacks.shares, opts):
        if row.error:
            blocked.append(
                f"owner={row.account} region={row.region} phase=received-provenance status=BLOCKED {row.error}")
            continue
        for group in persisted[row.account, row.region]:
            share = row.value.get(group.logical_id)
            if share is None or share.get("owningAccountId") != group.owner:
                blocked.append(f"{row.account}/{row.region}/{group.key}: "
                               "stored migration share ownership could not be proven")
                continue
            proven[group.owner, group.region, share["resourceShareArn"]] = group
    return proven, blocked


def classify_received(audit: ReceivedAudit, plan: Plan, proven: dict, owner_scopes: dict,
                      opts: Options) -> dict[str, dict]:
    """Every active received dependency of a migrating account must be covered by a
    planned temporary share. Owners outside the approved scope are proposed, never
    added silently. Returns the proposed-owner evidence."""
    intended_shares: dict[tuple[str, str], set[str]] = defaultdict(set)
    intended_resources: dict[tuple[str, str], set[str]] = defaultdict(set)
    covered: set[tuple[str, str, str, str]] = set()
    for group in plan.groups:
        for consumer in group.consumers:
            intended_shares[consumer, group.region].update(group.source_shares)
            intended_resources[consumer, group.region].update(group.resources)
            covered.update((consumer, group.owner, group.region, arn) for arn in group.resources)
    proposed: dict[str, dict] = {}

    def propose(entry: dict, pending: bool = False) -> None:
        evidence = proposed.setdefault(entry["owner"], {
            "consumers": set(), "regions": set(), "shares": set(), "resource_types": defaultdict(int),
            "resources": set(), "observations": 0, "pending_shares": set()})
        evidence["consumers"].add(entry["account"])
        evidence["regions"].add(entry["region"])
        (evidence["pending_shares"] if pending else evidence["shares"]).add(entry["share"])
        for item in entry["resources"]:
            evidence["resources"].add(item["arn"])
            evidence["resource_types"][item["type"]] += 1
            evidence["observations"] += 1

    for entry in audit.entries:
        account, owner, region, arn = entry["account"], entry["owner"], entry["region"], entry["share"]
        context, state, items = entry["context"], entry["share_status"], entry["resources"]
        seen = {item["arn"] for item in items}
        entry["status"] = "OWNER_INCLUDED"
        owned = proven.get((owner, region, arn))
        if owned is not None:
            if account not in owned.consumers or \
                    any(owned.resources.get(item["arn"]) != item["type"] for item in items):
                entry["status"] = "BLOCKED"
                audit.blocked.append(f"{context} status=BLOCKED received migration entitlement "
                                     "differs from its owning persisted scope; reconcile explicitly")
            else:
                entry["status"] = "CURRENT_MIGRATION"
                audit.excluded.append(f"{context} status=EXCLUDED "
                                      "current migration share proven through its owning persisted scope")
            continue
        relevant = (bool(items) or arn in intended_shares[account, region]
                    or bool(seen & intended_resources[account, region])
                    or account in opts.principals.get(arn, []))
        if state != "ACTIVE":
            if (state == "PENDING" and relevant) or (
                    any(item["status"] == "PENDING" for item in items) and
                    (arn in intended_shares[account, region]
                     or bool(seen & intended_resources[account, region]))):
                entry["status"] = "BLOCKED"
                audit.blocked.append(f"{context} status=BLOCKED "
                                     f"pending intended received entitlements (share status {state}); "
                                     "resolve the intended sharing/invitation before apply")
                if owner not in opts.owners:
                    propose(entry, pending=True)
            else:
                entry["status"] = "EXCLUDED"
                audit.excluded.append(f"{context} status=EXCLUDED "
                                      f"nonactive received share status {state}; no active access inferred")
            continue
        if not items:
            entry["status"] = "EXCLUDED"
            audit.excluded.append(f"{context} status=EXCLUDED empty active received share")
            continue
        if owner not in opts.owners:
            entry["status"] = "OUTSIDE_OWNER_SCOPE"
            propose(entry)
            continue
        if region not in owner_scopes.get(owner, []):
            entry["status"] = "BLOCKED"
            audit.blocked.append(f"{context} status=BLOCKED "
                                 "resource owner's Region is outside the selected discovery scope")
        for item in items:
            if item["status"] != "AVAILABLE":
                entry["status"] = "BLOCKED"
                audit.blocked.append(f"{context} resource={item['arn']} status=BLOCKED "
                                     f"intended received resource status {item['status']}")
        upstream = any(arn in reason for reason in plan.blocked)
        uncovered = [item["arn"] for item in items if item["status"] == "AVAILABLE"
                     and (account, owner, region, item["arn"]) not in covered]
        if uncovered and not upstream:
            entry["status"] = "NOT_COVERED"
            audit.blocked.append(f"{context} status=BLOCKED received dependencies are not covered by any "
                                 f"planned temporary share: {', '.join(sorted(uncovered))}; "
                                 "they would be lost when the account leaves")
    for owner, evidence in sorted(proposed.items()):
        types = ", ".join(f"{kind} x{count}" for kind, count in sorted(evidence["resource_types"].items()))
        audit.blocked.append(
            f"phase=owner-scope owner={owner} status=APPROVAL_REQUIRED owner {owner} is outside the "
            f"approved owner scope but provides {len(evidence['resources'])} unique received resources "
            f"({types or 'pending share'}) through {len(evidence['shares'] | evidence['pending_shares'])} "
            f"shares in {','.join(sorted(evidence['regions']))} to migrating accounts "
            f"{','.join(sorted(evidence['consumers']))} ({evidence['observations']} observations). "
            f"Record this plan with --record and approve the proposed owner list, then re-run plan "
            f"with an explicit profile/role mapping for {owner}. Received resources cannot be "
            "re-shared by the receiving account")
    return {owner: {"consumers": sorted(e["consumers"]), "regions": sorted(e["regions"]),
                    "shares": sorted(e["shares"]), "pending_shares": sorted(e["pending_shares"]),
                    "resource_types": dict(sorted(e["resource_types"].items())),
                    "unique_resources": len(e["resources"]), "observations": e["observations"]}
            for owner, e in sorted(proposed.items())}


def print_received(audit: ReceivedAudit, report: Reporter) -> None:
    inventory: dict[tuple[str, str, str], list[dict]] = defaultdict(list)
    for entry in audit.entries:
        inventory[entry["account"], entry["owner"], entry["region"]].append(entry)
        report.emit(f"account={entry['account']} owner={entry['owner']} region={entry['region']} "
                    f"share={entry['share']} phase=received-audit status={entry['status']} "
                    f"share_status={entry['share_status']} resources={len(entry['resources'])}")
        for resource in entry["resources"]:
            report.emit(f"  resource={resource['arn']} type={resource['type']} status={resource['status']}")
    for (account, owner, region), entries in sorted(inventory.items()):
        report.emit(f"account={account} owner={owner} region={region} phase=received-inventory "
                    f"shares={len(entries)} "
                    f"resources={len({item['arn'] for entry in entries for item in entry['resources']})}")
    for entry in audit.owned:
        report.emit(f"account={entry['account']} region={entry['region']} share={entry['share']} "
                    f"phase=owned-audit status=OWNED share_status={entry['share_status']}")
    report.emit("phase=received-inventory " + " ".join(f"{key}={value}" for key, value in audit.counts().items()))


def merge_plan(plan: Plan, addition: Plan) -> None:
    """Retain optional approval evidence carried by discovery's Group subtype."""
    prior = {group.key: group for group in plan.groups}
    for group in addition.groups:
        existing = prior.get(group.key)
        if existing is not None:
            old = getattr(existing, "permission_snapshots", {})
            new = getattr(group, "permission_snapshots", {})
            if old and new and old != new:
                plan.blocked.append(f"{group.owner}/{group.region}/{group.key}: permission evidence differs")
                continue
            if new:
                existing.permission_snapshots = new
            if hasattr(group, "source_stacks"):
                existing.source_stacks = sorted(set(getattr(existing, "source_stacks", [])
                                                    + group.source_stacks))
        plan.merge(Plan(addition.migration, groups=[group]))
    plan.blocked.extend(addition.blocked)
    plan.excluded.extend(addition.excluded)
    plan.existing.extend(addition.existing)
    plan.permission_changes.extend(addition.permission_changes)
    plan.notes.extend(addition.notes)


def backing_approval(approvals: list[dict], migration: str, change: dict) -> dict | None:
    """The record approval a change names, when it approves exactly that change: the
    same migration, permission, versions and policy hashes, with the share listed."""
    return next((approval for approval in approvals
                 if approval.get("approval_id") == change.get("approval_id")
                 and approval_for([approval], migration, change)), None)


def recorded_changes(deployed: dict[tuple[str, str], list[Group]]) -> dict[tuple, dict]:
    """Permission changes already recorded in the migration stacks: their shares exist
    and already attach the approved version, so they are history, never rewritten."""
    return {(group.owner, group.region, group.logical_id, *change_key(change)): change
            for groups in deployed.values() for group in groups
            for change in getattr(group, "permission_changes", [])}


def evidence_problems(deployed: dict[tuple[str, str], list[Group]], approvals: list[dict],
                      migration: str) -> list[str]:
    """Each permission change a migration stack records must be one this record approved."""
    problems = []
    for (owner, region, logical, *_key), change in sorted(recorded_changes(deployed).items()):
        if backing_approval(approvals, migration, change) is None:
            problems.append(
                f"phase=approval-evidence owner={owner} region={region} share={change['share']} "
                f"migration stack share {logical} records permission change "
                f"{change['approval_id']} ({change['permission_arn']} "
                f"v{change['from_version']}->v{change['to_version']}), which this migration record "
                "does not approve with the same versions, policy hashes and share")
    return problems


def entitlement_sites(groups: list) -> set[tuple[str, str, str, str]]:
    """(owner, region, consumer, resource ARN) of every entitlement these groups grant."""
    return {(value(g, "owner"), value(g, "region"), consumer, arn) for g in groups
            for consumer in value(g, "consumers") for arn in value(g, "resources")}


def uncovered_entitlements(baseline: dict, groups: list,
                           known: set | frozenset = frozenset()) -> list[tuple[str, str, str, str]]:
    """Entitlements, apart from ``known`` ones, with no entitlement item in the baseline."""
    covered = {(item.get("consumer"), item.get("region"), item.get("resource_arn"))
               for item in baseline.get("items", []) if item.get("kind") == "entitlement"}
    return sorted((owner, region, consumer, arn)
                  for owner, region, consumer, arn in entitlement_sites(groups) - set(known)
                  if (consumer, region, arn) not in covered)


def baseline_scope_problems(baseline: dict, groups: list, deployed: list) -> list[str]:
    """An apply never writes an entitlement the recorded original baseline does not cover.

    The baseline is captured once, at the first write gate, and never extended or
    replaced, so an entitlement added by a later plan has no recorded original state:
    verify could not validate it and complete could not retire it safely."""
    organizations = baseline.get("consumer_organizations", {})
    return [f"phase=baseline-scope status=BLOCKED owner={owner} region={region} "
            f"consumer={consumer} resource={arn}: this entitlement is not in the recorded "
            f"original baseline (captured in revision {baseline.get('captured_in_revision')})"
            + ("" if consumer in organizations else
               f" and consumer {consumer} has no baseline organization")
            + "; the baseline is never extended or replaced, so this migration record cannot "
              "add it"
            for owner, region, consumer, arn in uncovered_entitlements(
                baseline, groups, entitlement_sites(deployed))]


def capabilities_for(opts: Options) -> tuple[dict[str, bool], dict]:
    catalog = {key.lower(): value for key, value in external_catalog().items()}
    supplied = opts.capabilities or {}
    for kind, enabled in supplied.items():
        if enabled and catalog.get(kind) is not True:
            raise MigrationError(
                f"{kind}: supplied capability true is not supported by the official type catalog")
    catalog.update(supplied)
    provenance = {
        "source": "AWS RAM external-sharing type catalog",
        "supplied_restrictions": supplied,
        "limitation": "Type-level catalog support is not proof of resource subtype compatibility "
                      "or live migration continuity.",
    }
    return catalog, provenance


def grouped_scopes(groups: list[Group]) -> tuple[dict, dict]:
    grouped: dict[tuple[str, str], list[Group]] = defaultdict(list)
    for group in groups:
        grouped[group.owner, group.region].append(group)
    scopes: dict[str, list[str]] = defaultdict(list)
    for owner, region in sorted(grouped):
        scopes[owner].append(region)
    return dict(grouped), dict(scopes)


def validate_groups(groups: list[Group], scopes: dict[str, list[str]]) -> None:
    for group in groups:
        checked_account(group.owner)
        if group.owner not in scopes or group.region not in scopes[group.owner]:
            raise MigrationError("Group falls outside the explicit owner/Region scope")
        if not group.resources or not group.consumers or not group.permissions:
            raise MigrationError(f"{group.owner}/{group.region}/{group.key}: empty entitlement group")
        if len(set(group.consumers)) != len(group.consumers):
            raise MigrationError("Duplicate consumers in entitlement group")
        for consumer in group.consumers:
            checked_account(consumer)
        if group.owner in group.consumers:
            raise MigrationError("Owner must not be a consumer of its own migration share")


HEALTH = {
    "resolver_association": ("status", "COMPLETE"),
    "resolver_endpoint": ("status", "OPERATIONAL"),
    "tgw_attachment": ("state", "available"),
    "tgw_route": ("state", "active"),
    "pca_access": ("consumer_read", "OK"),
}
DROP_KIND = {"resolver_association": "association"}
UNAVAILABLE = "resource_checks_unavailable"
RESOLVER_TYPE = "route53resolver:resolverrule"


def verifier() -> Any:
    if verification is None:
        raise MigrationError("ram_migration_verification is required for baseline and verification")
    return verification


def value(obj: Any, name: str) -> Any:
    """Read an Observation/Comparison field from an object or a mapping."""
    return obj[name] if isinstance(obj, dict) else getattr(obj, name)


def temporary_share_arns(record: dict | None, shares: dict) -> frozenset[str]:
    arns = {s["share_arn"] for s in (record or {}).get("shares", []) if s.get("share_arn")}
    for by_logical in shares.values():
        arns.update(share["resourceShareArn"] for share in by_logical.values())
    return frozenset(arns)


def describe_item(item: dict) -> str:
    fields = [f"{key}={item[key]}" for key in (
        "consumer", "owner", "region", "resource_arn", "vpc_id", "rule_id", "association_id",
        "endpoint_id", "tgw_id", "attachment_id", "route_table_id", "destination", "pool_id",
        "allocation_id", "cidr", "status", "state", "owner_association_state", "ca_status",
        "consumer_read") if item.get(key) not in (None, "")]
    if item["kind"] == "entitlement":
        fields.append(f"via_shares={len(item.get('via_shares', []))} "
                      f"via_temporary={len(item.get('via_temporary', []))} "
                      f"via_other={len(item.get('via_other', []))}")
    return f"kind={item['kind']} " + " ".join(fields)


def group_accounts(groups: list) -> dict[str, list[str]]:
    """Every owner and consumer an observation of these groups covers."""
    accounts = {value(g, "owner") for g in groups} | \
        {consumer for g in groups for consumer in value(g, "consumers")}
    return {account: ["observation"] for account in sorted(accounts)}


def observe(router: Any, groups: list, temporary: frozenset[str], opts: Options,
            report: Reporter, phase: str) -> Any:
    progress = Progress(report, f"observation:{phase}", group_accounts(groups))
    observation = verifier().collect(router, groups, temporary_shares=temporary,
                                     workers=opts.args.region_workers)
    progress.observed(observation)
    for item in sorted(value(observation, "items"), key=lambda row: row["key"]):
        report.emit(f"phase={phase} {describe_item(item)}")
    for gap in value(observation, "gaps"):
        report.emit(f"phase={phase} status=GAP collector={gap.get('collector')} "
                    f"account={gap.get('account')} region={gap.get('region')} "
                    f"resource={gap.get('resource_arn')} reason={gap.get('reason')}")
    return observation


def unassociated_rules(groups: list, observation: Any,
                       baseline: dict | None = None) -> list[tuple[str, str, str]]:
    """Planned Resolver rules a consumer never associated: reported, never called missing.
    A rule associated in the baseline is never one of them; its loss is a baseline loss."""
    items = [*value(observation, "items"), *(baseline or {}).get("items", [])]
    associated = {(item.get("consumer"), item.get("region"), item.get("resource_arn"))
                  for item in items if item["kind"] == "resolver_association"}
    return sorted({(consumer, group.region, arn) for group in groups
                   for consumer in group.consumers for arn, kind in group.resources.items()
                   if kind.lower() == RESOLVER_TYPE and (consumer, group.region, arn) not in associated})


def capture_problems(observation: Any) -> list[str]:
    """A baseline is captured only from a complete, stable observation."""
    problems = [f"phase=baseline status=BLOCKED collector={gap.get('collector')} "
                f"account={gap.get('account')} region={gap.get('region')} "
                f"resource={gap.get('resource_arn')} {gap.get('reason')}; the original baseline "
                "cannot be captured completely" for gap in value(observation, "gaps")
                if gap.get("reason") != UNAVAILABLE]
    for item in value(observation, "items"):
        rule = HEALTH.get(item["kind"])
        if rule and item.get(rule[0]) != rule[1]:
            problems.append(f"phase=baseline status=BLOCKED {describe_item(item)}: not {rule[1]}; "
                            "capture requires a stable original state")
        if item["kind"] == "entitlement" and not item.get("via_shares"):
            problems.append(f"phase=baseline status=BLOCKED {describe_item(item)}: "
                            "not visible to the consumer")
    return problems


def losses(comparison: Any) -> list[dict]:
    rows = [{"key": entry["key"], "item": entry.get("item") or entry.get("before"),
             "reason": "missing"} for entry in value(comparison, "missing")]
    rows += [{"key": entry["key"], "item": entry.get("before") or entry.get("item"),
              "reason": "; ".join(entry.get("reasons", [])) or "degraded"}
             for entry in value(comparison, "degraded")]
    return rows


def scoped_items(items: list[dict], groups: list) -> list[dict]:
    """Baseline items belonging to these groups' consumers and resources."""
    pairs = {(consumer, arn) for group in groups for consumer in group.consumers
             for arn in group.resources}
    resources = {arn for _, arn in pairs}
    return [item for item in items if item.get("resource_arn") in resources and (
        item.get("consumer") is None or (item.get("consumer"), item.get("resource_arn")) in pairs)]


RECORDED_LOSS = ("the recorded baseline is never replaced - restore it or start a new "
                 "migration record")


def baseline_check(record: dict | None, observation: Any, groups: list) -> tuple[list[str], Any]:
    """Pre-write: capture problems if no baseline exists, else losses against it."""
    baseline = (record or {}).get("baseline")
    if baseline is None:
        return capture_problems(observation), None
    comparison = verifier().compare(scoped_items(baseline["items"], groups), observation)
    status = value(comparison, "status")
    if status == "LOSS":
        return [f"phase=baseline status=BLOCKED original {loss['reason']}: {loss['key']}; "
                f"{RECORDED_LOSS}" for loss in losses(comparison)], comparison
    if status != "INTACT":
        return [f"phase=baseline status=BLOCKED observation gap {gap.get('collector')} "
                f"{gap.get('account')} {gap.get('region')} {gap.get('reason')}"
                for gap in value(comparison, "gaps")] or [
                    "phase=baseline status=BLOCKED observation is incomplete"], comparison
    return [], comparison


def consumer_organizations(router: Any, consumers: list[str],
                           opts: Options) -> tuple[dict[str, str], list[str]]:
    def read(account, _region):
        try:
            organization = router.client(account, "organizations", RAM_HOME_REGION).describe_organization()
        except ClientError as exc:
            if exc.response.get("Error", {}).get("Code") == "AWSOrganizationsNotInUseException":
                return "STANDALONE"
            raise
        identifier = (organization.get("Organization") or {}).get("Id")
        if not identifier:
            raise MigrationError("Organization identity was not returned")
        return identifier
    found, errors = {}, []
    for row in scoped_fanout({account: ["organization"] for account in consumers}, read, opts):
        if row.error:
            errors.append(f"account={row.account} phase=organization status=BLOCKED {row.error}")
        else:
            found[row.account] = row.value
    return found, errors


def new_baseline(observation: Any, organizations: dict, revision: int) -> dict:
    gaps = list(value(observation, "gaps"))
    return {"schema": 1, "captured_at": value(observation, "observed_at"),
            "captured_in_revision": revision, "complete": not gaps, "gaps": gaps,
            "consumer_organizations": dict(sorted(organizations.items())),
            "items": sorted(value(observation, "items"), key=lambda row: row["key"])}


def drops_from(comparison: Any, observation: Any, organizations: dict, detected_by: str,
               last_present_at: str, evidence: str) -> list[dict]:
    if comparison is None or value(comparison, "status") != "LOSS":
        return []
    first_absent = value(observation, "observed_at")
    drops = []
    for loss in losses(comparison):
        item = loss["item"] or {}
        kind = DROP_KIND.get(item.get("kind"), item.get("kind", "entitlement"))
        consumer = item.get("consumer")
        drops.append({"id": drop_id(kind, consumer, item.get("region"), loss["key"], first_absent),
                      "kind": kind, "severity": "failure", "consumer": consumer,
                      "owner": item.get("owner"), "region": item.get("region"), "subject": loss["key"],
                      "last_present_at": last_present_at, "first_absent_at": first_absent,
                      "detected_by": detected_by,
                      "consumer_organization_at_detection": organizations.get(consumer, "UNKNOWN"),
                      "evidence": evidence, "reason": loss["reason"]})
    return drops


def migration_status(record: dict, comparison: Any | None, organizations: dict,
                     groups: list | None = None) -> tuple[str, list[str]]:
    """FAILED > INCONCLUSIVE > PENDING_MIGRATION > MIGRATION_VALIDATED.

    With ``groups``, an entitlement of a baseline consumer that the baseline does not
    cover is INCONCLUSIVE too: its original state was never recorded."""
    baseline = record.get("baseline")
    reasons = [f"failure drop {d['kind']} {d['subject']} first absent {d['first_absent_at']}"
               for d in failure_drops(record)]
    if comparison is not None and value(comparison, "status") == "LOSS":
        reasons += [f"{loss['reason']}: {loss['key']}" for loss in losses(comparison)]
    if reasons:
        return "FAILED", sorted(set(reasons))
    if baseline is None:
        return "INCONCLUSIVE", ["no original baseline is recorded; apply captures it before its first write"]
    if not baseline.get("complete"):
        return "INCONCLUSIVE", [f"baseline is incomplete: {gap.get('collector')} {gap.get('reason')}"
                                for gap in baseline.get("gaps", [])] or ["baseline is incomplete"]
    if comparison is None or value(comparison, "status") != "INTACT":
        gaps = value(comparison, "gaps") if comparison is not None else []
        return "INCONCLUSIVE", [f"observation gap: {gap.get('collector')} {gap.get('account')} "
                                f"{gap.get('region')} {gap.get('reason')}" for gap in gaps] or [
                                    "the current observation is incomplete"]
    before = baseline.get("consumer_organizations", {})
    unknown = [f"current organization of {consumer} is unknown"
               for consumer in sorted(before) if consumer not in organizations]
    unknown += [f"{consumer} has no baseline organization; the original baseline does not cover it"
                for consumer in sorted(set(organizations) - set(before))]
    unknown += [f"entitlement owner={owner} region={region} consumer={consumer} resource={arn} "
                "is not covered by the original baseline"
                for owner, region, consumer, arn in uncovered_entitlements(baseline, groups or [])
                if consumer in before]
    if unknown:
        return "INCONCLUSIVE", unknown
    staying = sorted(consumer for consumer, org in before.items() if organizations[consumer] == org)
    if staying:
        return "PENDING_MIGRATION", [f"{consumer} is still in its baseline organization {before[consumer]}"
                                     for consumer in staying]
    return "MIGRATION_VALIDATED", []


def fill_scope_from_record(opts: Options, record: dict) -> dict[str, set[str]]:
    """verify/complete use the reviewed scope; explicit flags must agree with it.

    Returns each owner's recorded group and share Regions, which include Regions
    implied by consumer dependencies or enabled-Region scans rather than --regions.
    """
    scope = record.get("scope") or {}
    owners = sorted(set(scope.get("stationary_owners", [])) | set(scope.get("migrating_owners", [])))
    consumers = sorted(set(scope.get("migrating_consumers", [])) | set(scope.get("migrating_owners", [])))
    regions = sorted(set(scope.get("regions", [])) | {RAM_HOME_REGION})
    detected = sorted(scope.get("detected_owners") or [])
    excluded = scope.get("excluded_regions") or None
    if not owners or not consumers:
        raise MigrationError("The migration record has no reviewed account scope; run plan --record")
    # Migrating owners found by their owned shares need not be repeated in --owners.
    if opts.owners and sorted(set(opts.owners)) not in (owners, sorted(set(owners) - set(detected))):
        raise MigrationError(f"--owners differs from the migration record scope {owners}")
    if opts.consumers and sorted(set(opts.consumers)) != consumers:
        raise MigrationError(f"--consumers differs from the migration record scope {consumers}")
    if opts.args.regions and sorted(set(opts.regions)) != regions:
        raise MigrationError(f"--regions differs from the migration record scope {regions}")
    if opts.excluded_regions and (excluded is None or
                                  sorted(set(opts.excluded_regions)) != excluded["regions"] or
                                  opts.exclusion_reason != excluded["reason"]):
        raise MigrationError("--exclude-regions/--exclude-reason differ from the migration record "
                             f"scope {json.dumps(excluded)}")
    opts.owners, opts.consumers, opts.regions = owners, consumers, regions
    opts.detected_owners = detected
    opts.excluded_regions = list(excluded["regions"]) if excluded else []
    opts.exclusion_reason = excluded["reason"] if excluded else None
    located: dict[str, set[str]] = defaultdict(set)
    for row in [*record.get("shares", []), *(record.get("plan") or {}).get("groups", [])]:
        located[row["owner"]].add(row["region"])
    return dict(located)


def transient(exc: Exception, verification: bool = False) -> bool:
    if isinstance(exc, ClientError):
        return exc.response.get("Error", {}).get("Code") in TRANSIENT_CODES
    if isinstance(exc, (TimeoutError, ConnectionError, ConnectionClosedError,
                        ConnectTimeoutError, EndpointConnectionError, ReadTimeoutError)):
        return True
    if isinstance(exc, MigrationError) and verification:
        text = str(exc).lower()
        if any(fragment in text for fragment in
               ("unexpected", "unapproved", "invalid", "ownership", "permission",
                "ambiguous", "unsupported", "differs", "does not match")):
            return False
        return any(fragment in text for fragment in
                   ("not ready", "associations incomplete", "resources not available", " missing",
                    " associating", " pending", "configuration is not ready"))
    return False


def poll(callback: Callable[[], Any], opts: Options, *, verification: bool = False):
    deadline = time.monotonic() + opts.args.timeout
    for attempt in range(opts.args.retry_limit):
        try:
            return callback()
        except Exception as exc:
            if not transient(exc, verification) or attempt + 1 == opts.args.retry_limit:
                raise
            delay = min(15, opts.args.poll_interval * 2 ** min(attempt, 6)) * random.uniform(0.75, 1.25)
            remaining = deadline - time.monotonic()
            if remaining <= delay:
                raise MigrationError(f"Polling timeout: {failure_text(exc)}") from exc
            time.sleep(delay)
    raise AssertionError("retry limit must be positive")


def accept_consumer(router: WriteGate, consumer: str, region: str, allowed: dict[str, str],
                    opts: Options, report: Reporter,
                    progress: dict | None = None) -> tuple[int, int]:
    initial_accepted: set[str] = set()
    pending_seen: set[str] = set()

    def observed_counts():
        final = pages(router.client(consumer, "ram", region), "get_resource_share_invitations",
                      "resourceShareInvitations")
        accepted = {r["resourceShareInvitationArn"] for r in final
                    if r["resourceShareArn"] in allowed and r["status"] == "ACCEPTED"
                    and r.get("senderAccountId") == allowed[r["resourceShareArn"]]
                    and r.get("receiverAccountId") == consumer}
        return len(accepted & pending_seen), len(accepted & initial_accepted)

    def attempt():
        client = router.client(consumer, "ram", region)
        invitations = pages(client, "get_resource_share_invitations", "resourceShareInvitations")
        for invitation in invitations:
            arn = invitation["resourceShareArn"]
            if arn not in allowed:
                continue
            if invitation.get("senderAccountId") != allowed[arn] or \
                    invitation.get("receiverAccountId") != consumer:
                raise MigrationError(f"{arn}: invitation owner/receiver mismatch")
            invitation_id = invitation["resourceShareInvitationArn"]
            if invitation["status"] == "ACCEPTED" and invitation_id not in pending_seen:
                initial_accepted.add(invitation_id)
            elif invitation["status"] == "PENDING":
                pending_seen.add(invitation_id)
        accept(router, consumer, region, allowed)
        for arn, owner in sorted(allowed.items()):
            associations = pages(router.client(owner, "ram", region),
                                 "get_resource_share_associations", "resourceShareAssociations",
                                 associationType="PRINCIPAL", resourceShareArns=[arn])
            state = next((r["status"] for r in associations
                          if r.get("associatedEntity") == consumer), "MISSING")
            report.emit(f"owner={owner} region={region} share={arn} consumer={consumer} "
                        f"phase=acceptance status={state}")
            if state in ("ASSOCIATING", "MISSING"):
                raise MigrationError(f"{arn}: consumer {consumer} {state}")
            if state != "ASSOCIATED":
                raise MigrationError(f"{arn}: consumer {consumer} {state}")
        return observed_counts()

    completed = False
    try:
        result = poll(attempt, opts, verification=True)
        completed = True
        return result
    finally:
        if progress is not None:
            try:
                progress[consumer, region] = observed_counts()
            except Exception as exc:
                if completed:
                    raise
                report.emit(f"consumer={consumer} region={region} phase=invitation-accounting "
                            f"status=INCOMPLETE {failure_text(exc)}")


def print_plan(plan: Plan, prepared: dict, report: Reporter) -> None:
    report.emit(f"migration={plan.migration} phase=plan writes=DISABLED")
    for group in sorted(plan.groups, key=lambda item: (item.owner, item.region, item.key)):
        report.emit(f"owner={group.owner} region={group.region} group={group.key} "
                    f"stack={stack_name(plan.migration, group.owner, group.region)} "
                    f"consumers={','.join(group.consumers)} "
                    "external_principals=true retain_on_organization_leave=true")
        for arn, kind in sorted(group.resources.items()):
            report.emit(f"  resource={arn} type={kind} permission={group.permissions[kind]}")
        report.emit(f"  source_shares={','.join(sorted(set(group.source_shares)))}")
    for (owner, region), (body, old) in sorted(prepared.items()):
        report.emit(f"owner={owner} region={region} phase=plan action={'UPDATE_OR_REUSE' if old else 'CREATE'} "
                    f"template={json.dumps(body, sort_keys=True)}")
    for reason in plan.excluded:
        report.emit(f"phase=plan status=EXCLUDED {reason}")
    for share in plan.existing:
        report.emit(f"phase=plan status=EXISTING share={share.get('resourceShareArn', 'unknown')}")
    for note in plan.notes:
        report.emit(f"phase=plan status=NOTE {note}")
    for reason in plan.blocked:
        report.emit(f"phase=preflight status=BLOCKED {reason}")


def account_scope(opts: Options) -> dict:
    """Explicit account roles; a stationary owner's own dependencies are not at risk.

    A migrating account that owns RAM shares is a migrating owner even when --owners
    does not name it (``detected_owners``). Regions the operator excluded, with the
    reason, are part of the reviewed scope."""
    owners, consumers = set(opts.owners), set(opts.consumers)
    return {
        "migrating_consumers": sorted(consumers - owners),
        "migrating_owners": sorted(owners & consumers),
        "stationary_owners": sorted(owners - consumers),
        "detected_owners": sorted(set(opts.detected_owners) & owners & consumers),
        "regions": sorted(opts.regions),
        "scan_enabled_regions": bool(opts.args.scan_enabled_regions),
        "excluded_regions": exclusion_scope(opts),
    }


def group_record(group: Group, migration: str) -> dict:
    return {
        "key": group.key, "logical_id": group.logical_id,
        "stack": stack_name(migration, group.owner, group.region),
        "owner": group.owner, "region": group.region,
        "consumers": list(group.consumers),
        "permissions": dict(sorted(group.permissions.items())),
        "resources": dict(sorted(group.resources.items())),
        "source_shares": sorted(set(group.source_shares)),
        "source_stacks": sorted(set(getattr(group, "source_stacks", []))),
        "permission_changes": list(getattr(group, "permission_changes", [])),
    }


def print_permission_changes(plan: Plan, approvals: list[dict], report: Reporter) -> list[dict]:
    """Every change is shown with its comparison, approved or not."""
    requests = permission_requests(plan.migration, plan.permission_changes)
    for request in requests:
        covered = all(approval_for(approvals, plan.migration, {**request, "share": share})
                      for share in request["shares"])
        report.emit(f"phase=permission-change change={request['id']} "
                    f"status={'APPROVED' if covered else 'APPROVAL_REQUIRED'} "
                    f"permission={request['permission_arn']} resource_type={request['resource_type']} "
                    f"version={request['from_version']}->{request['to_version']} "
                    f"shares={len(request['shares'])}")
        for line in describe_difference(request["difference"]):
            report.emit(f"  {line}")
        for share in request["shares"]:
            targets = sorted({change["applies_to"] for change in plan.permission_changes
                              if change["share"] == share and change.get("applies_to")
                              and all(change[f] == request[f] for f in CHANGE_FIELDS)})
            report.emit(f"  share={share}" + (f" applies_to={'; '.join(targets)}" if targets else ""))
    return requests


def reviewed_plan_problem(record: dict, plan: Plan, scope: dict) -> str | None:
    """Apply consumes the reviewed scope; it never adopts a newly discovered one."""
    entry = latest(record, "plan")
    if entry is None or not record.get("plan"):
        return "the migration record has no reviewed plan; run plan --record first"
    if entry["status"] != APPLICABLE or record["plan"].get("status") != APPLICABLE:
        return (f"the reviewed plan (revision {entry['revision']}) is {entry['status']}; resolve "
                "its blockers, re-run plan --record and review it before apply")
    if entry.get("tool_sources_digest") != tool_identity()["sources_digest"]:
        return ("tool sources changed since the reviewed plan; re-run plan --record with this "
                "tool version and review it")
    if record["plan"].get("digest") != plan_digest(plan.groups, scope):
        return (f"live entitlements or account roles differ from reviewed plan revision "
                f"{entry['revision']}; re-run plan --record and review the changes")
    return None


def record_plan(record: dict, plan: Plan, scope: dict, prepared: dict, received: Any,
                capability_provenance: dict, status: str, proposed: dict | None = None) -> dict:
    record = dict(record)
    record["scope"] = scope
    record["plan"] = {
        "status": status,
        "digest": plan_digest(plan.groups, scope),
        "groups": [group_record(g, plan.migration) for g in
                   sorted(plan.groups, key=lambda g: (g.owner, g.region, g.key))],
        "blocked": list(plan.blocked),
        "excluded": list(plan.excluded),
        "notes": list(plan.notes),
        "existing_shares": sorted({s.get("resourceShareArn", "unknown") for s in plan.existing}),
        "capability_provenance": capability_provenance,
        "received_entitlements": received.to_dict() if received is not None else None,
        "migration_stacks": [
            {"owner": owner, "region": region, "template": body,
             "existing_stack": old.get("StackId") if old else None}
            for (owner, region), (body, old) in sorted(prepared.items())],
    }
    record["permission_change_requests"] = permission_requests(plan.migration,
                                                               plan.permission_changes)
    record["owner_scope_request"] = owner_scope_request(plan.migration, proposed or {})
    return record


def share_records(previous: list[dict], groups: list[Group], shares: dict,
                  migration: str, *, verified: bool = True,
                  conflicts: list[str] | None = None) -> list[dict]:
    """Created-share identifiers accumulate; a recorded share is never forgotten.

    A stack share whose ARN differs from the recorded one raises, or, with
    ``conflicts``, is reported there while the recorded entry is kept unchanged, so
    one conflict never discards the other shares' entries. ``verified=False`` records
    a share read back from its stack before verification."""
    known = {(r["owner"], r["region"], r["logical_id"]): dict(r) for r in previous}
    for group in groups:
        share = shares.get((group.owner, group.region), {}).get(group.logical_id)
        if not share:
            continue
        key = (group.owner, group.region, group.logical_id)
        recorded = known.get(key, {}).get("share_arn")
        if recorded not in (None, share["resourceShareArn"]):
            problem = (f"{group.owner}/{group.region}/{group.logical_id}: recorded share "
                       f"{recorded} differs from {share['resourceShareArn']}")
            if conflicts is None:
                raise MigrationError(problem)
            conflicts.append(problem + "; the recorded share is kept, reconcile it explicitly")
            continue
        entry = known.setdefault(key, {
            "owner": group.owner, "region": group.region, "logical_id": group.logical_id,
            "entitlement_hash": group.key, "stack": stack_name(migration, group.owner, group.region),
            "first_recorded_at": timestamp()})
        entry["share_arn"] = share["resourceShareArn"]
        entry["consumers"] = sorted(set(entry.get("consumers", [])) | set(group.consumers))
        if verified:
            entry["last_verified_at"] = timestamp()
    return [known[k] for k in sorted(known)]


def run_approve(opts: Options, ask: Callable[[str], str], report: Reporter) -> int:
    path = opts.args.record
    record = load_record(path, opts.args.migration_id)
    migration = record["migration_id"]
    if latest(record, "plan") is None:
        raise MigrationError("approve requires a recorded plan; run plan --record first")
    excluded = (record.get("scope") or {}).get("excluded_regions")
    if excluded:
        report.emit(f"migration={migration} phase=approve scope=REGIONS_EXCLUDED"
                    f"{exclusion_text(excluded)}")
    pending = pending_requests(record)
    owners_request = record.get("owner_scope_request")
    if owners_request and owners_request["id"] in {
            a.get("approval_id") for a in record.get("approvals", {}).get("owner_scope", [])}:
        owners_request = None
    if not pending and not owners_request:
        report.emit(f"migration={migration} phase=approve status=NOTHING_PENDING")
        return 0
    approved = []
    owners_approved = None
    for request in pending:
        report.emit(f"migration={migration} phase=approve change={request['id']} "
                    f"permission={request['permission_arn']} resource_type={request['resource_type']} "
                    f"version={request['from_version']}->{request['to_version']}")
        report.emit(f"  from_policy_sha256={request['from_policy_sha256']}")
        report.emit(f"  to_policy_sha256={request['to_policy_sha256']}")
        for line in describe_difference(request["difference"]):
            report.emit(f"  {line}")
        for share in request["shares"]:
            report.emit(f"  share={share}")
        report.emit("  The approval covers only temporary migration shares for these source shares "
                    "in this migration. Original shares are not modified. A new temporary share "
                    "receives the current default version; a temporary share already in a "
                    "migration stack keeps the version it was created with.")
        token = f"APPROVE {migration} {request['id']}"
        try:
            reply = ask(f"Type {token} to approve this permission change: ")
        except EOFError:
            reply = ""
        if reply != token:
            report.emit(f"change={request['id']} phase=approve status=NOT_APPROVED "
                        "confirmation did not match")
            continue
        approved.append(request)
        report.emit(f"change={request['id']} phase=approve status=CONFIRMED")
    if owners_request:
        report.emit(f"migration={migration} phase=approve owner-scope={owners_request['id']} "
                    f"proposed_owners={','.join(owners_request['owners'])}")
        for owner, evidence in owners_request["evidence"].items():
            types = ", ".join(f"{k} x{v}" for k, v in evidence["resource_types"].items())
            report.emit(f"  owner={owner} unique_resources={evidence['unique_resources']} "
                        f"observations={evidence['observations']} shares={len(evidence['shares'])} "
                        f"pending_shares={len(evidence['pending_shares'])} "
                        f"regions={','.join(evidence['regions'])} "
                        f"consumers={','.join(evidence['consumers'])} types=[{types}]")
        report.emit("  Approval adds these owners to this migration's owner scope only. Plan must "
                    "then be re-run with explicit access mappings for them before anything is applied.")
        token = f"APPROVE-OWNERS {migration} {owners_request['id']}"
        try:
            reply = ask(f"Type {token} to approve this owner scope: ")
        except EOFError:
            reply = ""
        if reply == token:
            owners_approved = owners_request
            report.emit(f"owner-scope={owners_request['id']} phase=approve status=CONFIRMED")
        else:
            report.emit(f"owner-scope={owners_request['id']} phase=approve status=NOT_APPROVED "
                        "confirmation did not match")
    if approved or owners_approved:
        def add_approvals(current: dict) -> None:
            reviewed = {r["id"]: r for r in current.get("permission_change_requests", [])}
            for request in approved:
                if reviewed.get(request["id"]) != request:
                    raise MigrationError(f"{request['id']}: the record changed during review; "
                                         "re-run approve against the latest plan revision")
                approve_permission_change(current, request)
            if owners_approved:
                if current.get("owner_scope_request") != owners_approved:
                    raise MigrationError(f"{owners_approved['id']}: the record changed during review; "
                                         "re-run approve against the latest plan revision")
                approve_owner_scope(current, owners_approved)
        ids = [request["id"] for request in approved] + \
            ([owners_approved["id"]] if owners_approved else [])
        update_record(path, migration, add_approvals, mode="approve", status="APPROVED", approved=ids)
        for approval_id in ids:
            report.emit(f"approval={approval_id} phase=approve status=APPROVED")
        report.emit("Re-run plan with --record to produce a PLANNED revision for review before apply.")
    complete = len(approved) == len(pending) and (owners_request is None or owners_approved)
    return 0 if complete else 2


def summary(plan: Plan, report: Reporter, status: str, *, mode: str, recorded: bool,
            created: int = 0, reused: int = 0, accepted: int = 0,
            reused_invitations: int = 0, failures: int = 0, comparison: Any = None,
            unassociated: int = 0, sharing: str | None = None,
            migration: str | None = None, excluded: dict | None = None) -> None:
    resources = {arn for group in plan.groups for arn in group.resources}
    entitlements = {(group.owner, group.region, arn, consumer, group.permissions[kind])
                    for group in plan.groups for arn, kind in group.resources.items()
                    for consumer in group.consumers}
    line = (f"status={status} migration={plan.migration} resources_in_plan={len(resources)} "
            f"expected_entitlements={len(entitlements)} planned_shares={len(plan.groups)} "
            f"created_shares={created} reused_shares={reused} accepted_invitations={accepted} "
            f"reused_invitations={reused_invitations} exclusions={len(plan.excluded)} "
            f"blockers={len(plan.blocked)} verification_failures={failures}")
    if sharing:
        line += f" sharing_status={sharing}"
    if migration:
        line += f" migration_status={migration}"
    if comparison is not None:
        line += (f" baseline_status={value(comparison, 'status')} "
                 f"baseline_missing={len(value(comparison, 'missing'))} "
                 f"baseline_degraded={len(value(comparison, 'degraded'))} "
                 f"observation_gaps={len(value(comparison, 'gaps'))}")
    if unassociated:
        line += f" unassociated_resolver_rules={unassociated}"
    report.emit(line + exclusion_text(excluded))
    report.emit("Sharing status is not live migration acceptance evidence. "
                "Resource totals cover planned entitlements; excluded inventory is reported separately.")
    if excluded:
        report.emit(f"Regions {','.join(excluded['regions'])} were excluded by the operator "
                    f"({excluded['reason']}): nothing in them was inspected, so this result does "
                    "not cover them.")
    if unassociated:
        report.emit("Resolver rules without an association had none before migration; "
                    "no association repair was performed.")
    report_blockers(plan, report, status, mode=mode, recorded=recorded)


# Display order, then the next action per run: "unrecorded" is plan without --record
# and "*" any other mode; a mode with neither uses "other". {rerun} repeats this run and
# {replan} produces a new reviewed plan.
BLOCKER_ACTIONS = {
    "permission-approval-required": {
        "unrecorded":
            "re-run plan with --record <path> to record the permission-change requests, review "
            "each managed-permission comparison, run approve with that --record and type its "
            "APPROVE token, then re-run plan --record",
        "plan":
            "review each managed-permission comparison, run approve with the same --record and "
            "type its APPROVE token, then re-run plan --record; a drifted approval needs a new "
            "plan and approval",
        "apply":
            "a managed permission changed after the reviewed plan, which voids its approval: "
            "run plan with the same --record, review the new comparison, run approve and type "
            "its APPROVE token, re-run plan --record, then re-run apply",
    },
    "owner-outside-approved-scope": {
        "unrecorded":
            "re-run plan with --record <path> to record the proposed owners, run approve with "
            "that --record and type the APPROVE-OWNERS token, then re-run plan --record with a "
            "--profile-map or --role-map entry for each owner",
        "plan":
            "run approve with the same --record and type the APPROVE-OWNERS token for the "
            "proposed owners, then re-run plan --record with a --profile-map or --role-map entry "
            "for each owner",
        "apply":
            "owners outside the reviewed scope now provide received resources: run plan with "
            "the same --record, run approve and type the APPROVE-OWNERS token, re-run plan "
            "--record with a --profile-map or --role-map entry for each owner, review it, then "
            "re-run apply",
    },
    "received-dependency-not-covered": {
        "*": "no planned temporary share covers these received resources: check the owner's "
             "discovery exclusions, supply --principal-map for the original share if the "
             "consumer is an intended principal, then {replan}",
    },
    "configuration": {
        "*": "each named share needs explicit input: a --principal-map entry listing the "
             "intended account IDs resolves unresolved or historical consumers; a resource type "
             "is shared only where the AWS external-sharing catalog supports it and "
             "--capabilities can only restrict that, so plan an unsupported type's continuity "
             "separately; then {replan}",
    },
    "authentication": {
        "*": "refresh or supply credentials for each named account (aws sso login, --sso-role, "
             "--account-map, --profile-map or --role-map), then {rerun}; expired tokens are "
             "not retried",
    },
    "region-scope": {
        "plan": "make every Region resolvable: allow ec2:DescribeRegions for the named accounts "
                "or add the missing Regions to --regions, then re-run plan --record",
        "apply": "allow ec2:DescribeRegions for the named accounts, then re-run apply with the "
                 "same --record; a dependency in a Region outside the reviewed scope needs plan "
                 "--record with that Region in --regions and a review before apply",
        "verify": "allow ec2:DescribeRegions for the named accounts or omit "
                  "--scan-enabled-regions (verify takes its Regions from the record), then "
                  "re-run verify with the same --record",
    },
    "discovery-api-error": {
        "*": "resolve each named API error (operation and request ID are shown; for throttling "
             "lower {workers}), then {rerun}",
    },
    "baseline-loss": {
        "*": "each loss against the recorded baseline is now a permanent failure drop in this "
             "record: restoring the original access does not clear it and complete will refuse "
             "this record, so restore the original access and start a new migration record "
             "(new --migration-id and --record) instead of resuming apply with this one",
    },
    "baseline-capture": {
        "*": "the original state must be completely observable and stable before apply writes: "
             "restore it or grant the collectors read access, then re-run apply with the same "
             "--record; a recorded baseline is never replaced",
    },
    "baseline-scope": {
        "apply": "the recorded original baseline covers only what the first apply observed and "
                 "is never extended or replaced, so this record cannot add the listed "
                 "entitlements: plan them under a new migration record (new --migration-id and "
                 "--record), or re-run plan with the same --record without them, review it, "
                 "then re-run apply",
        "*": "an entitlement outside the recorded original baseline cannot be added under this "
             "migration record: remove it from the scope or plan it under a new migration "
             "record (new --migration-id and --record), then {rerun}",
    },
    "approval-evidence": {
        "*": "a migration stack records a permission-change approval that this migration record "
             "does not hold or that differs from it: use the record that approved it "
             "(approvals never transfer between records), or restore the stack's metadata if "
             "it was changed outside the tool, then {rerun}",
    },
    "reviewed-record-mismatch": {
        "apply": "the reviewed plan no longer matches this run: re-run plan with the same "
                 "--record using this tool version, review the new PLANNED revision, then re-run "
                 "apply, which resumes from the shares the record already holds",
        "verify": "the record and its migration stacks disagree: an apply that stopped before "
                  "recording its shares is resumed by apply with the same --record while its "
                  "reviewed plan still matches; then re-run verify with the same --record",
    },
    "other": {"*": "resolve each blocker listed above, then {rerun}"},
}
RERUN = {"plan": "re-run plan --record", "apply": "re-run apply with the same --record",
         "verify": "re-run verify with the same --record"}
REPLAN = {"plan": "re-run plan --record",
          "apply": "run plan with the same --record, review the new PLANNED revision, then "
                   "re-run apply",
          "verify": "re-run verify with the same --record"}
WORKERS = {"plan": "--share-workers, --region-workers or --account-workers",
           "apply": "--share-workers, --region-workers or --account-workers",
           "verify": "--region-workers or --account-workers"}
# First match wins: credentials are named as such in any phase, phase-specific
# categories come next, and an API failure (operation or request ID) is never
# taken for an approval or configuration need.
BLOCKER_PATTERNS = (
    ("authentication", re.compile(
        r"phase=authentication|ExpiredToken|InvalidClientTokenId|UnrecognizedClientException"
        r"|security token included in the request is (?:expired|invalid)"
        r"|SSO (?:session|token|login)|token has expired|unable to locate credentials",
        re.IGNORECASE)),
    ("region-scope", re.compile(
        r"phase=(?:regions|received-regions) |Region is outside the selected discovery scope"
        r"|outside the explicit owner/Region scope")),
    ("baseline-loss", re.compile(r"phase=baseline status=BLOCKED original .*"
                                 + re.escape(RECORDED_LOSS))),
    ("baseline-scope", re.compile(r"phase=baseline-scope ")),
    ("baseline-capture", re.compile(r"phase=baseline ")),
    ("approval-evidence", re.compile(r"phase=approval-evidence ")),
    ("owner-outside-approved-scope", re.compile(r"phase=owner-scope ")),
    ("reviewed-record-mismatch", re.compile(
        r"phase=reviewed-record |plan changed; run plan/apply")),
    ("discovery-api-error", re.compile(r"operation=\w+|\(request [^)]*\)")),
    ("permission-approval-required", re.compile(
        r"requires approval|changed since (?:plan )?approval|approval \S+ no longer covers")),
    ("received-dependency-not-covered", re.compile(r"not covered by any planned temporary share")),
    ("configuration", re.compile(
        r"external-sharing capability|provide (?:a )?principal-map override", re.IGNORECASE)),
)
SHARE_ARN = re.compile(r"arn:[\w-]+:ram:[\w-]*:\d{12}:resource-share/[\w.-]+")
RESOURCE_ARN = re.compile(r"arn:[\w-]+:(?!ram:|iam:|sts:|cloudformation:|organizations:)"
                          r"[\w-]+:[\w-]*:\d{12}:[^\s,;)]+")
ACCOUNT_FIELD = re.compile(r"\b(account|consumer|owner)=(\d{12})\b")
# Which count each account field feeds. account= names the receiving migrating
# account, except that a credential failure is per account whatever its role and a
# baseline collector gap may name an owner.
COUNTED_AS = {"account": "consumers", "consumer": "consumers", "owner": "owners"}
CATEGORY_COUNTED_AS = {
    "authentication": {"account": "accounts", "consumer": "accounts", "owner": "accounts"},
    "baseline-capture": {"account": "accounts", "consumer": "consumers", "owner": "owners"},
}
OWNER_EVIDENCE = re.compile(r"phase=owner-scope owner=(\d{12}) .*? provides (\d+) unique "
                            r"received resources .*? through (\d+) shares .*?\((\d+) observations\)")


def blocker_category(reason: str) -> str:
    return next((name for name, pattern in BLOCKER_PATTERNS if pattern.search(reason)), "other")


def blocker_action(category: str, mode: str, recorded: bool) -> str:
    actions = BLOCKER_ACTIONS[category]
    context = "unrecorded" if mode == "plan" and not recorded else mode
    text = actions.get(context) or actions.get(mode) or actions.get("*") or \
        BLOCKER_ACTIONS["other"]["*"]
    return text.format(rerun=RERUN[mode], replan=REPLAN[mode], workers=WORKERS[mode])


def report_blockers(plan: Plan, report: Reporter, status: str, *, mode: str,
                    recorded: bool) -> None:
    """A blocked run ends with its blockers grouped by category, counted, and the
    next action for each, for this mode and whether the run used a record."""
    if status != "BLOCKED" or not plan.blocked:
        return
    grouped: dict[str, list[str]] = defaultdict(list)
    for reason in plan.blocked:
        grouped[blocker_category(reason)].append(reason)
    report.emit(f"phase=blocker-summary status=BLOCKED blockers={len(plan.blocked)} "
                f"categories={len(grouped)}")
    for category in BLOCKER_ACTIONS:
        reasons = grouped.get(category)
        if not reasons:
            continue
        text = " ".join(reasons)
        fields = [f"blockers={len(reasons)}"]
        if category == "owner-outside-approved-scope":
            # One blocker per proposed owner; its evidence carries the unique counts.
            evidence = {match[1]: match.groups()[1:] for match in
                        map(OWNER_EVIDENCE.search, reasons) if match}
            fields.append(f"owners={len(evidence)}")
            fields += [f"{name}={sum(int(row[index]) for row in evidence.values())}"
                       for name, index in (("shares", 1), ("resources", 0), ("observations", 2))]
        else:
            counts: dict[str, set[str]] = {
                "shares": set(SHARE_ARN.findall(text)),
                "resources": {arn.rstrip(":.") for arn in RESOURCE_ARN.findall(text)},
                "accounts": set(), "consumers": set(), "owners": set()}
            roles = CATEGORY_COUNTED_AS.get(category, COUNTED_AS)
            for name, account in ACCOUNT_FIELD.findall(text):
                counts[roles[name]].add(account)
            fields += [f"{name}={len(found)}" for name, found in counts.items() if found]
        if category == "permission-approval-required":
            pending = [c for c in plan.permission_changes if c.get("status") == "APPROVAL_REQUIRED"]
            if pending:
                fields.append(f"approvals={len(permission_requests(plan.migration, pending))}")
        report.emit(f"phase=blocker-summary category={category} {' '.join(fields)} "
                    f"next_action={blocker_action(category, mode, recorded)}")


class ReviewedRecordChanged(MigrationError):
    """The record no longer holds the reviewed plan this apply confirmed."""


def run_shares(router: Router, opts: Options, ask: Callable[[str], str], report: Reporter) -> int:
    gate = WriteGate(router)
    args = opts.args
    plan = Plan(args.migration_id)
    record = None
    if args.record is not None:
        if args.mode == "plan" and not args.record.exists():
            record = new_record(args.migration_id)
        else:
            record = load_record(args.record, args.migration_id)
    recorded_regions: dict[str, set[str]] = {}
    if args.mode == "verify":
        recorded_regions = fill_scope_from_record(opts, record)
    approved_owner_scope = approved_owners(record) if record else set()
    added_owners = sorted(approved_owner_scope - set(opts.owners))
    if added_owners:
        opts.owners = sorted(set(opts.owners) | approved_owner_scope)
        report.emit(f"phase=owner-scope status=APPROVED owners={','.join(added_owners)} "
                    "source=record; supply profile/role mappings for these owners")

    def reviewed_scope() -> dict:
        scope = account_scope(opts)
        scope["approved_owner_scope"] = sorted(approved_owner_scope)
        return scope
    scope = reviewed_scope()
    approvals = record["approvals"]["permission_changes"] if record else []
    # Selects each next action, and puts any Region exclusion on every summary line.
    run = {"mode": args.mode, "recorded": record is not None, "excluded": exclusion_scope(opts)}

    def note(status: str, mutate: Callable[[dict], Any] = lambda _record: None,
             **details: Any) -> None:
        """Apply/verify outcomes, including blocked and failed runs, are history. Once
        apply has checked its reviewed plan, each entry names the plan it consumed."""
        nonlocal record
        if record is not None and args.mode in ("apply", "verify"):
            record = update_record(args.record, plan.migration, mutate, mode=args.mode,
                                   status=status, **{**opts.applied_plan, **details})
    plan.blocked.extend(authenticate(router, set(opts.owners + opts.consumers), opts, report))
    if plan.blocked:
        if not args.sso_role and not args.role_name:
            report.emit("For unmapped accounts, supply explicit --sso-role or an "
                        "--account-map/--profile-map/--role-map.")
        print_plan(plan, {}, report)
        summary(plan, report, "BLOCKED", **run)
        if args.mode == "plan" and record is not None:
            update_record(args.record, plan.migration,
                          lambda current: current.update(record_plan(
                              current, plan, scope, {}, None, {}, "BLOCKED")),
                          mode="plan", status="BLOCKED", create=True,
                          blockers=len(plan.blocked), phase="authentication")
        note("BLOCKED", blockers=list(plan.blocked), phase="authentication")
        return 1
    received = None
    if args.mode != "verify":
        # Consumer-driven: what the migrating accounts receive decides which owner
        # Regions must be inspected, so the inventory comes first. A migrating account
        # that owns shares is a migrating owner, so it joins the owner scope here.
        received = received_inventory(gate, opts, report)
        detect_owners(received, opts, report)
        scope = reviewed_scope()
    scopes, failures = region_scopes(gate, opts, report, dependency_regions(received)
                                     if received is not None else recorded_regions,
                                     exclude=args.mode != "verify")
    plan.blocked.extend(failures)
    # One explicit cache for this run's planning reads; rechecks and writes read fresh.
    cache = LookupCache()
    stacks = Stacks(gate, plan.migration, timeout=args.timeout, cache=cache)
    if not callable(getattr(stacks, "persisted_groups", None)):
        raise MigrationError("Stacks.persisted_groups(owner, region) is required for stored-scope verification")
    persisted: set[str] = set()
    persisted_groups: dict[tuple[str, str], list[Group]] = {}
    # Each migration stack's groups exactly as its template records them. Merging
    # discovery into persisted_groups changes those objects; this copy never changes.
    deployed: dict[tuple[str, str], list[Group]] = {}
    unread: set[tuple[str, str]] = set()  # owner Regions whose stored plan could not be read
    def load_persisted(owner, region):
        if stacks.existing(owner, region) is None:
            return []
        groups = stacks.persisted_groups(owner, region)
        validate_groups(groups, {owner: [region]})
        return groups
    for row in scoped_fanout(scopes, load_persisted, opts):
        if row.error:
            unread.add((row.account, row.region))
            plan.blocked.append(f"owner={row.account} region={row.region} phase=stored-plan {row.error}")
        else:
            if row.value:
                persisted_groups[row.account, row.region] = row.value
                deployed[row.account, row.region] = copy.deepcopy(row.value)
            persisted.update(group.key for group in row.value)
            merge_plan(plan, Plan(plan.migration, groups=row.value))
    if record is not None:
        # The permission changes a stack records are evidence of what its shares were
        # created under; this record must hold each approval they name.
        plan.blocked.extend(evidence_problems(deployed, approvals, plan.migration))
    # What each existing temporary share attaches, by entitlement key: it keeps the
    # version it was created with, whatever the current default is.
    kept = {g.key: g.permission_snapshots for groups in deployed.values() for g in groups
            if getattr(g, "permission_snapshots", None)}

    capability_provenance: dict = {}
    proposed: dict[str, dict] = {}
    if args.mode != "verify":
        capabilities, capability_provenance = capabilities_for(opts)
        report.emit(f"phase=plan capability_provenance={json.dumps(capability_provenance, sort_keys=True)}")
        discovery = Discovery(gate, set(opts.consumers), plan.migration, opts.principals, capabilities,
                              approved_changes=approvals,
                              migrating_owners=set(scope["migrating_owners"]),
                              share_workers=args.share_workers, cache=cache, deployed=kept)
        def inspect(owner, region):
            report.emit(f"owner={owner} region={region} phase=discovery status=STARTED")
            result = discovery.inspect(owner, region)
            validate_groups(result.groups, {owner: [region]})
            if any(set(group.consumers) - set(opts.consumers) for group in result.groups):
                raise MigrationError("Discovery returned consumers outside the approved population")
            return result
        for row in scoped_fanout(scopes, inspect, opts, Progress(report, "discovery", scopes)):
            if row.error:
                plan.blocked.append(f"owner={row.account} region={row.region} phase=discovery {row.error}")
            else:
                merge_plan(plan, row.value)
        proven, provenance_blocked = received_provenance(stacks, persisted_groups, opts)
        received.blocked.extend(provenance_blocked)
        proposed = classify_received(received, plan, proven, scopes, opts)
        scope["proposed_owners"] = sorted(proposed)
        print_received(received, report)
        plan.blocked.extend(received.blocked)
        plan.excluded.extend(received.excluded)
    additional_consumers = {consumer for group in plan.groups for consumer in group.consumers} \
        - set(opts.owners + opts.consumers)
    plan.blocked.extend(authenticate(router, additional_consumers, opts, report))
    grouped, group_scopes = grouped_scopes(plan.groups)
    prepared: dict = {}
    if args.mode != "verify":
        for row in scoped_fanout(group_scopes,
                                 lambda owner, region: stacks.prepare(owner, region, grouped[owner, region]),
                                 opts, Progress(report, "prepare", group_scopes)):
            if row.error:
                plan.blocked.append(f"owner={row.account} region={row.region} phase=stack-preflight {row.error}")
            else:
                body, old = row.value
                if len(json.dumps(body, sort_keys=True).encode()) > 51200:
                    plan.blocked.append(f"{row.account}/{row.region}: migration template exceeds inline CFN limit")
                prepared[row.account, row.region] = body, old

    if args.mode == "apply" and record is not None:
        problem = reviewed_plan_problem(record, plan, scope)
        if problem:
            plan.blocked.append(f"phase=reviewed-record {problem}")
        else:
            opts.applied_plan = {"plan_revision": latest(record, "plan")["revision"],
                                 "plan_digest": record["plan"]["digest"]}
        if record.get("baseline") is not None:
            plan.blocked.extend(baseline_scope_problems(
                record["baseline"], plan.groups, [g for groups in deployed.values() for g in groups]))
    if args.mode == "verify" and record is not None:
        # An unreadable stored plan is already a blocker; its shares are not missing.
        recorded = {(s["owner"], s["region"], s["logical_id"]) for s in record.get("shares", [])
                    if (s["owner"], s["region"]) not in unread}
        stored = {(g.owner, g.region, g.logical_id) for g in plan.groups}
        plan.blocked += [f"phase=reviewed-record recorded temporary share {owner}/{region}/{logical} "
                         "is missing from its migration stack" for owner, region, logical
                         in sorted(recorded - stored)]
        plan.blocked += [f"phase=reviewed-record stack entitlement {owner}/{region}/{logical} is not "
                         "in the migration record" for owner, region, logical in sorted(stored - recorded)]
    consumers_in_scope = sorted({c for g in plan.groups for c in g.consumers})
    preflight, organizations, pending_drops = None, {}, []
    if args.mode == "apply" and not plan.blocked and plan.groups:
        organizations, errors = consumer_organizations(gate, consumers_in_scope, opts)
        plan.blocked.extend(errors)
        preflight = observe(gate, plan.groups, temporary_share_arns(record, {}), opts, report,
                            "baseline-preflight")
        problems, comparison = baseline_check(record, preflight, plan.groups)
        plan.blocked.extend(problems)
        pending_drops = drops_from(comparison, preflight, organizations, "apply",
                                   record["baseline"]["captured_at"] if record and record.get("baseline")
                                   else "", f"record revision {record['revision'] if record else 0}")
    if args.mode != "verify":
        print_plan(plan, prepared, report)
        requests = print_permission_changes(plan, approvals, report)
        if args.mode == "plan" and record is not None:
            status = "BLOCKED" if plan.blocked else APPLICABLE
            pending = sum(not all(approval_for(approvals, plan.migration, {**r, "share": s})
                                  for s in r["shares"]) for r in requests)
            record = update_record(
                args.record, plan.migration,
                lambda current: current.update(record_plan(
                    current, plan, scope, prepared, received, capability_provenance, status,
                    proposed)),
                mode="plan", status=status, create=True,
                plan_digest=plan_digest(plan.groups, scope), blockers=len(plan.blocked),
                permission_changes_pending=pending)
            report.emit(f"phase=plan record={args.record} revision={record['revision']} "
                        f"status={status} digest={record['plan']['digest']}")
        if args.export_plan:
            exported = plan.to_dict()
            exported["capability_provenance"] = capability_provenance
            exported["received_entitlements"] = received.to_dict()
            exported["scope"] = scope
            exported["migration_stacks"] = [
                {"owner": owner, "region": region, "template": body,
                 "existing_stack": old.get("StackId") if old else None}
                for (owner, region), (body, old) in sorted(prepared.items())
            ]
            args.export_plan.write_text(json.dumps(exported, indent=2, sort_keys=True) + "\n",
                                        encoding="utf-8")
            report.emit(f"phase=plan exported={args.export_plan}")
    if plan.blocked:
        if args.mode == "verify":
            for reason in plan.blocked:
                report.emit(f"phase=verification status=BLOCKED {reason}")
        summary(plan, report, "BLOCKED", **run)
        note("BLOCKED", lambda current: add_drops(current, pending_drops),
             blockers=list(plan.blocked), drops=len(pending_drops))
        return 1
    if args.mode == "plan":
        summary(plan, report, "PLANNED", **run)
        return 0
    if not plan.groups:
        report.emit("status=INCOMPLETE No stored/planned migration entitlements found in the requested scope")
        summary(plan, report, "INCOMPLETE", failures=1, **run)
        note("INCOMPLETE", failures=["no stored or planned migration entitlements"])
        return 1

    failures = []
    created = reused = accepted_count = reused_invitations = 0
    if args.mode == "apply":
        token = f"APPLY {plan.migration}"
        try:
            reply = ask(f"Type {token} to create/reuse only these migration stacks and accept invitations: ")
        except EOFError:
            reply = ""
        if reply != token:
            report.emit("status=CANCELLED Confirmation did not match; no AWS writes requested")
            note("CANCELLED", writes="none")
            return 2
        # Recheck every template before opening the gate, so a newly visible
        # blocker in any Region prevents writes to every Region.
        for row in scoped_fanout(group_scopes,
                                 lambda owner, region: stacks.prepare(
                                     owner, region, grouped[owner, region], fresh=True),
                                 opts, Progress(report, "prepare-recheck", group_scopes)):
            if row.error:
                plan.blocked.append(f"{row.account}/{row.region}: post-confirmation preflight {row.error}")
            elif digest(row.value[0]) != digest(prepared[row.account, row.region][0]):
                plan.blocked.append(f"{row.account}/{row.region}: plan changed; run plan/apply again")
        # An approved permission change this apply writes is re-read on both sides
        # immediately before the gate opens; any drift requires a renewed approval. A
        # change a migration stack already records is history: its share already
        # attaches the approved version, its approval was checked against this record
        # above, and the original share may since have moved on or been deleted.
        history = recorded_changes(deployed)
        for group in plan.groups:
            for change in getattr(group, "permission_changes", []):
                try:
                    if history.get((group.owner, group.region, group.logical_id,
                                    *change_key(change))) == change:
                        report.emit(f"owner={group.owner} region={group.region} share={change['share']} "
                                    f"phase=permission-revalidation status=ALREADY_APPLIED "
                                    f"approval={change['approval_id']} migration stack share "
                                    f"{group.logical_id} already attaches version "
                                    f"{change['to_version']}; recorded changes are not revalidated")
                        continue
                    approval = backing_approval(approvals, plan.migration, change)
                    if approval is None:
                        raise MigrationError(f"approval {change['approval_id']} no longer covers "
                                             f"{change['share']}")
                    target = None
                    if group.key in persisted:
                        target = (kept.get(group.key) or {}).get(change["resource_type"])
                        if target is None:
                            raise MigrationError(f"{change['share']}: existing temporary share "
                                                 f"{group.logical_id} records no "
                                                 f"{change['resource_type']} permission snapshot")
                    revalidate_change(gate.client(group.owner, "ram", group.region), change,
                                      existing=target)
                    report.emit(f"owner={group.owner} region={group.region} share={change['share']} "
                                f"phase=permission-revalidation status=VERIFIED "
                                f"approval={approval['approval_id']}")
                except Exception as exc:
                    plan.blocked.append(f"{group.owner}/{group.region}: post-confirmation "
                                        f"permission revalidation {failure_text(exc)}")
        # The original baseline is observed again immediately before the first write.
        captured = None
        if not plan.blocked:
            at_gate = observe(gate, plan.groups, temporary_share_arns(record, {}), opts, report,
                              "baseline")
            problems, comparison = baseline_check(record, at_gate, plan.groups)
            if record.get("baseline") is None and not problems:
                moved = verifier().compare(value(preflight, "items"), at_gate)
                problems += [f"phase=baseline status=BLOCKED original state changed during "
                             f"confirmation ({loss['reason']}): {loss['key']}"
                             for loss in losses(moved)]
                if not problems:
                    captured = new_baseline(at_gate, organizations, record["revision"] + 1)
            plan.blocked.extend(problems)
            pending_drops = drops_from(comparison, at_gate, organizations, "apply",
                                       record["baseline"]["captured_at"] if record.get("baseline")
                                       else "", f"record revision {record['revision']}")
        if plan.blocked:
            for reason in plan.blocked:
                report.emit(f"phase=preflight status=BLOCKED {reason}")
            summary(plan, report, "BLOCKED", **run)
            note("BLOCKED", lambda current: add_drops(current, pending_drops),
                 blockers=list(plan.blocked), phase="post-confirmation", drops=len(pending_drops))
            return 1

        def open_gate(current: dict) -> None:
            """Under the record lock, immediately before the first write: the record must
            still hold the reviewed plan revision this apply confirmed. A plan recorded
            meanwhile, even an identical one, is reviewed before anything is written."""
            problem = reviewed_plan_problem(current, plan, scope)
            entry = latest(current, "plan")
            if problem is None and entry["revision"] != opts.applied_plan["plan_revision"]:
                problem = (f"plan revision {entry['revision']} was recorded after the reviewed "
                           f"revision {opts.applied_plan['plan_revision']}; review it, then re-run "
                           "apply")
            if problem is None and captured is not None and current.get("baseline") is not None:
                problem = "another apply recorded the original baseline; re-run apply"
            if problem:
                raise ReviewedRecordChanged("the migration record changed while this apply waited "
                                            f"for confirmation, and nothing was written: {problem}")
            if captured is not None:
                current["baseline"] = dict(captured, captured_in_revision=current["revision"] + 1)
        gate_details: dict[str, Any] = {"phase": "write-gate", "groups": len(plan.groups),
                                        "stacks": len(grouped)}
        if captured is not None:
            gate_details.update(baseline_items=len(captured["items"]),
                                baseline_complete=captured["complete"])
        try:
            record = update_record(args.record, plan.migration, open_gate, mode="apply",
                                   status="BASELINE_CAPTURED" if captured is not None else "STARTED",
                                   **opts.applied_plan, **gate_details)
        except ReviewedRecordChanged as exc:
            plan.blocked.append(f"phase=reviewed-record {exc}")
            report.emit(f"phase=preflight status=BLOCKED {plan.blocked[-1]}")
            summary(plan, report, "BLOCKED", **run)
            note("BLOCKED", blockers=list(plan.blocked), phase="write-gate")
            return 1
        if captured is not None:
            report.emit(f"phase=baseline status=CAPTURED items={len(captured['items'])} "
                        f"complete={str(captured['complete']).lower()} revision={record['revision']}")
        report.emit(f"phase=write-gate status=OPEN plan_revision={opts.applied_plan['plan_revision']} "
                    f"revision={record['revision']}")

        def created_shares() -> Callable[[dict], Any]:
            """After an interrupt: read back, through a closed gate, what this run created."""
            gate.open = False
            reader = Stacks(WriteGate(router), plan.migration, timeout=args.timeout)

            def read(owner, region):
                return {} if reader.existing(owner, region) is None else reader.shares(owner, region)
            found: dict[tuple[str, str], dict] = {}
            for row in scoped_fanout(group_scopes, read, opts):
                if row.error:
                    report.emit(f"owner={row.account} region={row.region} phase=interrupted-readback "
                                f"status=INCOMPLETE {row.error}")
                else:
                    found[row.account, row.region] = row.value
            return lambda current: current.update(shares=share_records(
                current.get("shares", []), plan.groups, found, plan.migration, verified=False,
                conflicts=[]))
        opts.interrupt_readback = created_shares
        gate.open = True
        writer = threading.Lock()
        known = {"shares": list(record.get("shares", []))}

        def record_stack(owner: str, region: str, name: str) -> None:
            """Each owner/Region stack's shares are recorded as soon as it completes, so an
            interrupted or killed run leaves at most its running stacks unrecorded."""
            here = grouped[owner, region]
            try:
                found = {(owner, region): stacks.shares(owner, region)}
            except Exception as exc:
                report.emit(f"owner={owner} region={region} phase=record status=INCOMPLETE stack "
                            f"shares were not read back ({failure_text(exc)}); the final "
                            "readback records them")
                return
            conflicts: list[str] = []
            updated = None
            with writer:
                # An unchanged stack whose shares are all recorded adds nothing.
                if share_records(known["shares"], here, found, plan.migration, verified=False,
                                 conflicts=conflicts) != known["shares"]:
                    try:
                        updated = update_record(
                            args.record, plan.migration,
                            lambda current: current.update(shares=share_records(
                                current.get("shares", []), here, found, plan.migration,
                                verified=False, conflicts=[])),
                            mode="apply", status="STACK_COMPLETE", **opts.applied_plan,
                            owner=owner, region=region, stack=name)
                    except Exception as exc:
                        report.emit(f"owner={owner} region={region} phase=record "
                                    f"status=NOT_RECORDED {failure_text(exc)}; the final record "
                                    "update retries")
                        return
                    known["shares"] = updated.get("shares", [])
            for problem in conflicts:
                report.emit(f"owner={owner} region={region} phase=record status=CONFLICT {problem}")
            if updated is not None:
                report.emit(f"owner={owner} region={region} phase=record status=STACK_COMPLETE "
                            f"revision={updated['revision']} "
                            f"stack_shares={len(found[owner, region])}")

        def create(owner: str, region: str) -> str:
            name = stacks.apply(owner, region, grouped[owner, region])
            record_stack(owner, region, name)
            return name
        for row in scoped_fanout(group_scopes, create, opts):
            if row.error:
                failures.append(f"owner={row.account} region={row.region} phase=creation {row.error}")
            else:
                report.emit(f"owner={row.account} region={row.region} phase=creation "
                            f"status=COMPLETE stack={row.value}")

    shares: dict[tuple[str, str], dict] = {}
    for row in scoped_fanout(group_scopes, stacks.shares, opts):
        if row.error:
            failures.append(f"owner={row.account} region={row.region} phase=share-readback {row.error}")
        else:
            shares[row.account, row.region] = row.value
    for group in plan.groups:
        share = shares.get((group.owner, group.region), {}).get(group.logical_id)
        if share is None:
            failures.append(f"{group.owner}/{group.region}/{group.key}: planned share missing from migration stack")
        elif group.key in persisted or args.mode == "verify":
            reused += 1
        else:
            created += 1
    if args.mode == "apply":
        # A stack share that differs from the recorded one is reported, never recorded
        # over it; the other shares are still recorded.
        conflicts: list[str] = []
        share_records(record.get("shares", []), plan.groups, shares, plan.migration,
                      conflicts=conflicts)
        failures += [f"phase=record {problem}" for problem in conflicts]

    if args.mode == "apply":
        allowed: dict[tuple[str, str], dict[str, str]] = defaultdict(dict)
        for group in plan.groups:
            share = shares.get((group.owner, group.region), {}).get(group.logical_id)
            if share:
                for consumer in group.consumers:
                    allowed[consumer, group.region][share["resourceShareArn"]] = group.owner
        consumer_scopes: dict[str, list[str]] = defaultdict(list)
        for consumer, region in allowed:
            consumer_scopes[consumer].append(region)
        acceptance_progress: dict[tuple[str, str], tuple[int, int]] = {}
        for row in scoped_fanout(consumer_scopes,
                                 lambda consumer, region: accept_consumer(
                                     gate, consumer, region, allowed[consumer, region], opts, report,
                                     acceptance_progress), opts):
            if row.error:
                failures.append(f"consumer={row.account} region={row.region} phase=acceptance {row.error}")
        accepted_count = sum(counts[0] for counts in acceptance_progress.values())
        reused_invitations = sum(counts[1] for counts in acceptance_progress.values())
    # Verification receives its own closed gate even after apply.
    readonly = WriteGate(router)
    verification_stacks = Stacks(readonly, plan.migration, timeout=args.timeout)
    def verify(owner, region):
        errors = []
        for group in grouped[owner, region]:
            share = shares.get((owner, region), {}).get(group.logical_id)
            if share is None:
                continue  # Missing shares already contribute a failure above.
            try:
                def check_current_share():
                    current = verification_stacks.shares(owner, region).get(group.logical_id)
                    if current is None:
                        raise MigrationError(f"{group.key}: migration share MISSING during verification")
                    verify_group(readonly, group, current, plan.migration)
                poll(check_current_share, opts, verification=True)
                for consumer in group.consumers:
                    report.emit(f"owner={owner} region={region} share={share['resourceShareArn']} "
                                f"consumer={consumer} phase=verification status=VERIFIED "
                                f"resources={len(group.resources)}")
            except Exception as exc:
                errors.append(f"owner={owner} region={region} share={share['resourceShareArn']} "
                              f"consumers={','.join(group.consumers)} phase=verification {failure_text(exc)}")
        return errors
    for row in scoped_fanout(group_scopes, verify, opts):
        if row.error:
            failures.append(f"{row.account}/{row.region}: verification {row.error}")
        else:
            failures.extend(row.value)
    sharing_status = "SHARING_INCOMPLETE" if failures else "SHARING_READY"

    # Every current observation is compared with the one recorded original baseline.
    phase = "post-apply" if args.mode == "apply" else "verification"
    final = observe(readonly, plan.groups, temporary_share_arns(record, shares), opts, report, phase)
    organizations_now, errors = consumer_organizations(readonly, consumers_in_scope, opts)
    baseline = record.get("baseline")
    comparison = verifier().compare(scoped_items(baseline["items"], plan.groups), final) \
        if baseline else None
    new_drops = drops_from(comparison, final, organizations_now, args.mode,
                           baseline["captured_at"] if baseline else "",
                           f"record revision {record['revision']}")
    projected = dict(record, drops=list(record.get("drops", [])) + new_drops)
    status_now, reasons = migration_status(projected, comparison, organizations_now, plan.groups)
    reasons += errors
    if errors and status_now in ("MIGRATION_VALIDATED", "PENDING_MIGRATION"):
        status_now = "INCONCLUSIVE"
    unassociated = unassociated_rules(plan.groups, final, baseline)
    for consumer, region, arn in unassociated:
        report.emit(f"consumer={consumer} region={region} resource={arn} phase={phase} "
                    "status=NOT_ASSOCIATED this rule had no association before migration; "
                    "sharing does not create one")
    for loss in (losses(comparison) if comparison is not None else []):
        report.emit(f"phase={phase} status=BASELINE_{loss['reason'].split(':')[0].upper()} "
                    f"key={loss['key']} {loss['reason']}")
    for reason in reasons:
        report.emit(f"phase={phase} migration_status={status_now} {reason}")
    for reason in failures:
        report.emit(f"status=INCOMPLETE {reason}")
    if args.mode == "apply":
        if comparison is not None and value(comparison, "status") != "INTACT":
            failures += [f"baseline {loss['reason']}: {loss['key']}" for loss in losses(comparison)] \
                or [f"post-apply observation is incomplete: {len(value(comparison, 'gaps'))} gaps"]
        if failures:
            report.emit("Successful temporary shares are retained. Resume this migration ID after resolving failures.")
        status = "INCOMPLETE" if failures else "SHARING_READY"
        code = 1 if failures else 0
    else:
        status = status_now if sharing_status == "SHARING_READY" else sharing_status
        code = 0 if status in ("MIGRATION_VALIDATED", "PENDING_MIGRATION") else \
            3 if status == "INCONCLUSIVE" else 1
    summary(plan, report, status, **run, created=created, reused=reused,
            accepted=accepted_count, reused_invitations=reused_invitations, failures=len(failures),
            comparison=comparison, unassociated=len(unassociated),
            sharing=sharing_status, migration=status_now)
    entry = {"at": value(final, "observed_at"), "mode": args.mode, "sharing_status": sharing_status,
             "migration_status": status_now, "reasons": reasons,
             "baseline_status": value(comparison, "status") if comparison is not None else None,
             "missing": len(value(comparison, "missing")) if comparison is not None else None,
             "degraded": len(value(comparison, "degraded")) if comparison is not None else None,
             "gaps": len(value(final, "gaps")), "consumer_organizations": organizations_now,
             **opts.applied_plan}

    def record_outcome(current: dict) -> None:
        if args.mode == "apply":
            current["shares"] = share_records(current.get("shares", []), plan.groups, shares,
                                              plan.migration, conflicts=[])
            # A plan recorded while this apply ran is kept, and was not applied.
            newer = latest(current, "plan")
            if newer is not None and newer["revision"] != opts.applied_plan["plan_revision"]:
                entry["plan_superseded_by"] = newer["revision"]
        add_drops(current, new_drops)
        current.setdefault("verifications", []).append(entry)
    note(status, record_outcome, failures=failures, created=created, reused=reused,
         accepted=accepted_count, migration_status=status_now, drops=len(new_drops))
    opts.interrupt_readback = None  # the outcome, with every share read back, is recorded
    if entry.get("plan_superseded_by"):
        report.emit(f"phase=record status=PLAN_SUPERSEDED plan revision {entry['plan_superseded_by']} "
                    f"was recorded while this apply ran; this apply applied reviewed revision "
                    f"{opts.applied_plan['plan_revision']} only. Review the newer plan before the "
                    "next apply")
    return code


def settle(router: Any, groups: list, baseline: dict, temporary: frozenset[str],
           organizations: dict, opts: Options, report: Reporter,
           phase: str) -> tuple[list[str], list[dict]]:
    """Keep re-verifying for the settle window; the first loss or gap stops completion."""
    deadline = time.monotonic() + opts.args.settle_seconds
    while True:
        observation = observe(router, groups, temporary, opts, report, phase)
        comparison = verifier().compare(scoped_items(baseline["items"], groups), observation)
        replacement = verifier().replacement_access(router, groups, temporary,
                                                    workers=opts.args.region_workers)
        problems = [f"original {loss['reason']}: {loss['key']}" for loss in losses(comparison)]
        if value(comparison, "status") == "INCONCLUSIVE":
            problems += [f"observation gap {gap.get('collector')} {gap.get('account')} "
                         f"{gap.get('region')} {gap.get('reason')}" for gap in value(comparison, "gaps")] \
                or ["observation is incomplete"]
        problems += [f"replacement access missing for {row.get('consumer')} {row.get('region')} "
                     f"{row.get('resource_arn')}" for row in replacement["uncovered"]]
        problems += [f"replacement gap {gap.get('account')} {gap.get('region')} {gap.get('reason')}"
                     for gap in replacement["gaps"]]
        if problems:
            return problems, drops_from(comparison, observation, organizations, "complete",
                                        baseline["captured_at"], phase)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return [], []
        time.sleep(min(30.0, remaining))


def run_complete(router: Router, opts: Options, ask: Callable[[str], str], report: Reporter) -> int:
    """Retire the temporary path only after proving nothing original is missing or dropped."""
    args = opts.args
    record = load_record(args.record, args.migration_id)
    migration = record["migration_id"]
    if record.get("completion"):
        report.emit(f"migration={migration} phase=complete status=ALREADY_COMPLETE "
                    f"at={record['completion'].get('completed_at')}")
        return 0
    fill_scope_from_record(opts, record)

    def note(status: str, mutate: Callable[[dict], Any] = lambda _record: None,
             **details: Any) -> None:
        nonlocal record
        record = update_record(args.record, migration, mutate, mode="complete", status=status,
                               **details)

    excluded = exclusion_text(exclusion_scope(opts))

    def refuse(problems: list[str], drops: list[dict] | None = None) -> int:
        for problem in problems:
            report.emit(f"phase=complete status=BLOCKED {problem}")
        report.emit(f"status=BLOCKED migration={migration} phase=complete blockers={len(problems)} "
                    f"temporary shares retained{excluded}")
        note("BLOCKED", lambda current: add_drops(current, drops or []), blockers=problems)
        return 1

    blocked = authenticate(router, set(opts.owners + opts.consumers), opts, report)
    if blocked:
        return refuse(blocked)
    entries = [entry for entry in record.get("shares", []) if entry.get("share_arn")]
    if not entries:
        return refuse(["the migration record has no temporary shares to retire"])
    gate = WriteGate(router)
    stacks = Stacks(gate, migration, timeout=args.timeout)
    scopes: dict[str, list[str]] = defaultdict(list)
    for entry in entries:
        if entry["region"] not in scopes[entry["owner"]]:
            scopes[entry["owner"]].append(entry["region"])
    groups: list[Group] = []
    shares: dict[tuple[str, str], dict] = {}
    problems: list[str] = []
    for row in scoped_fanout(scopes, lambda owner, region: (stacks.persisted_groups(owner, region),
                                                            stacks.shares(owner, region)), opts):
        if row.error:
            problems.append(f"owner={row.account} region={row.region} phase=stored-plan {row.error}")
        else:
            groups.extend(row.value[0])
            shares[row.account, row.region] = row.value[1]
    recorded = {(e["owner"], e["region"], e["logical_id"]): e for e in entries}
    stored = {(g.owner, g.region, g.logical_id): g for g in groups}
    problems += [f"recorded temporary share {'/'.join(key)} is missing from its migration stack"
                 for key in sorted(set(recorded) - set(stored))]
    problems += [f"stack entitlement {'/'.join(key)} is not in the migration record"
                 for key in sorted(set(stored) - set(recorded))]
    for key, entry in sorted(recorded.items()):
        live = shares.get(key[:2], {}).get(key[2])
        if live and live["resourceShareArn"] != entry["share_arn"]:
            problems.append(f"{'/'.join(key)}: stack share {live['resourceShareArn']} differs from "
                            f"recorded {entry['share_arn']}")
    if problems:
        return refuse(problems)

    temporary = temporary_share_arns(record, shares)
    consumers = sorted({consumer for group in groups for consumer in group.consumers})
    organizations, errors = consumer_organizations(gate, consumers, opts)
    problems += errors
    baseline = record.get("baseline")
    observation = observe(gate, groups, temporary, opts, report, "complete-preflight")
    comparison = None
    if baseline is None or not baseline.get("complete"):
        problems.append("a complete original baseline is required before the temporary path is retired")
    else:
        before = baseline.get("consumer_organizations", {})
        problems += [f"consumer {consumer} is not covered by the original baseline; its original "
                     "state was never recorded, so its temporary shares cannot be retired safely"
                     for consumer in consumers if consumer not in before]
        problems += [f"entitlement owner={owner} region={region} consumer={consumer} resource={arn} "
                     "is not covered by the original baseline; its original state was never "
                     "recorded, so its temporary share cannot be retired safely"
                     for owner, region, consumer, arn in uncovered_entitlements(baseline, groups)
                     if consumer in before]
        comparison = verifier().compare(scoped_items(baseline["items"], groups), observation)
        if value(comparison, "status") != "INTACT":
            problems += [f"original {loss['reason']}: {loss['key']}" for loss in losses(comparison)] or [
                f"observation gap {gap.get('collector')} {gap.get('account')} {gap.get('region')} "
                f"{gap.get('reason')}" for gap in value(comparison, "gaps")]
    problems += [f"failure drop recorded: {drop['kind']} {drop['subject']} first absent "
                 f"{drop['first_absent_at']}" for drop in failure_drops(record)]
    replacement = verifier().replacement_access(gate, groups, temporary, workers=args.region_workers)
    for row in replacement["covered"]:
        report.emit(f"phase=replacement status=COVERED consumer={row.get('consumer')} "
                    f"region={row.get('region')} resource={row.get('resource_arn')}")
    problems += [f"phase=replacement consumer={row.get('consumer')} region={row.get('region')} "
                 f"resource={row.get('resource_arn')}: only the temporary share provides access; "
                 "establish permanent replacement sharing first" for row in replacement["uncovered"]]
    problems += [f"phase=replacement gap {gap.get('account')} {gap.get('region')} {gap.get('reason')}"
                 for gap in replacement["gaps"]]
    if problems:
        return refuse(problems, drops_from(comparison, observation, organizations, "complete",
                                           baseline["captured_at"] if baseline else "",
                                           f"record revision {record['revision']}"))

    # Smallest share first: the first deletion is the canary step.
    order = sorted(entries, key=lambda e: (len(stored[e["owner"], e["region"], e["logical_id"]].resources),
                                           e["owner"], e["region"], e["logical_id"]))
    for entry in order:
        group = stored[entry["owner"], entry["region"], entry["logical_id"]]
        report.emit(f"owner={entry['owner']} region={entry['region']} phase=complete action=DELETE_SHARE "
                    f"share={entry['share_arn']} consumers={','.join(group.consumers)} "
                    f"resources={len(group.resources)}")
    owner_regions = sorted({(entry["owner"], entry["region"]) for entry in entries})
    for owner, region in owner_regions:
        report.emit(f"owner={owner} region={region} phase=complete action=DELETE_STACK "
                    f"stack={stack_name(migration, owner, region)}")
    token = f"COMPLETE {migration}"
    try:
        reply = ask(f"Type {token} to delete these temporary shares and stacks, re-verifying after each: ")
    except EOFError:
        reply = ""
    if reply != token:
        report.emit("status=CANCELLED Confirmation did not match; no AWS writes requested")
        return 2
    gate.open = True
    deleted: list[str] = []
    for entry in order:
        group = stored[entry["owner"], entry["region"], entry["logical_id"]]
        try:
            delete_share(gate, entry["owner"], entry["region"], entry["share_arn"], migration,
                         timeout=args.timeout)
        except Exception as exc:
            report.emit(f"status=FAILED share={entry['share_arn']} phase=complete {failure_text(exc)}")
            note("FAILED", failures=[failure_text(exc)], deleted=list(deleted))
            return 1
        deleted.append(entry["share_arn"])
        report.emit(f"owner={entry['owner']} region={entry['region']} share={entry['share_arn']} "
                    "phase=complete status=SHARE_DELETED")
        note("SHARE_DELETED", deleted=list(deleted), share=entry["share_arn"])
        losses_now, drops = settle(gate, [group], baseline, temporary, organizations, opts, report,
                                   f"complete-settle-{len(deleted)}")
        if losses_now:
            for problem in losses_now:
                report.emit(f"status=FAILED phase=complete {problem}")
            report.emit("Completion stopped; the remaining temporary shares are retained.")
            note("FAILED", lambda current: add_drops(current, drops), failures=losses_now,
                 deleted=list(deleted))
            return 1
    losses_now, drops = settle(gate, groups, baseline, temporary, organizations, opts, report,
                               "complete-final")
    if losses_now:
        for problem in losses_now:
            report.emit(f"status=FAILED phase=complete {problem}")
        note("FAILED", lambda current: add_drops(current, drops), failures=losses_now,
             deleted=list(deleted))
        return 1
    removed = []
    for owner, region in owner_regions:
        try:
            removed.append(stacks.delete(owner, region))
        except Exception as exc:
            report.emit(f"status=FAILED owner={owner} region={region} phase=complete {failure_text(exc)}")
            note("FAILED", failures=[failure_text(exc)], deleted=list(deleted), stacks=list(removed))
            return 1
        report.emit(f"owner={owner} region={region} phase=complete status=STACK_DELETED")
    completion = {"completed_at": timestamp(), "deleted_shares": deleted, "deleted_stacks": removed,
                  "consumer_organizations": organizations}
    note("COMPLETED", lambda current: current.__setitem__("completion", completion),
         deleted=len(deleted), stacks=len(removed))
    report.emit(f"status=COMPLETED migration={migration} deleted_shares={len(deleted)} "
                f"deleted_stacks={len(removed)} original baseline intact{excluded}")
    return 0


INTERRUPTED_NEXT = {
    "apply": "existing temporary shares are retained; re-run apply with this record to resume",
    "verify": "verify made no AWS changes; re-run verify with this record",
}


def record_interruption(args: argparse.Namespace | None, report: Reporter,
                        opts: Options | None = None, *, status: str = "INTERRUPTED",
                        failure: str | None = None) -> None:
    """An interrupted apply or verify is history in its record, when one exists. So is an
    apply that failed after its write gate opened (status INCOMPLETE). Such an apply also
    records the temporary shares it created, which verify and complete take their scope
    from; each stack's shares were already recorded when that stack completed."""
    if args is None or args.mode not in ("apply", "verify") or not args.record or \
            not args.migration_id or not Path(args.record).exists():
        return
    mutate: Callable[[dict], Any] = lambda _current: None
    readback = opts.interrupt_readback if opts is not None and args.mode == "apply" else None
    if readback is not None:
        report.emit(f"phase=record status={'INTERRUPTING' if failure is None else 'FAILING'} "
                    "reading back the temporary shares this run created")
        try:
            mutate = readback()
        except KeyboardInterrupt:
            report.emit("phase=record status=INCOMPLETE share readback interrupted; resume apply "
                        "with this record to record the shares it created")
        except Exception as exc:
            report.emit(f"phase=record status=INCOMPLETE share readback {failure_text(exc)}")
    details: dict[str, Any] = {**(opts.applied_plan if opts is not None else {}),
                               "retained": INTERRUPTED_NEXT[args.mode]}
    if failure is not None:
        details["failures"] = [failure]
    try:
        record = update_record(args.record, args.migration_id, mutate, mode=args.mode,
                               status=status, **details)
        report.emit(f"phase=record status={status} record={args.record} "
                    f"revision={record['revision']} recorded_shares={len(record.get('shares', []))} "
                    f"next_action={INTERRUPTED_NEXT[args.mode]}")
    except Exception as exc:
        report.emit(f"phase=record status=NOT_RECORDED {failure_text(exc)}")


def record_failure(args: argparse.Namespace, report: Reporter, opts: Options, failure: str) -> int:
    """An apply that fails after its write gate opened made AWS changes: its outcome and
    the shares it created are recorded, best effort, before the run ends."""
    report.emit(f"status=INCOMPLETE {failure}; successful temporary shares are retained")
    record_interruption(args, report, opts, status="INCOMPLETE", failure=failure)
    return 1


def main(argv: list[str] | None = None, *, input_fn: Callable[[str], str] | None = None) -> int:
    report = Reporter()
    args = opts = None
    try:
        args = build_parser().parse_args(argv)
        ask = input_fn if input_fn is not None else input
        opts = options(args, ask)
        if args.mode == "approve":
            return run_approve(opts, ask, report)
        if args.mode != "monitor":
            check_sdk()  # Offline service-model preflight, before authenticating.
        router = Router(opts.profiles, opts.mappings, role_name=args.role_name,
                        sso_role=args.sso_role or "")
        if args.mode == "complete":
            return run_complete(router, opts, ask, report)
        if args.mode == "monitor":
            try:
                module = importlib.import_module("ram_migration_monitor")
            except ImportError as exc:
                raise MigrationError("monitor requires the ram_migration_monitor module") from exc
            # The monitor owns read-only probe/evidence validation; its config
            # passes through intact.
            result = module.monitor(router, opts.monitor_config)
            code = result if type(result) is int else (1 if result is False else 0)
            report.emit(f"phase=monitor status={'FINISHED' if code == 0 else 'INCOMPLETE'} exit_code={code}")
            return code
        return run_shares(router, opts, ask, report)
    except KeyboardInterrupt:
        report.emit("status=INCOMPLETE Interrupted; existing temporary shares are retained")
        record_interruption(args, report, opts)
        return 130
    except (MigrationError, OSError, ValueError, EOFError, BotoCoreError, ClientError) as exc:
        if opts is not None and opts.interrupt_readback is not None:  # apply wrote to AWS
            return record_failure(args, report, opts, failure_text(exc))
        report.emit(f"status=BLOCKED {failure_text(exc)}")
        return 1
    except Exception as exc:
        if opts is not None and opts.interrupt_readback is not None:
            record_failure(args, report, opts, f"{type(exc).__name__}: {exc}")
        raise


if __name__ == "__main__":
    raise SystemExit(main())
