#!/usr/bin/env python3
"""RAMShift: keep migrating accounts' access to shared AWS resources while they move
between AWS Organizations (Python 3.11+).

plan (read-only) discovers what the migrating accounts receive through organization or
OU shares and writes a reviewed migration record. approve approves a proposed owner scope.
apply creates temporary account-targeted RAM shares that survive leaving an organization,
accepts their invitations and captures the pre-migration baseline. verify (read-only)
checks the temporary shares and the baseline. monitor (read-only, on demand) reports what
changed since the baseline. complete retires the temporary access of chosen accounts once
permanent sharing exists and nothing original is lost. RAMShift never moves accounts and
never changes original shares, IAM roles, trusts or policies.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import random
import re
import sys
import threading
import time
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any, Callable, Iterable

from botocore.exceptions import (
    BotoCoreError, ClientError, ConnectionClosedError, ConnectTimeoutError,
    EndpointConnectionError, ReadTimeoutError,
)

from ram_migration_common import (
    PRODUCT, TOOL_VERSION, Api, Group, MigrationError, Plan, Router, account_id, check_sdk, digest,
    error_text, pages, timestamp,
)
from ram_migration_discovery import (
    Discovery, LookupCache, describe_difference, external_catalog, failure_text, grants_less,
)
from ram_migration_record import (
    APPLICABLE, accepted_blockers, add_drops, approve_owner_scope, approved_owners, drop_id,
    failure_drops, latest, record_acceptances,
    new_record, owner_scope_request, plan_digest, retired_consumers, tool_identity,
)
from ram_migration_preflight import (
    destination_target, organization_preflight, policy_changes, recorded_destination,
)
from ram_migration_record import load as load_record
from ram_migration_record import retired_consumers, retired_pairs
from ram_migration_record import update as update_record
from ram_migration_stacks import (
    Readback, Stacks, accept, delete_share, remove_principals, stack_name, unserved_consumers,
    verify_group,
)

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
        prog="ramshift",
        epilog="Documentation: README.md and docs/USER_GUIDE.md shipped with RAMShift.",
    )
    parser.add_argument("--version", action="version",
                        version=f"{PRODUCT} {TOOL_VERSION}")
    parser.add_argument("mode", nargs="?",
                        choices=("plan", "approve", "apply", "verify", "complete", "monitor"),
                        default="plan")
    parser.add_argument("--migration-id", help="stable identifier for this migration")
    parser.add_argument("--record", type=Path,
                        help="versioned migration record: written by every mode except a "
                             "plan without it; required by approve, apply, verify, monitor and "
                             "complete")
    parser.add_argument("--owners", "--accounts", dest="owners", nargs="+", action="append",
                        default=[], help="explicit owner/inspection account IDs; spaces or commas")
    parser.add_argument("--consumers", nargs="+", action="append", default=[],
                        help="plan/apply: explicit migrating consumer account IDs; monitor/"
                             "complete: the tracked accounts of the record to act on; spaces "
                             "or commas")
    parser.add_argument("--exclude-consumers", nargs="+", action="append", default=[],
                        help="account IDs explicitly excluded from recipient discovery, "
                             "verification and invitation handling, including stationary "
                             "recipients; requires --exclude-consumers-reason")
    parser.add_argument("--exclude-consumers-reason",
                        help="mandatory reason for --exclude-consumers; recorded with the "
                             "reviewed scope and inherited by verify/monitor/complete")
    parser.add_argument("--accept-blockers", nargs="+", action="append", default=[],
                        metavar="BLOCKER",
                        help="approve: accept these blockers of the recorded plan so plan and "
                             "apply proceed without them: blocker IDs (blocker=b-... in plan "
                             "output), blocker categories, or all. Requires --accept-reason; each "
                             "acceptance is recorded with its consequence and binds to the "
                             "blocker's exact text")
    parser.add_argument("--accept-reason",
                        help="approve: mandatory one-line reason recorded with --accept-blockers")
    parser.add_argument("--all-accounts", action="store_true",
                        help="monitor/complete: act on every tracked account in the migration "
                             "record instead of the accounts named with --consumers")
    parser.add_argument("--force", action="store_true",
                        help="complete: retire the temporary access even when its safety checks "
                             "(baseline coverage, intact original state, recorded failure drops, "
                             "replacement access) fail. Each overridden check is reported and "
                             "recorded, the confirmation is FORCE-COMPLETE <migration-id>, and "
                             "identity and ownership checks are never overridden")
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
    parser.add_argument("--exclude-tgw-routes", action="store_true",
                        help="exclude TGW-targeted VPC route collection and verification only; "
                             "RAM visibility and attachment checks still run. Requires "
                             "--exclude-tgw-routes-reason and a fresh reviewed plan")
    parser.add_argument("--exclude-tgw-routes-reason",
                        help="mandatory reason for --exclude-tgw-routes; bound to the reviewed "
                             "plan and captured baseline, and inherited by verify/monitor/complete")
    parser.add_argument("--destination-ou",
                        help="plan/apply: destination OU (or root) ARN, "
                             "arn:aws:organizations::<management-account>:ou/<o-id>/<ou-id>; the "
                             "SCPs and RCPs on its path are evaluated for the reads verify and "
                             "monitor need after the move. Its management account must be "
                             "reachable through the account map or a base profile")
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
    parser.add_argument("--raw-output", action="store_true",
                        help="print the full technical event stream, one key=value line per "
                             "event, instead of the readable view")
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
    # monitor/complete: the migrating accounts named with --consumers; None with
    # --all-accounts. selected_consumers() checks them against the record.
    selected: list[str] | None = None
    # Explicit route verification exclusion; immutable after baseline capture.
    tgw_route_exclusion_reason: str | None = None
    # Derived from original-share evidence, never added to the migrating population.
    stationary_consumers: list[str] = field(default_factory=list)
    # Explicit recipient exclusions; cannot change after baseline capture.
    excluded_consumers: list[str] = field(default_factory=list)
    consumer_exclusion_reason: str | None = None


MIGRATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")
# Modes that act on migrating accounts chosen with --consumers or --all-accounts.
SELECTING_MODES = ("monitor", "complete")
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


def _consumer_exclusion_reason(text: Any) -> str:
    if not isinstance(text, str) or not text.strip():
        raise MigrationError("--exclude-consumers requires --exclude-consumers-reason: "
                             "a nonempty reason recorded with the recipient scope")
    if len(text) > MAX_REASON or any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise MigrationError("--exclude-consumers-reason must be one line of at most "
                             f"{MAX_REASON} characters without control characters")
    return text.strip()


def excluded_consumer_options(args: argparse.Namespace) -> tuple[list[str], str | None]:
    accounts = [checked_account(account)
                for account in split_values(getattr(args, "exclude_consumers", []))]
    reason = getattr(args, "exclude_consumers_reason", None)
    if not accounts and reason is None:
        return [], None
    if args.mode == "approve":
        raise MigrationError("--exclude-consumers is not supported by approve")
    if not accounts:
        raise MigrationError("--exclude-consumers-reason requires --exclude-consumers")
    return accounts, _consumer_exclusion_reason(reason)


def consumer_exclusion_scope(opts: Options) -> dict | None:
    if not opts.excluded_consumers:
        return None
    return {"accounts": sorted(set(opts.excluded_consumers)),
            "reason": _consumer_exclusion_reason(opts.consumer_exclusion_reason)}


def recorded_consumer_exclusions(scope: dict) -> dict | None:
    excluded = scope.get("excluded_consumers")
    if excluded is None:
        return None
    if not isinstance(excluded, dict) or set(excluded) != {"accounts", "reason"} or \
            not isinstance(excluded["accounts"], list) or not excluded["accounts"]:
        raise MigrationError("Invalid recorded recipient exclusions")
    accounts = sorted({checked_account(account) for account in excluded["accounts"]})
    reason = _consumer_exclusion_reason(excluded["reason"])
    if accounts != excluded["accounts"] or reason != excluded["reason"]:
        raise MigrationError("Recorded recipient exclusions are not canonical")
    return {"accounts": accounts, "reason": reason}


def consumer_scope_problem(record: dict, excluded: dict | None) -> str | None:
    baseline = record.get("baseline")
    if baseline is None:
        return None
    if recorded_consumer_exclusions(baseline) != excluded:
        return ("phase=baseline-scope status=BLOCKED recipient exclusions differ from the "
                "captured baseline; retire existing access and create a fresh plan")
    accounts = set((excluded or {}).get("accounts", []))
    tracked = set(baseline.get("consumer_organizations", {})) | {
        item.get("consumer") for item in baseline.get("items", [])}
    if accounts & tracked:
        return ("phase=baseline-scope status=BLOCKED excluded recipients remain in the "
                "captured baseline; an exclusion cannot hide recorded access")
    return None


def excluded_group_problems(groups: list[Group], excluded: set[str]) -> list[str]:
    return [
        f"owner={group.owner} region={group.region} phase=stored-plan status=BLOCKED "
        f"excluded_consumers={','.join(sorted(set(group.consumers) & excluded))} "
        f"remain in temporary share {group.logical_id}; retire that access before resetting "
        "the recipient scope"
        for group in groups if set(group.consumers) & excluded]


def report_consumer_exclusions(opts: Options, report: "Reporter") -> None:
    excluded = consumer_exclusion_scope(opts)
    if excluded:
        report.emit("phase=recipient-scope status=EXCLUDED "
                    f"accounts={','.join(excluded['accounts'])} "
                    f"reason={json.dumps(excluded['reason'])}")


def _route_exclusion_reason(text: Any) -> str:
    if not isinstance(text, str) or not text.strip():
        raise MigrationError("--exclude-tgw-routes requires --exclude-tgw-routes-reason: "
                             "a nonempty reason recorded with the verification scope")
    if len(text) > MAX_REASON or any(ord(char) < 32 or ord(char) == 127 for char in text):
        raise MigrationError("--exclude-tgw-routes-reason must be one line of at most "
                             f"{MAX_REASON} characters without control characters")
    return text.strip()


def excluded_tgw_route_reason(args: argparse.Namespace) -> str | None:
    enabled = getattr(args, "exclude_tgw_routes", False)
    reason = getattr(args, "exclude_tgw_routes_reason", None)
    if not enabled and reason is None:
        return None
    if args.mode == "approve":
        raise MigrationError("--exclude-tgw-routes is not supported by approve")
    if not enabled:
        raise MigrationError("--exclude-tgw-routes-reason requires --exclude-tgw-routes")
    return _route_exclusion_reason(reason)


def verification_exclusions(opts: Options) -> dict | None:
    if opts.tgw_route_exclusion_reason is None:
        return None
    return {"collectors": ["tgw_routes"], "item_kinds": ["tgw_route"],
            "reason": _route_exclusion_reason(opts.tgw_route_exclusion_reason)}


def recorded_verification_exclusions(scope: dict) -> dict | None:
    excluded = scope.get("verification_exclusions")
    if excluded is None:
        return None
    if not isinstance(excluded, dict) or set(excluded) != {"collectors", "item_kinds", "reason"} or \
            excluded["collectors"] != ["tgw_routes"] or excluded["item_kinds"] != ["tgw_route"]:
        raise MigrationError("Invalid recorded verification exclusions; only explicit TGW "
                             "route exclusion is supported")
    reason = _route_exclusion_reason(excluded["reason"])
    if reason != excluded["reason"]:
        raise MigrationError("Recorded TGW route exclusion reason is not canonical")
    return {"collectors": ["tgw_routes"], "item_kinds": ["tgw_route"], "reason": reason}


def verification_scope_problem(record: dict, excluded: dict | None) -> str | None:
    baseline = record.get("baseline")
    if baseline is None:
        return None
    captured = recorded_verification_exclusions(baseline)
    if captured != excluded:
        return ("phase=baseline-scope status=BLOCKED verification exclusions differ from the "
                "captured baseline; they cannot change after capture")
    if excluded and any(item.get("kind") == "tgw_route" for item in baseline.get("items", [])):
        return ("phase=baseline-scope status=BLOCKED captured baseline contains TGW routes; "
                "a verification exclusion cannot hide recorded items")
    return None


def verification_exclusion_text(excluded: dict | None) -> str:
    if excluded is None:
        return ""
    return (" excluded_verification_collectors=tgw_routes verification_exclusion_reason="
            + json.dumps(excluded["reason"]))


def report_verification_exclusions(opts: Options, report: "Reporter") -> None:
    excluded = verification_exclusions(opts)
    if excluded:
        report.emit("phase=verification-scope status=EXCLUDED collector=tgw_routes kind=tgw_route "
                    f"reason={json.dumps(excluded['reason'])}")
        report.emit("TGW route health and network reachability are outside this verification scope.")


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
    route_reason = excluded_tgw_route_reason(args)
    omitted_consumers, consumer_reason = excluded_consumer_options(args)
    if args.destination_ou is not None:
        if args.mode not in ("plan", "apply"):
            raise MigrationError("--destination-ou is supported only for plan and apply")
        destination_target(args.destination_ou)
    if (args.accept_blockers or args.accept_reason is not None) and args.mode != "approve":
        raise MigrationError("--accept-blockers and --accept-reason are supported only for approve")
    if args.mode == "approve":
        # Approval is an offline review of the record; it needs no AWS access.
        if not args.record:
            raise MigrationError("approve requires --record")
        if args.accept_blockers:
            reason = (args.accept_reason or "").strip()
            if not reason or "\n" in reason or "\r" in reason or len(reason) > MAX_REASON:
                raise MigrationError("--accept-blockers requires --accept-reason: one nonempty line "
                                     f"of at most {MAX_REASON} characters, recorded with each "
                                     "acceptance")
            args.accept_reason = reason
        elif args.accept_reason is not None:
            raise MigrationError("--accept-reason requires --accept-blockers")
        if args.migration_id and not MIGRATION_ID.fullmatch(args.migration_id):
            raise MigrationError("Supply a valid --migration-id or omit it to use the record's")
        excluded_regions(args, [])
        return Options(args, [], [], [], [], {}, {}, None, {})
    if args.mode in ("apply", "verify", "monitor", "complete") and not args.record:
        raise MigrationError(f"{args.mode} requires --record: the reviewed migration record "
                             "written by plan")
    from_record = args.mode in ("verify", "monitor", "complete")
    interactive = args.interactive or sys.stdin.isatty()
    if interactive:
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
    overlap = sorted(set(omitted_consumers) & set(owners + consumers))
    if overlap:
        raise MigrationError(f"Accounts {','.join(overlap)} are both requested and "
                             "excluded with --exclude-consumers")
    regions = split_values(args.regions)
    if any(not REGION.fullmatch(region) for region in regions):
        raise MigrationError("Regions must be AWS Region names")
    if args.force and args.mode != "complete":
        raise MigrationError("--force is supported only for complete")
    if args.all_accounts and args.mode not in ("monitor", "complete"):
        raise MigrationError("--all-accounts is supported only for monitor and complete")
    selected = None
    if args.mode in SELECTING_MODES:
        if bool(consumers) == bool(args.all_accounts):
            raise MigrationError(f"{args.mode} acts on chosen migrating accounts: supply --consumers "
                                 "<account IDs>, or --all-accounts for every migrating account in "
                                 "the migration record")
        # The record supplies the scope; --consumers only selects within it.
        selected, consumers = (None if args.all_accounts else consumers), []
    if not args.migration_id or not MIGRATION_ID.fullmatch(args.migration_id):
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
                   excluded_regions=excluded, exclusion_reason=reason, selected=selected,
                   tgw_route_exclusion_reason=route_reason,
                   excluded_consumers=omitted_consumers,
                   consumer_exclusion_reason=consumer_reason)


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
    """Temporary shares proven per logical share: a share that cannot be proven blocks
    alone, and never hides the provenance of its siblings in the same stack."""
    proven: dict[tuple[str, str, str], Group] = {}
    blocked = []
    persisted_scopes = grouped_scopes([group for groups in persisted.values() for group in groups])[1]
    for row in scoped_fanout(persisted_scopes, stacks.readback, opts):
        if row.error:
            blocked.append(
                f"owner={row.account} region={row.region} phase=received-provenance status=BLOCKED {row.error}")
            continue
        readback, logicals = row.value, set()
        for group in persisted[row.account, row.region]:
            logicals.add(group.logical_id)
            share = readback.shares.get(group.logical_id)
            if share is None or share.get("owningAccountId") != group.owner:
                reason = (f": {readback.reason(group.logical_id)}"
                          if group.logical_id in readback.failures else "")
                blocked.append(f"{row.account}/{row.region}/{group.key}: "
                               f"stored migration share ownership could not be proven{reason}")
                continue
            proven[group.owner, group.region, share["resourceShareArn"]] = group
        blocked += [f"owner={row.account} region={row.region} logical_id={logical} "
                    f"phase=received-provenance status=BLOCKED {readback.reason(logical)}"
                    for logical in sorted(set(readback.failures) - logicals)]
    return proven, blocked


def classify_received(audit: ReceivedAudit, plan: Plan, proven: dict, owner_scopes: dict,
                      opts: Options) -> dict[str, dict]:
    """Every active received dependency of a migrating account must be covered by a
    planned temporary share, unless owner-side discovery proved that account's own
    ASSOCIATED external=true association on that original share (recovered external
    access). Owners outside the approved scope are proposed, never added silently.
    Returns the proposed-owner evidence."""
    intended_shares: dict[tuple[str, str], set[str]] = defaultdict(set)
    intended_resources: dict[tuple[str, str], set[str]] = defaultdict(set)
    covered: set[tuple[str, str, str, str]] = set()
    for group in plan.groups:
        for consumer in group.consumers:
            intended_shares[consumer, group.region].update(group.source_shares)
            intended_resources[consumer, group.region].update(group.resources)
            covered.update((consumer, group.owner, group.region, arn) for arn in group.resources)
    external = {(row["consumer"], row["owner"], row["region"], row["share"]): row
                for row in plan.external_access}
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
        association = external.get((account, owner, region, arn))
        if association is not None:
            # Proven owner-side in this run's discovery of this owner and Region.
            entry["status"] = "RECOVERED_EXTERNAL"
            entry["association"] = {"status": association["status"],
                                    "external": association["external"]}
            audit.excluded.append(
                f"{context} status=EXCLUDED recovered external access: the owner's "
                f"principal association for {account} on this original share is "
                f"{association['status']} with external=true, which does not depend on "
                "organization membership; it is pre-existing access, neither duplicated in a "
                "temporary share nor modified")
            continue
        if region not in owner_scopes.get(owner, []):
            entry["status"] = "BLOCKED"
            audit.blocked.append(f"{context} status=BLOCKED "
                                 "resource owner's Region is outside the selected discovery scope")
        for item in items:
            if item["status"] not in ("AVAILABLE", *UNUSABLE_STATUSES):  # PENDING, UNKNOWN, ...
                entry["status"] = "BLOCKED"
                audit.blocked.append(f"{context} resource={item['arn']} status=BLOCKED "
                                     f"intended received resource status {item['status']}")
            elif item["status"] in UNUSABLE_STATUSES:
                audit.excluded.append(f"{context} resource={item['arn']} status=EXCLUDED received "
                                      f"resource status {item['status']}: the account has no access "
                                      "to it now, so the migration does not change it")
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
        association = entry.get("association")
        report.emit(f"account={entry['account']} owner={entry['owner']} region={entry['region']} "
                    f"share={entry['share']} phase=received-audit status={entry['status']} "
                    f"share_status={entry['share_status']} resources={len(entry['resources'])}"
                    + (f" association_status={association['status']} external="
                       f"{str(association['external']).lower()}" if association else ""))
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
    """Retain the permission snapshots and source stacks carried by discovery's Group subtype."""
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
    plan.external_access.extend(addition.external_access)
    plan.owner_continuity.extend(addition.owner_continuity)


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


def baseline_scope_problems(baseline: dict, groups: list, deployed: list,
                            migrating_owners: Iterable[str] = ()) -> list[str]:
    """An apply never writes an entitlement the recorded original baseline does not cover.

    The baseline is captured once, at the first write gate, and never extended or
    replaced, so an entitlement added by a later plan has no recorded original state:
    verify could not validate it and complete could not retire it safely."""
    organizations = baseline.get("consumer_organizations", {})
    problems = [f"phase=baseline-scope status=BLOCKED owner={owner} region={region} "
            f"consumer={consumer} resource={arn}: this entitlement is not in the recorded "
            f"original baseline (captured in revision {baseline.get('captured_in_revision')})"
            + ("" if consumer in organizations else
               f" and consumer {consumer} has no baseline organization")
            + "; the baseline is never extended or replaced, so this migration record cannot "
              "add it"
            for owner, region, consumer, arn in uncovered_entitlements(
                baseline, groups, entitlement_sites(deployed))]
    problems += [
        f"phase=baseline-scope status=BLOCKED owner={owner}: the migrating owner's "
        "original organization is not in the captured baseline; use a separate "
        "owner-phase record because the original baseline is never extended or replaced"
        for owner in sorted(set(migrating_owners) - set(organizations))]
    return problems


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


def validate_discovered_consumers(groups: list[Group], moving: set[str],
                                  migrating_owners: set[str]) -> None:
    """Extra recipients require discovery's original-share continuity evidence."""
    for group in groups:
        stationary = set(getattr(group, "stationary_consumers", ()))
        outside = set(group.consumers) - moving
        if stationary - set(group.consumers) or stationary & moving or \
                outside != stationary or stationary and group.owner not in migrating_owners:
            raise MigrationError(
                "Discovery returned consumers outside the moving population without "
                "stationary-consumer evidence from a migrating owner's original share")


HEALTH = {
    "resolver_association": ("status", "COMPLETE"),
    "resolver_endpoint": ("status", "OPERATIONAL"),
    "tgw_attachment": ("state", "available"),
    "tgw_route": ("state", "active"),
    "pca_access": ("consumer_read", "OK"),
}
DROP_KIND = {"resolver_association": "association"}
UNAVAILABLE = "resource_checks_unavailable"
# Resource statuses that mean the account cannot use the resource through this share now.
UNUSABLE_STATUSES = ("ZONAL_RESOURCE_INACCESSIBLE", "LIMIT_EXCEEDED", "UNAVAILABLE")
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
    # Reads stay within the reviewed Regions plus every Region a group was planned in
    # (dependency Regions, scanned Regions and a migrating owner's enabled Regions).
    allowed = sorted(set(opts.regions) | {value(group, "region") if isinstance(group, dict)
                                          else group.region for group in groups})
    observation = verifier().collect(router, groups, temporary_shares=temporary,
                                     workers=opts.args.region_workers, allowed_regions=allowed,
                                     include_tgw_routes=opts.tgw_route_exclusion_reason is None)
    progress.observed(observation)
    for item in sorted(value(observation, "items"), key=lambda row: row["key"]):
        report.emit(f"phase={phase} {describe_item(item)}")
    for gap in value(observation, "gaps"):
        report.emit(f"phase={phase} status=GAP collector={gap.get('collector')} "
                    f"account={gap.get('account')} region={gap.get('region')} "
                    f"resource={gap.get('resource_arn')} reason={gap.get('reason')}")
    for limit in limits_of(observation):
        report.emit(f"phase={phase} status=LIMITED account={limit.get('account')} "
                    f"region={limit.get('region')} resource={limit.get('resource_arn')} "
                    f"type={limit.get('type')} RAM access is verified; this resource type has no "
                    "resource-specific health check")
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
    """A baseline is captured only from a complete observation: an unread item could be
    anything. Two read results block too: a planned entitlement the consumer cannot see
    (a temporary share would grant access it does not have now), and a consumer's Private
    CA read that is not OK (this tool's own read was denied or failed, so CA access is
    unknown). Other unhealthy state is recorded as found (see pre_existing)."""
    problems = [f"phase=baseline status=BLOCKED collector={gap.get('collector')} "
                f"account={gap.get('account')} region={gap.get('region')} "
                f"resource={gap.get('resource_arn')} {gap.get('reason')}; the original baseline "
                "cannot be captured completely" for gap in value(observation, "gaps")
                if gap.get("reason") != UNAVAILABLE]
    for item in value(observation, "items"):
        if item["kind"] == "entitlement" and not item.get("via_shares"):
            problems.append(f"phase=baseline status=BLOCKED {describe_item(item)}: not visible "
                            "to the consumer now, so a temporary share would grant access it does "
                            "not have; re-run plan, which bridges only current access")
        if item["kind"] == "pca_access" and item.get("consumer_read") not in (None, "OK"):
            problems.append(f"phase=baseline status=BLOCKED {describe_item(item)}: the consumer's "
                            "Private CA read was not confirmed, so its CA access is unknown; grant "
                            "the read, then re-run apply")
    return problems


def pre_existing(observation: Any, phase: str) -> list[str]:
    """Items already unhealthy, or entitlements already invisible, before the migration.
    The migration cannot have caused them and they never block: the baseline records
    them as found, and they are a loss only if they disappear or their binding changes."""
    lines = []
    for item in value(observation, "items"):
        rule = HEALTH.get(item["kind"])
        if item["kind"] == "pca_access":  # the consumer read is capture_problems' to judge
            rule = ("ca_status", "ACTIVE")
        if rule and item.get(rule[0]) != rule[1]:
            lines.append(f"phase={phase} status=PRE_EXISTING {describe_item(item)}: not {rule[1]} "
                         "before the migration; recorded as found, never a blocker")
    return lines


def limits_of(observation: Any) -> list[dict]:
    """Resources whose RAM access is observed but whose type has no health collector."""
    if isinstance(observation, dict):
        return list(observation.get("limits") or [])
    return list(getattr(observation, "limits", None) or [])


def baseline_gaps(baseline: dict) -> list[dict]:
    """Read gaps of a captured baseline. Older baselines recorded resource types without a
    health collector as gaps (resource_checks_unavailable); those are limits, not gaps."""
    return [gap for gap in baseline.get("gaps", []) if gap.get("reason") != UNAVAILABLE]


def baseline_complete(baseline: dict | None) -> bool:
    return baseline is not None and (bool(baseline.get("complete")) or not baseline_gaps(baseline))


def losses(comparison: Any) -> list[dict]:
    rows = [{"key": entry["key"], "item": entry.get("item") or entry.get("before"),
             "reason": "missing"} for entry in value(comparison, "missing")]
    rows += [{"key": entry["key"], "item": entry.get("before") or entry.get("item"),
              "reason": "; ".join(entry.get("reasons", [])) or "degraded"}
             for entry in value(comparison, "degraded")]
    return rows


def scoped_items(items: list[dict], groups: list, observation: Any = None) -> list[dict]:
    """Baseline items belonging to these groups' consumers and resources.

    An item of no consumer, such as a Resolver endpoint, belongs to any group using one of
    its resources: its rule_arns, or for a baseline captured before rule_arns its
    resource_arn, or else the observation of these groups produced it again."""
    pairs = {(consumer, arn) for group in groups for consumer in group.consumers
             for arn in group.resources}
    resources = {arn for _, arn in pairs}
    observed = {item["key"] for item in value(observation, "items")} if observation is not None else set()
    return [item for item in items if (
        (item.get("consumer"), item.get("resource_arn")) in pairs if item.get("consumer") is not None
        else item.get("resource_arn") in resources or resources & set(item.get("rule_arns") or ())
        or item["key"] in observed)]


RECORDED_LOSS = ("the recorded baseline is never replaced - restore it or start a new "
                 "migration record")


def baseline_check(record: dict | None, observation: Any, groups: list) -> tuple[list[str], Any]:
    """Pre-write: capture problems if no baseline exists, else losses against it."""
    baseline = (record or {}).get("baseline")
    if baseline is None:
        return capture_problems(observation), None
    comparison = verifier().compare(scoped_items(baseline["items"], groups, observation), observation)
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


def new_baseline(observation: Any, organizations: dict, revision: int,
                 excluded_verification: dict | None = None,
                 excluded_consumers: dict | None = None) -> dict:
    gaps = [gap for gap in value(observation, "gaps") if gap.get("reason") != UNAVAILABLE]
    return {"schema": 1, "captured_at": value(observation, "observed_at"),
            "captured_in_revision": revision, "complete": not gaps, "gaps": gaps,
            "limits": limits_of(observation),
            "consumer_organizations": dict(sorted(organizations.items())),
            "verification_exclusions": excluded_verification,
            "excluded_consumers": excluded_consumers,
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


def share_changes(baseline_items: list[dict], observation: Any,
                  temporary: frozenset[str]) -> tuple[list[dict], list[dict]]:
    """Per observed baseline entitlement: each original share that no longer lists the
    resource for its consumer (dropped), and each share other than a temporary share of
    this migration that lists it now but did not before migration (added). An unobserved
    entitlement is judged by compare(), never here."""
    now = {item["key"]: item for item in value(observation, "items")}
    dropped, added = [], []
    for before in baseline_items:
        after = now.get(before["key"]) if before["kind"] == "entitlement" else None
        if after is None:
            continue
        original, current = set(before.get("via_shares", [])) - temporary, set(after.get("via_shares", []))
        access = ("ORIGINAL" if original & current else
                  "REPLACEMENT" if current - temporary else
                  "TEMPORARY_ONLY" if current else "NONE")
        dropped += [{"item": before, "share": share, "access": access}
                    for share in sorted(original - current)]
        added += [{"item": before, "share": share, "access": access}
                  for share in sorted(current - temporary - original)]
    return dropped, added


def original_share_drops(dropped: list[dict], observation: Any, organizations: dict,
                         detected_by: str, last_present_at: str, evidence: str) -> list[dict]:
    """Informational drop events: one per original share and consumer, naming the
    resources it no longer lists for that consumer."""
    first_absent = value(observation, "observed_at")
    resources: dict[tuple[str, str, str, str], set[str]] = defaultdict(set)
    for row in dropped:
        item = row["item"]
        resources[item["consumer"], item["owner"], item["region"], row["share"]].add(item["resource_arn"])
    return [{"id": drop_id("original_share", consumer, region, share, first_absent),
             "kind": "original_share", "severity": "informational", "consumer": consumer,
             "owner": owner, "region": region, "subject": share, "resources": sorted(arns),
             "last_present_at": last_present_at, "first_absent_at": first_absent,
             "detected_by": detected_by,
             "consumer_organization_at_detection": organizations.get(consumer, "UNKNOWN"),
             "evidence": evidence,
             "reason": "the original share no longer lists these resources for the consumer"}
            for (consumer, owner, region, share), arns in sorted(resources.items())]


def untracked(baseline: dict, accounts: Iterable[str]) -> set[str]:
    """Accounts a baseline captured before migrating owners' organizations were recorded
    (1.0, whose baselines have no excluded_consumers field) records nothing for, such as a
    migrating owner that received nothing: nothing of theirs can be judged. A later baseline
    records every migrating owner's organization, so a missing one stays inconclusive."""
    if "excluded_consumers" in baseline:
        return set()
    named = set((baseline.get("consumer_organizations") or {})) | {
        item.get("consumer") for item in baseline.get("items", [])}
    return set(accounts) - named


def migration_status(record: dict, comparison: Any | None, organizations: dict,
                     groups: list | None = None,
                     retired: set[str] | frozenset[str] = frozenset()) -> tuple[str, list[str]]:
    """FAILED > INCONCLUSIVE > PENDING_MIGRATION > MIGRATION_VALIDATED.

    With ``groups``, an entitlement of a baseline consumer that the baseline does not
    cover is INCONCLUSIVE too: its original state was never recorded. ``retired``
    consumers, whose temporary access complete retired, have left the scope: their failure
    drops and baseline organizations are not judged (the drops stay recorded)."""
    baseline = record.get("baseline")
    reasons = [f"failure drop {d['kind']} {d['subject']} first absent {d['first_absent_at']}"
               for d in failure_drops(record) if d.get("consumer") not in retired]
    if comparison is not None and value(comparison, "status") == "LOSS":
        reasons += [f"{loss['reason']}: {loss['key']}" for loss in losses(comparison)]
    if reasons:
        return "FAILED", sorted(set(reasons))
    if baseline is None:
        return "INCONCLUSIVE", ["no original baseline is recorded; apply captures it before its first write"]
    if not baseline_complete(baseline):
        return "INCONCLUSIVE", [f"baseline is incomplete: {gap.get('collector')} {gap.get('reason')}"
                                for gap in baseline_gaps(baseline)] or ["baseline is incomplete"]
    if comparison is None or value(comparison, "status") != "INTACT":
        gaps = value(comparison, "gaps") if comparison is not None else []
        return "INCONCLUSIVE", [f"observation gap: {gap.get('collector')} {gap.get('account')} "
                                f"{gap.get('region')} {gap.get('reason')}" for gap in gaps] or [
                                    "the current observation is incomplete"]
    before = {consumer: organization for consumer, organization
              in baseline.get("consumer_organizations", {}).items() if consumer not in retired}
    scope = record.get("scope") or {}
    ignored = untracked(baseline, scope.get("migrating_owners", []))
    organizations = {k: v for k, v in organizations.items() if k not in ignored}
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
    scope = record.get("scope") or {}
    moving = set(scope.get("migrating_consumers", [])) | set(scope.get("migrating_owners", []))
    if not moving:
        moving = set(before) - set(scope.get("stationary_consumers", []))
    unrecorded_owners = set(scope.get("migrating_owners", [])) - set(before) - set(retired) - ignored
    if unrecorded_owners:
        return "INCONCLUSIVE", [
            f"migrating owner {owner} has no original baseline organization"
            for owner in sorted(unrecorded_owners)]
    staying = sorted(consumer for consumer, org in before.items()
                     if consumer in moving and organizations[consumer] == org)
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
    verification_excluded = recorded_verification_exclusions(scope)
    consumer_excluded = recorded_consumer_exclusions(scope)
    if opts.excluded_consumers and consumer_exclusion_scope(opts) != consumer_excluded:
        raise MigrationError("--exclude-consumers/--exclude-consumers-reason differ from "
                             "the migration record recipient scope")
    if opts.tgw_route_exclusion_reason is not None and \
            verification_exclusions(opts) != verification_excluded:
        raise MigrationError("--exclude-tgw-routes/--exclude-tgw-routes-reason differ from "
                             "the migration record verification scope")
    problem = verification_scope_problem(record, verification_excluded)
    if problem:
        raise MigrationError(problem)
    problem = consumer_scope_problem(record, consumer_excluded)
    if problem:
        raise MigrationError(problem)
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
    stationary = scope.get("stationary_consumers") or []
    if not isinstance(stationary, list):
        raise MigrationError("The migration record has invalid stationary-consumer scope")
    opts.stationary_consumers = sorted({checked_account(account) for account in stationary})
    if set(opts.stationary_consumers) & set(consumers):
        raise MigrationError("Stationary and migrating consumer scopes overlap")
    omitted = set((consumer_excluded or {}).get("accounts", []))
    tracked = set(owners + consumers + opts.stationary_consumers) | {
        account for entry in [*record.get("shares", []),
                              *(record.get("plan") or {}).get("groups", [])]
        for account in entry.get("consumers", [])}
    if omitted & tracked:
        raise MigrationError("Excluded recipients remain in the migration record scope or "
                             "temporary shares; retire existing access and create a fresh plan")
    opts.detected_owners = detected
    opts.excluded_regions = list(excluded["regions"]) if excluded else []
    opts.exclusion_reason = excluded["reason"] if excluded else None
    opts.tgw_route_exclusion_reason = verification_excluded["reason"] if verification_excluded else None
    opts.excluded_consumers = sorted(omitted)
    opts.consumer_exclusion_reason = consumer_excluded["reason"] if consumer_excluded else None
    located: dict[str, set[str]] = defaultdict(set)
    for row in [*record.get("shares", []), *(record.get("plan") or {}).get("groups", [])]:
        located[row["owner"]].add(row["region"])
    return dict(located)


def selected_consumers(opts: Options, record: dict) -> list[str]:
    """The moving and stationary accounts monitor/complete track from the record."""
    # A re-plan may narrow the scope; an account a recorded temporary share serves, or the
    # baseline records, stays selectable so its temporary access can still be retired.
    population = sorted(set(opts.consumers) | set(opts.stationary_consumers)
                        | {c for entry in record.get("shares", []) for c in entry.get("consumers", [])}
                        | set(((record.get("baseline") or {}).get("consumer_organizations") or {})))
    if opts.selected is None:
        return population
    unknown = sorted(set(opts.selected) - set(population))
    if unknown:
        raise MigrationError(f"--consumers {','.join(unknown)}: not a tracked account of this "
                             f"migration record; its tracked accounts are {','.join(population)}")
    return sorted(set(opts.selected))


def retired_at(record: dict, consumer: str) -> str:
    """When complete recorded this consumer's latest retirement."""
    return max((row.get("at") or "" for row in record.get("retirements") or []
                if row.get("consumer") == consumer), default="")


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
    for row in plan.accepted:
        report.emit(accepted_line(row))
    for reason in plan.blocked:
        report.emit(f"phase=preflight status=BLOCKED {reason} blocker={blocker_id(reason)}")


def accepted_line(row: dict) -> str:
    return (f"phase=preflight status=ACCEPTED blocker={row['blocker_id']} "
            f"category={row['category']} accepted_at={row.get('accepted_at')} "
            f"accepted_reason={json.dumps(row.get('accepted_reason'))} "
            f"consequence={json.dumps(row.get('consequence'))} {row['blocker']}")


def account_scope(opts: Options) -> dict:
    """Explicit account roles; a stationary owner's own dependencies are not at risk.

    A migrating account that owns RAM shares is a migrating owner even when --owners
    does not name it (``detected_owners``). Regions the operator excluded, with the
    reason, are part of the reviewed scope."""
    owners, consumers = set(opts.owners), set(opts.consumers)
    if set(opts.excluded_consumers) & (owners | consumers | set(opts.stationary_consumers)):
        raise MigrationError("Excluded recipients overlap the requested or stationary "
                             "account scope")
    scope = {
        "migrating_consumers": sorted(consumers - owners),
        "migrating_owners": sorted(owners & consumers),
        "stationary_owners": sorted(owners - consumers),
        "detected_owners": sorted(set(opts.detected_owners) & owners & consumers),
        "regions": sorted(opts.regions),
        "scan_enabled_regions": bool(opts.args.scan_enabled_regions),
        "excluded_regions": exclusion_scope(opts),
        "verification_exclusions": verification_exclusions(opts),
    }
    if opts.excluded_consumers:
        scope["excluded_consumers"] = consumer_exclusion_scope(opts)
    if opts.stationary_consumers:
        scope["stationary_consumers"] = sorted(set(opts.stationary_consumers) - consumers)
    return scope


def group_record(group: Group, migration: str) -> dict:
    result = {
        "key": group.key, "logical_id": group.logical_id,
        "stack": stack_name(migration, group.owner, group.region),
        "owner": group.owner, "region": group.region,
        "consumers": list(group.consumers),
        "permissions": dict(sorted(group.permissions.items())),
        "resources": dict(sorted(group.resources.items())),
        "source_shares": sorted(set(group.source_shares)),
        "source_stacks": sorted(set(getattr(group, "source_stacks", []))),
    }
    stationary = getattr(group, "stationary_consumers", ())
    if stationary:
        result["stationary_consumers"] = list(stationary)
    return result


# One comparison: its source shares are listed under it.
COMPARISON_FIELDS = ("permission_arn", "resource_type", "from_version", "to_version",
                     "from_policy_sha256", "to_policy_sha256")


def print_permission_changes(plan: Plan, report: Reporter) -> None:
    """Every managed-permission difference, as information. A temporary share attaches the
    current default, or the version an existing one keeps, whatever the original attaches;
    the difference never blocks and needs no approval. One that narrows access is also a
    warning: once the original share stops applying, the migrating consumers keep only
    what the temporary share grants."""
    compared: dict[tuple, list[dict]] = defaultdict(list)
    for change in plan.permission_changes:
        compared[tuple(change[f] for f in COMPARISON_FIELDS)].append(change)
    for _key, changes in sorted(compared.items()):
        first, shares = changes[0], sorted({change["share"] for change in changes})
        subject = (f"permission={first['permission_arn']} resource_type={first['resource_type']} "
                   f"version={first['from_version']}->{first['to_version']}")
        report.emit(f"phase=permission-change status=INFO {subject} "
                    f"from_policy_sha256={first['from_policy_sha256']} "
                    f"to_policy_sha256={first['to_policy_sha256']} shares={len(shares)}")
        for line in describe_difference(first["difference"]):
            report.emit(f"  {line}")
        for share in shares:
            targets = sorted({change["applies_to"] for change in changes
                              if change["share"] == share and change.get("applies_to")})
            report.emit(f"  share={share}" + (f" applies_to={'; '.join(targets)}" if targets else ""))
        less = grants_less(first["difference"])
        if less:
            report.emit(f"phase=permission-change status=WARNING {subject} shares={len(shares)} "
                        "the temporary share grants less than the original share "
                        f"({', '.join(less)}); once the original share stops applying, the "
                        "migrating consumers keep only what the temporary share grants")


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


def organization_policies(router: Any, plan: Plan, opts: Options, report: Reporter,
                          organization_shares: dict[str, list[str]]) -> dict:
    """The read-only organization-policy preflight (ram_migration_preflight) for the
    owners that write this plan's temporary shares, their consumers and, with
    --destination-ou, the destination path. Only shares in the plan's groups decide
    where RAM organization sharing is relied on. Its blockers join the plan's."""
    sources = {arn for group in plan.groups for arn in group.source_shares}
    return organization_preflight(
        router, plan.groups, opts.consumers, destination=opts.args.destination_ou,
        organization_shares={arn: principals for arn, principals in organization_shares.items()
                             if arn in sources},
        include_tgw_routes=opts.tgw_route_exclusion_reason is None,
        emit=report.emit)


def record_plan(record: dict, plan: Plan, scope: dict, prepared: dict, received: Any,
                capability_provenance: dict, status: str, proposed: dict | None = None,
                preflight: dict | None = None) -> dict:
    record = dict(record)
    record["scope"] = scope
    record["plan"] = {
        "status": status,
        "digest": plan_digest(plan.groups, scope),
        "groups": [group_record(g, plan.migration) for g in
                   sorted(plan.groups, key=lambda g: (g.owner, g.region, g.key))],
        "blocked": list(plan.blocked),
        "blockers": blocker_entries(plan.blocked),
        "accepted": copy.deepcopy(plan.accepted),
        "excluded": list(plan.excluded),
        "notes": list(plan.notes),
        "owner_continuity": sorted(copy.deepcopy(plan.owner_continuity),
                                   key=lambda row: (row["owner"], row["region"], row["share"])),
        # Information for reviewers, as print_permission_changes shows it; never approved.
        "permission_changes": copy.deepcopy(plan.permission_changes),
        "existing_shares": sorted({s.get("resourceShareArn", "unknown") for s in plan.existing}),
        "capability_provenance": capability_provenance,
        "received_entitlements": received.to_dict() if received is not None else None,
        "migration_stacks": [
            {"owner": owner, "region": region, "template": body,
             "existing_stack": old.get("StackId") if old else None}
            for (owner, region), (body, old) in sorted(prepared.items())],
        "organization_policy_preflight": preflight,
    }
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
    """The proposed owner scope is the only thing approved. A managed-permission difference
    needs no approval; the permission-change requests and approvals a record from an
    earlier version holds are history and are not shown."""
    path = opts.args.record
    record = load_record(path, opts.args.migration_id)
    migration = record["migration_id"]
    if latest(record, "plan") is None:
        raise MigrationError("approve requires a recorded plan; run plan --record first")
    if opts.args.accept_blockers:
        return run_accept(record, opts, ask, report)
    excluded = (record.get("scope") or {}).get("excluded_regions")
    if excluded:
        report.emit(f"migration={migration} phase=approve scope=REGIONS_EXCLUDED"
                    f"{exclusion_text(excluded)}")
    owners_request = record.get("owner_scope_request")
    if owners_request and owners_request["id"] in {
            a.get("approval_id") for a in record.get("approvals", {}).get("owner_scope", [])}:
        owners_request = None
    if not owners_request:
        report.emit(f"migration={migration} phase=approve status=NOTHING_PENDING")
        return 0
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
    if reply != token:
        report.emit(f"owner-scope={owners_request['id']} phase=approve status=NOT_APPROVED "
                    "confirmation did not match")
        return 2
    report.emit(f"owner-scope={owners_request['id']} phase=approve status=CONFIRMED")

    def add_approval(current: dict) -> None:
        if current.get("owner_scope_request") != owners_request:
            raise MigrationError(f"{owners_request['id']}: the record changed during review; "
                                 "re-run approve against the latest plan revision")
        approve_owner_scope(current, owners_request)
    update_record(path, migration, add_approval, mode="approve", status="APPROVED",
                  approved=[owners_request["id"]])
    report.emit(f"approval={owners_request['id']} phase=approve status=APPROVED")
    report.emit("Re-run plan with --record to produce a PLANNED revision for review before apply.")
    return 0


def run_accept(record: dict, opts: Options, ask: Callable[[str], str], report: Reporter) -> int:
    """Accept blockers of the latest recorded plan, chosen by ID, category or all. Each
    acceptance records its consequence and reason and binds to the blocker's exact text and
    the moving accounts it was reviewed for; plan and apply then report it as ACCEPTED.
    Exit 0 when every chosen blocker is accepted, 1 when one cannot be, 2 when not confirmed."""
    path, migration = opts.args.record, record["migration_id"]
    revision = latest(record, "plan")["revision"]
    scope = record.get("scope") or {}
    blockers = list((record.get("plan") or {}).get("blocked") or [])
    accepted = accepted_blockers(record)
    reviewed = {row["blocker_id"] for row in (record.get("plan") or {}).get("accepted") or []}
    chosen: dict[str, str] = {}
    for selector in split_values(opts.args.accept_blockers):
        if selector == "all":
            hits = blockers
        elif selector in BLOCKER_ACTIONS:
            hits = [reason for reason in blockers if blocker_category(reason) == selector]
            if not hits:
                raise MigrationError(f"--accept-blockers {selector}: the plan recorded in revision "
                                     f"{revision} has no blocker of that category")
        else:
            hits = [reason for reason in blockers if blocker_id(reason) == selector]
            if not hits and selector in reviewed:
                report.emit(f"blocker={selector} phase=approve status=ALREADY_ACCEPTED")
                continue
            if not hits:
                raise MigrationError(
                    f"--accept-blockers {selector}: not a blocker ID or category of the plan "
                    f"recorded in revision {revision}; run plan --record to list its blockers "
                    "(blocker=b-... on each phase=preflight status=BLOCKED line)")
        for reason in hits:
            chosen.setdefault(blocker_id(reason), reason)
    rows, refused = [], 0
    for identity, reason in chosen.items():
        key = acceptance_key(identity, scope)
        if key in accepted:  # accepted already; re-run plan --record to apply it
            report.emit(f"blocker={identity} phase=approve status=ALREADY_ACCEPTED "
                        f"accepted_at={accepted[key].get('accepted_at')}")
            continue
        category, consequence, refusal = acceptance_of(reason)
        if refusal is not None:
            refused += 1
            report.emit(f"blocker={identity} phase=approve status=NOT_ACCEPTABLE category={category} "
                        f"why={json.dumps(refusal)} {reason}")
            continue
        report.emit(f"blocker={identity} phase=approve category={category} "
                    f"consequence={json.dumps(consequence)} {reason}")
        rows.append({"blocker_id": identity, "acceptance_key": key,
                     "scope_accounts": scope_accounts(scope), "category": category,
                     "blocker": reason, "consequence": consequence,
                     "accepted_reason": opts.args.accept_reason, "plan_revision": revision})
    if not rows:
        report.emit(f"migration={migration} phase=approve status=NOTHING_ACCEPTED "
                    f"not_acceptable={refused}")
        return 1 if refused else 0
    token = f"ACCEPT-BLOCKERS {migration} {len(rows)}"
    try:
        reply = ask(f"Type {token} to accept these {len(rows)} blockers with their consequences: ")
    except EOFError:
        reply = ""
    if reply != token:
        report.emit(f"migration={migration} phase=approve status=NOT_ACCEPTED confirmation did not match")
        return 2

    def add(current: dict) -> None:
        if latest(current, "plan")["revision"] != revision:
            raise MigrationError("a plan was recorded during review; re-run approve against it")
        at = timestamp()
        record_acceptances(current, [dict(row, accepted_at=at) for row in rows])
    update_record(path, migration, add, mode="approve", status="ACCEPTED",
                  accepted=[row["blocker_id"] for row in rows], accept_reason=opts.args.accept_reason,
                  not_acceptable=refused)
    for row in rows:
        report.emit(f"blocker={row['blocker_id']} phase=approve status=ACCEPTED")
    if refused:
        report.emit(f"migration={migration} phase=approve status=PARTLY_ACCEPTED accepted="
                    f"{len(rows)} not_acceptable={refused}: resolve the others, then re-run plan --record")
        return 1
    report.emit("Re-run plan with --record: accepted blockers are reported as ACCEPTED and no "
                "longer block; a blocker whose text or moving accounts change needs a new acceptance.")
    return 0


def summary(plan: Plan, report: Reporter, status: str, *, mode: str, recorded: bool,
            created: int = 0, reused: int = 0, accepted: int = 0,
            reused_invitations: int = 0, failures: int = 0, comparison: Any = None,
            unassociated: int = 0, sharing: str | None = None,
            migration: str | None = None, excluded: dict | None = None,
            groups: list | None = None, verification_exclusions: dict | None = None) -> None:
    """``groups``, when given, are what the totals count instead of the plan's groups."""
    groups = plan.groups if groups is None else groups
    resources = {arn for group in groups for arn in group.resources}
    entitlements = {(group.owner, group.region, arn, consumer, group.permissions[kind])
                    for group in groups for arn, kind in group.resources.items()
                    for consumer in group.consumers}
    line = (f"status={status} migration={plan.migration} resources_in_plan={len(resources)} "
            f"expected_entitlements={len(entitlements)} planned_shares={len(groups)} "
            f"created_shares={created} reused_shares={reused} accepted_invitations={accepted} "
            f"reused_invitations={reused_invitations} exclusions={len(plan.excluded)} "
            f"blockers={len(plan.blocked)} verification_failures={failures}")
    if plan.accepted:
        line += f" accepted_blockers={len(plan.accepted)}"
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
    report.emit(line + exclusion_text(excluded) + verification_exclusion_text(verification_exclusions))
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
    "organization-policy-deny": {
        "*": "an SCP or RCP on the named account's organization path denies actions the "
             "migration needs: the policy, its target, the statement and the actions are named, "
             "and a target whose policies allow none of them denies them too (an allow-list "
             "without them). This tool never edits organization policies and an administrator "
             "role does not override them: obtain an approved exception from the policy owner, "
             "then {rerun}; leaving the account out of this migration needs a new reviewed plan",
    },
    "organization-policy-gap": {
        "*": "the preflight could not decide whether the named statements apply to the "
             "migration's requests (a condition key or operator it does not evaluate, a policy "
             "variable, a resource pattern or a malformed statement); each is listed for human "
             "review with its text (phase=org-policy status=REVIEW). The run stays blocked "
             "while any is undecided: have the policy owner make the statement decidable for "
             "these requests or grant an approved exception, then {rerun}",
    },
    "organization-policy-unreadable": {
        "*": "the organization policies of the named accounts or destination could not be "
             "read, and unread policies never pass: make each named management account "
             "reachable through --account-map, --profile-map or --role-map, or a base profile, "
             "with read access (a read-only role suffices) to organizations "
             "DescribeOrganization, ListParents, ListPoliciesForTarget, DescribePolicy and "
             "ListAWSServiceAccessForOrganization, then {rerun}; a throttled read "
             "(TooManyRequestsException) needs only the re-run",
    },
    "ram-organization-prerequisites": {
        "*": "shares with OU or organization principals rely on RAM sharing with AWS "
             "Organizations, which needs ALL features and ram.amazonaws.com trusted access in "
             "the named organization; this tool never enables them: have that organization's "
             "management account enable them through its approved change process, then {rerun}",
    },
    "authentication": {
        "*": "refresh or supply credentials for each named account (aws sso login, --sso-role, "
             "--account-map, --profile-map or --role-map), then {rerun}; expired tokens are "
             "not retried. A token rejected only in an opt-in Region such as af-south-1 means "
             "that Region is not enabled in that account, or the token came from the global "
             "STS endpoint: role and SSO sessions this tool opens use Regional STS endpoints, "
             "so give a base profile credentials from a Regional STS endpoint",
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
    "region-denied-by-policy": {
        "*": "an organization policy (SCP or RCP) explicitly denies RAM reads for the named "
             "accounts in these Regions, for example a Control Tower Region deny, so nothing "
             "there can be inspected: leave the Regions out with --exclude-regions <Regions> "
             "--exclude-reason \"<reason>\", or accept these blockers; then {rerun}",
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
    "reviewed-record-mismatch": {
        "apply": "the reviewed plan no longer matches this run: re-run plan with the same "
                 "--record using this tool version, review the new PLANNED revision, then re-run "
                 "apply, which resumes from the shares the record already holds",
        "verify": "the record and its migration stacks disagree: an apply that stopped before "
                  "recording its shares is resumed by apply with the same --record while its "
                  "reviewed plan still matches; then re-run verify with the same --record",
    },
    "policy-created-share": {
        "*": "each named share was created by RAM from a resource-based policy (featureSet "
             "CREATED_FROM_POLICY) or is being promoted (PROMOTING_TO_STANDARD), and is never "
             "inspected as a standard share: in its owner account run aws ram "
             "promote-permission-created-from-policy and then aws ram "
             "promote-resource-share-created-from-policy, wait until its featureSet is "
             "STANDARD, then {replan}",
    },
    "ram-share-quota": {
        "*": "a planned temporary share exceeds a fixed AWS RAM per-share quota (5,000 resource "
             "or 5,000 principal associations, not adjustable) and nothing was written; this "
             "tool version never splits an entitlement group across shares, so put migrating "
             "consumers in separate migration records (new --migration-id and --record) to "
             "reduce a group's principals and escalate a group with more resources than the "
             "quota, then {replan}",
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
# taken for a configuration need.
BLOCKER_PATTERNS = (
    ("authentication", re.compile(
        r"phase=authentication|ExpiredToken|InvalidClientTokenId|UnrecognizedClientException"
        r"|security token included in the request is (?:expired|invalid)"
        r"|SSO (?:session|token|login)|token has expired|unable to locate credentials",
        re.IGNORECASE)),
    ("organization-policy-unreadable", re.compile(
        r"phase=(?:org-policy|ram-org-prerequisites) status=BLOCKED decision=UNREADABLE ")),
    ("organization-policy-gap", re.compile(r"phase=org-policy status=GAP ")),
    ("organization-policy-deny", re.compile(
        r"phase=org-policy status=BLOCKED decision=(?:EXPLICIT_DENY|NO_ALLOW) ")),
    ("ram-organization-prerequisites", re.compile(r"phase=ram-org-prerequisites ")),
    ("region-scope", re.compile(
        r"phase=(?:regions|received-regions) |Region is outside the selected discovery scope"
        r"|outside the explicit owner/Region scope")),
    ("baseline-loss", re.compile(r"phase=baseline status=BLOCKED original .*"
                                 + re.escape(RECORDED_LOSS))),
    ("baseline-scope", re.compile(r"phase=baseline-scope ")),
    ("baseline-capture", re.compile(r"phase=baseline ")),
    ("owner-outside-approved-scope", re.compile(r"phase=owner-scope ")),
    ("reviewed-record-mismatch", re.compile(
        r"phase=reviewed-record |plan changed; run plan/apply")),
    ("policy-created-share", re.compile(r"featureSet (?:CREATED_FROM_POLICY|PROMOTING_TO_STANDARD):")),
    ("ram-share-quota", re.compile(r"AWS RAM allows at most \d+ \w+ associations per resource share")),
    # A read an SCP or RCP explicitly denies (for example a Control Tower Region deny):
    # known, not an unreadable failure.
    ("region-denied-by-policy", re.compile(
        r"phase=(?:received-audit|discovery|owned-audit)\b.*with an explicit deny in a "
        r"(?:service|resource) control policy")),
    ("discovery-api-error", re.compile(r"operation=\w+|\(request [^)]*\)")),
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
# Organization-policy blockers name each account with its role, and the policies
# and organizations involved, which are counted too.
ORGANIZATION_CATEGORIES = ("organization-policy-deny", "organization-policy-gap",
                           "organization-policy-unreadable", "ram-organization-prerequisites")
CATEGORY_COUNTED_AS.update({category: {"account": "accounts", "consumer": "accounts",
                                       "owner": "accounts"}
                            for category in ORGANIZATION_CATEGORIES})
POLICY_ID = re.compile(r"\b(p-[0-9A-Za-z_]{8,128})\b")
ORGANIZATION_FIELD = re.compile(r"\borganization=(o-[a-z0-9]{10,32})\b")
OWNER_EVIDENCE = re.compile(r"phase=owner-scope owner=(\d{12}) .*? provides (\d+) unique "
                            r"received resources .*? through (\d+) shares .*?\((\d+) observations\)")


def blocker_category(reason: str) -> str:
    return next((name for name, pattern in BLOCKER_PATTERNS if pattern.search(reason)), "other")


# What accepting a blocker means: the run proceeds without what the blocker concerns.
ACCEPTABLE = {
    "owner-outside-approved-scope":
        "that owner's resources are not bridged: the migrating accounts lose access to them "
        "when they leave their organization",
    "received-dependency-not-covered":
        "these received resources are not bridged: the migrating accounts lose access to them "
        "when they leave their organization",
    "configuration":
        "this share is not bridged: its migrating consumers lose access to it when they leave "
        "their organization",
    "policy-created-share":
        "this share is not bridged: its migrating consumers keep access only if its resource "
        "policy grants them directly rather than through their organization",
    "organization-policy-deny":
        "the named policy may deny apply, verify, monitor or complete requests when they run; "
        "a denied write fails without changing original sharing",
    "organization-policy-gap":
        "the undecided statement may deny apply, verify, monitor or complete requests when they "
        "run; a denied write fails without changing original sharing",
    "organization-policy-unreadable":
        "unread policies may deny apply, verify, monitor or complete requests when they run; a "
        "denied write fails without changing original sharing",
    "region-denied-by-policy":
        "nothing in that Region is inspected for that account: an organization policy denies "
        "RAM reads there, which usually means the account cannot use shared resources there "
        "either",
}
SHARE_LEVEL = ("this share is not bridged: its migrating consumers lose access to it when they "
               "leave their organization")
RECEIVED_LEVEL = ("this received access is not bridged: the account loses it when it leaves its "
                  "organization")
# Blockers that guard what the tool knows or the record proves; accepting one would leave
# the run blind or inconsistent, so each names what to do instead.
NOT_ACCEPTABLE = {
    "authentication": "an account that cannot be authenticated cannot be inspected or written; "
                      "supply its access",
    "region-scope": "leave a Region out explicitly with --exclude-regions and --exclude-reason",
    "discovery-api-error": "an unread inventory could hold anything; resolve the error (or exclude "
                           "the Region explicitly) and re-run",
    "baseline-loss": "a recorded loss is permanent evidence; start a new migration record",
    "baseline-capture": "an unread original state cannot be recorded; restore read access and re-run",
    "baseline-scope": "the recorded baseline is never extended; plan it under a new migration record",
    "reviewed-record-mismatch": "the run must match the reviewed record; re-run plan and review it",
    "ram-share-quota": "AWS RAM rejects a share over its fixed quota; split the migration",
}
NOT_ACCEPTABLE_OTHER = ("it is an unread or unexpected condition, or guards the tool's own "
                        "consistency; resolve it and re-run")
# Share-level and received-access blockers that are known decisions about access, not
# unread state: only these can be accepted.
SHARE_DECISIONS = re.compile(
    r"source status PENDING|resource status PENDING|Unsupported account-level principal "
    r"conversion|Provide principal-map override to resolve historical|Original account-facing "
    r"consumers are unresolved|Cannot re-share resource owned by another account|external "
    r"principal association of \d{12} on this original share is not settled|stationary "
    r"recipients \[[^\]]*\] hold no ASSOCIATED|principal-map stationary consumers|Service-only "
    r"template conflicts with live account principals|Principal-map override cannot broaden|"
    r"source managed permission missing|Owning template has no intended principals")
RECEIVED_DECISIONS = re.compile(
    r"share=\S+ phase=received-audit .*(?:pending intended received entitlements|intended "
    r"received resource status)")


def blocker_id(reason: str) -> str:
    """Stable identity of one blocker's exact text. Request IDs are ignored, and so is the
    post-confirmation prefix apply adds when it reads the same condition again."""
    text = re.sub(r"^post-confirmation ", "", reason)
    text = re.sub(r"\(request [^)]*\)|\brequest[= ][\w-]+", "", text)
    # An AccessDenied text names the caller's role session, which differs per session.
    text = re.sub(r"(arn:[\w-]+:sts::\d{12}:assumed-role/[\w+=,.@-]+)/[\w+=,.@-]+", r"\1/*", text)
    return "b-" + digest(text, 12)


def scope_accounts(scope: dict | None) -> list[str]:
    """The moving accounts an acceptance was reviewed for."""
    scope = scope or {}
    return sorted(set(scope.get("migrating_consumers", [])) | set(scope.get("migrating_owners", [])))


def acceptance_key(identity: str, scope: dict | None) -> str:
    """A blocker's ID for one reviewed set of moving accounts: accepting a share-level
    blocker for some accounts never covers accounts added by a later plan."""
    return f"{identity}@{digest(scope_accounts(scope), 12)}"


def acceptance_of(reason: str) -> tuple[str, str | None, str | None]:
    """(category, consequence when accepted, or why it cannot be accepted)."""
    category = blocker_category(reason)
    if category in ACCEPTABLE:
        return category, ACCEPTABLE[category], None
    if category == "other":
        if SHARE_ARN.match(reason) and SHARE_DECISIONS.search(reason):
            return category, SHARE_LEVEL, None
        if RECEIVED_DECISIONS.search(reason):
            return category, RECEIVED_LEVEL, None
        return category, None, NOT_ACCEPTABLE_OTHER
    return category, None, NOT_ACCEPTABLE.get(category, NOT_ACCEPTABLE_OTHER)


def export_document(exported: dict, plan: Plan, scope: dict) -> dict:
    """The --export-plan file for people: a summary first, then every section in a stable
    reading order (the keys an earlier export had are all kept)."""
    groups = sorted(plan.groups, key=lambda g: (g.owner, g.region, g.key))
    summary = {
        "about": "RAMShift plan export: what plan would create and why it did or did not block. "
                 "Informational only; apply reads the migration record, not this file.",
        "migration_id": plan.migration,
        "status": "BLOCKED" if plan.blocked else "PLANNED",
        "accounts": {key: scope.get(key, []) for key in (
            "migrating_consumers", "migrating_owners", "stationary_owners", "stationary_consumers")},
        "regions": scope.get("regions", []),
        "temporary_shares": [
            {"owner": g.owner, "region": g.region, "stack": stack_name(plan.migration, g.owner, g.region),
             "accounts": list(g.consumers), "resources": len(g.resources),
             "resource_types": dict(sorted(Counter(g.resources.values()).items())),
             "source_shares": sorted(set(g.source_shares))} for g in groups],
        "blockers": len(plan.blocked), "accepted_blockers": len(plan.accepted),
        "exclusions": len(plan.excluded), "permission_differences": len(plan.permission_changes),
        "next_step": ("Resolve or accept the blockers, then run plan --record again."
                      if plan.blocked else
                      "Review the plan, then run apply with the same inputs and --record."),
    }
    order = ("blockers", "accepted", "groups", "permission_changes", "excluded", "notes",
             "existing", "external_access", "owner_continuity", "scope",
             "organization_policy_preflight", "received_entitlements", "capability_provenance",
             "migration_stacks")
    return {"summary": summary, **{k: exported[k] for k in order if k in exported},
            **{k: exported[k] for k in sorted(exported) if k not in order}}


def blocker_entries(blocked: list[str], mode: str = "plan") -> list[dict]:
    """Each blocker as people need it: its ID, category, whether it can be accepted and
    what accepting it means, the next action, and its full text."""
    rows = []
    for reason in blocked:
        category, consequence, refusal = acceptance_of(reason)
        rows.append({"id": blocker_id(reason), "category": category,
                     "can_accept": consequence is not None,
                     "if_accepted": consequence, "why_it_cannot_be_accepted": refusal,
                     "next_action": blocker_action(category, mode, True), "text": reason})
    return rows


def accept_recorded(plan: Plan, record: dict | None, scope: dict | None) -> None:
    """Move every blocker the record accepts out of ``plan.blocked`` into ``plan.accepted``.
    Idempotent; only an acceptable blocker with a recorded acceptance of its exact ID, for
    the same moving accounts, moves."""
    accepted = accepted_blockers(record) if record is not None else {}
    if not accepted:
        return
    remaining = []
    for reason in plan.blocked:
        row = accepted.get(acceptance_key(blocker_id(reason), scope))
        if row is not None and acceptance_of(reason)[1] is not None:
            plan.accepted.append({**row, "blocker": reason})
        else:
            remaining.append(reason)
    plan.blocked = remaining


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
    # Which blockers can be accepted instead of resolved; the summary stays the last output.
    for group, reasons in sorted(grouped.items()):
        acceptable = sum(acceptance_of(reason)[1] is not None for reason in reasons)
        if acceptable and mode in ("plan", "apply"):
            report.emit(f"phase=accept-hint blockers={acceptable} of={group} command=\"approve "
                        f"--record <path> --accept-blockers {group} --accept-reason <reason>\" "
                        "(or name blocker IDs); each consequence is shown and recorded before you "
                        "confirm, and plan then proceeds without what they concern")
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
            if category in ORGANIZATION_CATEGORIES:
                counts["policies"] = set(POLICY_ID.findall(text))
                counts["organizations"] = set(ORGANIZATION_FIELD.findall(text))
            fields += [f"{name}={len(found)}" for name, found in counts.items() if found]
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
    if args.mode == "apply" and record is not None and record.get("retirements"):
        raise MigrationError(
            "this migration is being completed: complete has retired the temporary access of "
            f"{','.join(sorted({row['consumer'] for row in record['retirements']}))} under "
            f"migration ID {plan.migration}, so apply creates no further temporary shares for it; "
            "plan and apply them under a new --migration-id and --record")
    if args.mode == "verify" and record is not None and record.get("completion"):
        # Every temporary share is retired; the baseline comparison is the monitor's.
        report.emit(f"status=ALREADY_COMPLETE migration={plan.migration} phase=verification "
                    f"completed_at={record['completion'].get('completed_at')} no temporary shares "
                    "remain to verify; run monitor to compare with the pre-migration baseline")
        return 0
    recorded_regions: dict[str, set[str]] = {}
    # verify: consumers complete retired have left the scope, and so has every temporary
    # share retired from all its consumers (deleted); per share, the consumers retired from it.
    retired: set[str] = set()
    retired_from: dict[tuple[str, str, str], frozenset[str]] = {}
    closed: set[tuple[str, str, str]] = set()
    if args.mode == "verify":
        recorded_regions = fill_scope_from_record(opts, record)
        retired, pairs = retired_consumers(record), retired_pairs(record)
        for entry in record.get("shares", []):
            if entry.get("share_arn"):
                key = (entry["owner"], entry["region"], entry["logical_id"])
                retired_from[key] = frozenset(consumer for consumer in entry.get("consumers", [])
                                              if (entry["share_arn"], consumer) in pairs)
                if retired_from[key] >= set(entry.get("consumers", [])):
                    closed.add(key)
        for consumer in sorted(retired):
            report.emit(f"consumer={consumer} phase=verification status=RETIRED "
                        f"at={retired_at(record, consumer)}")
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
    if record is not None:
        problem = verification_scope_problem(record, verification_exclusions(opts))
        if problem:
            raise MigrationError(problem)
        problem = consumer_scope_problem(record, consumer_exclusion_scope(opts))
        if problem:
            raise MigrationError(problem)
    report_verification_exclusions(opts, report)
    report_consumer_exclusions(opts, report)
    # Selects each next action, and puts any Region exclusion on every summary line.
    run = {"mode": args.mode, "recorded": record is not None, "excluded": exclusion_scope(opts),
           "verification_exclusions": verification_exclusions(opts)}

    def note(status: str, mutate: Callable[[dict], Any] = lambda _record: None,
             **details: Any) -> None:
        """Apply/verify outcomes, including blocked and failed runs, are history. Once
        apply has checked its reviewed plan, each entry names the plan it consumed."""
        nonlocal record
        if record is not None and args.mode in ("apply", "verify"):
            record = update_record(args.record, plan.migration, mutate, mode=args.mode,
                                   status=status, **{**opts.applied_plan, **details})
    plan.blocked.extend(authenticate(router, set(opts.owners) | (set(opts.consumers) - retired),
                                     opts, report))
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
        problems = excluded_group_problems(groups, set(opts.excluded_consumers))
        if problems:
            raise MigrationError("; ".join(problems))
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
    stack_groups = list(plan.groups)
    if args.mode == "verify":
        # A share retired from every consumer is deleted and no longer expected in its stack.
        plan.groups = [g for g in plan.groups if (g.owner, g.region, g.logical_id) not in closed]
    # What each existing temporary share attaches, by entitlement key: it keeps the
    # version it was created with, whatever the current default is.
    kept = {g.key: g.permission_snapshots for groups in deployed.values() for g in groups
            if getattr(g, "permission_snapshots", None)}

    capability_provenance: dict = {}
    proposed: dict[str, dict] = {}
    organization_shares: dict[str, list[str]] = {}  # original share -> its OU/org principals
    if args.mode != "verify":
        capabilities, capability_provenance = capabilities_for(opts)
        report.emit(f"phase=plan capability_provenance={json.dumps(capability_provenance, sort_keys=True)}")
        discovery = Discovery(gate, set(opts.consumers), plan.migration, opts.principals, capabilities,
                              migrating_owners=set(scope["migrating_owners"]),
                              share_workers=args.share_workers, cache=cache, deployed=kept,
                              excluded_consumers=set(opts.excluded_consumers),
                              consumer_exclusion_reason=opts.consumer_exclusion_reason)
        def inspect(owner, region):
            report.emit(f"owner={owner} region={region} phase=discovery status=STARTED")
            result = discovery.inspect(owner, region)
            validate_groups(result.groups, {owner: [region]})
            validate_discovered_consumers(
                result.groups, set(opts.consumers), set(scope["migrating_owners"]))
            return result
        for row in scoped_fanout(scopes, inspect, opts, Progress(report, "discovery", scopes)):
            if row.error:
                plan.blocked.append(f"owner={row.account} region={row.region} phase=discovery {row.error}")
            else:
                merge_plan(plan, row.value)
        organization_shares = dict(getattr(discovery, "organization_principals", {}))
        proven, provenance_blocked = received_provenance(stacks, persisted_groups, opts)
        received.blocked.extend(provenance_blocked)
        proposed = classify_received(received, plan, proven, scopes, opts)
        scope["proposed_owners"] = sorted(proposed)
        print_received(received, report)
        plan.blocked.extend(received.blocked)
        plan.excluded.extend(received.excluded)
        opts.stationary_consumers = sorted(
            {consumer for group in plan.groups for consumer in group.consumers}
            - set(opts.consumers))
        scope = reviewed_scope()
        scope["proposed_owners"] = sorted(proposed)
        if opts.stationary_consumers:
            report.emit(
                f"phase=owner-continuity status=SCOPED "
                f"stationary_consumers={','.join(opts.stationary_consumers)} "
                "source=original-share-evidence accounts_are_migrating=false")
    additional_consumers = {consumer for group in plan.groups for consumer in group.consumers} \
        - set(opts.owners + opts.consumers + opts.excluded_consumers)
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
    # Read-only SCP/RCP evaluation; plan records it with the reviewed plan.
    org_policy: dict | None = None
    if args.mode == "plan":
        org_policy = organization_policies(gate, plan, opts, report, organization_shares)
        plan.blocked.extend(org_policy["blockers"])

    if args.mode == "apply" and record is not None:
        problem = reviewed_plan_problem(record, plan, scope)
        if problem:
            plan.blocked.append(f"phase=reviewed-record {problem}")
        else:
            opts.applied_plan = {"plan_revision": latest(record, "plan")["revision"],
                                 "plan_digest": record["plan"]["digest"]}
            reviewed = recorded_destination(record["plan"].get("organization_policy_preflight"))
            if reviewed != args.destination_ou:
                plan.blocked.append(
                    f"phase=reviewed-record --destination-ou {args.destination_ou or 'none'} "
                    f"differs from the destination {reviewed or 'none'} that reviewed plan "
                    f"revision {opts.applied_plan['plan_revision']} evaluated; pass the same "
                    "--destination-ou, or re-run plan --record with the intended destination "
                    "and review it")
        if record.get("baseline") is not None:
            plan.blocked.extend(baseline_scope_problems(
                record["baseline"], plan.groups, [g for groups in deployed.values() for g in groups],
                scope["migrating_owners"]))
    if args.mode == "verify" and record is not None:
        # An unreadable stored plan is already a blocker; its shares are not missing. A
        # closed share may be gone with its stack, or still in it.
        recorded = {(s["owner"], s["region"], s["logical_id"]) for s in record.get("shares", [])
                    if (s["owner"], s["region"]) not in unread} - closed
        stored = {(g.owner, g.region, g.logical_id) for g in plan.groups}
        plan.blocked += [f"phase=reviewed-record recorded temporary share {owner}/{region}/{logical} "
                         "is missing from its migration stack" for owner, region, logical
                         in sorted(recorded - stored)]
        plan.blocked += [f"phase=reviewed-record stack entitlement {owner}/{region}/{logical} is not "
                         "in the migration record" for owner, region, logical in sorted(stored - recorded)]
    # What is observed and judged: verify's retired consumers have left the scope, and an
    # unretired consumer's entitlements stay observed even through a closed share's group.
    observed = plan.groups if args.mode != "verify" else [
        replace(g, consumers=tuple(c for c in g.consumers if c not in retired))
        if set(g.consumers) & retired else g for g in stack_groups if set(g.consumers) - retired]
    consumers_in_scope = sorted(
        ({c for g in observed for c in g.consumers} | set(scope["migrating_owners"])) - retired)
    preflight, organizations, pending_drops = None, {}, []
    if args.mode in ("plan", "apply"):
        accept_recorded(plan, record, scope)  # accepted blockers never stop the checks below
    if args.mode == "apply" and not plan.blocked and plan.groups:
        organizations, errors = consumer_organizations(gate, consumers_in_scope, opts)
        plan.blocked.extend(errors)
        preflight = observe(gate, plan.groups, temporary_share_arns(record, {}), opts, report,
                            "baseline-preflight")
        problems, comparison = baseline_check(record, preflight, plan.groups)
        if record is None or record.get("baseline") is None:
            for line in pre_existing(preflight, "baseline-preflight"):
                report.emit(line)
        plan.blocked.extend(problems)
        pending_drops = drops_from(comparison, preflight, organizations, "apply",
                                   record["baseline"]["captured_at"] if record and record.get("baseline")
                                   else "", f"record revision {record['revision'] if record else 0}")
    if args.mode == "apply" and not plan.blocked and plan.groups:
        org_policy = organization_policies(gate, plan, opts, report, organization_shares)
        plan.blocked.extend(org_policy["blockers"])
        for line in policy_changes((record.get("plan") or {}).get("organization_policy_preflight"),
                                   org_policy):
            report.emit(line)
    if args.mode in ("plan", "apply"):
        accept_recorded(plan, record, scope)
    if args.mode != "verify":
        print_plan(plan, prepared, report)
        print_permission_changes(plan, report)
        if args.mode == "plan" and record is not None:
            status = "BLOCKED" if plan.blocked else APPLICABLE
            record = update_record(
                args.record, plan.migration,
                lambda current: current.update(record_plan(
                    current, plan, scope, prepared, received, capability_provenance, status,
                    proposed, org_policy)),
                mode="plan", status=status, create=True,
                plan_digest=plan_digest(plan.groups, scope), blockers=len(plan.blocked),
                permission_changes=len(plan.permission_changes))
            report.emit(f"phase=plan record={args.record} revision={record['revision']} "
                        f"status={status} digest={record['plan']['digest']}")
        if args.export_plan:
            exported = plan.to_dict()
            exported["blockers"] = blocker_entries(plan.blocked, args.mode)
            exported["capability_provenance"] = capability_provenance
            exported["received_entitlements"] = received.to_dict()
            exported["scope"] = scope
            exported["organization_policy_preflight"] = org_policy
            exported["migration_stacks"] = [
                {"owner": owner, "region": region, "template": body,
                 "existing_stack": old.get("StackId") if old else None}
                for (owner, region), (body, old) in sorted(prepared.items())
            ]
            args.export_plan.write_text(json.dumps(export_document(exported, plan, scope),
                                                   indent=2) + "\n", encoding="utf-8")
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
        # The organization policies are read again, fresh: an SCP or RCP changed during
        # the confirmation blocks every write.
        recheck = organization_policies(gate, plan, opts, report, organization_shares)
        plan.blocked.extend(f"post-confirmation {reason}" for reason in recheck["blockers"])
        for line in policy_changes(org_policy, recheck, since="the read before the confirmation"):
            report.emit(line)
        # The original baseline is observed again immediately before the first write.
        captured = None
        if not plan.blocked:
            organizations_at_gate, errors = consumer_organizations(gate, consumers_in_scope, opts)
            plan.blocked.extend(errors)
            if not errors and organizations_at_gate != organizations:
                plan.blocked.append(
                    "phase=baseline status=BLOCKED account organization changed during "
                    "confirmation; re-run plan before any sharing writes")
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
                    captured = new_baseline(at_gate, organizations, record["revision"] + 1,
                                            verification_exclusions(opts),
                                            consumer_exclusion_scope(opts))
            plan.blocked.extend(problems)
            pending_drops = drops_from(comparison, at_gate, organizations, "apply",
                                       record["baseline"]["captured_at"] if record.get("baseline")
                                       else "", f"record revision {record['revision']}")
        accepted_before = len(plan.accepted)
        accept_recorded(plan, record, scope)
        for row in plan.accepted[accepted_before:]:
            report.emit(accepted_line(row))
        if plan.blocked:
            for reason in plan.blocked:
                report.emit(f"phase=preflight status=BLOCKED {reason} blocker={blocker_id(reason)}")
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
            if problem is None and (current.get("retirements") or current.get("completion")):
                problem = ("complete retired temporary access meanwhile; this migration creates no "
                           "further temporary shares")
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
                if reader.existing(owner, region) is None:
                    return {}
                readback = reader.readback(owner, region)  # proven shares are still recorded
                for logical in sorted(readback.failures):
                    report.emit(f"owner={owner} region={region} logical_id={logical} "
                                "phase=interrupted-readback status=INCOMPLETE "
                                f"{readback.reason(logical)}")
                return readback.shares
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
                readback = stacks.readback(owner, region)
            except Exception as exc:
                report.emit(f"owner={owner} region={region} phase=record status=INCOMPLETE stack "
                            f"shares were not read back ({failure_text(exc)}); the final "
                            "readback records them")
                return
            for logical in sorted(readback.failures):
                report.emit(f"owner={owner} region={region} logical_id={logical} phase=record "
                            f"status=INCOMPLETE share was not proven ({readback.reason(logical)}); "
                            "it is not recorded, and the final readback reports it")
            found = {(owner, region): readback.shares}
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

    # Per logical share: a share that cannot be proven fails alone, and its proven
    # siblings are still recorded, accepted and verified.
    shares: dict[tuple[str, str], dict] = {}
    readbacks: dict[tuple[str, str], Readback] = {}
    for row in scoped_fanout(group_scopes, stacks.readback, opts):
        if row.error:
            failures.append(f"owner={row.account} region={row.region} phase=share-readback {row.error}")
        else:
            shares[row.account, row.region] = row.value.shares
            readbacks[row.account, row.region] = row.value
    planned = {(group.owner, group.region, group.logical_id) for group in plan.groups}
    for (owner, region), readback in sorted(readbacks.items()):
        failures += [f"owner={owner} region={region} logical_id={logical} phase=share-readback "
                     f"{readback.reason(logical)}" for logical in sorted(readback.failures)
                     if (owner, region, logical) not in planned | closed]
    for group in plan.groups:
        share = shares.get((group.owner, group.region), {}).get(group.logical_id)
        readback = readbacks.get((group.owner, group.region))
        if share is None and readback is not None and group.logical_id in readback.failures:
            failures.append(f"{group.owner}/{group.region}/{group.key}: planned share could not be "
                            f"proven from its migration stack: {readback.reason(group.logical_id)}")
        elif share is None:
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
            # Consumers complete removed from this share are no longer its principals.
            gone = retired_from.get((owner, region, group.logical_id), frozenset())
            try:
                def check_current_share():
                    readback = verification_stacks.readback(owner, region)
                    if group.logical_id in readback.failures:  # this share only, never a sibling
                        raise readback.failures[group.logical_id]
                    current = readback.shares.get(group.logical_id)
                    if current is None:
                        raise MigrationError(f"{group.key}: migration share MISSING during verification")
                    verify_group(readonly, group, current, plan.migration, retired=gone)
                poll(check_current_share, opts, verification=True)
                for consumer in (c for c in group.consumers if c not in gone):
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
    temporary = temporary_share_arns(record, shares)
    final = observe(readonly, observed, temporary, opts, report, phase)
    organizations_now, errors = consumer_organizations(readonly, consumers_in_scope, opts)
    baseline = record.get("baseline")
    comparison = verifier().compare(scoped_items(baseline["items"], observed, final), final) \
        if baseline else None
    new_drops = drops_from(comparison, final, organizations_now, args.mode,
                           baseline["captured_at"] if baseline else "",
                           f"record revision {record['revision']}")
    if baseline:
        # Original shares that stopped reaching a consumer are expected while it moves;
        # they are recorded as informational drops and never change the status.
        dropped, _ = share_changes(scoped_items(baseline["items"], observed, final), final, temporary)
        for row in dropped:
            report.emit(f"consumer={row['item']['consumer']} region={row['item']['region']} "
                        f"resource={row['item']['resource_arn']} phase={phase} "
                        f"change=ORIGINAL_SHARE_DROPPED share={row['share']} access={row['access']}")
        new_drops += original_share_drops(dropped, final, organizations_now, args.mode,
                                          baseline["captured_at"],
                                          f"record revision {record['revision']}")
    projected = dict(record, drops=list(record.get("drops", [])) + new_drops)
    status_now, reasons = migration_status(projected, comparison, organizations_now, observed,
                                           retired)
    reasons += errors
    if errors and status_now in ("MIGRATION_VALIDATED", "PENDING_MIGRATION"):
        status_now = "INCONCLUSIVE"
    unassociated = unassociated_rules(observed, final, baseline)
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
    # The totals count only the principals each temporary share is still expected to serve.
    serving = [replace(g, consumers=tuple(c for c in g.consumers if c not in gone))
               if (gone := retired_from.get((g.owner, g.region, g.logical_id))) else g
               for g in plan.groups]
    summary(plan, report, status, **run, created=created, reused=reused,
            accepted=accepted_count, reused_invitations=reused_invitations, failures=len(failures),
            comparison=comparison, unassociated=len(unassociated),
            sharing=sharing_status, migration=status_now, groups=serving)
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


def settle(router: Any, groups: list, baseline: dict | None, temporary: frozenset[str],
           organizations: dict, opts: Options, report: Reporter, phase: str,
           seconds: float | None = None) -> tuple[list[str], list[dict]]:
    """Keep re-verifying for the settle window, --settle-seconds unless ``seconds`` is given
    (0 observes once); the first loss or gap ends it. Without a baseline, which only --force
    accepts, nothing original is compared, but gaps and replacement access still count."""
    deadline = time.monotonic() + (opts.args.settle_seconds if seconds is None else seconds)
    items = (baseline or {}).get("items", [])
    while True:
        observation = observe(router, groups, temporary, opts, report, phase)
        comparison = verifier().compare(scoped_items(items, groups, observation), observation)
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
                                        (baseline or {}).get("captured_at", ""), phase)
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            return [], []
        time.sleep(min(30.0, remaining))


def run_complete(router: Router, opts: Options, ask: Callable[[str], str], report: Reporter) -> int:
    """Retire the temporary access of the chosen migrating accounts (--consumers, or every one
    with --all-accounts), only after proving nothing original of theirs is missing or dropped.

    A recorded temporary share serving a chosen account is deleted when it serves no other
    unretired account, and otherwise loses only the chosen accounts' principals; a migration
    stack is deleted once every recorded share in it is. The checks before any write are
    scoped to the chosen accounts. --force overrides the baseline, original-state, failure-drop
    and replacement-access checks only, never identity, record-versus-stack or ownership
    checks. Every retirement is recorded as soon as AWS holds it."""
    args = opts.args
    record = load_record(args.record, args.migration_id)
    migration = record["migration_id"]
    if record.get("completion"):
        report.emit(f"migration={migration} phase=complete status=ALREADY_COMPLETE "
                    f"at={record['completion'].get('completed_at')}")
        return 0
    fill_scope_from_record(opts, record)
    selection = selected_consumers(opts, record)
    report_verification_exclusions(opts, report)
    report_consumer_exclusions(opts, report)

    def note(status: str, mutate: Callable[[dict], Any] = lambda _record: None,
             **details: Any) -> None:
        nonlocal record
        record = update_record(args.record, migration, mutate, mode="complete", status=status,
                               **details)

    excluded = (exclusion_text(exclusion_scope(opts))
                + verification_exclusion_text(verification_exclusions(opts)))

    def refuse(problems: list[str], drops: list[dict] | None = None) -> int:
        for problem in problems:
            report.emit(f"phase=complete status=BLOCKED {problem}")
        if args.force:  # every check --force overrides has been overridden by now
            report.emit("phase=complete status=NOT_OVERRIDDEN --force never overrides identity, "
                        "record-versus-stack or ownership checks")
        report.emit(f"status=BLOCKED migration={migration} phase=complete blockers={len(problems)} "
                    f"temporary shares retained{excluded}")
        note("BLOCKED", lambda current: add_drops(current, drops or []), blockers=problems)
        return 1

    def listed(accounts: Any) -> str:
        return ",".join(sorted(accounts)) or "none"

    recorded = {(entry["owner"], entry["region"], entry["logical_id"]): entry
                for entry in record.get("shares", []) if entry.get("share_arn")}
    if not recorded:
        return refuse(["the migration record has no temporary shares to retire"])
    pairs = retired_pairs(record)
    retired = retired_consumers(record)
    served = {consumer for entry in recorded.values() for consumer in entry["consumers"]}
    for consumer in selection:
        if consumer in retired:
            report.emit(f"consumer={consumer} phase=complete status=ALREADY_RETIRED "
                        f"at={retired_at(record, consumer)}")
        elif consumer not in served:
            report.emit(f"consumer={consumer} phase=complete status=NO_TEMPORARY_SHARES no "
                        "recorded temporary share serves this account")
    chosen = [consumer for consumer in selection if consumer in served and consumer not in retired]
    # Per recorded share: the chosen accounts this run retires from it, and the unretired
    # others it keeps serving. Retirement is per share: a chosen account a stopped run
    # already retired from a share is not acted on there again.
    acting = {key: [c for c in entry["consumers"]
                    if c in chosen and (entry["share_arn"], c) not in pairs]
              for key, entry in recorded.items()}
    keeping = {key: [c for c in entry["consumers"]
                     if c not in chosen and (entry["share_arn"], c) not in pairs]
               for key, entry in recorded.items()}
    closed = {key for key, entry in recorded.items()
              if all((entry["share_arn"], c) in pairs for c in entry["consumers"])}
    affected = [key for key in sorted(recorded) if acting[key]]
    touched = sorted({key[:2] for key in affected})
    # A touched stack is emptied when none of its shares keeps serving anyone. Once no
    # account remains, the stacks earlier runs emptied are deleted too, unless already gone.
    emptied = [stack for stack in touched
               if not any(keeping[key] for key in recorded if key[:2] == stack)]
    final = not served - retired - set(chosen)
    leftover = sorted({key[:2] for key in recorded} - set(touched)) if final else []
    if not affected and not leftover:
        report.emit(f"status=NOTHING_TO_RETIRE migration={migration} "
                    f"retired_accounts={listed(retired)} "
                    f"remaining_accounts={listed(served - retired)}{excluded}")
        return 0

    blocked = authenticate(router, {owner for owner, _ in touched + leftover} | set(chosen),
                           opts, report)
    if blocked:
        return refuse(blocked)
    gate = WriteGate(router)
    stacks = Stacks(gate, migration, timeout=args.timeout)
    scopes: dict[str, list[str]] = defaultdict(list)
    for owner, region in touched:
        scopes[owner].append(region)
    stored: dict[tuple[str, str, str], Group] = {}
    readbacks: dict[tuple[str, str], Readback] = {}
    problems: list[str] = []
    for row in scoped_fanout(scopes, lambda owner, region: (stacks.persisted_groups(owner, region),
                                                            stacks.readback(owner, region)), opts):
        if row.error:
            problems.append(f"owner={row.account} region={row.region} phase=stored-plan {row.error}")
        else:
            stored.update({(g.owner, g.region, g.logical_id): g for g in row.value[0]})
            readbacks[row.account, row.region] = row.value[1]
    shares = {stack: readback.shares for stack, readback in readbacks.items()}
    # Every share of a stack this run writes to is the recorded one, and one retired from
    # every consumer is deleted: RAM returns it DELETED, or no longer at all.
    here = {key: entry for key, entry in recorded.items() if key[:2] in touched}
    problems += [f"recorded temporary share {'/'.join(key)} is missing from its migration stack"
                 for key in sorted(set(here) - set(stored))]
    problems += [f"stack entitlement {'/'.join(key)} is not in the migration record"
                 for key in sorted(set(stored) - set(here))]
    for (owner, region), readback in sorted(readbacks.items()):
        problems += [f"owner={owner} region={region} logical_id={logical} phase=stored-plan "
                     f"{readback.reason(logical)}" for logical in sorted(readback.failures)
                     if (owner, region, logical) not in closed]
    for key, entry in sorted(here.items()):
        live = shares.get(key[:2], {}).get(key[2])
        if live and live["resourceShareArn"] != entry["share_arn"]:
            problems.append(f"{'/'.join(key)}: stack share {live['resourceShareArn']} differs from "
                            f"recorded {entry['share_arn']}")
        elif live and key in closed and live.get("status") != "DELETED":
            problems.append(f"{'/'.join(key)}: temporary share {entry['share_arn']} is "
                            f"{live.get('status')}, but this record retired it from every consumer")
    leftover_scopes: dict[str, list[str]] = defaultdict(list)
    for owner, region in leftover:
        leftover_scopes[owner].append(region)
    for row in scoped_fanout(leftover_scopes,
                             lambda owner, region: stacks.existing(owner, region) is not None, opts):
        if row.error:
            problems.append(f"owner={row.account} region={row.region} phase=stored-plan {row.error}")
        elif row.value:
            emptied.append((row.account, row.region))
    if problems:
        return refuse(problems)

    temporary = temporary_share_arns(record, shares)
    # The chosen accounts' temporary entitlements this run retires: the scope of every check.
    retiring = {key: replace(stored[key], consumers=tuple(acting[key])) for key in affected}
    checks: list[str] = []
    organizations: dict[str, str] = {}
    baseline = record.get("baseline")
    observation = comparison = None
    if retiring:
        organizations, checks = consumer_organizations(gate, chosen, opts)
        observation = observe(gate, list(retiring.values()), temporary, opts, report,
                              "complete-preflight")
        if not baseline_complete(baseline):
            checks.append("a complete original baseline is required before the temporary path "
                          "is retired")
        else:
            before = baseline.get("consumer_organizations", {})
            checks += [f"consumer {consumer} is not covered by the original baseline; its "
                       "original state was never recorded, so its temporary shares cannot be "
                       "retired safely" for consumer in chosen if consumer not in before]
            checks += [f"entitlement owner={owner} region={region} consumer={consumer} "
                       f"resource={arn} is not covered by the original baseline; its original "
                       "state was never recorded, so its temporary share cannot be retired safely"
                       for owner, region, consumer, arn
                       in uncovered_entitlements(baseline, list(retiring.values()))
                       if consumer in before]
            comparison = verifier().compare(
                scoped_items(baseline["items"], list(retiring.values()), observation), observation)
            if value(comparison, "status") != "INTACT":
                checks += [f"original {loss['reason']}: {loss['key']}"
                           for loss in losses(comparison)] or [
                    f"observation gap {gap.get('collector')} {gap.get('account')} "
                    f"{gap.get('region')} {gap.get('reason')}" for gap in value(comparison, "gaps")]
        # A drop naming no consumer is an owner-side loss that every consumer of that owner
        # and Region relies on.
        checks += [f"failure drop recorded: {drop['kind']} {drop['subject']} first absent "
                   f"{drop['first_absent_at']}" for drop in failure_drops(record)
                   if drop.get("consumer") in chosen or drop.get("consumer") is None and
                   (drop.get("owner"), drop.get("region")) in touched]
        replacement = verifier().replacement_access(gate, list(retiring.values()), temporary,
                                                    workers=args.region_workers)
        for row in replacement["covered"]:
            report.emit(f"phase=replacement status=COVERED consumer={row.get('consumer')} "
                        f"region={row.get('region')} resource={row.get('resource_arn')}")
        checks += [f"phase=replacement consumer={row.get('consumer')} region={row.get('region')} "
                   f"resource={row.get('resource_arn')}: only the temporary share provides access; "
                   "establish permanent replacement sharing first" for row in replacement["uncovered"]]
        checks += [f"phase=replacement gap {gap.get('account')} {gap.get('region')} {gap.get('reason')}"
                   for gap in replacement["gaps"]]
    drops = drops_from(comparison, observation, organizations, "complete",
                       baseline["captured_at"] if baseline else "",
                       f"record revision {record['revision']}")
    if checks and not args.force:
        return refuse(checks, drops)
    forced = bool(checks)
    for problem in checks:
        report.emit(f"phase=complete status=OVERRIDDEN {problem}")

    # Smallest share first: the first action is the canary step.
    order = sorted(affected, key=lambda key: (len(stored[key].resources), *key))
    for key in order:
        owner, region, _logical = key
        detail = (f"share={recorded[key]['share_arn']} consumers={','.join(acting[key])} "
                  f"resources={len(stored[key].resources)}")
        if keeping[key]:
            report.emit(f"owner={owner} region={region} phase=complete action=REMOVE_PRINCIPALS "
                        f"{detail} retained_consumers={','.join(keeping[key])}")
        else:
            report.emit(f"owner={owner} region={region} phase=complete action=DELETE_SHARE {detail}")
    for owner, region in sorted(emptied):
        report.emit(f"owner={owner} region={region} phase=complete action=DELETE_STACK "
                    f"stack={stack_name(migration, owner, region)}")
    run: dict[str, Any] = {"consumers": chosen}
    if forced:
        run["forced"] = True
    elif args.force:
        run["force"] = "unused"  # nothing failed, so --force changed nothing
    deleted: list[str] = []
    removed = 0  # principals removed
    removed_stacks: list[str] = []
    overridden = list(checks)
    if affected or emptied:
        if forced:
            token = f"FORCE-COMPLETE {migration}"
            prompt = (f"Type {token} to retire the temporary access of {listed(chosen)} with the "
                      f"actions above despite the failed safety checks overridden above "
                      f"({len(checks)}); these accounts may lose access to the resources above: ")
        elif chosen:
            token = f"COMPLETE {migration}"
            prompt = (f"Type {token} to retire the temporary access of {listed(chosen)} with the "
                      "actions above, re-verifying after each: ")
        else:
            token = f"COMPLETE {migration}"
            prompt = f"Type {token} to delete the emptied migration stacks above: "
        try:
            reply = ask(prompt)
        except EOFError:
            reply = ""
        if reply != token:
            report.emit("status=CANCELLED Confirmation did not match; no AWS writes requested")
            return 2
        if forced:
            note("FORCED", lambda current: add_drops(current, drops), overridden=checks,
                 drops=len(drops), **run)
        gate.open = True

    def retire(key: tuple[str, str, str], consumers: list[str],
               action: str) -> Callable[[dict], Any]:
        """One retirement entry per (share, consumer), each recorded once."""
        entry = recorded[key]
        rows = [{"consumer": consumer, "owner": entry["owner"], "region": entry["region"],
                 "logical_id": entry["logical_id"], "share_arn": entry["share_arn"],
                 "action": action, "at": timestamp(), "forced": forced} for consumer in consumers]

        def mutate(current: dict) -> None:
            known = retired_pairs(current)
            current.setdefault("retirements", []).extend(
                row for row in rows if (row["share_arn"], row["consumer"]) not in known)
        return mutate

    def check(groups: list, phase: str) -> tuple[list[str], list[dict]]:
        """After a write: re-verify for the settle window, or when forced observe once."""
        try:
            return settle(gate, groups, baseline, temporary, organizations, opts, report, phase,
                          seconds=0 if forced else None)
        except Exception as exc:  # an observation that fails never passes
            return [f"{phase} observation failed: {failure_text(exc)}"], []

    def stopped(problems: list[str], found: list[dict], retained: str) -> int:
        for problem in problems:
            report.emit(f"status=FAILED phase=complete {problem}")
        report.emit(f"Completion stopped; {retained} retained.")
        note("FAILED", lambda current: add_drops(current, found), failures=problems,
             deleted=list(deleted), principals_removed=removed, **run)
        return 1

    # The losses this run recorded: one still absent at a later observation is the same
    # loss, first absent when first recorded, never a new drop.
    lost = {(drop["kind"], drop["consumer"], drop["region"], drop["subject"]) for drop in drops}

    def overrode(problems: list[str], found: list[dict], **details: Any) -> None:
        """When forced, a loss or gap after a write is reported and recorded, not stopped at."""
        for problem in problems:
            report.emit(f"phase=complete status=OVERRIDDEN {problem}")
        overridden.extend(problems)
        found = [drop for drop in found
                 if (drop["kind"], drop["consumer"], drop["region"], drop["subject"]) not in lost]
        lost.update((drop["kind"], drop["consumer"], drop["region"], drop["subject"])
                    for drop in found)
        note("OVERRIDDEN", lambda current: add_drops(current, found), problems=problems,
             drops=len(found), **details, **run)

    for index, key in enumerate(order, 1):
        owner, region, _logical = key
        arn, consumers = recorded[key]["share_arn"], acting[key]
        status, action = ("PRINCIPALS_REMOVED", "PRINCIPAL_REMOVED") if keeping[key] else \
            ("SHARE_DELETED", "SHARE_DELETED")
        try:
            if keeping[key]:
                remove_principals(gate, owner, region, arn, migration, consumers,
                                  timeout=args.timeout)
            else:
                delete_share(gate, owner, region, arn, migration, timeout=args.timeout)
        except (Exception, KeyboardInterrupt) as exc:
            # A call can fail, or be interrupted, after AWS acted: what the share now holds,
            # read back through a closed gate, is what the record keeps.
            interrupted = isinstance(exc, KeyboardInterrupt)
            failure = "interrupted" if interrupted else failure_text(exc)
            try:
                gone = sorted(unserved_consumers(WriteGate(router), owner, region, arn, consumers))
            except Exception as unread:
                gone = []
                report.emit(f"owner={owner} region={region} share={arn} phase=record "
                            f"status=UNKNOWN the share could not be read back "
                            f"({failure_text(unread)}); run complete with this record again "
                            "to reconcile it")
            if gone and keeping[key]:
                removed += len(gone)
            elif gone:
                deleted.append(arn)
            report.emit(f"status={'INTERRUPTED' if interrupted else 'FAILED'} share={arn} "
                        f"phase=complete {failure}" + (f" retired={','.join(gone)}" if gone else ""))
            note("INTERRUPTED" if interrupted else "FAILED", retire(key, gone, action),
                 failures=[failure], share=arn, retired=gone, deleted=list(deleted),
                 principals_removed=removed, **run)
            if interrupted:
                raise
            return 1
        if keeping[key]:
            removed += len(consumers)
        else:
            deleted.append(arn)
        report.emit(f"owner={owner} region={region} share={arn} phase=complete status={status} "
                    f"consumers={','.join(consumers)}")
        note(status, retire(key, consumers, action), share=arn, retired=consumers,
             deleted=list(deleted), principals_removed=removed, **run)
        problems, found = check([retiring[key]], f"complete-settle-{index}")
        if problems and not forced:
            return stopped(problems, found, "the remaining temporary shares are")
        if problems:
            overrode(problems, found, share=arn)
    if retiring:
        problems, found = check(list(retiring.values()), "complete-final")
        if problems and not forced:
            return stopped(problems, found, "the migration stacks are")
        if problems:
            overrode(problems, found)
    for owner, region in sorted(emptied):
        try:
            removed_stacks.append(stacks.delete(owner, region))
        except Exception as exc:
            report.emit(f"status=FAILED owner={owner} region={region} phase=complete "
                        f"{failure_text(exc)}")
            note("FAILED", failures=[failure_text(exc)], deleted=list(deleted),
                 stacks=list(removed_stacks), principals_removed=removed, **run)
            return 1
        report.emit(f"owner={owner} region={region} phase=complete status=STACK_DELETED")

    # COMPLETED once no account remains: every recorded share is then deleted, and so is
    # every migration stack, by this run or an earlier one.
    retired = retired_consumers(record)
    remaining = sorted(served - retired)
    status = "PARTIALLY_COMPLETED" if remaining else "COMPLETED"
    completion = {"completed_at": timestamp(), "deleted_shares": deleted,
                  "deleted_stacks": removed_stacks, "consumer_organizations": organizations,
                  "forced": forced, "overridden": overridden}
    note(status, (lambda _current: None) if remaining else
         (lambda current: current.__setitem__("completion", completion)),
         deleted=len(deleted), principals_removed=removed, stacks=len(removed_stacks),
         retired=sorted(retired), remaining=remaining, **run)
    line = (f"status={status} migration={migration} deleted_shares={len(deleted)} "
            f"deleted_stacks={len(removed_stacks)} removed_principals={removed} "
            f"retired_accounts={listed(retired)} remaining_accounts={listed(remaining)}")
    if forced:
        line += f" forced=true overridden={len(overridden)}"
    elif retiring:
        line += " original baseline intact"
    report.emit(line + excluded)
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


def baseline_groups(baseline: dict, consumers: list[str]) -> list[Group]:
    """One observation group per owner, Region and consumer, from the baseline's
    entitlements: the monitor observes exactly what the pre-migration snapshot holds."""
    resources: dict[tuple[str, str, str], dict[str, str]] = defaultdict(dict)
    for item in baseline.get("items", []):
        if item["kind"] == "entitlement" and item.get("consumer") in consumers:
            if not item.get("type"):
                raise MigrationError(f"baseline entitlement {item['key']} records no resource type")
            resources[item["owner"], item["region"], item["consumer"]][item["resource_arn"]] = item["type"]
    return [Group(owner, region, (consumer,), {}, dict(sorted(arns.items())))
            for (owner, region, consumer), arns in sorted(resources.items())]


MONITOR_EXIT = {"UNCHANGED": 0, "CHANGED": 0, "INCONCLUSIVE": 3, "LOSS": 1}


def run_monitor(router: Router, opts: Options, report: Reporter) -> int:
    """On demand and read-only in AWS: what changed for the chosen migrating accounts
    since the pre-migration baseline. Each run is recorded with its new drop events.

    UNCHANGED or CHANGED (only expected changes: an original share no longer reaching
    a consumer, a share added, an item added, a new organization) exit 0; INCONCLUSIVE
    (no complete baseline, a read gap, an unknown organization) exits 3; LOSS (a
    baseline item missing or degraded) exits 1."""
    args = opts.args
    record = load_record(args.record, args.migration_id)
    migration = record["migration_id"]
    fill_scope_from_record(opts, record)
    chosen = selected_consumers(opts, record)
    report_verification_exclusions(opts, report)
    report_consumer_exclusions(opts, report)
    excluded = (exclusion_text(exclusion_scope(opts))
                + verification_exclusion_text(verification_exclusions(opts)))
    baseline = record.get("baseline")
    retired = retired_consumers(record)
    reasons: list[str] = []
    if baseline is None:
        reasons.append("no original baseline is recorded; apply captures it before its first write")
    elif not baseline_complete(baseline):
        reasons += [f"the original baseline is incomplete: {gap.get('collector')} {gap.get('account')} "
                    f"{gap.get('region')} {gap.get('reason')}" for gap in baseline_gaps(baseline)] \
            or ["the original baseline is incomplete"]
    before = (baseline or {}).get("consumer_organizations", {})
    ignored = untracked(baseline, chosen) if baseline is not None else set()
    for consumer in sorted(ignored):
        report.emit(f"consumer={consumer} phase=monitor status=NOT_TRACKED the original baseline "
                    "records nothing for this account (it received nothing to protect), so "
                    "nothing of it is compared")
    reasons += [f"consumer {consumer} is not covered by the original baseline"
                for consumer in chosen
                if baseline is not None and consumer not in before and consumer not in ignored]
    groups = baseline_groups(baseline, chosen) if baseline is not None else []

    def finish(status: str, details: dict) -> int:
        nonlocal record
        code = MONITOR_EXIT[status]
        entry = {"at": details.pop("at", timestamp()), "mode": "monitor", "consumers": chosen,
                 "monitor_status": status, "reasons": sorted(set(reasons)), **details}
        drops = entry.pop("new_drops", [])

        def mutate(current: dict) -> None:
            entry["recorded_drops"] = add_drops(current, drops)
            current.setdefault("verifications", []).append(entry)
        for reason in sorted(set(reasons)):
            report.emit(f"phase=monitor status={status} {reason}")
        try:
            record = update_record(args.record, migration, mutate, mode="monitor", status=status,
                                   consumers=chosen, drops=len(drops))
            recorded = f"recorded_drops={entry['recorded_drops']} revision={record['revision']}"
        except MigrationError as exc:
            # The report stands, but its drops are not evidence for complete: never exit 0.
            report.emit(f"phase=record status=NOT_RECORDED {failure_text(exc)}")
            recorded, code = "recorded=false", code or 1
        counts = " ".join(f"{name}={len(entry.get('changes', {}).get(name, []))}" for name in (
            "original_share_drops", "shares_added", "lost", "degraded", "added", "unobserved"))
        report.emit(f"status={status} migration={migration} phase=monitor consumers={','.join(chosen)} "
                    f"{counts} gaps={entry.get('gaps', 0)} {recorded} exit_code={code}{excluded}")
        return code

    report.emit(f"migration={migration} phase=monitor status=STARTED consumers={','.join(chosen)} "
                f"baseline_captured_at={(baseline or {}).get('captured_at')} "
                f"baseline_items={len((baseline or {}).get('items', []))}{excluded}")
    if not baseline_complete(baseline):
        return finish("INCONCLUSIVE", {})
    blocked = authenticate(router, {g.owner for g in groups} | set(chosen), opts, report)
    if blocked:
        reasons += blocked
        return finish("INCONCLUSIVE", {})
    gate = WriteGate(router)  # never opened: the monitor only reads AWS
    temporary = temporary_share_arns(record, {})
    observation = observe(gate, groups, temporary, opts, report, "monitor") if groups else \
        {"observed_at": timestamp(), "items": [], "gaps": []}
    items = scoped_items(baseline["items"], groups, observation)
    comparison = verifier().compare(items, observation)
    organizations, errors = consumer_organizations(gate, chosen, opts)
    reasons += errors
    for consumer in chosen:
        now = organizations.get(consumer, "UNKNOWN")
        change = "UNKNOWN" if consumer not in organizations or consumer not in before else \
            "UNCHANGED" if now == before[consumer] else "CHANGED"
        if change == "UNKNOWN" and consumer in before:
            reasons.append(f"current organization of {consumer} is unknown")
        report.emit(f"consumer={consumer} phase=monitor organization_at_baseline="
                    f"{before.get(consumer, 'NOT_RECORDED')} organization_now={now} "
                    f"organization_change={change}"
                    + (" temporary_access=RETIRED" if consumer in retired else ""))
    dropped, gained = share_changes(items, observation, temporary)
    for label, rows in (("ORIGINAL_SHARE_DROPPED", dropped), ("SHARE_ADDED", gained)):
        for row in rows:
            item = row["item"]
            report.emit(f"consumer={item['consumer']} region={item['region']} owner={item['owner']} "
                        f"resource={item['resource_arn']} phase=monitor change={label} "
                        f"share={row['share']} access={row['access']}")
    for entry in value(comparison, "missing"):
        report.emit(f"phase=monitor change=LOST key={entry['key']} {describe_item(entry['item'])}")
    for entry in value(comparison, "degraded"):
        report.emit(f"phase=monitor change=DEGRADED key={entry['key']} "
                    f"reasons={json.dumps(entry['reasons'])} {describe_item(entry['after'])}")
    current = {item["key"]: item for item in value(observation, "items")}
    for key in value(comparison, "added"):
        report.emit(f"phase=monitor change=ADDED key={key} {describe_item(current[key])}")
    for entry in value(comparison, "unobserved"):
        report.emit(f"phase=monitor change=UNOBSERVED key={entry['key']} "
                    f"reasons={json.dumps(entry['reasons'])}")
    evidence = f"record revision {record['revision']}"
    drops = drops_from(comparison, observation, organizations, "monitor", baseline["captured_at"],
                       evidence)
    drops += original_share_drops(dropped, observation, organizations, "monitor",
                                  baseline["captured_at"], evidence)
    # (consumer, key) per change; owner-side items such as Resolver endpoints have no consumer.
    found = {"original_share_drops": [(r["item"]["consumer"], f"{r['item']['key']}|{r['share']}")
                                      for r in dropped],
             "shares_added": [(r["item"]["consumer"], f"{r['item']['key']}|{r['share']}")
                              for r in gained],
             "lost": [(e["item"].get("consumer"), e["key"]) for e in value(comparison, "missing")],
             "degraded": [(e["before"].get("consumer"), e["key"])
                          for e in value(comparison, "degraded")],
             "added": [(current[key].get("consumer"), key) for key in value(comparison, "added")],
             "unobserved": [(e["before"].get("consumer"), e["key"])
                            for e in value(comparison, "unobserved")]}
    changes = {name: sorted(key for _, key in rows) for name, rows in found.items()}
    state = value(comparison, "status")
    moved = any(organizations.get(c) not in (None, before.get(c)) for c in chosen)
    status = "LOSS" if state == "LOSS" else "INCONCLUSIVE" if state != "INTACT" or reasons else \
        "CHANGED" if moved or any(changes[name] for name in (
            "original_share_drops", "shares_added", "added")) else "UNCHANGED"
    for consumer in chosen:
        report.emit(f"consumer={consumer} phase=monitor " + " ".join(
            f"{name}={sum(who == consumer for who, _ in rows)}" for name, rows in found.items()))
    return finish(status, {"at": value(observation, "observed_at"), "baseline_status": state,
                           "gaps": len(value(observation, "gaps")), "changes": changes,
                           "consumer_organizations": organizations, "new_drops": drops,
                           "retired_consumers": sorted(retired & set(chosen))})


def main(argv: list[str] | None = None, *, input_fn: Callable[[str], str] | None = None,
         readable: bool = False) -> int:
    """``readable`` renders the run for people (ram_migration_console) unless --raw-output
    asks for the technical event stream, which is always what the run itself emits."""
    state: dict[str, Any] = {"report": Reporter()}
    code = None
    try:
        code = _run(argv, input_fn, readable, state)
        return code
    finally:
        report = state["report"]
        close = getattr(report, "close", None)
        if close is not None:
            if code is not None:
                report.exit_code = code  # the readable result shows the code the run returns
            close()


def _run(argv: list[str] | None, input_fn: Callable[[str], str] | None, readable: bool,
         state: dict[str, Any]) -> int:
    report: Any = state["report"]
    args = opts = None
    try:
        args = build_parser().parse_args(argv)
        if readable and not args.raw_output:
            from ram_migration_console import ReadableReporter
            report = state["report"] = ReadableReporter(args.mode, args)
        reply = input_fn if input_fn is not None else input

        def ask(prompt: str) -> str:
            flush = getattr(report, "flush", None)
            if flush is not None:
                flush()  # everything a confirmation covers is on screen before it
            return reply(prompt)
        opts = options(args, ask)
        report.context = opts
        if args.mode == "approve":
            return run_approve(opts, ask, report)
        if args.mode != "monitor":
            check_sdk()  # Offline service-model preflight, before authenticating.
        router = Router(opts.profiles, opts.mappings, role_name=args.role_name,
                        sso_role=args.sso_role or "")
        if args.mode == "complete":
            return run_complete(router, opts, ask, report)
        if args.mode == "monitor":
            return run_monitor(router, opts, report)
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
    raise SystemExit(main(readable=True))
