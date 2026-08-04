#!/usr/bin/env python3
"""Interactive orchestration for additive RAM migration shares (Python 3.11+).

Plan is the default and cannot request writable clients. With ``--record`` it
writes a versioned migration record that ``approve``, ``apply`` and ``verify``
consume. Approve binds explicit approvals to exact permission changes and owner
scope. Apply requires a PLANNED record revision whose entitlements still match
live discovery, then opens its write gate only after complete preflight and
the exact ``APPLY <migration-id>`` reply.
This tool neither moves accounts nor cleans up shares or Resolver associations.
"""
from __future__ import annotations

import argparse
import importlib
import json
import random
import re
import sys
import threading
import time
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from botocore.exceptions import (
    BotoCoreError, ClientError, ConnectionClosedError, ConnectTimeoutError,
    EndpointConnectionError, ReadTimeoutError,
)

from ram_migration_common import (
    Api, Group, MigrationError, Plan, Router, account_id, check_sdk, digest,
    error_text, pages, timestamp,
)
from ram_migration_discovery import (
    Discovery, describe_difference, external_catalog, revalidate_change,
)
from ram_migration_record import (
    APPLICABLE, approval_for, approve_owner_scope, approve_permission_change, approved_owners,
    latest, new_record, owner_scope_request, pending_requests, permission_requests,
    plan_digest, tool_identity,
)
from ram_migration_record import load as load_record
from ram_migration_record import update as update_record
from ram_migration_stacks import Stacks, accept, stack_name, verify_group

RAM_HOME_REGION = "us-east-1"
REGION = re.compile(r"^[a-z]{2}(?:-[a-z]+)+-\d+$")
ROLE = re.compile(r"^arn:[a-z0-9-]+:iam::([0-9]{12}):role/[A-Za-z0-9+=,.@_/-]+$")
TRANSIENT_CODES = {
    "Throttling", "ThrottlingException", "TooManyRequestsException",
    "RequestLimitExceeded", "ServiceUnavailable", "ServiceUnavailableException",
    "InternalError", "InternalFailure", "InternalServerException",
    "ResourceShareInvitationArnNotFoundException", "UnknownResourceException",
}


def failure_text(exc: Exception) -> str:
    operation = f"operation={exc.operation_name} " if isinstance(exc, ClientError) else ""
    return operation + error_text(exc)


def bounded_integer(value: str) -> int:
    number = int(value)
    if not 1 <= number <= 64:
        raise argparse.ArgumentTypeError("use an integer between 1 and 64")
    return number


def positive_number(value: str) -> float:
    number = float(value)
    if not 0 < number < float("inf"):
        raise argparse.ArgumentTypeError("use a positive finite number")
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
                        choices=("plan", "approve", "apply", "verify", "monitor"),
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
    parser.add_argument("--timeout", type=positive_number, default=1800,
                        help="seconds per stack operation or invitation/verification polling task")
    parser.add_argument("--retry-limit", "--retries", type=bounded_integer, default=20,
                        help="bounded eventual-consistency/transient polling attempts")
    parser.add_argument("--poll-interval", type=positive_number, default=2,
                        help="initial polling delay in seconds, with bounded jitter/backoff")
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


MIGRATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}")


def options(args: argparse.Namespace, ask: Callable[[str], str]) -> Options:
    if args.mode == "approve":
        # Approval is an offline review of the record; it needs no AWS access.
        if not args.record:
            raise MigrationError("approve requires --record")
        if args.migration_id and not MIGRATION_ID.fullmatch(args.migration_id):
            raise MigrationError("Supply a valid --migration-id or omit it to use the record's")
        return Options(args, [], [], [], [], {}, {}, None, {})
    if args.mode in ("apply", "verify") and not args.record:
        raise MigrationError(f"{args.mode} requires --record: the reviewed migration record "
                             "written by plan")
    interactive = args.interactive or sys.stdin.isatty()
    if args.mode != "monitor" and interactive:
        if not args.migration_id:
            args.migration_id = ask("Migration identifier: ").strip()
        if not args.owners:
            args.owners = [ask("Owner/inspection account IDs (comma or space separated): ").split()]
        if args.mode in ("plan", "apply") and not args.consumers:
            args.consumers = [ask("Migrating consumer account IDs (comma or space separated): ").split()]
        if not args.regions and not args.scan_enabled_regions:
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
        if not owners:
            raise MigrationError("Supply explicit --owners/--accounts")
        if args.mode in ("plan", "apply") and not consumers:
            raise MigrationError("Supply explicit --consumers")
        if not regions and not args.scan_enabled_regions:
            raise MigrationError("Supply --regions or --scan-enabled-regions")
    if args.export_plan and args.mode not in ("plan", "apply"):
        raise MigrationError("--export-plan is supported only for plan/apply")
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
    if interactive and set(owners + consumers) - set(mappings) and not args.sso_role and not args.role_name:
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
                   json_object(args.monitor_config, "monitor-config"))


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
    def __init__(self):
        self.lock = threading.Lock()

    def emit(self, message: str) -> None:
        with self.lock:
            print(message, flush=True)


@dataclass
class Outcome:
    account: str
    region: str
    value: Any = None
    error: str | None = None


def fanout(scopes: dict[str, list[str]], callback: Callable[[str, str], Any],
           account_workers: int, region_workers: int) -> list[Outcome]:
    """At most account_workers accounts and region_workers tasks per account."""
    def one_account(account: str) -> list[Outcome]:
        output = []
        with ThreadPoolExecutor(max_workers=region_workers) as executor:
            futures = {executor.submit(callback, account, region): region
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
        futures = [executor.submit(one_account, account) for account in sorted(scopes)]
        for future in as_completed(futures):
            output.extend(future.result())
    return sorted(output, key=lambda row: (row.account, row.region))


def scoped_fanout(scopes, callback, opts: Options):
    return fanout(scopes, callback, opts.args.account_workers, opts.args.region_workers)


def authenticate(router: Router, accounts: set[str], opts: Options, report: Reporter) -> list[str]:
    def check(account, _region):
        router.session(account)  # Router validates the actual STS caller, not its profile label.
        report.emit(f"account={account} phase=authentication status=VERIFIED")
    return [f"account={row.account} phase=authentication status=BLOCKED {row.error}"
            for row in scoped_fanout({account: ["identity"] for account in accounts}, check, opts)
            if row.error]


def region_scopes(router: WriteGate, opts: Options, report: Reporter,
                  dependencies: dict[str, set[str]] | None = None) -> tuple[dict, list[str]]:
    """Explicit Regions, plus every Region where a migrating account receives
    this owner's resources (consumer-driven), plus all enabled Regions on request."""
    dependencies = dependencies or {}
    scopes = {owner: sorted(set(opts.regions) | dependencies.get(owner, set()))
              for owner in opts.owners}
    failures = []
    if opts.args.scan_enabled_regions:
        def scan(owner, _region):
            rows = router.client(owner, "ec2", RAM_HOME_REGION).describe_regions(AllRegions=True)["Regions"]
            enabled = [r["RegionName"] for r in rows
                       if r.get("OptInStatus") in ("opt-in-not-required", "opted-in")]
            if not enabled:
                raise MigrationError("No enabled Regions returned; discovery scope is unresolved")
            return sorted(set(opts.regions + enabled) | dependencies.get(owner, set())), set(enabled)
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
        }

    def to_dict(self) -> dict:
        entries = [{k: v for k, v in entry.items() if k != "context"} for entry in self.entries]
        return {"scopes": self.scopes, "counts": self.counts(), "entries": entries,
                "blocked": self.blocked, "excluded": self.excluded}


def received_scopes(router: WriteGate, opts: Options,
                    report: Reporter) -> tuple[dict[str, list[str]], list[str]]:
    """Consumer-driven: every enabled Region of every migrating account, plus
    RAM's global home. Stationary owners are not audited: their own received
    dependencies are not affected by the migration."""
    failures = []
    failed_accounts = set()
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
        scopes[account] = sorted(known | {RAM_HOME_REGION})
    return scopes, failures


def received_inventory(router: WriteGate, opts: Options, report: Reporter) -> ReceivedAudit:
    """Read-only inventory of what the migrating accounts actually receive."""
    scopes, errors = received_scopes(router, opts, report)
    audit = ReceivedAudit(scopes=scopes, blocked=errors)

    def inspect(account, region):
        result = ReceivedAudit()
        ram = router.client(account, "ram", region)
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

    for row in scoped_fanout(scopes, inspect, opts):
        if row.error:
            audit.blocked.append(f"account={row.account} region={row.region} "
                                 f"phase=received-audit status=BLOCKED {row.error}")
        else:
            audit.entries.extend(row.value.entries)
            audit.blocked.extend(row.value.blocked)
    return audit


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
            f"Approve the proposed owner list, then re-run plan with an explicit profile/role mapping for "
            f"{owner}. Received resources cannot be re-shared by the receiving account")
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


@dataclass(frozen=True, order=True)
class Association:
    association_id: str
    rule_id: str
    vpc_id: str
    status: str


@dataclass
class ResolverSnapshot:
    observed_at: str = field(default_factory=timestamp)
    records: dict[tuple[str, str, str], tuple[Association, ...]] = field(default_factory=dict)


def resolver_snapshot(router: WriteGate, groups: list[Group], opts: Options,
                      report: Reporter, phase: str) -> tuple[ResolverSnapshot, list[str]]:
    """Resolve IDs from the owner's actual rule inventory; never parse IDs from ARNs."""
    snapshot = ResolverSnapshot()
    wanted: dict[tuple[str, str], set[str]] = defaultdict(set)
    expected: dict[tuple[str, str], set[tuple[str, str, str]]] = defaultdict(set)
    for group in groups:
        for arn, kind in group.resources.items():
            if kind.lower() in ("route53resolver:resolverrule", "route53resolver:resolver-rule"):
                wanted[group.owner, group.region].add(arn)
                for consumer in group.consumers:
                    expected[consumer, group.region].add((group.owner, group.region, arn))
    failures = []
    rules: dict[tuple[str, str, str], str] = {}
    owner_scopes: dict[str, list[str]] = defaultdict(list)
    for owner, region in wanted:
        owner_scopes[owner].append(region)

    def rule_ids(owner, region):
        rows = pages(router.client(owner, "route53resolver", region),
                     "list_resolver_rules", "ResolverRules")
        found = {r["Arn"]: r["Id"] for r in rows if r.get("Arn") in wanted[owner, region]}
        if set(found) != wanted[owner, region] or any(not value for value in found.values()):
            raise MigrationError("Cannot resolve all planned Resolver rule IDs from the owner inventory")
        return found

    for row in scoped_fanout(owner_scopes, rule_ids, opts):
        if row.error:
            failures.append(f"owner={row.account} region={row.region} phase={phase} {row.error}")
        else:
            rules.update({(row.account, row.region, arn): rule for arn, rule in row.value.items()})
    if failures:
        return snapshot, failures

    consumer_scopes: dict[str, list[str]] = defaultdict(list)
    for consumer, region in expected:
        consumer_scopes[consumer].append(region)

    def associations(consumer, region):
        rows = pages(router.client(consumer, "route53resolver", region),
                     "list_resolver_rule_associations", "ResolverRuleAssociations")
        result = {}
        for key in expected[consumer, region]:
            arn, rule_id = key[2], rules[key]
            matches = [r for r in rows if r.get("ResolverRuleId") == rule_id]
            if any(not all(r.get(field) for field in ("Id", "ResolverRuleId", "VPCId", "Status"))
                   for r in matches):
                raise MigrationError(f"{arn}: Resolver association identity/status fields missing")
            records = tuple(sorted(Association(r["Id"], r["ResolverRuleId"], r["VPCId"], r["Status"])
                                   for r in matches))
            if len({record.association_id for record in records}) != len(records):
                raise MigrationError(f"{arn}: duplicate Resolver association IDs")
            result[consumer, region, arn] = records
        return result

    for row in scoped_fanout(consumer_scopes, associations, opts):
        if row.error:
            failures.append(f"consumer={row.account} region={row.region} phase={phase} {row.error}")
            continue
        snapshot.records.update(row.value)
        for (consumer, region, arn), records in sorted(row.value.items()):
            if not records:
                report.emit(f"consumer={consumer} region={region} resource={arn} phase={phase} "
                            "status=MISSING_ASSOCIATION no association observed; sharing does not repair it")
            for record in records:
                report.emit(f"consumer={consumer} region={region} resource={arn} phase={phase} "
                            f"vpc={record.vpc_id} rule={record.rule_id} association={record.association_id} "
                            f"status={record.status} timestamp={snapshot.observed_at}")
                if record.status != "COMPLETE":
                    failures.append(f"{consumer}/{region}/{arn}/{record.association_id}: "
                                    f"Resolver association {record.status} during {phase}")
    return snapshot, failures


def compare_resolver(before: ResolverSnapshot, after: ResolverSnapshot) -> list[str]:
    failures = []
    for key, original in before.records.items():
        current = after.records.get(key)
        if current is None or original != current:
            failures.append(f"consumer={key[0]} region={key[1]} resource={key[2]} "
                            "phase=resolver-comparison status=INCOMPLETE "
                            f"association state changed: before={original!r} after={current!r}")
    return failures


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
    for reason in plan.blocked:
        report.emit(f"phase=preflight status=BLOCKED {reason}")


def account_scope(opts: Options) -> dict:
    """Explicit account roles; a stationary owner's own dependencies are not at risk."""
    owners, consumers = set(opts.owners), set(opts.consumers)
    return {
        "migrating_consumers": sorted(consumers - owners),
        "migrating_owners": sorted(owners & consumers),
        "stationary_owners": sorted(owners - consumers),
        "regions": sorted(opts.regions),
        "scan_enabled_regions": bool(opts.args.scan_enabled_regions),
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
            report.emit(f"  share={share}")
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
                  migration: str) -> list[dict]:
    """Created-share identifiers accumulate; a recorded share is never forgotten."""
    known = {(r["owner"], r["region"], r["logical_id"]): dict(r) for r in previous}
    for group in groups:
        share = shares.get((group.owner, group.region), {}).get(group.logical_id)
        if not share:
            continue
        key = (group.owner, group.region, group.logical_id)
        entry = known.setdefault(key, {
            "owner": group.owner, "region": group.region, "logical_id": group.logical_id,
            "entitlement_hash": group.key, "stack": stack_name(migration, group.owner, group.region),
            "first_recorded_at": timestamp()})
        if entry.get("share_arn") not in (None, share["resourceShareArn"]):
            raise MigrationError(f"{group.owner}/{group.region}/{group.logical_id}: recorded share "
                                 f"{entry['share_arn']} differs from {share['resourceShareArn']}")
        entry["share_arn"] = share["resourceShareArn"]
        entry["consumers"] = sorted(set(entry.get("consumers", [])) | set(group.consumers))
        entry["last_verified_at"] = timestamp()
    return [known[k] for k in sorted(known)]


def run_approve(opts: Options, ask: Callable[[str], str], report: Reporter) -> int:
    path = opts.args.record
    record = load_record(path, opts.args.migration_id)
    migration = record["migration_id"]
    if latest(record, "plan") is None:
        raise MigrationError("approve requires a recorded plan; run plan --record first")
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
                    "in this migration. Original shares are not modified, and AWS attaches only "
                    "the current default version.")
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


def summary(plan: Plan, report: Reporter, status: str, *, created: int = 0, reused: int = 0,
            accepted: int = 0, reused_invitations: int = 0, failures: int = 0,
            missing_baseline: int = 0) -> None:
    resources = {arn for group in plan.groups for arn in group.resources}
    entitlements = {(group.owner, group.region, arn, consumer, group.permissions[kind])
                    for group in plan.groups for arn, kind in group.resources.items()
                    for consumer in group.consumers}
    report.emit(f"status={status} migration={plan.migration} resources_in_plan={len(resources)} "
                f"expected_entitlements={len(entitlements)} planned_shares={len(plan.groups)} "
                f"created_shares={created} reused_shares={reused} accepted_invitations={accepted} "
                f"reused_invitations={reused_invitations} exclusions={len(plan.excluded)} "
                f"blockers={len(plan.blocked)} verification_failures={failures} "
                f"missing_preexisting_associations={missing_baseline}")
    report.emit("Sharing status is not live migration acceptance evidence. "
                "Resource totals cover planned entitlements; excluded inventory is reported separately.")
    if missing_baseline:
        report.emit("Resolver continuity is unproven where preexisting associations were absent; "
                    "no association repair was performed.")


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
    approved_owner_scope = approved_owners(record) if record else set()
    added_owners = sorted(approved_owner_scope - set(opts.owners))
    if added_owners:
        opts.owners = sorted(set(opts.owners) | approved_owner_scope)
        report.emit(f"phase=owner-scope status=APPROVED owners={','.join(added_owners)} "
                    "source=record; supply profile/role mappings for these owners")
    scope = account_scope(opts)
    scope["approved_owner_scope"] = sorted(approved_owner_scope)
    approvals = record["approvals"]["permission_changes"] if record else []

    def note(status: str, mutate: Callable[[dict], Any] = lambda _record: None,
             **details: Any) -> None:
        """Apply/verify outcomes, including blocked and failed runs, are history."""
        nonlocal record
        if record is not None and args.mode in ("apply", "verify"):
            record = update_record(args.record, plan.migration, mutate, mode=args.mode,
                                   status=status, **details)
    plan.blocked.extend(authenticate(router, set(opts.owners + opts.consumers), opts, report))
    if plan.blocked:
        if not args.sso_role and not args.role_name:
            report.emit("For unmapped accounts, supply explicit --sso-role or an "
                        "--account-map/--profile-map/--role-map.")
        print_plan(plan, {}, report)
        summary(plan, report, "BLOCKED")
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
        # Regions must be inspected, so the inventory comes first.
        received = received_inventory(gate, opts, report)
    scopes, failures = region_scopes(gate, opts, report, dependency_regions(received))
    plan.blocked.extend(failures)
    stacks = Stacks(gate, plan.migration, timeout=args.timeout)
    if not callable(getattr(stacks, "persisted_groups", None)):
        raise MigrationError("Stacks.persisted_groups(owner, region) is required for stored-scope verification")
    persisted: set[str] = set()
    persisted_groups: dict[tuple[str, str], list[Group]] = {}
    def load_persisted(owner, region):
        if stacks.existing(owner, region) is None:
            return []
        groups = stacks.persisted_groups(owner, region)
        validate_groups(groups, {owner: [region]})
        return groups
    for row in scoped_fanout(scopes, load_persisted, opts):
        if row.error:
            plan.blocked.append(f"owner={row.account} region={row.region} phase=stored-plan {row.error}")
        else:
            if row.value:
                persisted_groups[row.account, row.region] = row.value
            persisted.update(group.key for group in row.value)
            merge_plan(plan, Plan(plan.migration, groups=row.value))

    capability_provenance: dict = {}
    proposed: dict[str, dict] = {}
    if args.mode != "verify":
        capabilities, capability_provenance = capabilities_for(opts)
        report.emit(f"phase=plan capability_provenance={json.dumps(capability_provenance, sort_keys=True)}")
        discovery = Discovery(gate, set(opts.consumers), plan.migration, opts.principals, capabilities,
                              approved_changes=approvals,
                              migrating_owners=set(scope["migrating_owners"]))
        def inspect(owner, region):
            report.emit(f"owner={owner} region={region} phase=discovery status=STARTED")
            result = discovery.inspect(owner, region)
            validate_groups(result.groups, {owner: [region]})
            if any(set(group.consumers) - set(opts.consumers) for group in result.groups):
                raise MigrationError("Discovery returned consumers outside the approved population")
            return result
        for row in scoped_fanout(scopes, inspect, opts):
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
                                 opts):
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
    baseline = ResolverSnapshot()
    if args.mode == "apply" and not plan.blocked:
        baseline, failures = resolver_snapshot(gate, plan.groups, opts, report, "resolver-before")
        plan.blocked.extend(failures)
    missing_baseline = sum(not records for records in baseline.records.values())
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
        summary(plan, report, "BLOCKED", missing_baseline=missing_baseline)
        note("BLOCKED", blockers=list(plan.blocked))
        return 1
    if args.mode == "plan":
        summary(plan, report, "PLANNED")
        return 0
    if not plan.groups:
        report.emit("status=INCOMPLETE No stored/planned migration entitlements found in the requested scope")
        summary(plan, report, "INCOMPLETE", failures=1)
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
            return 2
        # Recheck every template before opening the gate, so a newly visible
        # blocker in any Region prevents writes to every Region.
        for row in scoped_fanout(group_scopes,
                                 lambda owner, region: stacks.prepare(owner, region, grouped[owner, region]),
                                 opts):
            if row.error:
                plan.blocked.append(f"{row.account}/{row.region}: post-confirmation preflight {row.error}")
            elif digest(row.value[0]) != digest(prepared[row.account, row.region][0]):
                plan.blocked.append(f"{row.account}/{row.region}: plan changed; run plan/apply again")
        # An approved permission change is re-read on both sides immediately before
        # the gate opens; any drift requires a renewed approval.
        for group in plan.groups:
            for change in getattr(group, "permission_changes", []):
                try:
                    if approval_for(approvals, plan.migration, change) is None:
                        raise MigrationError(f"approval {change['approval_id']} no longer covers "
                                             f"{change['share']}")
                    revalidate_change(gate.client(group.owner, "ram", group.region), change)
                    report.emit(f"owner={group.owner} region={group.region} share={change['share']} "
                                f"phase=permission-revalidation status=VERIFIED "
                                f"approval={change['approval_id']}")
                except Exception as exc:
                    plan.blocked.append(f"{group.owner}/{group.region}: post-confirmation "
                                        f"permission revalidation {failure_text(exc)}")
        if plan.blocked:
            for reason in plan.blocked:
                report.emit(f"phase=preflight status=BLOCKED {reason}")
            summary(plan, report, "BLOCKED", missing_baseline=missing_baseline)
            note("BLOCKED", blockers=list(plan.blocked), phase="post-confirmation")
            return 1
        gate.open = True
        for row in scoped_fanout(group_scopes,
                                 lambda owner, region: stacks.apply(owner, region, grouped[owner, region]),
                                 opts):
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
    final, resolver_errors = resolver_snapshot(readonly, plan.groups, opts, report, "resolver-after")
    failures.extend(resolver_errors)
    if args.mode == "apply":
        failures.extend(compare_resolver(baseline, final))
    for reason in failures:
        report.emit(f"status=INCOMPLETE {reason}")
    if args.mode == "apply" and failures:
        report.emit("Successful temporary shares are retained. Resume this migration ID after resolving failures.")
    status = "INCOMPLETE" if failures else "READY"
    summary(plan, report, status, created=created, reused=reused,
            accepted=accepted_count, reused_invitations=reused_invitations, failures=len(failures),
            missing_baseline=missing_baseline)
    def record_shares(current: dict) -> None:
        if args.mode == "apply":
            current["shares"] = share_records(current.get("shares", []), plan.groups, shares,
                                              plan.migration)
    note(status, record_shares, failures=failures, created=created, reused=reused,
         accepted=accepted_count)
    return 1 if failures else 0


def main(argv: list[str] | None = None, *, input_fn: Callable[[str], str] | None = None) -> int:
    report = Reporter()
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
        return 130
    except (MigrationError, OSError, ValueError, EOFError, BotoCoreError, ClientError) as exc:
        report.emit(f"status=BLOCKED {failure_text(exc)}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
