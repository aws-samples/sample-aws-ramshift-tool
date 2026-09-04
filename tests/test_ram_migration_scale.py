"""Scale, concurrency, interruption and operator-feedback tests (requirement 7).

Offline only: discovery runs against thread-safe in-memory RAM/CloudFormation
views, and the CLI runs against the local harness of test_ram_migration_cli.
"""
from __future__ import annotations

import copy
import json
import random
import re
import signal
import threading
import time
from collections import Counter
from types import SimpleNamespace
from typing import Any

import pytest
from botocore.exceptions import ClientError

import ram_migration_record as record_module
import temporary_migration_ram_shares as cli
from ram_migration_common import Api, MigrationError, Plan
from ram_migration_discovery import Discovery, LookupCache
from ram_migration_record import plan_digest
from test_ram_migration_cli import (  # noqa: F401 - fixtures are used by name
    CONSUMER, HOME, IPAM, MIGRATION, OTHER_CONSUMER, OTHER_OWNER, OWNER, REGION, RESOLVER,
    LocalClients, args, association, denied, forbid_real_authentication_or_network, group,
    harness, main, migration_record, tgw_like_change, with_record,
)

LATE_OWNER = "000000000009"
RULE_PERMISSION = "arn:aws:ram::aws:permission/AWSRAMDefaultPermissionResolverRule"
POOL_PERMISSION = "arn:aws:ram::aws:permission/AWSRAMDefaultPermissionIpamPool"
OTHER_PERMISSION = "arn:aws:ram::aws:permission/AWSRAMDefaultPermissionUnlisted"
UNLISTED = "ec2:UnlistedType"
ORIGINAL_STACK = f"arn:aws:cloudformation:{REGION}:{OWNER}:stack/original/0001"
RULE_POLICY = {"Effect": "Allow", "Action": ["route53resolver:AssociateResolverRule",
                                             "route53resolver:GetResolverRule"]}
NARROW_POLICY = {"Effect": "Allow", "Action": ["route53resolver:GetResolverRule"]}
POOL_POLICY = {"Effect": "Allow", "Action": ["ec2:AllocateIpamPoolCidr"]}
CAPABILITIES = {RESOLVER.lower(): True, IPAM.lower(): True}
PERMISSIONS = {  # (ARN, requested version) -> (version, default, type, policy)
    (RULE_PERMISSION, None): ("2", True, RESOLVER, RULE_POLICY),
    (RULE_PERMISSION, 1): ("1", False, RESOLVER, NARROW_POLICY),
    (POOL_PERMISSION, None): ("1", True, IPAM, POOL_POLICY),
    (OTHER_PERMISSION, None): ("1", True, UNLISTED, POOL_POLICY),
}


def share_arn(index: int) -> str:
    return f"arn:aws:ram:{REGION}:{OWNER}:resource-share/s{index:02d}"


def rule(index: int) -> str:
    return f"arn:aws:route53resolver:{REGION}:{OWNER}:resolver-rule/rslvr-rr-{index:02d}"


def client_error(code: str, operation: str, message: str = "Rate exceeded") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message},
                        "ResponseMetadata": {"RequestId": f"request-{code}"}}, operation)


def expired(operation: str) -> ClientError:
    return client_error("ExpiredTokenException", operation,
                        "The security token included in the request is expired")


def estate() -> dict[str, dict]:
    """Nine source shares: one four-share group from one owning stack, a two-consumer
    pool, an empty share, a service-only share, an unsupported type and a share
    whose attached permission version differs from the default, which joins the group."""
    shares = {share_arn(i): {"resources": {rule(i): RESOLVER}, "principals": [CONSUMER],
                             "permission": (RULE_PERMISSION, "2"), "stack": f"Share{i}"}
              for i in range(1, 5)}
    shares[share_arn(5)] = {"resources": {f"arn:aws:ec2:{REGION}:{OWNER}:ipam-pool/ipam-pool-05": IPAM},
                            "principals": [OTHER_CONSUMER, CONSUMER],
                            "permission": (POOL_PERMISSION, "1")}
    shares[share_arn(6)] = {"resources": {}, "principals": [CONSUMER]}
    shares[share_arn(7)] = {"resources": {rule(7): RESOLVER},
                            "principals": ["route53resolver.amazonaws.com"]}
    shares[share_arn(8)] = {"resources": {f"arn:aws:ec2:{REGION}:{OWNER}:unlisted/x-08": UNLISTED},
                            "principals": [CONSUMER], "permission": (OTHER_PERMISSION, "1")}
    shares[share_arn(9)] = {"resources": {rule(9): RESOLVER}, "principals": [CONSUMER],
                            "permission": (RULE_PERMISSION, "1")}
    return shares


class FakeOwner:
    """Thread-safe, read-only RAM and CloudFormation views of one owner Region."""
    def __init__(self, listing: list[str] | None = None, delay: float = 0.0):
        self.shares = estate()
        self.listing = listing or sorted(self.shares)
        self.delay = delay
        self.errors: dict[tuple[str, str], Exception] = {}
        self.calls: Counter = Counter()
        self.lock = threading.Lock()
        self.meta = SimpleNamespace(partition="aws", region_name=REGION)
        self.stack = {"StackId": ORIGINAL_STACK, "StackName": "original", "Tags": [],
                      "CreationTime": "2026-10-01T00:00:00Z", "StackStatus": "CREATE_COMPLETE"}
        self.template: dict | None = None  # default: one resource per stack-owned share
        self.hooks: dict[tuple[str, str | None], Any] = {}  # run once, before that read

    def _read(self, operation: str, key: str | None = None) -> None:
        with self.lock:
            self.calls[operation] += 1
            self.calls[operation, key] += 1
            hook = self.hooks.pop((operation, key), None)
        if hook:
            hook()
        if self.delay:
            time.sleep(self.delay)
        if (operation, key) in self.errors:
            raise self.errors[operation, key]

    def get_resource_shares(self, resourceOwner):
        self._read("get_resource_shares")
        return {"resourceShares": [{"resourceShareArn": arn, "owningAccountId": OWNER,
                                    "status": "ACTIVE", "tags": []} for arn in self.listing]}

    def list_resources(self, resourceOwner, resourceShareArns):
        arn, = resourceShareArns
        self._read("list_resources", arn)
        return {"resources": [{"arn": a, "type": t, "resourceShareArn": arn}
                              for a, t in self.shares[arn]["resources"].items()]}

    def get_resource_share_associations(self, associationType, resourceShareArns):
        arn, = resourceShareArns
        self._read("get_resource_share_associations", arn)
        return {"resourceShareAssociations": [
            {"resourceShareArn": arn, "associatedEntity": p, "associationType": "PRINCIPAL",
             "status": "ASSOCIATED"} for p in self.shares[arn]["principals"]]}

    def list_resource_share_permissions(self, resourceShareArn):
        self._read("list_resource_share_permissions", resourceShareArn)
        permission, version = self.shares[resourceShareArn]["permission"]
        kind = next(iter(self.shares[resourceShareArn]["resources"].values()))
        return {"permissions": [{"arn": permission, "version": version, "resourceType": kind}]}

    def get_permission(self, permissionArn, permissionVersion=None):
        self._read("get_permission", f"{permissionArn}@{permissionVersion}")
        version, default, kind, policy = PERMISSIONS[permissionArn, permissionVersion]
        return {"permission": {"arn": permissionArn, "version": version, "defaultVersion": default,
                               "resourceType": kind, "permission": json.dumps(policy),
                               "status": "ATTACHABLE", "featureSet": "STANDARD"}}

    def describe_stack_resources(self, PhysicalResourceId):
        self._read("describe_stack_resources", PhysicalResourceId)
        logical = self.shares[PhysicalResourceId].get("stack")
        if logical is None:
            raise client_error("ValidationError", "DescribeStackResources",
                               f"Stack for {PhysicalResourceId} does not exist")
        return {"StackResources": [{"StackId": ORIGINAL_STACK, "LogicalResourceId": logical,
                                    "PhysicalResourceId": PhysicalResourceId,
                                    "ResourceType": "AWS::RAM::ResourceShare"}]}

    def describe_stacks(self, StackName):
        self._read("describe_stacks", StackName)
        return {"Stacks": [copy.deepcopy(self.stack)]}

    def get_template(self, StackName, TemplateStage):
        self._read("get_template", StackName)
        return {"TemplateBody": json.dumps(self.template or {"Resources": {
            spec["stack"]: {"Type": "AWS::RAM::ResourceShare",
                            "Properties": {"Principals": spec["principals"]}}
            for spec in self.shares.values() if spec.get("stack")}})}


class FakeRouter:
    def __init__(self, owner: FakeOwner):
        self.owner = owner

    def client(self, account, service, region, write=False):
        assert (account, region, write) == (OWNER, REGION, False)
        return Api(self.owner, write)


def discover(owner: FakeOwner, *, workers: int = 1, cache: LookupCache | None = None,
             completion: list[str] | None = None) -> tuple[Plan, list[str]]:
    discovery = Discovery(FakeRouter(owner), {CONSUMER, OTHER_CONSUMER}, "scale-test", {},
                          CAPABILITIES, share_workers=workers, cache=cache)
    finished: list[str] = []
    if completion is not None:
        # Force the order in which share inspections finish.
        done = {arn: threading.Event() for arn in completion}
        inspect_share = discovery._inspect_share

        def ordered(owner_id, region, ram, share, members):
            result = inspect_share(owner_id, region, ram, share, members)
            arn = share["resourceShareArn"]
            index = completion.index(arn)
            assert index == 0 or done[completion[index - 1]].wait(10)
            finished.append(arn)
            done[arn].set()
            return result
        discovery._inspect_share = ordered
    return discovery.inspect(OWNER, REGION), finished


SCOPE = {"migrating_consumers": [CONSUMER, OTHER_CONSUMER], "migrating_owners": [],
         "stationary_owners": [OWNER], "regions": [REGION], "scan_enabled_regions": False}


# ---------------------------------------------------------------------------
# Concurrent discovery: bounded, deterministic, cached
# ---------------------------------------------------------------------------
def test_concurrent_discovery_is_deterministic_for_any_listing_or_completion_order():
    arns = sorted(estate())
    shuffled = arns[:]
    random.Random(7).shuffle(shuffled)
    sequential, _ = discover(FakeOwner())
    forward, forward_order = discover(FakeOwner(listing=arns[::-1]), workers=9, completion=arns)
    backward, backward_order = discover(FakeOwner(listing=shuffled), workers=9,
                                        cache=LookupCache(), completion=arns[::-1])
    assert forward_order == arns and backward_order == arns[::-1]
    assert sequential.to_dict() == forward.to_dict() == backward.to_dict()
    assert plan_digest(sequential.groups, SCOPE) == plan_digest(forward.groups, SCOPE) == \
        plan_digest(backward.groups, SCOPE)
    rules, pool = sorted(sequential.groups, key=lambda g: len(g.consumers))
    # Merged in share-ARN order; share 9's v1 -> v2 difference never keeps it out.
    assert list(rules.resources) == [rule(i) for i in (1, 2, 3, 4, 9)]
    assert rules.source_shares == arns[:4] + [share_arn(9)]
    assert rules.source_stacks == [ORIGINAL_STACK]
    assert pool.consumers == (CONSUMER, OTHER_CONSUMER)
    assert sequential.excluded == [f"{share_arn(6)}: empty share",
                                   f"{share_arn(7)}: service-principal-only share"]
    assert [reason.split(": ")[0] for reason in sequential.blocked] == [share_arn(8)]
    change, = sequential.permission_changes
    assert (change["share"], change["from_version"], change["to_version"]) == (share_arn(9), "1", "2")


def test_share_level_concurrency_is_bounded_by_share_workers():
    owner = FakeOwner(delay=0.005)
    discovery = Discovery(FakeRouter(owner), {CONSUMER, OTHER_CONSUMER}, "scale-test", {},
                          CAPABILITIES, share_workers=3)
    active, peak, lock = [0], [0], threading.Lock()
    inspect_share = discovery._inspect_share

    def counted(*arguments):
        with lock:
            active[0] += 1
            peak[0] = max(peak[0], active[0])
        try:
            return inspect_share(*arguments)
        finally:
            with lock:
                active[0] -= 1
    discovery._inspect_share = counted
    discovery.inspect(OWNER, REGION)
    assert 1 < peak[0] <= 3


@pytest.mark.parametrize("workers", [0, 17, "4", True])
def test_share_workers_outside_one_to_sixteen_are_rejected(workers):
    with pytest.raises(MigrationError, match="between 1 and 16"):
        Discovery(FakeRouter(FakeOwner()), {CONSUMER}, "scale-test", {}, CAPABILITIES,
                  share_workers=workers)


def test_run_cache_dedupes_permission_and_template_reads_across_concurrent_shares():
    uncached, cached = FakeOwner(), FakeOwner()
    discover(uncached, workers=4)
    discover(cached, workers=4, cache=LookupCache())
    default_rule = ("get_permission", f"{RULE_PERMISSION}@None")
    assert uncached.calls[default_rule] == 5 and cached.calls[default_rule] == 1
    assert uncached.calls["get_template"] == 4 and cached.calls["get_template"] == 1
    # Per-share reads are never shared between shares.
    assert cached.calls["list_resources"] == uncached.calls["list_resources"] == 9
    assert cached.calls["describe_stack_resources"] == 8  # the empty share stops earlier


def parameter_template(references: dict[str, str]) -> dict:
    """Each logical share takes its principals from a CommaDelimitedList parameter."""
    return {"Parameters": {name: {"Type": "CommaDelimitedList"} for name in set(references.values())},
            "Resources": {logical: {"Type": "AWS::RAM::ResourceShare",
                                    "Properties": {"Principals": {"Ref": name}}}
                          for logical, name in references.items()}}


def narrowed_between_shares() -> FakeOwner:
    """Share1 and Share2 use !Ref Consumers. After Share1 is inspected, the owner moves
    Share2 to a new BConsumers parameter and CloudFormation disassociates the removed
    consumer. The StackId does not change; LastUpdatedTime does."""
    owner = FakeOwner(listing=[share_arn(1), share_arn(2)])
    for index in (1, 2):
        owner.shares[share_arn(index)]["principals"] = [CONSUMER, OTHER_CONSUMER]
    owner.stack["Parameters"] = [{"ParameterKey": "Consumers",
                                  "ParameterValue": f"{CONSUMER},{OTHER_CONSUMER}"}]
    owner.template = parameter_template({"Share1": "Consumers", "Share2": "Consumers"})

    def narrow():
        owner.stack.update(LastUpdatedTime="2026-10-14T00:00:00Z", StackStatus="UPDATE_COMPLETE")
        owner.stack["Parameters"].append({"ParameterKey": "BConsumers", "ParameterValue": CONSUMER})
        owner.template = parameter_template({"Share1": "Consumers", "Share2": "BConsumers"})
        owner.shares[share_arn(2)]["principals"] = [CONSUMER]
    owner.hooks["list_resources", share_arn(2)] = narrow
    return owner


def test_a_stack_update_between_share_inspections_is_never_served_a_cached_template():
    cached_owner = narrowed_between_shares()
    cached, _ = discover(cached_owner, cache=LookupCache())
    uncached, _ = discover(narrowed_between_shares())
    assert cached.to_dict() == uncached.to_dict()
    consumers = {arn: g.consumers for g in cached.groups for arn in g.source_shares}
    # The removed consumer is never granted through Share2's temporary share.
    assert consumers == {share_arn(1): (CONSUMER, OTHER_CONSUMER), share_arn(2): (CONSUMER,)}
    assert cached_owner.calls["get_template"] == 2  # one read per template version


def test_lookup_cache_is_single_flight_never_keeps_failures_and_returns_copies():
    cache, loads, release = LookupCache(), [], threading.Event()

    def slow():
        loads.append(1)
        release.wait(5)
        return {"Policy": {"Statement": []}}
    results = []
    threads = [threading.Thread(target=lambda: results.append(cache.get(("k",), slow)))
               for _ in range(8)]
    for thread in threads:
        thread.start()
    time.sleep(0.05)
    release.set()
    for thread in threads:
        thread.join(5)
    assert len(loads) == 1 and len(results) == 8
    results[0]["Policy"]["Statement"].append("mutated")
    assert cache.get(("k",), slow) == {"Policy": {"Statement": []}}

    def failing():
        loads.append(2)
        raise client_error("Throttling", "GetPermission")
    with pytest.raises(ClientError):
        cache.get(("failing",), failing)
    assert cache.get(("failing",), lambda: "read again") == "read again"
    cache.discard(("k",))
    assert cache.get(("k",), lambda: "fresh") == "fresh"


@pytest.mark.parametrize("operation,error,category", [
    ("list_resources", client_error("Throttling", "ListResources"), "discovery-api-error"),
    ("list_resources", client_error("TooManyRequestsException", "ListResources"),
     "discovery-api-error"),
    ("get_resource_share_associations", expired("GetResourceShareAssociations"),
     "authentication"),
])
def test_throttled_or_expired_share_reads_are_named_blockers_for_that_share_only(
        operation, error, category):
    owner = FakeOwner()
    owner.errors[operation, share_arn(3)] = error
    plan, _ = discover(owner, workers=4, cache=LookupCache())
    reason = next(r for r in plan.blocked if r.startswith(share_arn(3)))
    code = error.response["Error"]["Code"]
    assert reason.startswith(f"{share_arn(3)}: owner={OWNER} region={REGION} "
                             f"operation={error.operation_name} {code}: ")
    assert f"(request request-{code})" in reason
    assert cli.blocker_category(reason) == category
    rules = next(g for g in plan.groups if RESOLVER in g.permissions)
    assert set(rules.resources) == {rule(1), rule(2), rule(4), rule(9)}  # other shares still planned


# ---------------------------------------------------------------------------
# Blocker summary
# ---------------------------------------------------------------------------
LARGE_PROPOSED = "000000000005"   # proposed owner: 66 observations
LARGE_POOLS = "000000000006"      # proposed owner: 12 IPAM observations
LARGE_UPSTREAM = "000000000007"   # shares only with the stationary owner


def receive_many(h, receiver: str, owner: str, suffix: str, resources: list[tuple[str, str]]) -> str:
    arn = f"arn:aws:ram:{REGION}:{owner}:resource-share/{suffix}"
    h.received_shares[receiver, REGION].append(
        {"resourceShareArn": arn, "owningAccountId": owner, "status": "ACTIVE"})
    h.received_resources[receiver, REGION, arn] = [
        {"arn": a, "type": t, "status": "AVAILABLE", "resourceShareArn": arn} for a, t in resources]
    return arn


def large_estate_example(h) -> list[str]:
    """Two shares from the stationary owner whose permission versions differ from the
    default, a proposed owner seen 66 times, one seen 12 times through IPAM pools, and 26
    receipts of the stationary owner itself, which are not migration dependencies."""
    groups, changes = [], []
    for index in (1, 2):
        share = f"arn:aws:ram:{REGION}:{OWNER}:resource-share/tgw-{index}"
        g = group()
        g.resources = {f"arn:aws:ec2:{REGION}:{OWNER}:ipam-pool/tgw-{index}": IPAM}
        g.source_shares = [share]
        groups.append(g)
        changes.append(dict(tgw_like_change(), share=share))
        receive_many(h, CONSUMER, OWNER, f"tgw-{index}", list(g.resources.items()))
    h.source[OWNER, REGION] = groups
    h.permission_changes[OWNER, REGION] = changes
    rules = [(f"arn:aws:route53resolver:{REGION}:{LARGE_PROPOSED}:resolver-rule/rslvr-rr-{n:02d}",
              RESOLVER) for n in range(22)]
    gateways = [(f"arn:aws:ec2:{REGION}:{LARGE_PROPOSED}:transit-gateway/tgw-{n:02d}",
                 "ec2:TransitGateway") for n in range(11)]
    for receiver in (CONSUMER, OTHER_CONSUMER):
        receive_many(h, receiver, LARGE_PROPOSED, "rules-a", rules[:11])
        receive_many(h, receiver, LARGE_PROPOSED, "rules-b", rules[11:])
        receive_many(h, receiver, LARGE_PROPOSED, "gateways", gateways)
    receive_many(h, CONSUMER, LARGE_POOLS, "pools", [
        (f"arn:aws:ec2:{REGION}:{LARGE_POOLS}:ipam-pool/ipam-pool-{n:02d}", IPAM) for n in range(12)])
    return [receive_many(h, OWNER, LARGE_UPSTREAM, f"upstream-{n:02d}", [
        (f"arn:aws:ec2:{REGION}:{LARGE_UPSTREAM}:subnet/subnet-{n:02d}", "ec2:Subnet")])
        for n in range(26)]


def summary_lines(output: str) -> list[str]:
    return [line for line in output.splitlines() if line.startswith("phase=blocker-summary")]


@pytest.mark.parametrize("recorded", [False, True])
def test_blocker_summary_for_the_large_estate_example(harness, capsys, migration_record, recorded):
    stationary = large_estate_example(harness)
    argv = args(consumers=f"{CONSUMER},{OTHER_CONSUMER}")
    assert main(with_record(argv, migration_record) if recorded else argv) == 1
    output = capsys.readouterr().out
    header, owners = lines = summary_lines(output)
    assert output.splitlines()[-2:] == lines  # the last thing a blocked run prints
    assert header == "phase=blocker-summary status=BLOCKED blockers=2 categories=1"
    assert owners.startswith("phase=blocker-summary category=owner-outside-approved-scope "
                             "blockers=2 owners=2 shares=4 resources=45 observations=78 "
                             "next_action=")
    # The two shares' permission differences are information, never blockers.
    info, = [line for line in output.splitlines() if line.startswith("phase=permission-change ")]
    assert info.startswith("phase=permission-change status=INFO ") and info.endswith(" shares=2")
    assert "APPROVE-OWNERS" in owners and "--profile-map or --role-map" in owners
    assert ("phase=plan record=" in output) == recorded
    if recorded:
        assert "next_action=run approve with the same --record and type the APPROVE-OWNERS" in owners
    else:  # no record holds the requests yet: record the plan first
        assert "next_action=re-run plan with --record <path> to record the" in owners
        assert "the same --record" not in owners
    assert "provides 33 unique received resources" in output and "(66 observations)" in output
    assert "provides 12 unique received resources (ec2:IpamPool x12)" in output
    # The stationary owner's own receipts are not dependencies at all.
    assert LARGE_UPSTREAM not in output and not any(arn in output for arn in stationary)
    assert not any(call[0] == "received-shares" and call[1] == OWNER for call in harness.calls)
    assert not harness.writes()


SUMMARY_SHARE = f"arn:aws:ram:{REGION}:{OWNER}:resource-share/original"
CAPABILITY = (f"{SUMMARY_SHARE}-8: owner={OWNER} region={REGION} {UNLISTED}: unsupported or "
              "unverified external-sharing capability")
PRINCIPAL_MAP = (f"{SUMMARY_SHARE}: owner={OWNER} region={REGION} Original account-facing "
                 "consumers are unresolved; provide a principal-map override")
RECHECK_DENIED = (f"{OWNER}/{REGION}: post-confirmation preflight operation=GetPermission "
                  "AccessDeniedException: denied (request r5)")
RECHECK_THROTTLED = (f"{OWNER}/{REGION}: post-confirmation preflight operation=GetPermission "
                     "ThrottlingException: Rate exceeded (request r6)")
DEFAULT_DRIFT = (f"{OWNER}/{REGION}: post-confirmation preflight {RULE_PERMISSION}: the default "
                 "managed permission changed since discovery read it")
BASELINE_LOSS = (f"phase=baseline status=BLOCKED original missing: resolver_association|"
                 f"{CONSUMER}|{REGION}|a-1; {cli.RECORDED_LOSS}")
BASELINE_MOVED = (f"phase=baseline status=BLOCKED original state changed during confirmation "
                  f"(missing): resolver_association|{CONSUMER}|{REGION}|a-1")


def test_categories_put_api_failures_before_configuration_needs():
    assert cli.blocker_category(CAPABILITY) == cli.blocker_category(PRINCIPAL_MAP) == "configuration"
    assert cli.blocker_category(RECHECK_DENIED) == "discovery-api-error"
    assert cli.blocker_category(RECHECK_THROTTLED) == "discovery-api-error"
    assert cli.blocker_category(DEFAULT_DRIFT) == "other"  # a re-run reads the new default
    assert cli.blocker_category(BASELINE_LOSS) == "baseline-loss"
    assert cli.blocker_category(BASELINE_MOVED) == "baseline-capture"  # nothing recorded yet
    restricted = (f"{SUMMARY_SHARE}: owner={OWNER} region={REGION} Unsupported account-level "
                  "principal conversion: arn:aws:iam::000000000002:role/x; principal-map "
                  "overrides cannot broaden restricted access")
    assert cli.blocker_category(restricted) == "other"
    assert cli.blocker_category(f"{SUMMARY_SHARE}: owner={OWNER} region={REGION} source status "
                                "PENDING") == "other"


def test_blocker_summary_groups_every_category_with_counts_and_next_actions(capsys):
    share, pool = SUMMARY_SHARE, f"arn:aws:ec2:{REGION}:{OWNER}:ipam-pool/uncovered"
    plan = Plan("scale-test", blocked=[
        f"account={CONSUMER} phase=authentication status=BLOCKED operation=GetCallerIdentity "
        "AccessDeniedException: explicit deny (request r1)",
        f"owner={OWNER} region={REGION} phase=discovery operation=ListResources "
        "ExpiredTokenException: The security token included in the request is expired (request r2)",
        f"owner={OWNER} phase=regions status=BLOCKED operation=DescribeRegions "
        "AccessDeniedException: denied (request r3)",
        *(f"account={CONSUMER} owner={owner} region={REGION} share={share}-{owner} "
          "phase=received-audit status=BLOCKED received dependencies are not covered by any "
          f"planned temporary share: {pool}-{owner}; they would be lost when the account leaves"
          for owner in (OWNER, OTHER_OWNER, LATE_OWNER)),
        PRINCIPAL_MAP, CAPABILITY,
        f"{share}-3: owner={OWNER} region={REGION} operation=ListResources ThrottlingException: "
        "Rate exceeded (request r4)",
        RECHECK_DENIED, DEFAULT_DRIFT, BASELINE_LOSS,
        f"phase=baseline status=BLOCKED kind=resolver_association consumer={CONSUMER}: not COMPLETE",
        "phase=reviewed-record tool sources changed since the reviewed plan",
        f"{OWNER}/{REGION}: migration template exceeds inline CFN limit",
    ])
    cli.report_blockers(plan, cli.Reporter(), "BLOCKED", mode="plan", recorded=True)
    lines = summary_lines(capsys.readouterr().out)
    assert lines[0] == "phase=blocker-summary status=BLOCKED blockers=15 categories=9"
    found = {re.search(r"category=(\S+)", line)[1]: line for line in lines[1:]}
    assert list(found) == ["received-dependency-not-covered", "configuration", "authentication",
                           "region-scope", "discovery-api-error", "baseline-loss",
                           "baseline-capture", "reviewed-record-mismatch", "other"]
    # One migrating account at risk, from three owners: consumers and owners are separate.
    assert "blockers=3 shares=3 resources=3 consumers=1 owners=3 next_action=" in \
        found["received-dependency-not-covered"]
    assert "blockers=2 accounts=2 next_action=" in found["authentication"]
    assert "aws sso login" in found["authentication"]
    assert "blockers=2 shares=2 owners=1 next_action=" in found["configuration"]
    assert "--principal-map" in found["configuration"] and "--capabilities" in found["configuration"]
    assert "blockers=2 shares=1 owners=1 next_action=" in found["discovery-api-error"]
    assert "blockers=2 next_action=" in found["other"]
    assert "permanent failure drop" in found["baseline-loss"]
    assert "new migration record" in found["baseline-loss"] and \
        "re-run apply" not in found["baseline-loss"]
    assert "blockers=1 consumers=1 next_action=" in found["baseline-capture"]
    assert "--regions" in found["region-scope"] and "never replaced" in found["baseline-capture"]
    cli.report_blockers(plan, cli.Reporter(), "INCOMPLETE", mode="plan", recorded=True)
    cli.report_blockers(Plan("scale-test"), cli.Reporter(), "BLOCKED", mode="plan", recorded=True)
    assert not capsys.readouterr().out


RERUNS_APPLY = {"authentication", "region-scope", "discovery-api-error", "baseline-capture",
                "other"}


@pytest.mark.parametrize("category", list(cli.BLOCKER_ACTIONS))
def test_every_next_action_follows_the_run_mode_and_the_record(category):
    plan = cli.blocker_action(category, "plan", True)
    unrecorded = cli.blocker_action(category, "plan", False)
    apply = cli.blocker_action(category, "apply", True)
    verify = cli.blocker_action(category, "verify", True)
    # verify takes its scope from the record: a new plan would rewrite an applied record.
    assert "plan --record" not in verify and "run plan" not in verify
    assert "apply" in apply
    if category not in ("baseline-loss", "baseline-capture"):  # only apply checks a baseline
        assert "re-run verify with the same --record" in verify
    assert "approve with the same --record" not in unrecorded
    if category in RERUNS_APPLY:
        assert "re-run apply with the same --record" in apply
    if category == "owner-outside-approved-scope":
        assert "with --record <path>" in unrecorded and "the same --record" in plan
    if category == "baseline-loss":
        assert all("new migration record" in text for text in (plan, apply, verify))


def test_blocked_verify_says_rerun_verify_and_an_unread_stored_plan_is_not_a_missing_share(
        harness, capsys, monkeypatch):
    harness.stored = copy.deepcopy(harness.source)
    assert main(args("verify")) == 0  # records the reviewed plan, the apply, then verifies
    capsys.readouterr()

    class Throttled(cli.Stacks):
        def persisted_groups(self, owner, region):
            raise client_error("ThrottlingException", "GetTemplate")
    monkeypatch.setattr(cli, "Stacks", Throttled)
    assert main(args("verify")) == 1
    output = capsys.readouterr().out
    assert "phase=reviewed-record" not in output and "reviewed-record-mismatch" not in output
    header, api = summary_lines(output)
    assert header == "phase=blocker-summary status=BLOCKED blockers=1 categories=1"
    assert api.startswith("phase=blocker-summary category=discovery-api-error blockers=1 "
                          "owners=1 next_action=")
    assert api.endswith("then re-run verify with the same --record")
    assert "plan --record" not in api and "--share-workers" not in api


def recheck_throttled(monkeypatch):
    """The post-confirmation recheck, which reads fresh, is throttled."""
    class Stacks(cli.Stacks):
        def prepare(self, owner, region, groups, fresh=False):
            if fresh:
                raise client_error("Throttling", "DescribeStacks")
            return super().prepare(owner, region, groups, fresh)
    monkeypatch.setattr(cli, "Stacks", Stacks)


def organization_denied(monkeypatch):
    def describe_organization(self, **_kwargs):
        raise denied("DescribeOrganization")
    monkeypatch.setattr(LocalClients, "describe_organization", describe_organization)


@pytest.mark.parametrize("failure,confirmed", [
    (recheck_throttled, True), (organization_denied, False)])
def test_blocked_apply_api_errors_say_rerun_apply_not_plan(harness, capsys, monkeypatch,
                                                           migration_record, failure, confirmed):
    # The plan is reviewed before the failure starts: an organization that cannot be
    # read blocks plan itself, in the organization-policy preflight.
    assert main(with_record(args(), migration_record)) == 0
    failure(monkeypatch)
    confirmations = []
    assert main(with_record(args("apply"), migration_record),
                input_fn=lambda prompt: confirmations.append(prompt) or f"APPLY {MIGRATION}") == 1
    assert bool(confirmations) == confirmed and not harness.writes()
    api, = [line for line in summary_lines(capsys.readouterr().out) if "category=" in line]
    assert "category=discovery-api-error blockers=1 " in api
    assert api.endswith("then re-run apply with the same --record")
    assert "plan --record" not in api


def test_a_loss_against_the_recorded_baseline_names_the_permanent_drop_not_a_resume(
        harness, capsys, migration_record):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    harness.resolver_samples[CONSUMER, REGION] = [[association()]]
    assert main(args("apply"), input_fn=harness.confirm) == 0
    harness.resolver_samples[CONSUMER, REGION] = [[]]  # the association is gone at resume
    capsys.readouterr()
    assert main(args("apply"), input_fn=lambda _: pytest.fail("a loss blocks before confirming")) == 1
    loss, = [line for line in summary_lines(capsys.readouterr().out) if "category=" in line]
    assert loss.startswith("phase=blocker-summary category=baseline-loss blockers=1 next_action=")
    assert "permanent failure drop" in loss and "new migration record" in loss
    assert "then re-run apply" not in loss
    drop, = record_module.load(migration_record, MIGRATION)["drops"]
    assert drop["severity"] == "failure"


def test_successful_plan_prints_no_blocker_summary(harness, capsys):
    assert main(args()) == 0
    assert not summary_lines(capsys.readouterr().out)


@pytest.mark.parametrize("failing", ["listing", "every-share"])
def test_expired_credentials_during_real_discovery_are_a_named_authentication_blocker(
        harness, capsys, monkeypatch, failing):
    """The real Discovery runs inside the CLI; the owner's reads go to FakeOwner views."""
    views = {REGION: FakeOwner(), HOME: FakeOwner()}
    views[HOME].listing = []
    owner = views[REGION]
    if failing == "listing":
        owner.errors["get_resource_shares", None] = expired("GetResourceShares")
    else:
        for arn in owner.listing:
            owner.errors["list_resources", arn] = expired("ListResources")
    local_client = cli.Router.client

    def client(self, account, service, region, write=False):
        if account == OWNER and service in ("ram", "cloudformation"):
            return views[region]
        return local_client(self, account, service, region, write)
    monkeypatch.setattr(cli.Router, "client", client)
    monkeypatch.setattr(cli, "Discovery", Discovery)
    assert main(args(), input_fn=lambda _: pytest.fail("plan never confirms")) == 1
    output = capsys.readouterr().out
    blocked = [line for line in output.splitlines() if line.startswith("phase=preflight status=BLOCKED")]
    token = ("ExpiredTokenException: The security token included in the request is expired "
             "(request request-ExpiredTokenException)")
    if failing == "listing":
        assert blocked == [f"phase=preflight status=BLOCKED owner={OWNER} region={REGION} "
                           f"phase=discovery operation=GetResourceShares {token}"]
    else:
        assert blocked == [f"phase=preflight status=BLOCKED {arn}: owner={OWNER} region={REGION} "
                           f"operation=ListResources {token}" for arn in owner.listing]
    auth, = [line for line in summary_lines(output) if "category=" in line]
    shares = "" if failing == "listing" else f"shares={len(owner.listing)} "
    assert auth.startswith(f"phase=blocker-summary category=authentication "
                           f"blockers={len(blocked)} {shares}accounts=1 next_action=")
    assert not harness.writes()


# ---------------------------------------------------------------------------
# Progress, options and fresh rechecks
# ---------------------------------------------------------------------------
PROGRESS = re.compile(r"^phase=progress stage=(\S+) account=(\d{12}) done=(\d+)/(\d+) "
                      r"overall=(\d+)/(\d+) elapsed_seconds=\d+\.\d(.*)$")


def test_long_phases_report_per_account_progress_with_elapsed_time(harness, capsys):
    harness.source[OTHER_OWNER, REGION] = [group(owner=OTHER_OWNER)]
    assert main(args("apply", owners=f"{OWNER},{OTHER_OWNER}"), input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    rows = [m.groups() for m in map(PROGRESS.match, output.splitlines()) if m]
    final = {}
    for stage, account, done, total, overall, everything, detail in rows:
        assert int(done) <= int(total) and int(overall) <= int(everything)
        final[stage, account] = (done, total, detail)
    assert {stage for stage, _ in final} == {
        "received-inventory", "discovery", "prepare", "prepare-recheck",
        "observation:baseline-preflight", "observation:baseline", "observation:post-apply"}
    assert final["received-inventory", CONSUMER][:2] == ("2", "2")
    assert final["discovery", OWNER][:2] == final["discovery", OTHER_OWNER][:2] == ("2", "2")
    assert final["prepare", OTHER_OWNER][:2] == ("1", "1")
    assert re.fullmatch(r" items=\d+ gaps=0", final["observation:baseline", CONSUMER][2])
    assert "phase=progress stage=discovery status=STARTED accounts=2 tasks=4" in output


def test_share_workers_option_is_bounded_and_reaches_discovery_with_the_run_cache(harness):
    parser = cli.build_parser()
    assert parser.parse_args([]).share_workers == 4
    for value in ("0", "17", "two"):
        with pytest.raises(SystemExit):
            parser.parse_args(["--share-workers", value])
    assert main(args() + ["--share-workers", "16"]) == 0
    assert harness.discovery_kwargs["share_workers"] == 16
    assert isinstance(harness.discovery_kwargs["cache"], LookupCache)


def test_post_confirmation_recheck_reads_fresh(harness):
    assert main(args("apply"), input_fn=harness.confirm) == 0
    assert harness.prepare_fresh == [(OWNER, REGION, False), (OWNER, REGION, True)]


@pytest.mark.parametrize("code", ["Throttling", "TooManyRequestsException"])
def test_throttled_verification_is_retried_within_the_retry_limit(harness, capsys, monkeypatch, code):
    harness.stored = copy.deepcopy(harness.source)
    g = harness.stored[OWNER, REGION][0]
    remaining = [1]

    def throttle_once(_router, _group):
        if remaining[0]:
            remaining[0] -= 1
            return client_error(code, "ListResourceSharePermissions")
        return None
    harness.verify_errors[g.key] = throttle_once
    delays = []
    monkeypatch.setattr(cli.time, "sleep", delays.append)
    assert main(args("verify")) == 0
    assert len([call for call in harness.calls if call[0] == "verify"]) == 2
    assert len(delays) == 1 and 0 < delays[0] <= 15 * 1.25
    assert "sharing_status=SHARING_READY" in capsys.readouterr().out


@pytest.mark.parametrize("code", ["Throttling", "TooManyRequestsException"])
def test_persistent_throttling_stops_at_the_retry_limit(harness, capsys, monkeypatch, code):
    harness.stored = copy.deepcopy(harness.source)
    g = harness.stored[OWNER, REGION][0]
    harness.verify_errors[g.key] = client_error(code, "ListResourceSharePermissions")
    delays = []
    monkeypatch.setattr(cli.time, "sleep", delays.append)
    argv = args("verify")
    argv[argv.index("--retry-limit") + 1] = "3"
    assert main(argv) == 1
    assert len([call for call in harness.calls if call[0] == "verify"]) == 3 and len(delays) == 2
    output = capsys.readouterr().out
    assert f"{code}: Rate exceeded" in output and "status=INCOMPLETE" in output


# ---------------------------------------------------------------------------
# Interruption, expired credentials, resume and idempotency
# ---------------------------------------------------------------------------
def history(path) -> list[tuple[str, str]]:
    return [(h["mode"], h["status"]) for h in record_module.load(path, MIGRATION)["history"]]


def test_interrupted_apply_exits_130_keeps_created_shares_and_records_history(
        harness, capsys, migration_record):
    owners = f"{OWNER},{OTHER_OWNER},{LATE_OWNER}"
    for owner in (OTHER_OWNER, LATE_OWNER):
        harness.source[owner, REGION] = [group(owner=owner)]
    harness.apply_errors[OTHER_OWNER, REGION] = KeyboardInterrupt()
    argv = args("apply", owners=owners) + ["--account-workers", "1"]
    assert main(argv, input_fn=harness.confirm) == 130
    output = capsys.readouterr().out
    assert "status=INTERRUPTING no new tasks start" in output
    assert "status=INCOMPLETE Interrupted; existing temporary shares are retained" in output
    assert "phase=record status=INTERRUPTED" in output and "recorded_shares=1 " in output
    assert (OWNER, REGION) in harness.stored                 # completed work is retained
    assert ("apply", LATE_OWNER, REGION) not in harness.calls  # nothing starts after the interrupt
    assert not any(call[0] in ("accept-write", "delete-share", "delete-stack") for call in harness.calls)
    record = record_module.load(migration_record, MIGRATION)
    entry = record["history"][-1]
    assert (entry["mode"], entry["status"]) == ("apply", "INTERRUPTED")
    assert "re-run apply with this record to resume" in entry["retained"]
    created, = record["shares"]                              # the share it created is recorded
    assert (created["owner"], created["region"]) == (OWNER, REGION)
    assert created["share_arn"] == harness.share(harness.stored[OWNER, REGION][0])["resourceShareArn"]

    # verify takes its scope from the record, which now holds what was created.
    assert main(args("verify", owners=owners)) == 0
    assert "status=PENDING_MIGRATION" in capsys.readouterr().out

    del harness.apply_errors[OTHER_OWNER, REGION]           # resume with the same record
    assert main(argv, input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    assert "created_shares=2 reused_shares=1" in output and "status=SHARING_READY" in output
    assert len(record_module.load(migration_record, MIGRATION)["shares"]) == 3
    # Each completed stack is recorded at once; an unchanged, recorded stack is not again.
    assert history(migration_record) == [
        ("plan", "PLANNED"), ("apply", "BASELINE_CAPTURED"), ("apply", "STACK_COMPLETE"),
        ("apply", "INTERRUPTED"), ("verify", "PENDING_MIGRATION"), ("apply", "STARTED"),
        ("apply", "STACK_COMPLETE"), ("apply", "STACK_COMPLETE"), ("apply", "SHARING_READY")]


def test_an_interrupted_share_readback_still_records_the_interruption(
        harness, capsys, monkeypatch, migration_record):
    harness.source[OTHER_OWNER, REGION] = [group(owner=OTHER_OWNER)]
    interrupted = []

    class Stacks(cli.Stacks):
        def apply(self, owner, region, groups):
            if owner == OTHER_OWNER:
                interrupted.append(owner)
                raise KeyboardInterrupt
            return super().apply(owner, region, groups)

        def shares(self, owner, region):
            if interrupted:
                raise KeyboardInterrupt  # Ctrl-C again during the readback
            return super().shares(owner, region)
    monkeypatch.setattr(cli, "Stacks", Stacks)
    assert main(args("apply", owners=f"{OWNER},{OTHER_OWNER}") + ["--account-workers", "1"],
                input_fn=harness.confirm) == 130
    output = capsys.readouterr().out
    assert "phase=record status=INCOMPLETE share readback interrupted" in output
    record = record_module.load(migration_record, MIGRATION)
    # The stack that completed before the interrupt was recorded when it completed.
    assert [share["owner"] for share in record["shares"]] == [OWNER]
    assert history(migration_record)[-2:] == [("apply", "STACK_COMPLETE"), ("apply", "INTERRUPTED")]


def test_interrupted_verify_records_verify_as_its_resume_step(harness, capsys, migration_record):
    harness.stored = copy.deepcopy(harness.source)
    harness.verify_errors[harness.stored[OWNER, REGION][0].key] = KeyboardInterrupt()
    assert main(args("verify")) == 130
    output = capsys.readouterr().out
    entry = record_module.load(migration_record, MIGRATION)["history"][-1]
    assert (entry["mode"], entry["status"]) == ("verify", "INTERRUPTED")
    assert entry["retained"] == "verify made no AWS changes; re-run verify with this record"
    assert "next_action=verify made no AWS changes; re-run verify with this record" in output
    assert "re-run apply" not in output and "reading back" not in output


@pytest.mark.parametrize("mode", ["apply", "verify"])
def test_interruption_with_a_record_path_that_does_not_exist_writes_nothing(
        harness, capsys, monkeypatch, tmp_path, mode):
    def interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "check_sdk", interrupt)
    missing = tmp_path / "missing-record.json"
    assert cli.main(with_record(args(mode), missing)) == 130
    output = capsys.readouterr().out
    assert "Interrupted" in output and "phase=record" not in output and not missing.exists()


def test_interruption_at_the_migration_id_prompt_leaves_the_record_unchanged(
        harness, capsys, migration_record):
    assert main(with_record(args(), migration_record)) == 0
    before = record_module.load(migration_record, MIGRATION)

    def interrupt(_prompt):
        raise KeyboardInterrupt
    assert cli.main(["verify", "--record", str(migration_record), "--interactive",
                     "--profile", "explicit-source"], input_fn=interrupt) == 130
    assert "phase=record" not in capsys.readouterr().out
    assert record_module.load(migration_record, MIGRATION) == before


@pytest.mark.skipif(not hasattr(signal, "pthread_kill"), reason="needs POSIX thread signals")
def test_a_main_thread_interrupt_is_acknowledged_at_once_while_running_tasks_drain():
    started, again, release = threading.Event(), threading.Event(), threading.Event()
    events, main_thread = [], threading.main_thread().ident

    def callback(account, region):
        events.append(("started", account, region))
        started.set()
        assert release.wait(10)
        events.append(("finished", account, region))

    def acknowledge(line):
        events.append(("acknowledged", line))
        (release if again.is_set() else again).set()

    def interrupt():  # Ctrl-C, then Ctrl-C again while the running task drains
        if started.wait(10):
            signal.pthread_kill(main_thread, signal.SIGINT)
            if again.wait(10):
                signal.pthread_kill(main_thread, signal.SIGINT)
    interrupter = threading.Thread(target=interrupt)
    interrupter.start()
    with pytest.raises(KeyboardInterrupt):
        try:
            cli.fanout({OWNER: [HOME, REGION], LATE_OWNER: [REGION]}, callback, 1, 1,
                       notify=acknowledge)
        finally:
            interrupter.join(10)
    waiting = ("acknowledged", "status=INTERRUPTING no new tasks start; waiting for 1 running "
                               "tasks to finish; their changes are retained")
    # Both interrupts are acknowledged before the running task finishes; nothing else starts.
    assert events == [("started", OWNER, HOME), waiting, waiting, ("finished", OWNER, HOME)]


def test_interruption_without_a_record_still_exits_130(harness, capsys, monkeypatch):
    def interrupt(*_args, **_kwargs):
        raise KeyboardInterrupt
    monkeypatch.setattr(cli, "check_sdk", interrupt)
    assert cli.main(args("plan")) == 130
    output = capsys.readouterr().out
    assert "Interrupted" in output and "phase=record" not in output


def test_expired_credentials_during_apply_keep_and_record_created_shares_then_resume(
        harness, capsys, migration_record):
    harness.source[OTHER_OWNER, REGION] = [group(owner=OTHER_OWNER)]
    harness.apply_errors[OTHER_OWNER, REGION] = expired("CreateChangeSet")
    argv = args("apply", owners=f"{OWNER},{OTHER_OWNER}")
    assert main(argv, input_fn=harness.confirm) == 1
    output = capsys.readouterr().out
    assert "status=INCOMPLETE" in output and "ExpiredTokenException" in output
    assert "Successful temporary shares are retained" in output
    record = record_module.load(migration_record, MIGRATION)
    created, = record["shares"]
    assert (created["owner"], created["region"]) == (OWNER, REGION) and created["share_arn"]
    assert (record["history"][-1]["mode"], record["history"][-1]["status"]) == ("apply", "INCOMPLETE")
    assert not any(call[0] in ("delete-share", "delete-stack") for call in harness.calls)

    del harness.apply_errors[OTHER_OWNER, REGION]
    harness.calls.clear()
    assert main(argv, input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    assert "status=SHARING_READY" in output and "created_shares=1 reused_shares=1" in output
    writes = [call for call in harness.calls if call[0] == "write"]
    assert [call[1] for call in writes] == [OTHER_OWNER]     # the completed stack is not rewritten
    assert len([call for call in harness.calls if call[0] == "accept-write"]) == 1
    record = record_module.load(migration_record, MIGRATION)
    assert sorted(s["owner"] for s in record["shares"]) == [OWNER, OTHER_OWNER]
    assert [s["share_arn"] for s in record["shares"] if s["owner"] == OWNER] == [created["share_arn"]]
    assert history(migration_record).count(("apply", "BASELINE_CAPTURED")) == 1


def test_repeated_apply_is_idempotent_and_writes_nothing_new(harness, capsys, migration_record):
    assert main(args("apply"), input_fn=harness.confirm) == 0
    first = record_module.load(migration_record, MIGRATION)
    harness.calls.clear()
    assert main(args("apply"), input_fn=harness.confirm) == 0
    assert not harness.writes()
    output = capsys.readouterr().out
    assert "created_shares=0 reused_shares=1" in output and "reused_invitations=1" in output
    second = record_module.load(migration_record, MIGRATION)
    assert [s["share_arn"] for s in second["shares"]] == [s["share_arn"] for s in first["shares"]]
    assert second["baseline"] == first["baseline"]
    assert history(migration_record).count(("apply", "BASELINE_CAPTURED")) == 1
