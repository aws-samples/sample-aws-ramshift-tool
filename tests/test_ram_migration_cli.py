"""Local orchestration tests. These are not real account-migration evidence."""
from __future__ import annotations

import contextlib
import copy
import io
import json
import sys
import threading
import urllib.request
from collections import Counter, defaultdict
from types import SimpleNamespace

import boto3
import botocore.session
import pytest
from botocore.exceptions import ClientError, EndpointConnectionError, NoCredentialsError

import temporary_migration_ram_shares as cli
from ram_migration_common import Group, MigrationError, Plan
from ram_migration_discovery import ApprovedGroup, permission_change
import ram_migration_record as record_module
from ram_migration_stacks import Readback, additive_template, check_quotas, template_for

OWNER = "000000000001"
CONSUMER = "000000000002"
OTHER_CONSUMER = "000000000003"
OTHER_OWNER = "000000000004"
REGION = "us-west-2"
HOME = "us-east-1"
MIGRATION = "local-test"
IPAM = "ec2:IpamPool"
RESOLVER = "route53resolver:ResolverRule"
# The local organization: every account directly under one root, with the AWS
# managed FullAWSAccess SCP attached everywhere, RCPs not enabled and RAM sharing
# with AWS Organizations enabled.
MANAGER = "000000000090"
ROOT = "r-local"
FULL_ACCESS = "p-FullAWSAccess"
FULL_ACCESS_DOCUMENT = {"Version": "2012-10-17",
                        "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}
SCP = "SERVICE_CONTROL_POLICY"


def denied(operation="GetResourceShares"):
    return ClientError(
        {"Error": {"Code": "AccessDeniedException", "Message": "explicit deny"},
         "ResponseMetadata": {"RequestId": "local-request-id"}},
        operation,
    )


def group(owner=OWNER, region=REGION, consumer=CONSUMER, kind=IPAM):
    resource = (f"arn:aws:route53resolver:{region}:{owner}:resolver-rule/arn-name"
                if kind == RESOLVER else f"arn:aws:ec2:{region}:{owner}:ipam-pool/test")
    return Group(owner, region, (consumer,), {kind: f"arn:aws:ram::aws:permission/{kind}"},
                 {resource: kind}, [f"arn:aws:ram:{region}:{owner}:resource-share/original"])


def args(mode=None, *, owners=OWNER, consumers=CONSUMER, regions=REGION):
    result = [mode] if mode else []
    result += ["--migration-id", MIGRATION, "--owners", owners, "--regions", regions,
               "--profile", "explicit-source", "--retry-limit", "2"]
    if consumers is not None:
        result += ["--consumers", consumers]
    return result


@pytest.fixture(autouse=True)
def forbid_real_authentication_or_network(monkeypatch):
    def forbidden(*_args, **_kwargs):
        raise AssertionError("Local CLI tests must not read credentials or access the network")
    monkeypatch.setattr(boto3, "Session", forbidden)
    monkeypatch.setattr(botocore.session.Session, "get_credentials", forbidden)
    monkeypatch.setattr(botocore.session.Session, "create_client", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    monkeypatch.setattr(sys, "stdin", SimpleNamespace(isatty=lambda: False))


class LocalClients:
    def __init__(self, harness, account, service, region):
        self.harness, self.account, self.service, self.region = harness, account, service, region
        self.meta = SimpleNamespace()

    def describe_regions(self, **kwargs):
        self.harness.calls.append(("regions", self.account, kwargs))
        if self.account in self.harness.region_errors:
            raise self.harness.region_errors[self.account]
        return {"Regions": self.harness.enabled_regions[self.account]}

    def get_resource_shares(self, **kwargs):
        key = self.account, self.region
        if kwargs["resourceOwner"] == "SELF":   # what a migrating account owns itself
            self.harness.calls.append(("owned-shares", self.account, self.region, kwargs))
            if key in self.harness.owned_errors:
                raise self.harness.owned_errors[key]
            return {"resourceShares": copy.deepcopy(self.harness.owned_shares[key])}
        assert kwargs["resourceOwner"] == "OTHER-ACCOUNTS"
        self.harness.calls.append(("received-shares", self.account, self.region, kwargs))
        if key in self.harness.received_errors:
            raise self.harness.received_errors[key]
        pages = self.harness.received_share_pages.get(key)
        if pages is not None:
            index = int(kwargs.get("nextToken", "0"))
            result = {"resourceShares": copy.deepcopy(pages[index])}
            if index + 1 < len(pages):
                result["nextToken"] = str(index + 1)
            return result
        return {"resourceShares": copy.deepcopy(self.harness.received_shares[key])}

    def list_resources(self, **kwargs):
        assert kwargs["resourceOwner"] == "OTHER-ACCOUNTS"
        self.harness.calls.append(("received-resources", self.account, self.region, kwargs))
        arn, = kwargs["resourceShareArns"]
        key = self.account, self.region, arn
        if key in self.harness.received_errors:
            raise self.harness.received_errors[key]
        pages = self.harness.received_resource_pages.get(key)
        if pages is not None:
            index = int(kwargs.get("nextToken", "0"))
            result = {"resources": copy.deepcopy(pages[index])}
            if index + 1 < len(pages):
                result["nextToken"] = str(index + 1)
            return result
        return {"resources": copy.deepcopy(self.harness.received_resources[key])}

    def create_change_set(self, **kwargs):
        self.harness.calls.append(("write", self.account, self.region, kwargs))
        return {"Id": "local-change-set"}

    def get_resource_share_invitations(self, **_kwargs):
        return {"resourceShareInvitations":
                copy.deepcopy(self.harness.invitations[self.account, self.region])}

    def accept_resource_share_invitation(self, resourceShareInvitationArn):
        self.harness.calls.append(("accept-write", resourceShareInvitationArn))
        for invitation in self.harness.invitations[self.account, self.region]:
            if invitation["resourceShareInvitationArn"] == resourceShareInvitationArn:
                invitation["status"] = "ACCEPTED"
                return {}
        raise AssertionError("Only the exact intended invitation may be accepted")

    def get_resource_share_associations(self, **_kwargs):
        key = self.account, self.region
        states = self.harness.principal_states[key]
        state = states.pop(0) if len(states) > 1 else states[0]
        return {"resourceShareAssociations": [
            {"associatedEntity": account, "status": state}
            for account in (CONSUMER, OTHER_CONSUMER)
        ]}

    def list_resolver_rules(self, **_kwargs):
        if self.harness.resolver_error:
            raise self.harness.resolver_error
        return {"ResolverRules": [
            {"Arn": arn, "Id": "actual-owner-rule-id"}
            for g in self.harness.source.get((self.account, self.region), [])
            + self.harness.stored.get((self.account, self.region), [])
            for arn, kind in g.resources.items() if kind == RESOLVER
        ]}

    def describe_organization(self, **_kwargs):
        self.harness.calls.append(("organization", self.account))
        org = self.harness.organizations[self.account]
        if isinstance(org, Exception):
            raise org
        if org == "STANDALONE":
            raise ClientError({"Error": {"Code": "AWSOrganizationsNotInUseException",
                                         "Message": "not in an organization"}}, "DescribeOrganization")
        return {"Organization": {"Id": org, "MasterAccountId": self.harness.org_manager,
                                 "FeatureSet": self.harness.org_feature_set}}

    # Organizations reads through the management account (the policy preflight).
    def list_parents(self, ChildId, **_kwargs):
        self.harness.org_read(self.account, "ListParents", ChildId)
        identifier, kind = self.harness.org_parents.get(ChildId, (ROOT, "ROOT"))
        return {"Parents": [{"Id": identifier, "Type": kind}]}

    def list_policies_for_target(self, TargetId, Filter, **_kwargs):
        self.harness.org_read(self.account, "ListPoliciesForTarget", TargetId, Filter)
        identifiers = self.harness.org_attachments.get(
            (TargetId, Filter), [FULL_ACCESS] if Filter == SCP else [])
        return {"Policies": [{"Id": identifier, "Name": self.harness.org_policies[identifier][0],
                              "Type": Filter, "AwsManaged": identifier == FULL_ACCESS}
                             for identifier in identifiers]}

    def describe_policy(self, PolicyId):
        self.harness.org_read(self.account, "DescribePolicy", PolicyId)
        name, document = self.harness.org_policies[PolicyId]
        return {"Policy": {"PolicySummary": {"Id": PolicyId, "Name": name},
                           "Content": json.dumps(document)}}

    def list_aws_service_access_for_organization(self, **_kwargs):
        self.harness.org_read(self.account, "ListAWSServiceAccessForOrganization", None)
        return {"EnabledServicePrincipals": [{"ServicePrincipal": principal}
                                             for principal in self.harness.org_services]}

    def list_resolver_rule_associations(self, **_kwargs):
        samples = self.harness.resolver_samples[self.account, self.region]
        sample = samples.pop(0) if len(samples) > 1 else samples[0]
        return {"ResolverRuleAssociations": copy.deepcopy(sample)}


class FakeVerification:
    """Reference implementation of the verification contract over harness state."""
    def __init__(self, harness):
        self.harness = harness

    def origin(self, g, consumer, arn):
        """The planned or deployed group granting this consumer this resource; an
        observation group, such as the monitor's baseline groups, need not be one."""
        h = self.harness
        key = g.owner, g.region
        for candidate in [g, *getattr(h, "stored", {}).get(key, []),
                          *getattr(h, "source", {}).get(key, [])]:
            if candidate.permissions and consumer in candidate.consumers and arn in candidate.resources:
                return candidate
        return g

    def items(self, groups, temporary, pop=True):
        h = self.harness
        items = []
        samples = {}
        for g in groups:
            for consumer in g.consumers:
                key = consumer, g.region
                if key not in samples:
                    queue = h.resolver_samples[key]
                    samples[key] = (queue.pop(0) if pop and len(queue) > 1 else queue[0])
                for arn, kind in sorted(g.resources.items()):
                    site = (consumer, g.region, arn)
                    granted = self.origin(g, consumer, arn)
                    other = [] if site in h.original_lost else sorted(set(granted.source_shares))
                    if site in h.replacement:
                        other = sorted(set(other) | {f"arn:aws:ram:{g.region}:{g.owner}:resource-share/permanent"})
                    via_temp = self.temporary_paths(g, consumer, arn, temporary)
                    items.append({"kind": "entitlement", "key": f"entitlement|{consumer}|{g.region}|{arn}",
                                  "consumer": consumer, "owner": g.owner, "region": g.region,
                                  "resource_arn": arn, "type": kind, "via_shares": other + via_temp,
                                  "via_temporary": via_temp, "via_other": other})
                    if kind == RESOLVER:
                        for row in samples[key]:
                            items.append({"kind": "resolver_association",
                                          "key": f"resolver_association|{consumer}|{g.region}|{row['Id']}",
                                          "consumer": consumer, "owner": g.owner, "region": g.region,
                                          "resource_arn": arn, "rule_id": row["ResolverRuleId"],
                                          "vpc_id": row["VPCId"], "association_id": row["Id"],
                                          "status": row["Status"]})
        return items

    def temporary_paths(self, g, consumer, arn, temporary):
        """The recorded temporary shares through which the consumer still sees ``arn``: g's
        own, or that of a stored group listing both (g may be narrowed to some consumers),
        unless complete deleted the share or removed the consumer from it."""
        h = self.harness
        shares = {Harness.share(candidate)["resourceShareArn"]
                  for candidate in [g, *getattr(h, "stored", {}).get((g.owner, g.region), [])]
                  if consumer in candidate.consumers and arn in candidate.resources}
        return sorted(share for share in shares if share in temporary and share not in h.deleted_shares
                      and (share, consumer) not in getattr(h, "removed_principals", set()))

    def collect(self, router, groups, *, temporary_shares=frozenset(), workers=4):
        self.harness.calls.append(("collect", len(groups), tuple(sorted(temporary_shares))))
        return SimpleNamespace(observed_at=f"t{len(self.harness.calls)}",
                               items=self.items(groups, temporary_shares),
                               gaps=[dict(gap) for gap in self.harness.collect_gaps])

    def compare(self, baseline_items, observation):
        current = {item["key"]: item for item in observation.items}
        present, missing, degraded = [], [], []
        for item in baseline_items:
            now = current.get(item["key"])
            if now is None:
                missing.append({"key": item["key"], "item": item})
                continue
            reasons = []
            if item["kind"] == "entitlement" and not now.get("via_shares"):
                reasons.append("not visible to the consumer")
            if item["kind"] == "resolver_association":
                if now.get("status") != "COMPLETE":
                    reasons.append(f"status {now.get('status')}")
                for field in ("vpc_id", "rule_id"):
                    if now.get(field) != item.get(field):
                        reasons.append(f"{field} changed")
            if reasons:
                degraded.append({"key": item["key"], "before": item, "after": now, "reasons": reasons})
            else:
                present.append(item["key"])
        keys = {item["key"] for item in baseline_items}
        gaps = list(observation.gaps)
        status = "LOSS" if missing or degraded else ("INCONCLUSIVE" if gaps else "INTACT")
        return SimpleNamespace(present=present, missing=missing, degraded=degraded,
                               added=[k for k in current if k not in keys], gaps=gaps,
                               unobserved=[], status=status)

    def replacement_access(self, router, groups, temporary_shares, *, workers=4):
        covered, uncovered = [], []
        for item in self.items(groups, temporary_shares, pop=False):
            if item["kind"] == "entitlement":
                row = {k: item[k] for k in ("consumer", "region", "resource_arn")}
                (covered if item["via_other"] else uncovered).append(row)
        return {"covered": covered, "uncovered": uncovered,
                "gaps": [dict(gap) for gap in self.harness.replacement_gaps]}


class Harness:
    def __init__(self, monkeypatch):
        self.calls = []
        self.source = {(OWNER, REGION): [group()]}
        self.stored = {}
        self.discovery_errors = {}
        self.auth_errors = {}
        self.prepare_errors = {}
        self.apply_errors = {}
        self.verify_errors = {}
        self.verify_hook = None
        self.readback_failures = {}       # (owner, region) -> {logical ID: exception}
        self.external_access = {}         # (owner, region) -> discovery's recovered external access
        self.share_states = {}
        self.share_reads = Counter()
        self.prepare_counts = Counter()
        self.prepare_fresh = []           # (owner, region, fresh) per prepare call
        self.drift = set()
        self.invitations = defaultdict(list)
        self.principal_states = defaultdict(lambda: ["ASSOCIATED"])
        self.resolver_samples = defaultdict(lambda: [[]])
        self.resolver_error = None
        self.missing_shares = set()
        self.received_shares = defaultdict(list)
        self.received_resources = defaultdict(list)
        self.received_share_pages = {}
        self.received_resource_pages = {}
        self.received_errors = {}
        self.owned_shares = defaultdict(list)    # (account, region) -> shares it owns
        self.owned_errors = {}
        self.region_errors = {}
        self.enabled_regions = defaultdict(lambda: [
            {"RegionName": HOME, "OptInStatus": "opt-in-not-required"},
            {"RegionName": REGION, "OptInStatus": "opt-in-not-required"},
        ])
        self.catalog = {IPAM.lower(): True, RESOLVER.lower(): True}
        self.permission_changes = {}
        self.discovery_kwargs = {}
        self.organizations = defaultdict(lambda: "o-sourceorg01")
        self.original_lost = set()        # (consumer, region, resource) no longer visible via originals
        self.replacement = set()          # (consumer, region, resource) visible via a permanent share
        self.collect_gaps = []            # gaps every collect returns
        self.replacement_gaps = []
        self.deleted_shares = []
        self.deleted_stacks = []
        self.removed_principals = set()   # (share ARN, consumer) complete disassociated
        self.after_delete = None          # callback(harness, share_arn) run after a deletion
        self.after_remove = None          # callback(harness, share_arn, consumers) after a removal
        self.org_manager = MANAGER
        self.org_feature_set = "ALL"
        self.org_parents = {}             # child -> (parent ID, type); default: the root
        self.org_attachments = {}         # (target, policy type) -> policy IDs; default above
        self.org_policies = {FULL_ACCESS: ("FullAWSAccess", FULL_ACCESS_DOCUMENT)}
        self.org_services = ["ram.amazonaws.com"]
        self.org_errors = {}              # (operation, key) -> exception
        self.org_after_confirmation = None  # callback(harness) run at the APPLY confirmation
        self.organization_principals = {}  # discovery: original share -> OU/org principals
        harness = self

        class LocalRouter:
            def __init__(self, profiles, mappings, **kwargs):
                self.identity_profiles = {}
                harness.router = self
                harness.calls.append(("router", profiles, mappings, kwargs))

            def session(self, account):
                harness.calls.append(("authentication", account))
                if account in harness.auth_errors:
                    raise harness.auth_errors[account]
                return SimpleNamespace()

            def client(self, account, service, region, write=False):
                harness.calls.append(("client", account, service, region, write))
                return LocalClients(harness, account, service, region)

        class LocalDiscovery:
            def __init__(self, router, consumers, migration, overrides, capabilities, **kwargs):
                harness.calls.append(("discovery-inputs", consumers, overrides, capabilities))
                harness.discovery_kwargs = kwargs
                self.migration = migration
                self.organization_principals = copy.deepcopy(harness.organization_principals)

            def inspect(self, owner, region):
                harness.calls.append(("discovery", owner, region))
                error = harness.discovery_errors.get((owner, region))
                if error:
                    return Plan(self.migration, blocked=[str(error)])
                plan = Plan(self.migration, groups=copy.deepcopy(harness.source.get((owner, region), [])),
                            excluded=["local empty share"] if region == HOME else [],
                            external_access=copy.deepcopy(
                                harness.external_access.get((owner, region), [])),
                            # Like Discovery: a difference is reported and its share is still
                            # planned, with the version its temporary share attaches.
                            permission_changes=copy.deepcopy(
                                harness.permission_changes.get((owner, region), [])))
                return plan

        class LocalStacks:
            def __init__(self, router, migration, timeout, cache=None):
                self.router, self.migration, self.cache = router, migration, cache
                harness.calls.append(("stacks-inputs", timeout))

            def existing(self, owner, region):
                harness.calls.append(("existing", owner, region))
                return {"StackId": "local-stored-stack"} if (owner, region) in harness.stored else None

            def persisted_groups(self, owner, region):
                harness.calls.append(("persisted", owner, region))
                return copy.deepcopy(harness.stored[owner, region])

            def prepare(self, owner, region, groups, fresh=False):
                key = owner, region
                harness.calls.append(("prepare", owner, region))
                harness.prepare_fresh.append((owner, region, fresh))
                harness.prepare_counts[key] += 1
                if key in harness.prepare_errors:
                    raise harness.prepare_errors[key]
                body = template_for(groups, self.migration)
                check_quotas(body)  # as Stacks.prepare does, before any write
                if key in harness.drift and harness.prepare_counts[key] > 1:
                    body["Description"] = "changed after confirmation"
                return body, self.existing(owner, region)

            def apply(self, owner, region, groups):
                harness.calls.append(("apply", owner, region))
                if (owner, region) in harness.apply_errors:
                    raise harness.apply_errors[owner, region]
                if harness.stored.get((owner, region)) == groups:
                    return "local-migration-stack"  # like Stacks.apply: nothing new to write
                self.router.client(owner, "cloudformation", region, write=True).create_change_set()
                harness.stored[owner, region] = copy.deepcopy(groups)
                for g in groups:
                    for consumer in g.consumers:
                        rows = harness.invitations[consumer, region]
                        arn = harness.share(g)["resourceShareArn"]
                        if not any(row["resourceShareArn"] == arn for row in rows):
                            rows.append(harness.invitation(g, consumer))
                return "local-migration-stack"

            def delete(self, owner, region):
                """Like Stacks.delete: refused while any of the stack's shares exists."""
                harness.calls.append(("delete-stack", owner, region))
                if any(harness.share(g)["resourceShareArn"] not in harness.deleted_shares
                       for g in harness.stored.get((owner, region), [])):
                    raise MigrationError("temporary share still exists; complete deletes and "
                                         "verifies every share before deleting its stack")
                harness.deleted_stacks.append((owner, region))
                harness.stored.pop((owner, region), None)
                return f"local-stack-{owner}-{region}"

            def shares(self, owner, region):
                harness.calls.append(("shares", owner, region))
                harness.share_reads[owner, region] += 1
                if (owner, region) not in harness.stored:
                    raise MigrationError("Migration stack does not exist")
                states = harness.share_states.get((owner, region), ["ACTIVE"])
                state = states.pop(0) if len(states) > 1 else states[0]
                deleted = set(harness.deleted_shares)
                return {g.logical_id: dict(harness.share(g), status="DELETED" if
                                           harness.share(g)["resourceShareArn"] in deleted else state)
                        for g in harness.stored[owner, region] if g.key not in harness.missing_shares}

            def readback(self, owner, region):
                """Like Stacks.readback: proven shares, and each unproven share's failure."""
                found = self.shares(owner, region)
                failures = {logical: copy.copy(error) for logical, error in
                            harness.readback_failures.get((owner, region), {}).items()}
                return Readback({logical: share for logical, share in found.items()
                                 if logical not in failures}, failures)

        def local_verify(router, g, share, migration, retired=frozenset()):
            harness.calls.append(("verify", g.key, share["resourceShareArn"], migration))
            if retired:
                harness.calls.append(("verify-retired", g.key, tuple(sorted(retired))))
            if harness.verify_hook:
                harness.verify_hook(router, g, share)
            if g.key in harness.verify_errors:
                error = harness.verify_errors[g.key]
                if callable(error):
                    error = error(router, g)
                if error:
                    raise error
            router.client(g.owner, "ram", g.region)

        def local_delete_share(router, owner, region, arn, migration, timeout=600):
            harness.calls.append(("delete-share", owner, region, arn))
            router.client(owner, "ram", region, write=True)  # the write gate must be open
            harness.deleted_shares.append(arn)
            if harness.after_delete:
                harness.after_delete(harness, arn)

        def local_remove_principals(router, owner, region, arn, migration, consumers, timeout=600):
            harness.calls.append(("remove-principals", owner, region, arn, tuple(consumers)))
            router.client(owner, "ram", region, write=True)  # the write gate must be open
            harness.removed_principals.update((arn, consumer) for consumer in consumers)
            if harness.after_remove:
                harness.after_remove(harness, arn, consumers)

        def local_unserved(router, owner, region, arn, consumers):
            """Like unserved_consumers, read back after a failed or interrupted action."""
            harness.calls.append(("readback", arn))
            return {consumer for consumer in consumers if arn in harness.deleted_shares
                    or (arn, consumer) in harness.removed_principals}

        monkeypatch.setattr(cli, "Router", LocalRouter)
        monkeypatch.setattr(cli, "verification", FakeVerification(self))
        monkeypatch.setattr(cli, "delete_share", local_delete_share)
        monkeypatch.setattr(cli, "remove_principals", local_remove_principals)
        monkeypatch.setattr(cli, "unserved_consumers", local_unserved)
        monkeypatch.setattr(cli, "Discovery", LocalDiscovery)
        monkeypatch.setattr(cli, "Stacks", LocalStacks)
        monkeypatch.setattr(cli, "verify_group", local_verify)
        monkeypatch.setattr(cli, "external_catalog", lambda: dict(harness.catalog))

    @staticmethod
    def share(g):
        return {"resourceShareArn": f"arn:aws:ram:{g.region}:{g.owner}:resource-share/temporary-{g.key}",
                "owningAccountId": g.owner}

    @classmethod
    def invitation(cls, g, consumer=CONSUMER, status="PENDING"):
        return {"resourceShareArn": cls.share(g)["resourceShareArn"],
                "resourceShareInvitationArn": f"local-invitation-{consumer}-{g.key}",
                "senderAccountId": g.owner, "receiverAccountId": consumer, "status": status}

    def confirm(self, _prompt):
        self.calls.append(("confirmation",))
        if self.org_after_confirmation:
            self.org_after_confirmation(self)
        return f"APPLY {MIGRATION}"

    def org_read(self, account, operation, *key):
        self.calls.append(("org-read", account, operation, *key))
        error = self.org_errors.get((operation, key[0] if key else None))
        if error:
            raise error

    def writes(self):
        return [call for call in self.calls if call[0] in ("write", "accept-write")]

    def receive(self, receiver=CONSUMER, owner=OWNER, region=REGION,
                share_status="ACTIVE", resource_status="AVAILABLE", suffix="original", resources=True):
        arn = f"arn:aws:ram:{region}:{owner}:resource-share/{suffix}"
        share = {"resourceShareArn": arn, "owningAccountId": owner, "status": share_status}
        self.received_shares[receiver, region].append(share)
        if resources:
            self.received_resources[receiver, region, arn].append(
                {"arn": f"arn:aws:ec2:{region}:{owner}:ipam-pool/test",
                 "type": IPAM, "status": resource_status, "resourceShareArn": arn})
        return share


@pytest.fixture
def harness(monkeypatch):
    value = Harness(monkeypatch)
    CURRENT["harness"] = value
    return value


CURRENT = {}
# Rewritten by every run; the discovery kwargs hold the run cache, which holds a lock.
_UNSNAPSHOTTED = {"router", "discovery_kwargs"}


@pytest.fixture(autouse=True)
def migration_record(tmp_path_factory, monkeypatch):
    CURRENT.clear()
    CURRENT["record"] = tmp_path_factory.mktemp("records") / "migration-record.json"
    yield CURRENT["record"]
    CURRENT.clear()


def snapshot(harness):
    return {k: copy.deepcopy(v) for k, v in vars(harness).items() if k not in _UNSNAPSHOTTED}


def restore(harness, saved):
    for key, value in saved.items():
        setattr(harness, key, value)


def simulate_recorded_apply(harness, path):
    """Record what an earlier apply would have: created shares and the original baseline."""
    groups = [g for stored in harness.stored.values() for g in stored]
    if not groups:
        return
    shares = defaultdict(dict)
    for g in groups:
        shares[g.owner, g.region][g.logical_id] = Harness.share(g)
    items = FakeVerification(harness).items(groups, frozenset(), pop=False)
    consumers = sorted({c for g in groups for c in g.consumers})
    observation = SimpleNamespace(observed_at="t0", items=items, gaps=[])

    def mutate(current):
        current["baseline"] = cli.new_baseline(
            observation, {c: harness.organizations[c] for c in consumers}, current["revision"] + 1)
        current["shares"] = cli.share_records([], groups, shares, MIGRATION)
    record_module.update(path, MIGRATION, mutate, mode="apply", status="SHARING_READY")


def main(argv, input_fn=None):
    """Run the CLI as operators must: apply/verify consume a reviewed plan record.

    For apply/verify without an explicit --record, first run plan --record against
    an untouched copy of the fake AWS state, then run the requested command.
    """
    argv = list(argv)
    mode = argv[0] if argv and argv[0] in ("plan", "approve", "apply", "verify", "monitor") else "plan"
    if mode in ("apply", "verify") and "--record" not in argv:
        record = CURRENT["record"]
        harness = CURRENT.get("harness")
        if not record.exists():
            saved = snapshot(harness) if harness else None
            plan_argv, skip = ["plan"], False
            for item in argv[1:]:
                if skip:
                    skip = False
                    continue
                if item == "--export-plan":
                    skip = True
                    continue
                plan_argv.append(item)
            if "--consumers" not in plan_argv:
                plan_argv += ["--consumers", CONSUMER]  # verify takes scope from the record
            with contextlib.redirect_stdout(io.StringIO()):
                cli.main(plan_argv + ["--record", str(record)],
                         input_fn=lambda _: pytest.fail("plan must not prompt"))
            if harness:
                restore(harness, saved)
                if mode == "verify":
                    simulate_recorded_apply(harness, record)
        argv += ["--record", str(record)]
    return cli.main(argv, input_fn=input_fn)


def test_parser_defaults_have_no_cloud_target_or_role():
    parsed = cli.build_parser().parse_args([])
    assert parsed.mode == "plan"
    assert parsed.owners == parsed.consumers == parsed.regions == parsed.profile == []
    assert parsed.source_profile is parsed.destination_profile is parsed.sso_role is None
    assert not hasattr(parsed, "cleanup")


def test_default_plan_is_readonly_including_global_home(harness, capsys, tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    assert main(args(), input_fn=lambda _: pytest.fail("Plan must not confirm")) == 0
    assert not harness.writes()
    assert not any(call[0] in ("apply", "verify") for call in harness.calls)
    discovered = {(call[1], call[2]) for call in harness.calls if call[0] == "discovery"}
    assert discovered == {(OWNER, REGION), (OWNER, HOME)}
    assert list(tmp_path.iterdir()) == []
    output = capsys.readouterr().out
    assert "status=PLANNED" in output and "expected_entitlements=1" in output
    assert OWNER in output and CONSUMER in output
    assert "live migration acceptance evidence" in output


@pytest.mark.parametrize("mode", ["plan", "apply"])
def test_received_unselected_owner_is_proposed_without_authenticating_foreign_account(
        harness, capsys, mode):
    share = harness.receive(receiver=CONSUMER, owner=OTHER_OWNER)
    argv = args(mode) + ["--role-map", json.dumps({
        OTHER_OWNER: f"arn:aws:iam::{OTHER_OWNER}:role/UnselectedRole"})]
    assert main(argv, input_fn=lambda _: pytest.fail("Audit blocker must precede confirmation")) == 1
    output = capsys.readouterr().out
    assert f"owner {OTHER_OWNER} is outside the approved owner scope" in output
    assert "status=OUTSIDE_OWNER_SCOPE" in output
    assert share["resourceShareArn"] in output and "ipam-pool/test" in output
    assert f"account={CONSUMER} owner={OTHER_OWNER} region={REGION}" in output
    assert "received_owners=1" in output and "received_shares=1" in output
    assert "received_resources=1" in output and "status=BLOCKED" in output
    assert not harness.writes() and not any(call[0] == "apply" for call in harness.calls)
    assert ("authentication", OTHER_OWNER) not in harness.calls
    assert not any(call[0] == "client" and call[1] == OTHER_OWNER for call in harness.calls)


@pytest.mark.parametrize("mode", ["plan", "apply"])
def test_received_approved_owner_is_accounted_for_without_re_sharing_received_resources(
        harness, capsys, mode):
    harness.receive()
    assert main(args(mode), input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    assert "phase=received-audit status=OWNER_INCLUDED" in output
    assert f"account={CONSUMER} owner={OWNER} region={REGION} phase=received-inventory shares=1 resources=1" in output
    assert "received_resource_observations=1" in output
    assert not any(call[0] == "apply" and call[1] == CONSUMER for call in harness.calls)
    if mode == "plan":
        assert not harness.writes()


@pytest.mark.parametrize("mode", ["plan", "apply"])
def test_adding_received_resource_owner_explicitly_allows_scoped_owner_discovery(harness, mode):
    harness.receive(owner=OTHER_OWNER)
    harness.source[OTHER_OWNER, REGION] = [group(owner=OTHER_OWNER)]
    argv = args(mode, owners=f"{OWNER},{OTHER_OWNER}") + [
        "--profile-map", json.dumps({OTHER_OWNER: "approved-other-owner"})]
    assert main(argv, input_fn=harness.confirm) == 0
    assert ("authentication", OTHER_OWNER) in harness.calls
    assert ("discovery", OTHER_OWNER, REGION) in harness.calls
    assert not any(call[0] == "apply" and call[1] == CONSUMER for call in harness.calls)
    if mode == "plan":
        assert not harness.writes()


@pytest.mark.parametrize("mode", ["plan", "apply"])
def test_stationary_owner_received_dependencies_are_not_migration_blockers(harness, capsys, mode):
    # The owner is not migrating, so what it receives from others is not at risk.
    harness.receive(receiver=OWNER, owner=OTHER_OWNER)
    assert main(args(mode), input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    assert "outside the approved owner scope" not in output
    assert not any(call[0] == "received-shares" and call[1] == OWNER for call in harness.calls)


def test_received_audit_reads_only_migrating_accounts_and_global_home(harness):
    assert main(args()) == 0
    pairs = {(call[1], call[2]) for call in harness.calls if call[0] == "received-shares"}
    assert pairs == {(CONSUMER, REGION), (CONSUMER, HOME)}
    assert ("regions", CONSUMER, {"AllRegions": True}) in harness.calls
    assert all(call[3]["resourceOwner"] == "OTHER-ACCOUNTS"
               for call in harness.calls if call[0] == "received-shares")
    assert not harness.writes()


def test_received_global_resource_in_home_region_is_a_dependency(harness, capsys):
    share = harness.receive(owner=OTHER_OWNER, region=HOME)
    resource = harness.received_resources[CONSUMER, HOME, share["resourceShareArn"]][0]
    resource["arn"] = f"arn:aws:service::{OTHER_OWNER}:global/resource"
    assert main(args(), input_fn=lambda _: pytest.fail("Plan has no confirmation")) == 1
    output = capsys.readouterr().out
    assert resource["arn"] in output and f"region={HOME}" in output
    assert not harness.writes()


def test_received_audit_paginates_shares_and_resources(harness, capsys):
    first = harness.receive(suffix="first")
    second = harness.receive(suffix="second")
    harness.received_share_pages[CONSUMER, REGION] = [[first], [second]]
    resource = harness.received_resources[CONSUMER, REGION, first["resourceShareArn"]][0]
    another = dict(resource, arn=resource["arn"] + "-second")
    harness.received_resource_pages[CONSUMER, REGION, first["resourceShareArn"]] = [[resource], [another]]
    harness.source[OWNER, REGION][0].resources[another["arn"]] = IPAM  # every receipt is covered
    assert main(args()) == 0
    assert any(call[0] == "received-shares" and call[3].get("nextToken") == "1"
               for call in harness.calls)
    assert any(call[0] == "received-resources" and call[3].get("nextToken") == "1"
               for call in harness.calls)
    output = capsys.readouterr().out
    assert "received_shares=2" in output and "received_resources=2" in output
    assert "received_resource_observations=3" in output


def test_current_migration_receipt_requires_actual_persisted_share_provenance(harness, capsys):
    g = harness.source[OWNER, REGION][0]
    harness.stored[OWNER, REGION] = [copy.deepcopy(g)]
    physical = harness.share(g)["resourceShareArn"]
    harness.receive(suffix=physical.rsplit("/", 1)[1])
    assert main(args()) == 0
    output = capsys.readouterr().out
    assert "phase=received-audit status=CURRENT_MIGRATION" in output
    assert "proven through its owning persisted scope" in output
    assert not harness.writes()


def test_temporary_prefix_and_migration_tags_do_not_exempt_unknown_owners(harness, capsys):
    share = harness.receive(owner=OTHER_OWNER, suffix="TemporaryMigrationRAMShares-lookalike")
    share["name"] = f"TemporaryMigrationRAMShares-{MIGRATION}"
    share["tags"] = [{"key": "Purpose", "value": "TemporaryMigrationRAMShares"},
                     {"key": "MigrationId", "value": MIGRATION}]
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Unproven receipt must block")) == 1
    output = capsys.readouterr().out
    assert f"owner {OTHER_OWNER} is outside the approved owner scope" in output
    assert "status=CURRENT_MIGRATION" not in output
    assert not harness.writes()


@pytest.mark.parametrize("resource_status", ["PENDING", "AVAILABLE"])
def test_matching_persisted_share_does_not_hide_extra_received_resources(
        harness, capsys, resource_status):
    g = harness.source[OWNER, REGION][0]
    harness.stored[OWNER, REGION] = [copy.deepcopy(g)]
    physical = harness.share(g)["resourceShareArn"]
    harness.receive(suffix=physical.rsplit("/", 1)[1], resource_status=resource_status)
    resources = harness.received_resources[CONSUMER, REGION, physical]
    resources.append(dict(resources[0], arn=resources[0]["arn"] + "-unapproved"))
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Unapproved scope must not be ignored")) == 1
    output = capsys.readouterr().out
    assert "status=CURRENT_MIGRATION" not in output
    assert "differs from its owning persisted scope" in output
    assert not harness.writes()


def test_current_migration_resource_type_must_match_persisted_approval(harness, capsys):
    g = harness.source[OWNER, REGION][0]
    harness.stored[OWNER, REGION] = [copy.deepcopy(g)]
    physical = harness.share(g)["resourceShareArn"]
    harness.receive(suffix=physical.rsplit("/", 1)[1])
    harness.received_resources[CONSUMER, REGION, physical][0]["type"] = "service:DifferentType"
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Stored resource type differs")) == 1
    assert "differs from its owning persisted scope" in capsys.readouterr().out
    assert not harness.writes()


def test_similarly_named_share_from_approved_owner_is_not_a_proven_current_share(harness, capsys):
    harness.stored = copy.deepcopy(harness.source)
    harness.receive(suffix="TemporaryMigrationRAMShares-legacy")
    assert main(args()) == 0
    output = capsys.readouterr().out
    assert "status=OWNER_INCLUDED" in output and "status=CURRENT_MIGRATION" not in output
    assert not harness.writes()


def test_matching_share_does_not_exempt_consumers_outside_persisted_group(harness, capsys):
    g = harness.source[OWNER, REGION][0]
    harness.stored[OWNER, REGION] = [copy.deepcopy(g)]
    physical = harness.share(g)["resourceShareArn"]
    harness.receive(receiver=OTHER_CONSUMER, suffix=physical.rsplit("/", 1)[1], resource_status="PENDING")
    assert main(args("apply", consumers=f"{CONSUMER},{OTHER_CONSUMER}"),
                    input_fn=lambda _: pytest.fail("Receipt is outside persisted entitlement scope")) == 1
    assert "status=CURRENT_MIGRATION" not in capsys.readouterr().out
    assert not harness.writes()


def test_pending_received_resources_block_without_acceptance(harness, capsys):
    share = harness.receive(share_status="PENDING", resource_status="PENDING")
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Pending entitlement must block")) == 1
    output = capsys.readouterr().out
    assert share["resourceShareArn"] in output and "pending intended received entitlements" in output
    assert not harness.writes()


def test_pending_intended_empty_share_is_not_excluded(harness, capsys):
    share = harness.receive(share_status="PENDING", resources=False)
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Intended pending share must block")) == 1
    assert share["resourceShareArn"] in capsys.readouterr().out
    assert not harness.writes()


def test_pending_empty_share_named_in_principal_inventory_is_an_intended_dependency(harness, capsys):
    share = harness.receive(owner=OTHER_OWNER, share_status="PENDING", resources=False)
    inventory = json.dumps({share["resourceShareArn"]: [CONSUMER]})
    assert main(args("apply") + ["--principal-map", inventory],
                    input_fn=lambda _: pytest.fail("Intended inventory dependency is pending")) == 1
    output = capsys.readouterr().out
    assert "pending intended received entitlements" in output
    assert f"owner {OTHER_OWNER} is outside the approved owner scope" in output
    assert not harness.writes()


@pytest.mark.parametrize("state,has_resources", [
    ("PENDING", False), ("DELETED", True), ("DELETING", True), ("FAILED", True),
])
def test_nonactive_unrelated_receipts_are_named_exclusions_not_implicitly_accepted(
        harness, capsys, state, has_resources):
    share = harness.receive(owner=OTHER_OWNER, share_status=state,
                            resources=has_resources, suffix="unrelated")
    assert main(args(), input_fn=lambda _: pytest.fail("Plan must not accept anything")) == 0
    output = capsys.readouterr().out
    assert share["resourceShareArn"] in output
    assert f"nonactive received share status {state}" in output
    assert "include owner" not in output and not harness.writes()
    assert ("authentication", OTHER_OWNER) not in harness.calls


def test_received_audit_api_denial_is_a_named_blocker(harness, capsys):
    harness.received_errors[CONSUMER, REGION] = denied("GetResourceShares")
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Audit denial must block")) == 1
    output = capsys.readouterr().out
    assert f"account={CONSUMER} region={REGION} phase=received-audit status=BLOCKED" in output
    assert "operation=GetResourceShares" in output and "local-request-id" in output
    assert not harness.writes()


def test_received_resource_denial_blocks_even_when_other_shares_are_audited(harness, capsys):
    first = harness.receive(suffix="first")
    harness.receive(suffix="second")
    harness.received_errors[CONSUMER, REGION, first["resourceShareArn"]] = denied("ListResources")
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Resource read is incomplete")) == 1
    output = capsys.readouterr().out
    assert "operation=ListResources" in output and "resource-share/second" in output
    assert not harness.writes()


def test_received_audit_covers_every_enabled_consumer_region_without_a_flag(harness, capsys):
    harness.enabled_regions[CONSUMER].append({"RegionName": "eu-west-1", "OptInStatus": "not-opted-in"})
    harness.enabled_regions[CONSUMER].append({"RegionName": "ap-south-1", "OptInStatus": "opted-in"})
    assert main(args(regions=f"{REGION},eu-west-1")) == 0
    pairs = {(call[1], call[2]) for call in harness.calls if call[0] == "received-shares"}
    assert (CONSUMER, "eu-west-1") not in pairs            # explicitly requested, not enabled
    assert (CONSUMER, "ap-south-1") in pairs               # enabled, found without --scan-enabled-regions
    assert (CONSUMER, HOME) in pairs                       # RAM's home Region for global resources
    assert not any(account == OWNER for account, _region in pairs)
    assert f"account={CONSUMER} region=eu-west-1 phase=received-regions status=EXCLUDED" in capsys.readouterr().out
    assert not any(call[0] == "regions" and call[1] == OWNER for call in harness.calls)


def test_owner_discovery_follows_the_regions_consumers_receive_from(harness):
    harness.enabled_regions[CONSUMER].append({"RegionName": "ap-south-1", "OptInStatus": "opted-in"})
    harness.receive(region="ap-south-1")
    harness.source[OWNER, "ap-south-1"] = [group(region="ap-south-1")]
    assert main(args()) == 0
    discovered = {(call[1], call[2]) for call in harness.calls if call[0] == "discovery"}
    assert (OWNER, "ap-south-1") in discovered             # not in --regions; implied by a dependency


def test_consumer_enabled_region_denial_blocks_complete_audit(harness, capsys):
    harness.region_errors[CONSUMER] = denied("DescribeRegions")
    assert main(args("apply") + ["--scan-enabled-regions"],
                    input_fn=lambda _: pytest.fail("Regional audit scope is unresolved")) == 1
    output = capsys.readouterr().out
    assert "phase=received-regions status=BLOCKED operation=DescribeRegions" in output
    assert not any(call[0] == "received-shares" and call[1] == CONSUMER for call in harness.calls)
    assert not harness.writes()


def test_verify_does_not_audit_unrelated_received_owners_or_legacy_paths(harness, capsys):
    harness.stored = copy.deepcopy(harness.source)
    harness.source = {}
    harness.receive(owner=OTHER_OWNER)
    harness.received_errors[CONSUMER, REGION] = denied("GetResourceShares")
    assert main(args("verify", consumers=None)) == 0
    assert "sharing_status=SHARING_READY" in capsys.readouterr().out
    assert not any(call[0] in ("received-shares", "received-resources") for call in harness.calls)
    assert ("authentication", OTHER_OWNER) not in harness.calls
    assert not harness.writes()


def test_received_counts_and_blockers_are_part_of_optional_export(harness, tmp_path):
    harness.receive(owner=OTHER_OWNER)
    path = tmp_path / "blocked-plan.json"
    assert main(args() + ["--export-plan", str(path)]) == 1
    audit = json.loads(path.read_text())["received_entitlements"]
    assert audit["counts"]["received_resources"] == 1
    assert audit["scopes"][CONSUMER] == [HOME, REGION]
    assert audit["entries"][0]["owner"] == OTHER_OWNER
    assert any(f"owner {OTHER_OWNER} is outside the approved owner scope" in reason
               for reason in audit["blocked"])
    assert not harness.writes()


def test_received_totals_distinguish_unique_resources_from_recipient_observations(harness, capsys):
    harness.source[OWNER, REGION][0].consumers = (CONSUMER, OTHER_CONSUMER)
    harness.receive()
    harness.receive(receiver=OTHER_CONSUMER)
    assert main(args(consumers=f"{CONSUMER},{OTHER_CONSUMER}")) == 0
    output = capsys.readouterr().out
    assert "received_shares=1 received_resources=1" in output
    assert "received_share_observations=2 received_resource_observations=2" in output
    assert not harness.writes()


@pytest.mark.parametrize("mutation", ["owner", "region", "partition", "status"])
def test_received_inventory_mismatch_blocks_before_writes(harness, capsys, mutation):
    share = harness.receive()
    resource = harness.received_resources[CONSUMER, REGION, share["resourceShareArn"]][0]
    if mutation == "owner":
        resource["arn"] = resource["arn"].replace(OWNER, OTHER_OWNER)
    elif mutation == "region":
        resource["arn"] = resource["arn"].replace(REGION, "eu-west-1")
    elif mutation == "partition":
        resource["arn"] = resource["arn"].replace("arn:aws:", "arn:aws-cn:")
    else:
        share.pop("status")
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Malformed audit must block")) == 1
    output = capsys.readouterr().out
    assert "phase=received-audit status=BLOCKED" in output
    assert not harness.writes()


def test_explicit_maps_derive_profiles_and_preserve_leading_zeros(harness):
    role = f"arn:aws:iam::{OTHER_CONSUMER}:role/ExplicitRole"
    argv = args()
    del argv[argv.index("--profile"):argv.index("--profile") + 2]
    argv += ["--profile-map", json.dumps({OWNER: "owner-profile", CONSUMER: "consumer-profile"}),
             "--role-map", json.dumps({OTHER_CONSUMER: role})]
    assert main(argv) == 0
    constructor = next(call for call in harness.calls if call[0] == "router")
    assert constructor[1] == ["owner-profile", "consumer-profile"]
    assert constructor[2] == {OWNER: "owner-profile", CONSUMER: "consumer-profile", OTHER_CONSUMER: role}
    assert constructor[3]["sso_role"] == ""


def test_source_destination_profiles_and_explicit_sso_role_are_passed_through(harness):
    argv = args()
    del argv[argv.index("--profile"):argv.index("--profile") + 2]
    argv += ["--source-profile", "chosen-source", "--destination-profile", "chosen-destination",
             "--sso-role", "ChosenRole"]
    assert main(argv) == 0
    constructor = next(call for call in harness.calls if call[0] == "router")
    assert constructor[1] == ["chosen-source", "chosen-destination"]
    assert constructor[3]["sso_role"] == "ChosenRole"


def test_account_map_can_be_loaded_from_an_explicit_json_file(harness, tmp_path):
    path = tmp_path / "accounts.json"
    path.write_text(json.dumps({OWNER: "owner-only", CONSUMER: "consumer-only"}))
    argv = args()
    del argv[argv.index("--profile"):argv.index("--profile") + 2]
    assert main(argv + ["--account-map", str(path)]) == 0
    constructor = next(call for call in harness.calls if call[0] == "router")
    assert constructor[1] == ["owner-only", "consumer-only"]


@pytest.mark.parametrize("option,value", [
    ("--owners", "123"),
    ("--owners", "１２３４５６７８９０１２"),
    ("--consumers", "00000000002"),
    ("--regions", "not-a-region"),
    ("--account-map", '{"000000000001": 1}'),
    ("--account-map", '{"1": "profile"}'),
    ("--profile-map", '{"000000000001": "arn:aws:iam::000000000001:role/Test"}'),
    ("--role-map", '{"000000000001": "profile"}'),
    ("--role-map", '{"000000000001": "arn:aws:iam::000000000002:role/Test"}'),
    ("--account-map", '{"000000000001": " profile "}'),
    ("--principal-map", '{"not-an-arn": ["000000000002"]}'),
    ("--principal-map", '{"arn:aws:ram:us-west-2:000000000001:resource-share/test": [2]}'),
    ("--principal-map", '{"arn:aws:ram:us-west-2:000000000001:resource-share/test": "000000000002"}'),
    ("--capabilities", '{"ec2:IpamPool": "true"}'),
])
def test_bad_scope_or_maps_fail_before_authentication(harness, option, value):
    argv = args()
    if option in argv:
        argv[argv.index(option) + 1] = value
    else:
        argv += [option, value]
    assert main(argv) == 1
    assert not harness.calls


def test_conflicting_maps_are_rejected(harness, capsys):
    assert main(args() + ["--account-map", json.dumps({OWNER: "a"}),
                             "--profile-map", json.dumps({OWNER: "b"})]) == 1
    assert "conflicting" in capsys.readouterr().out
    assert not harness.calls


def test_role_map_without_any_base_profile_is_rejected(harness, capsys):
    argv = args()
    del argv[argv.index("--profile"):argv.index("--profile") + 2]
    argv += ["--role-map", json.dumps({OWNER: f"arn:aws:iam::{OWNER}:role/Test"})]
    assert main(argv) == 1
    assert "base --profile" in capsys.readouterr().out


def test_principal_inventory_is_passed_to_discovery(harness):
    source = harness.source[OWNER, REGION][0].source_shares[0]
    mapping = {source: [CONSUMER, OTHER_CONSUMER]}
    assert main(args() + ["--principal-map", json.dumps(mapping)]) == 0
    assert next(call for call in harness.calls if call[0] == "discovery-inputs")[2] == mapping


def test_interactive_flow_prompts_explicit_role(harness):
    replies = iter([MIGRATION, OWNER, CONSUMER, REGION, "configured-profile", "ExplicitSSORole"])
    prompts = []
    def ask(prompt):
        prompts.append(prompt)
        return next(replies)
    assert main(["--interactive"], input_fn=ask) == 0
    assert "SSO role" in prompts[-1]
    assert next(call for call in harness.calls if call[0] == "router")[3]["sso_role"] == "ExplicitSSORole"


def test_blank_interactive_role_has_mapping_guidance(harness, capsys):
    replies = iter([""])
    assert main(args() + ["--interactive"], input_fn=lambda _: next(replies)) == 0
    assert "--account-map/--profile-map/--role-map" in capsys.readouterr().out


def test_no_ambient_profile_fallback(harness, capsys):
    argv = args()
    del argv[argv.index("--profile"):argv.index("--profile") + 2]
    assert main(argv) == 1
    assert "explicit" in capsys.readouterr().out and not harness.calls


def test_sdk_failure_precedes_authentication(harness, monkeypatch, capsys):
    def fail():
        raise MigrationError("SDK lacks RAM retention write/readback support")
    monkeypatch.setattr(cli, "check_sdk", fail)
    assert main(args("apply"), input_fn=harness.confirm) == 1
    assert not harness.calls
    assert "SDK lacks" in capsys.readouterr().out


def test_bootstrap_error_is_printed_without_login_attempt(harness, monkeypatch, capsys):
    def fail(*_args, **_kwargs):
        raise MigrationError("bootstrap: complete aws configure sso and select account and role")
    monkeypatch.setattr(cli, "Router", fail)
    assert main(args()) == 1
    assert "select account and role" in capsys.readouterr().out


def test_missing_credentials_are_reported_as_a_cli_failure(harness, monkeypatch, capsys):
    def fail(*_args, **_kwargs):
        raise NoCredentialsError()
    monkeypatch.setattr(cli, "Router", fail)
    assert main(args()) == 1
    assert "status=BLOCKED" in capsys.readouterr().out
    assert not harness.writes()


def test_authentication_error_is_actionable_and_aborts_before_writes(harness, capsys):
    harness.auth_errors[CONSUMER] = denied("GetCallerIdentity")
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Blocked apply must not confirm")) == 1
    output = capsys.readouterr().out
    assert "operation=GetCallerIdentity" in output and "local-request-id" in output
    assert CONSUMER in output and "--sso-role" in output
    assert not harness.writes()


def test_optional_export_is_only_a_plan(harness, tmp_path):
    path = tmp_path / "plan.json"
    assert main(args() + ["--export-plan", str(path)]) == 0
    exported = json.loads(path.read_text())
    assert exported["groups"][0]["owner"] == OWNER
    assert exported["groups"][0]["consumers"] == [CONSUMER]
    assert exported["migration_stacks"][0]["template"]["Resources"]
    assert exported["capability_provenance"]["source"].startswith("AWS RAM")
    assert not any(key in exported for key in ("results", "acceptance", "PASS", "credentials"))
    assert not harness.writes()


def test_capability_restrictions_cannot_invent_official_support(harness, capsys, migration_record):
    # The reviewed plan used the official catalog; apply cannot widen it afterwards.
    assert main(args() + ["--record", str(migration_record)]) == 0
    capsys.readouterr()
    assert main(args("apply") + ["--capabilities", '{"unknown:Type": true}'],
                    input_fn=lambda _: pytest.fail("Unsupported capabilities must not confirm")) == 1
    assert "not supported by the official type catalog" in capsys.readouterr().out
    assert not harness.writes()


def test_capability_source_and_extra_denials_are_explicit(harness, capsys):
    assert main(args() + ["--capabilities", '{"unknown:Type": false}']) == 0
    output = capsys.readouterr().out
    assert '"supplied_restrictions": {"unknown:type": false}' in output
    assert "not proof of resource subtype compatibility" in output
    received = next(call for call in harness.calls if call[0] == "discovery-inputs")[3]
    assert received[IPAM.lower()] is True and received["unknown:type"] is False


def test_all_plan_blockers_abort_apply_without_confirmation(harness):
    harness.discovery_errors[OWNER, HOME] = "unresolved intended principals"
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Must abort before confirmation")) == 1
    assert not harness.writes() and not any(call[0] == "apply" for call in harness.calls)


def test_stack_blocker_in_any_region_prevents_every_write(harness):
    harness.source[OWNER, HOME] = [group(region=HOME)]
    harness.prepare_errors[OWNER, HOME] = denied("GetTemplate")
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Must abort before confirmation")) == 1
    assert harness.prepare_counts[OWNER, REGION] == 1
    assert not harness.writes()


@pytest.mark.parametrize("reply", ["yes", "APPLY another-migration", " APPLY local-test", "APPLY local-test\n"])
def test_confirmation_must_match_exact_typed_token(harness, reply, capsys):
    assert main(args("apply"), input_fn=lambda _: reply) == 2
    assert "CANCELLED" in capsys.readouterr().out
    assert not harness.writes()


def test_confirmation_eof_is_safe_cancellation(harness):
    def eof(_):
        raise EOFError
    assert main(args("apply"), input_fn=eof) == 2
    assert not harness.writes()


def test_apply_confirms_once_before_writes_and_verifies(harness, capsys):
    assert main(args("apply"), input_fn=harness.confirm) == 0
    labels = [call[0] for call in harness.calls]
    assert labels.count("confirmation") == 1
    assert labels.index("confirmation") < labels.index("write") < labels.index("accept-write") < labels.index("verify")
    assert harness.prepare_counts[OWNER, REGION] == 2
    output = capsys.readouterr().out
    assert "status=SHARING_READY" in output and "accepted_invitations=1" in output
    assert "created_shares=1" in output
    assert not any(call[0] in ("cleanup", "delete", "associate-resolver", "migrate") for call in harness.calls)


def test_changed_plan_after_confirmation_aborts_before_any_write(harness, capsys):
    harness.drift.add((OWNER, REGION))
    assert main(args("apply"), input_fn=harness.confirm) == 1
    assert "plan changed" in capsys.readouterr().out
    assert not harness.writes()


def test_partial_creation_failure_retains_and_verifies_successful_regions(harness, capsys):
    good = harness.source[OWNER, REGION][0]
    harness.source[OTHER_OWNER, REGION] = [group(owner=OTHER_OWNER)]
    harness.apply_errors[OTHER_OWNER, REGION] = MigrationError("partial stack failure")
    assert main(args("apply", owners=f"{OWNER},{OTHER_OWNER}"), input_fn=harness.confirm) == 1
    assert (OWNER, REGION) in harness.stored
    assert any(call[0] == "verify" and call[1] == good.key for call in harness.calls)
    output = capsys.readouterr().out
    assert "Successful temporary shares are retained" in output and "status=INCOMPLETE" in output


def test_apply_reuses_stored_groups_when_source_entitlements_disappeared(harness, capsys):
    harness.stored = copy.deepcopy(harness.source)
    harness.source = {}
    g = harness.stored[OWNER, REGION][0]
    harness.invitations[CONSUMER, REGION] = [harness.invitation(g, status="ACCEPTED")]
    assert main(args("apply"), input_fn=harness.confirm) == 0
    assert not any(call[0] == "accept-write" for call in harness.calls)
    output = capsys.readouterr().out
    assert "reused_shares=1" in output and "created_shares=0" in output
    assert "reused_invitations=1" in output


def test_verify_uses_stored_groups_without_source_discovery_or_acceptance(harness, capsys):
    harness.stored = copy.deepcopy(harness.source)
    harness.source = {}
    assert main(args("verify", consumers=None), input_fn=lambda _: pytest.fail("Verify must not confirm")) == 0
    assert not harness.writes()
    assert any(call[0] == "persisted" for call in harness.calls)
    assert not any(call[0] in ("discovery", "prepare", "apply") for call in harness.calls)
    assert ("authentication", CONSUMER) in harness.calls
    assert "sharing_status=SHARING_READY" in capsys.readouterr().out


def test_verify_without_stored_entitlements_is_not_ready(harness, capsys):
    assert main(args("verify", consumers=None)) == 1
    assert "No stored/planned migration entitlements" in capsys.readouterr().out
    assert not harness.writes()


def test_missing_stored_share_is_a_verification_failure(harness, capsys):
    harness.stored = copy.deepcopy(harness.source)
    harness.missing_shares.add(harness.stored[OWNER, REGION][0].key)
    assert main(args("verify")) == 1
    assert "planned share missing" in capsys.readouterr().out
    assert not harness.writes()


def test_verify_cannot_request_a_write_client(harness, capsys):
    harness.stored = copy.deepcopy(harness.source)
    g = harness.stored[OWNER, REGION][0]
    def write_request(router, candidate):
        router.client(candidate.owner, "ram", candidate.region, write=True)
    harness.verify_errors[g.key] = write_request
    assert main(args("verify")) == 1
    assert "write gate is closed" in capsys.readouterr().out
    assert not harness.writes()


def test_apply_final_verification_gate_is_closed(harness, capsys):
    g = harness.source[OWNER, REGION][0]
    def write_request(router, candidate):
        router.client(candidate.owner, "ram", candidate.region, write=True)
    harness.verify_errors[g.key] = write_request
    assert main(args("apply"), input_fn=harness.confirm) == 1
    assert "write gate is closed" in capsys.readouterr().out
    assert len([call for call in harness.calls if call[0] == "write"]) == 1


def test_closed_write_gate_rejects_before_router_or_aws_access():
    calls = []

    class UntouchedRouter:
        def client(self, *args, **kwargs):
            calls.append((args, kwargs))
            pytest.fail("An unconfirmed write gate must not request an AWS client")

    gate = cli.WriteGate(UntouchedRouter())
    with pytest.raises(MigrationError, match="write gate is closed"):
        gate.client(OWNER, "ram", REGION, write=True)
    assert calls == []


def test_write_gate_also_guards_clients_returned_by_bad_helpers(harness):
    main(args())
    gate = cli.WriteGate(harness.router)
    with pytest.raises(MigrationError, match="Read-only"):
        gate.client(OWNER, "ram", REGION).accept_resource_share_invitation(resourceShareInvitationArn="bad")
    with pytest.raises(MigrationError, match="guarded client"):
        gate.session(OWNER)
    assert not harness.writes()


def test_region_discovery_is_per_owner_and_excludes_disabled_regions(harness):
    harness.enabled_regions[OWNER] += [{"RegionName": "eu-west-1", "OptInStatus": "opted-in"},
                                       {"RegionName": "ap-east-1", "OptInStatus": "not-opted-in"}]
    harness.enabled_regions[OTHER_OWNER] += [{"RegionName": "eu-north-1", "OptInStatus": "opted-in"}]
    assert main(args(owners=f"{OWNER},{OTHER_OWNER}") + ["--scan-enabled-regions"]) == 0
    discovered = {(call[1], call[2]) for call in harness.calls if call[0] == "discovery"}
    assert (OWNER, "eu-west-1") in discovered and (OTHER_OWNER, "eu-north-1") in discovered
    assert (OTHER_OWNER, "eu-west-1") not in discovered
    assert not any(region == "ap-east-1" for _, region in discovered)
    assert all((owner, HOME) in discovered for owner in (OWNER, OTHER_OWNER))


def test_fanout_obeys_account_and_per_account_region_bounds():
    lock = threading.Lock()
    active = Counter()
    maxima = {"accounts": 0, "regions": 0, "total": 0}
    scopes = {f"{index:012}": ["a", "b", "c", "d"] for index in range(5)}
    def work(account, region):
        with lock:
            active[account] += 1
            maxima["accounts"] = max(maxima["accounts"], len([v for v in active.values() if v]))
            maxima["regions"] = max(maxima["regions"], active[account])
            maxima["total"] = max(maxima["total"], sum(active.values()))
        threading.Event().wait(0.01)
        with lock:
            active[account] -= 1
        return region
    results = cli.fanout(scopes, work, account_workers=2, region_workers=3)
    assert len(results) == 20 and all(row.error is None for row in results)
    assert maxima["accounts"] <= 2 and maxima["regions"] <= 3 and maxima["total"] <= 6


def test_acceptance_leaves_unrelated_invitations_alone(harness):
    unrelated = harness.invitation(group(owner=OTHER_OWNER))
    harness.invitations[CONSUMER, REGION].append(unrelated)
    assert main(args("apply"), input_fn=harness.confirm) == 0
    assert harness.invitations[CONSUMER, REGION][0]["status"] == "PENDING"
    accepted = [call[1] for call in harness.calls if call[0] == "accept-write"]
    assert unrelated["resourceShareInvitationArn"] not in accepted
    assert len(accepted) == 1


def test_invitation_sender_mismatch_fails_without_accepting(harness, capsys):
    g = harness.source[OWNER, REGION][0]
    invitation = harness.invitation(g)
    invitation["senderAccountId"] = OTHER_OWNER
    harness.invitations[CONSUMER, REGION] = [invitation]
    assert main(args("apply"), input_fn=harness.confirm) == 1
    assert "invitation owner/receiver mismatch" in capsys.readouterr().out
    assert not any(call[0] == "accept-write" for call in harness.calls)


def test_expired_invitation_is_not_retried_or_withdrawn(harness, capsys):
    g = harness.source[OWNER, REGION][0]
    harness.invitations[CONSUMER, REGION] = [harness.invitation(g, status="EXPIRED")]
    assert main(args("apply"), input_fn=harness.confirm) == 1
    assert "EXPIRED" in capsys.readouterr().out
    assert not any(call[0] == "accept-write" for call in harness.calls)


def test_partial_invitation_acceptance_is_counted_and_retained(harness, capsys):
    first = harness.source[OWNER, REGION][0]
    second = group()
    second.permissions[IPAM] = "arn:aws:ram::aws:permission/AnotherApprovedPermission"
    harness.source[OWNER, REGION].append(second)
    harness.invitations[CONSUMER, REGION] = [
        harness.invitation(first), harness.invitation(second, status="EXPIRED")]
    assert main(args("apply"), input_fn=harness.confirm) == 1
    assert harness.invitations[CONSUMER, REGION][0]["status"] == "ACCEPTED"
    output = capsys.readouterr().out
    assert "accepted_invitations=1" in output
    assert "Successful temporary shares are retained" in output


def test_acceptance_polls_association_completion_with_bounded_retries(harness, monkeypatch):
    harness.principal_states[OWNER, REGION] = ["MISSING", "ASSOCIATING", "ASSOCIATED"]
    delays = []
    monkeypatch.setattr(cli.time, "sleep", delays.append)
    argv = args("apply")
    argv[argv.index("--retry-limit") + 1] = "3"
    assert main(argv, input_fn=harness.confirm) == 0
    assert len(delays) == 2
    assert len([call for call in harness.calls if call[0] == "accept-write"]) == 1


def test_access_denial_is_not_polled_and_keeps_request_id(harness, capsys):
    harness.stored = copy.deepcopy(harness.source)
    g = harness.stored[OWNER, REGION][0]
    harness.verify_errors[g.key] = denied("ListResources")
    assert main(args("verify")) == 1
    assert len([call for call in harness.calls if call[0] == "verify"]) == 1
    output = capsys.readouterr().out
    assert "operation=ListResources" in output and "request local-request-id" in output


def test_verification_eventual_consistency_is_bounded(harness, monkeypatch, capsys):
    harness.stored = copy.deepcopy(harness.source)
    g = harness.stored[OWNER, REGION][0]
    harness.verify_errors[g.key] = MigrationError("resource associations incomplete")
    delays = []
    monkeypatch.setattr(cli.time, "sleep", delays.append)
    assert main(args("verify")) == 1
    assert len([call for call in harness.calls if call[0] == "verify"]) == 2
    assert len(delays) == 1 and "status=INCOMPLETE" in capsys.readouterr().out


def test_verification_refreshes_share_state_on_every_poll(harness, monkeypatch):
    harness.stored = copy.deepcopy(harness.source)
    harness.share_states[OWNER, REGION] = ["PENDING", "PENDING", "ACTIVE"]
    observed = []
    def verify(_router, _group, share):
        observed.append(share["status"])
        if share["status"] != "ACTIVE":
            raise MigrationError("migration configuration is not ready")
    harness.verify_hook = verify
    monkeypatch.setattr(cli.time, "sleep", lambda _: None)
    assert main(args("verify")) == 0
    assert observed == ["PENDING", "ACTIVE"]
    assert harness.share_reads[OWNER, REGION] == 3


def test_transport_errors_are_retried_locally_within_the_limit(harness, monkeypatch):
    harness.stored = copy.deepcopy(harness.source)
    g = harness.stored[OWNER, REGION][0]
    harness.verify_errors[g.key] = EndpointConnectionError(endpoint_url="https://local.invalid")
    delays = []
    monkeypatch.setattr(cli.time, "sleep", delays.append)
    assert main(args("verify")) == 1
    assert len([call for call in harness.calls if call[0] == "verify"]) == 2
    assert len(delays) == 1


@pytest.mark.parametrize("message", [
    "unexpected or missing principal entitlements",
    "permission policy differs from approved policy",
    "invalid ownership configuration is not ready",
])
def test_invalid_or_unapproved_entitlements_are_not_polled(harness, message):
    harness.stored = copy.deepcopy(harness.source)
    g = harness.stored[OWNER, REGION][0]
    harness.verify_errors[g.key] = MigrationError(message)
    assert main(args("verify")) == 1
    assert len([call for call in harness.calls if call[0] == "verify"]) == 1


def association(association_id="association-original", vpc="vpc-original", status="COMPLETE"):
    return {"Id": association_id, "ResolverRuleId": "actual-owner-rule-id", "VPCId": vpc, "Status": status}


def test_apply_baseline_keeps_actual_ids_and_compares_after_writes(harness, capsys, migration_record):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    harness.resolver_samples[CONSUMER, REGION] = [[association()], [association()], [association()]]
    assert main(args("apply"), input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    assert "association_id=association-original" in output and "rule_id=actual-owner-rule-id" in output
    assert "phase=baseline status=CAPTURED" in output and "phase=post-apply" in output
    assert "status=SHARING_READY" in output and "baseline_status=INTACT" in output
    baseline = record_module.load(migration_record, MIGRATION)["baseline"]
    assert f"resolver_association|{CONSUMER}|{REGION}|association-original" in \
        {item["key"] for item in baseline["items"]}
    assert baseline["complete"] and baseline["consumer_organizations"] == {CONSUMER: "o-sourceorg01"}


@pytest.mark.parametrize("after,reason", [
    ([], "MISSING"),
    ([association("association-replacement")], "MISSING"),
    ([association(vpc="vpc-replacement")], "VPC_ID"),
    ([association(status="FAILED")], "STATUS"),
])
def test_any_change_to_a_baseline_association_fails_and_is_a_permanent_drop(
        harness, after, reason, capsys, migration_record):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    harness.resolver_samples[CONSUMER, REGION] = [[association()], [association()], after]
    assert main(args("apply"), input_fn=harness.confirm) == 1
    output = capsys.readouterr().out
    assert "status=INCOMPLETE" in output
    assert not any(line.startswith("status=SHARING_READY") for line in output.splitlines())
    assert f"status=BASELINE_{reason}" in output
    drop, = record_module.load(migration_record, MIGRATION)["drops"]
    assert (drop["kind"], drop["severity"], drop["detected_by"]) == ("association", "failure", "apply")


def test_unassociated_rules_are_reported_not_claimed_as_missing(harness, capsys):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    assert main(args("apply"), input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    assert "status=NOT_ASSOCIATED" in output and "unassociated_resolver_rules=1" in output
    assert "baseline_missing=0" in output and "no association repair was performed" in output
    assert "PASS" not in output


def test_unhealthy_resolver_baseline_blocks_before_confirmation(harness):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    harness.resolver_samples[CONSUMER, REGION] = [[association(status="CREATING")]]
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Baseline is blocked")) == 1
    assert not harness.writes()


def test_collector_access_denial_blocks_baseline_before_writes(harness, capsys, migration_record):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    assert main(with_record(args(), migration_record)) == 0
    harness.collect_gaps = [{"collector": "resolver", "account": OWNER, "region": REGION,
                             "resource_arn": "arn:resolver", "reason":
                             "AccessDeniedException request local-request-id operation=ListResolverRules"}]
    assert main(with_record(args("apply"), migration_record),
                input_fn=lambda _: pytest.fail("Baseline is blocked")) == 1
    output = capsys.readouterr().out
    assert "operation=ListResolverRules" in output and "cannot be captured completely" in output
    assert not harness.writes()
    assert record_module.load(migration_record, MIGRATION)["baseline"] is None


def test_merge_retains_optional_permission_and_stack_evidence():
    first = group()
    second = ApprovedGroup(first.owner, first.region, first.consumers, first.permissions,
                           first.resources, first.source_shares, {"kind": {"Policy": {}}}, ["stack-id"])
    plan = Plan(MIGRATION, groups=[first])
    cli.merge_plan(plan, Plan(MIGRATION, groups=[second]))
    assert plan.groups[0].permission_snapshots == second.permission_snapshots
    assert plan.groups[0].source_stacks == ["stack-id"]


def test_discovery_may_not_broaden_requested_consumer_population(harness, capsys):
    harness.source[OWNER, REGION] = [group(consumer=OTHER_CONSUMER)]
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Plan is blocked")) == 1
    assert "outside the approved population" in capsys.readouterr().out
    assert not harness.writes()


@pytest.mark.parametrize("mode", ["verify", "monitor"])
def test_plan_export_is_rejected_for_other_modes(harness, tmp_path, mode):
    assert main(args(mode) + ["--export-plan", str(tmp_path / "unused.json")]) == 1
    assert not harness.calls


@pytest.mark.parametrize("option,value", [
    ("--account-workers", "0"),
    ("--region-workers", "65"),
    ("--retry-limit", "-1"),
    ("--timeout", "0"),
    ("--timeout", "nan"),
    ("--poll-interval", "inf"),
])
def test_parallelism_and_time_limits_are_validated(harness, option, value):
    with pytest.raises(SystemExit) as exc:
        main(args() + [option, value])
    assert exc.value.code == 2 and not harness.calls


# ---------------------------------------------------------------------------
# Reviewed record; managed-permission differences are information, never approved
# ---------------------------------------------------------------------------
IPAM_PERMISSION = f"arn:aws:ram::aws:permission/{IPAM}"
ORIGINAL_SHARE = f"arn:aws:ram:{REGION}:{OWNER}:resource-share/original"
V2 = {"Effect": "Allow", "Action": ["ec2:DescribeTransitGateways"]}
V3 = {"Effect": "Allow", "Action": ["ec2:DescribeTransitGateways", "ec2:CreateClientVpnEndpoint"]}
NEW_SHARE = "new temporary share (receives the current default)"


def tgw_like_change(before=("2", V2), after=("3", V3)):
    """The original share attaches ``before``; its temporary share attaches ``after``."""
    from ram_migration_discovery import policy_semantics
    (old, old_policy), (new, new_policy) = before, after
    prior = {"Arn": IPAM_PERMISSION, "Version": old, "ResourceType": IPAM,
             "Policy": policy_semantics(old_policy), "DefaultVersion": False}
    target = {"Arn": IPAM_PERMISSION, "Version": new, "ResourceType": IPAM,
              "Policy": policy_semantics(new_policy), "DefaultVersion": True}
    return permission_change(OWNER, REGION, ORIGINAL_SHARE, prior, target)


def with_record(argv, path):
    return list(argv) + ["--record", str(path)]


def permission_lines(output):
    return [line for line in output.splitlines() if line.startswith("phase=permission-change ")]


def test_a_v2_to_v3_difference_plans_as_information_and_the_record_keeps_it(
        harness, capsys, migration_record, tmp_path):
    """The temporary share attaches the current default, v3. The difference is shown, never
    blocks and needs no approval; the record's plan and the export keep it for reviewers."""
    change = dict(tgw_like_change(), applies_to=NEW_SHARE)
    harness.permission_changes[OWNER, REGION] = [change]
    export = tmp_path / "plan.json"
    assert main(with_record(args(), migration_record) + ["--export-plan", str(export)]) == 0
    output = capsys.readouterr().out
    assert permission_lines(output) == [
        f"phase=permission-change status=INFO permission={IPAM_PERMISSION} resource_type={IPAM} "
        f"version=2->3 from_policy_sha256={change['from_policy_sha256']} "
        f"to_policy_sha256={change['to_policy_sha256']} shares=1"]
    assert "  grants more: Allow ec2:CreateClientVpnEndpoint" in output
    assert "  actions added: Allow ec2:CreateClientVpnEndpoint" in output
    assert f"  share={ORIGINAL_SHARE} applies_to={NEW_SHARE}" in output
    assert "APPROVAL_REQUIRED" not in output and "phase=blocker-summary" not in output
    assert "status=PLANNED" in summary_line(output) and "blockers=0" in summary_line(output)
    record = read_record(migration_record)
    assert record["plan"]["status"] == "PLANNED" and record["plan"]["blocked"] == []
    assert record["plan"]["permission_changes"] == [change]
    assert record["history"][-1]["permission_changes"] == 1
    assert "permission_change_requests" not in record and record["approvals"] == {"owner_scope": []}
    assert json.loads(export.read_text())["permission_changes"] == [change]
    planned, = record["plan"]["groups"]
    assert planned["source_shares"] == [ORIGINAL_SHARE] and "permission_changes" not in planned
    assert not harness.writes()


def test_a_difference_that_narrows_access_is_also_a_warning(harness, capsys):
    """The original attaches v3; its temporary share attaches v2, which grants less."""
    harness.permission_changes[OWNER, REGION] = [tgw_like_change(before=("3", V3), after=("2", V2))]
    assert main(args()) == 0
    output = capsys.readouterr().out
    info, warning = permission_lines(output)
    assert info.startswith(f"phase=permission-change status=INFO permission={IPAM_PERMISSION} "
                           f"resource_type={IPAM} version=3->2 ")
    assert warning == (
        f"phase=permission-change status=WARNING permission={IPAM_PERMISSION} "
        f"resource_type={IPAM} version=3->2 shares=1 the temporary share grants less than the "
        "original share (Allow ec2:CreateClientVpnEndpoint); once the original share stops "
        "applying, the migrating consumers keep only what the temporary share grants")
    assert "  grants less: Allow ec2:CreateClientVpnEndpoint" in output
    assert "status=PLANNED" in summary_line(output)


def test_apply_proceeds_without_any_permission_approval(harness, capsys, migration_record):
    harness.permission_changes[OWNER, REGION] = [tgw_like_change()]
    assert main(with_record(args(), migration_record)) == 0
    capsys.readouterr()
    prompts = []
    assert main(with_record(args("apply"), migration_record),
                input_fn=lambda prompt: prompts.append(prompt) or harness.confirm(prompt)) == 0
    output = capsys.readouterr().out
    assert len(prompts) == 1 and f"APPLY {MIGRATION}" in prompts[0]
    assert permission_lines(output)[0].startswith("phase=permission-change status=INFO ")
    assert "permission-revalidation" not in output and "status=SHARING_READY" in summary_line(output)
    confirmation = harness.calls.index(("confirmation",))
    first_write = harness.calls.index(next(c for c in harness.calls if c[0] == "write"))
    assert confirmation < first_write
    record = read_record(migration_record)
    assert [(h["mode"], h["status"]) for h in record["history"]] == [
        ("plan", "PLANNED"), ("apply", "BASELINE_CAPTURED"), ("apply", "STACK_COMPLETE"),
        ("apply", "SHARING_READY")]
    # Every apply entry names the reviewed plan it consumed.
    assert {(h["plan_revision"], h["plan_digest"]) for h in record["history"]
            if h["mode"] == "apply"} == {(1, record["plan"]["digest"])}
    template = record["plan"]["migration_stacks"][0]["template"]
    assert "PermissionChanges" not in next(iter(template["Resources"].values()))["Metadata"]
    share, = record["shares"]
    assert share["share_arn"].startswith(f"arn:aws:ram:{REGION}:{OWNER}:resource-share/temporary-")


def test_approve_has_nothing_to_approve_for_a_permission_difference(harness, capsys,
                                                                    migration_record):
    harness.permission_changes[OWNER, REGION] = [tgw_like_change()]
    assert main(with_record(args(), migration_record)) == 0
    before = read_record(migration_record)
    harness.calls.clear()
    capsys.readouterr()
    assert main(["approve", "--record", str(migration_record)],
                input_fn=lambda _p: pytest.fail("a permission difference needs no approval")) == 0
    assert f"migration={MIGRATION} phase=approve status=NOTHING_PENDING" in capsys.readouterr().out
    assert not any(call[0] in ("router", "authentication", "client") for call in harness.calls)
    assert read_record(migration_record) == before


def test_apply_refuses_a_blocked_reviewed_plan(harness, capsys, migration_record):
    harness.discovery_errors[OWNER, HOME] = "a blocker the reviewed plan found"
    assert main(with_record(args(), migration_record)) == 1
    del harness.discovery_errors[OWNER, HOME]  # resolved, but never reviewed
    assert main(with_record(args("apply"), migration_record),
                input_fn=lambda _: pytest.fail("blocked record must not confirm")) == 1
    assert "reviewed plan (revision 1) is BLOCKED" in capsys.readouterr().out
    assert not harness.writes()


def test_apply_never_adopts_a_rediscovered_scope(harness, capsys, migration_record):
    assert main(with_record(args(), migration_record)) == 0
    harness.source[OWNER, REGION][0].resources[f"arn:aws:ec2:{REGION}:{OWNER}:ipam-pool/new"] = IPAM
    assert main(with_record(args("apply"), migration_record),
                input_fn=lambda _: pytest.fail("changed scope must not confirm")) == 1
    assert "differ from reviewed plan revision 1" in capsys.readouterr().out
    assert not harness.writes()


def test_apply_refuses_a_plan_reviewed_with_other_tool_sources(harness, capsys, migration_record,
                                                               monkeypatch):
    assert main(with_record(args(), migration_record)) == 0
    real = cli.tool_identity()
    monkeypatch.setattr(cli, "tool_identity", lambda: {**real, "sources_digest": "0" * 64})
    assert main(with_record(args("apply"), migration_record),
                input_fn=lambda _: pytest.fail("must not confirm")) == 1
    assert "tool sources changed since the reviewed plan" in capsys.readouterr().out
    assert not harness.writes()


def test_record_from_another_migration_is_refused(harness, capsys, migration_record):
    assert main(with_record(args(), migration_record)) == 0
    other = [item if item != MIGRATION else "prod-scope" for item in args("apply")]
    assert main(with_record(other, migration_record),
                input_fn=lambda _: pytest.fail("must not confirm")) == 1
    assert "approvals never transfer between migrations" in capsys.readouterr().out
    assert not harness.writes()


@pytest.mark.parametrize("mode", ["apply", "verify"])
def test_apply_and_verify_require_the_reviewed_record(harness, capsys, mode):
    assert cli.main(args(mode), input_fn=lambda _: pytest.fail("must not confirm")) == 1
    assert f"{mode} requires --record" in capsys.readouterr().out
    assert not harness.writes()


# ---------------------------------------------------------------------------
# Consumer-driven dependency scope and owner-scope approval (v0.2.0)
# ---------------------------------------------------------------------------
def receive_two_from_other_owner(harness):
    share = harness.receive(owner=OTHER_OWNER, suffix="a")
    rows = harness.received_resources[CONSUMER, REGION, share["resourceShareArn"]]
    rows.append(dict(rows[0], arn=rows[0]["arn"] + "-2"))
    harness.receive(receiver=OTHER_CONSUMER, owner=OTHER_OWNER, suffix="b")


def owner_token(path):
    request = record_module.load(path, MIGRATION)["owner_scope_request"]
    return request, f"APPROVE-OWNERS {MIGRATION} {request['id']}"


def test_out_of_scope_owner_is_one_actionable_proposal(harness, capsys, migration_record):
    receive_two_from_other_owner(harness)
    argv = with_record(args(consumers=f"{CONSUMER},{OTHER_CONSUMER}"), migration_record)
    assert main(argv) == 1
    output = capsys.readouterr().out
    lines = [l for l in output.splitlines()
             if f"phase=owner-scope owner={OTHER_OWNER} status=APPROVAL_REQUIRED" in l]
    assert len(lines) == 1                       # not one blocker per repeated observation
    assert "provides 2 unique received resources (ec2:IpamPool x3)" in lines[0]
    assert "through 2 shares" in lines[0] and "(3 observations)" in lines[0]
    assert f"to migrating accounts {CONSUMER},{OTHER_CONSUMER}" in lines[0]
    assert ("authentication", OTHER_OWNER) not in harness.calls
    request, _ = owner_token(migration_record)
    assert request["owners"] == [OTHER_OWNER]
    assert request["evidence"][OTHER_OWNER]["unique_resources"] == 2
    assert record_module.load(migration_record, MIGRATION)["scope"]["proposed_owners"] == [OTHER_OWNER]


def test_owner_scope_expands_only_after_bound_approval_and_explicit_mapping(
        harness, capsys, migration_record):
    harness.receive(owner=OTHER_OWNER)
    harness.source[OTHER_OWNER, REGION] = [group(owner=OTHER_OWNER)]
    plan_argv = with_record(args(), migration_record)
    assert main(plan_argv) == 1
    request, token = owner_token(migration_record)
    assert main(["approve", "--record", str(migration_record)],
                input_fn=lambda _p: f"APPROVE-OWNERS {MIGRATION}") == 2
    assert main(plan_argv) == 1                  # a wrong token never expands the scope
    assert ("authentication", OTHER_OWNER) not in harness.calls
    capsys.readouterr()
    assert main(["approve", "--record", str(migration_record)], input_fn=lambda _p: token) == 0
    assert f"proposed_owners={OTHER_OWNER}" in capsys.readouterr().out
    harness.auth_errors[OTHER_OWNER] = denied("GetCallerIdentity")
    assert main(plan_argv) == 1                  # approved, but still needs its own access
    assert "phase=owner-scope status=APPROVED" in capsys.readouterr().out
    del harness.auth_errors[OTHER_OWNER]
    assert main(plan_argv + ["--profile-map", json.dumps({OTHER_OWNER: "approved-other-owner"})]) == 0
    assert ("discovery", OTHER_OWNER, REGION) in harness.calls
    record = record_module.load(migration_record, MIGRATION)
    assert record["scope"]["approved_owner_scope"] == [OTHER_OWNER]
    assert OTHER_OWNER in record["scope"]["stationary_owners"]
    assert record["plan"]["status"] == "PLANNED"


def test_uncovered_received_dependency_from_a_selected_owner_blocks(harness, capsys):
    share = harness.receive(suffix="extra")
    harness.received_resources[CONSUMER, REGION, share["resourceShareArn"]][0]["arn"] = \
        f"arn:aws:ec2:{REGION}:{OWNER}:ipam-pool/uncovered"
    assert main(args()) == 1
    output = capsys.readouterr().out
    assert "status=NOT_COVERED" in output
    assert "not covered by any planned temporary share" in output and "ipam-pool/uncovered" in output
    assert not harness.writes()


def test_coverage_does_not_repeat_an_upstream_discovery_blocker(harness, capsys):
    harness.discovery_errors[OWNER, REGION] = MigrationError(
        f"{ORIGINAL_SHARE}: owner={OWNER} region={REGION} source status PENDING")
    harness.receive()
    assert main(args()) == 1
    output = capsys.readouterr().out
    assert "source status PENDING" in output and "not covered by any planned" not in output


def test_record_scope_distinguishes_account_roles(harness, migration_record):
    argv = with_record(args(owners=f"{OWNER},{OTHER_OWNER}",
                            consumers=f"{CONSUMER},{OTHER_OWNER}"), migration_record)
    assert main(argv + ["--profile-map", json.dumps({OTHER_OWNER: "other-owner"})]) == 0
    scope = record_module.load(migration_record, MIGRATION)["scope"]
    assert scope["migrating_consumers"] == [CONSUMER]
    assert scope["migrating_owners"] == [OTHER_OWNER]
    assert scope["stationary_owners"] == [OWNER]
    assert harness.discovery_kwargs["migrating_owners"] == {OTHER_OWNER}
    received = {call[1] for call in harness.calls if call[0] == "received-shares"}
    assert received == {CONSUMER, OTHER_OWNER}   # migrating owners are audited, stationary are not


# ---------------------------------------------------------------------------
# Original baseline, verification statuses and guarded completion
# ---------------------------------------------------------------------------
RULE = f"arn:aws:route53resolver:{REGION}:{OWNER}:resolver-rule/arn-name"
POOL = f"arn:aws:ec2:{REGION}:{OWNER}:ipam-pool/test"
ASSOCIATION_KEY = f"resolver_association|{CONSUMER}|{REGION}|association-original"
OTHER_PERMISSION = "arn:aws:ram::aws:permission/AnotherApprovedPermission"


def entitlement_key(arn, consumer=CONSUMER, region=REGION):
    return f"entitlement|{consumer}|{region}|{arn}"


def mode_args(mode, path, *extra):
    """verify/monitor/complete take owners, consumers and Regions from the record; monitor
    and complete act on every migrating account unless a test names some."""
    selection = ["--all-accounts"] if mode in ("monitor", "complete") and "--consumers" not in extra else []
    return [mode, "--migration-id", MIGRATION, "--profile", "explicit-source",
            "--retry-limit", "2", "--record", str(path), *selection, *extra]


def complete_args(path, *extra):
    return mode_args("complete", path, "--settle-seconds", "0", *extra)


def quietly(argv, input_fn=None):
    with contextlib.redirect_stdout(io.StringIO()):
        return main(argv, input_fn=input_fn)


def read_record(path):
    return record_module.load(path, MIGRATION)


def applied(harness, path, argv=None, code=0):
    """plan --record, then apply through the CLI: stacks, shares, baseline, verification."""
    argv = list(argv or args())
    assert quietly(with_record(argv, path)) == 0
    assert quietly(with_record(["apply", *argv], path), harness.confirm) == code
    harness.calls.clear()
    return read_record(path)


def resolver_applied(harness, path, sample=None):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    harness.resolver_samples[CONSUMER, REGION] = [sample if sample is not None else [association()]]
    return applied(harness, path)


def rewrite(path, **fields):
    """A tool-written revision with these fields replaced, e.g. a record from an older release."""
    record_module.update(path, MIGRATION, lambda current: current.update(fields),
                         mode="apply", status="LOCAL_FIXTURE")


def recorded_drop(path, kind="association", severity="failure", subject=ASSOCIATION_KEY):
    """A drop event written by the monitor through the record module."""
    drop = {"kind": kind, "severity": severity, "consumer": CONSUMER, "owner": OWNER,
            "region": REGION, "subject": subject, "last_present_at": "2026-10-14T05:00:00Z",
            "first_absent_at": "2026-10-14T05:05:00Z", "detected_by": "monitor",
            "consumer_organization_at_detection": "o-sourceorg01",
            "evidence": "local-evidence/monitor.json"}
    drop["id"] = record_module.drop_id(kind, CONSUMER, REGION, subject, drop["first_absent_at"])
    record_module.update(path, MIGRATION, lambda current: record_module.add_drops(current, [drop]),
                         mode="monitor", status="DROP_RECORDED")
    return drop


def gap(collector="tgw", reason="AccessDeniedException operation=DescribeTransitGatewayAttachments"):
    return {"collector": collector, "account": CONSUMER, "region": REGION,
            "resource_arn": POOL, "reason": reason}


def summary_line(output):
    return next(line for line in output.splitlines()
                if line.startswith("status=") and f" migration={MIGRATION} " in line)


def pool_group(*names, owner=OWNER, region=REGION, permission=IPAM_PERMISSION, consumers=(CONSUMER,)):
    return Group(owner, region, tuple(consumers), {IPAM: permission},
                 {f"arn:aws:ec2:{region}:{owner}:ipam-pool/{name}": IPAM for name in names},
                 [f"arn:aws:ram:{region}:{owner}:resource-share/original"])


def share_arn(g):
    return Harness.share(g)["resourceShareArn"]


def confirm_complete(harness):
    def confirm(_prompt):
        harness.calls.append(("confirmation",))
        return f"COMPLETE {MIGRATION}"
    return confirm


def write_clients(harness):
    return [index for index, call in enumerate(harness.calls) if call[0] == "client" and call[4]]


def completion_events(harness):
    return [f"collect-{call[1]}" if call[0] == "collect" else call[0] for call in harness.calls
            if call[0] in ("collect", "delete-share", "remove-principals", "delete-stack")]


# verify ---------------------------------------------------------------------
def test_verify_without_a_baseline_is_inconclusive_and_never_creates_one(
        harness, capsys, migration_record):
    applied(harness, migration_record)
    rewrite(migration_record, baseline=None)
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 3
    output = capsys.readouterr().out
    assert "status=INCONCLUSIVE" in summary_line(output)
    assert "sharing_status=SHARING_READY migration_status=INCONCLUSIVE" in output
    assert "no original baseline is recorded" in output
    record = read_record(migration_record)
    assert record["baseline"] is None
    entry = record["verifications"][-1]
    assert (entry["mode"], entry["migration_status"], entry["baseline_status"]) == (
        "verify", "INCONCLUSIVE", None)
    assert not harness.writes()


@pytest.mark.parametrize("persisting", [True, False])
def test_verify_with_an_incomplete_baseline_is_inconclusive(
        harness, capsys, migration_record, persisting):
    harness.collect_gaps = [gap("pca", "resource_checks_unavailable")]
    record = applied(harness, migration_record, code=1)  # gaps never count as success
    assert record["baseline"]["complete"] is False and record["shares"]
    if not persisting:
        harness.collect_gaps = []  # a later complete observation cannot complete the baseline
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 3
    output = capsys.readouterr().out
    assert "status=INCONCLUSIVE" in summary_line(output)
    assert "migration_status=INCONCLUSIVE baseline is incomplete: pca resource_checks_unavailable" in output
    assert read_record(migration_record)["baseline"] == record["baseline"]


def test_verify_observation_gaps_are_inconclusive(harness, capsys, migration_record):
    applied(harness, migration_record)
    harness.collect_gaps = [gap()]
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 3
    output = capsys.readouterr().out
    assert "phase=verification status=GAP collector=tgw" in output
    assert "migration_status=INCONCLUSIVE observation gap: tgw" in output
    line = summary_line(output)
    assert "status=INCONCLUSIVE" in line
    assert "baseline_status=INCONCLUSIVE baseline_missing=0 baseline_degraded=0 observation_gaps=1" in line
    assert read_record(migration_record)["drops"] == []


@pytest.mark.parametrize("change,kind,subject,reason", [
    ("association-missing", "association", ASSOCIATION_KEY, "missing"),
    ("association-failed", "association", ASSOCIATION_KEY, "status FAILED"),
    ("entitlement-invisible", "entitlement", entitlement_key(RULE), "not visible to the consumer"),
])
def test_verify_baseline_loss_fails_and_records_a_verify_drop(
        harness, capsys, migration_record, change, kind, subject, reason):
    record = resolver_applied(harness, migration_record)
    if change == "association-missing":
        harness.resolver_samples[CONSUMER, REGION] = [[]]
    elif change == "association-failed":
        harness.resolver_samples[CONSUMER, REGION] = [[association(status="FAILED")]]
    else:
        harness.original_lost.add((CONSUMER, REGION, RULE))
        harness.deleted_shares.append(share_arn(harness.stored[OWNER, REGION][0]))
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 1
    output = capsys.readouterr().out
    assert "status=FAILED" in summary_line(output)
    assert f"migration_status=FAILED {reason}: {subject}" in output
    after = read_record(migration_record)
    drop, = record_module.failure_drops(after)
    # A lost original share is recorded too, as an informational drop.
    assert {d["kind"] for d in after["drops"] if d["severity"] == "informational"} <= {"original_share"}
    assert (drop["kind"], drop["severity"], drop["detected_by"], drop["subject"]) == (
        kind, "failure", "verify", subject)
    assert (drop["consumer"], drop["owner"], drop["region"]) == (CONSUMER, OWNER, REGION)
    assert drop["consumer_organization_at_detection"] == "o-sourceorg01"
    assert drop["last_present_at"] == record["baseline"]["captured_at"]
    assert after["baseline"] == record["baseline"]
    assert (after["history"][-1]["mode"], after["history"][-1]["status"]) == ("verify", "FAILED")


def test_verify_recorded_failure_drop_fails_even_when_the_baseline_is_intact(
        harness, capsys, migration_record):
    resolver_applied(harness, migration_record)
    drop = recorded_drop(migration_record)
    harness.organizations[CONSUMER] = "o-destination1"
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 1
    output = capsys.readouterr().out
    line = summary_line(output)
    assert "status=FAILED" in line and "baseline_status=INTACT baseline_missing=0" in line
    assert f"failure drop association {ASSOCIATION_KEY} first absent {drop['first_absent_at']}" in output
    assert read_record(migration_record)["drops"] == [drop]
    assert read_record(migration_record)["verifications"][-1]["migration_status"] == "FAILED"


def test_verify_informational_original_share_drop_is_not_a_failure(harness, capsys, migration_record):
    applied(harness, migration_record)
    recorded_drop(migration_record, kind="original_share", severity="informational",
                  subject=ORIGINAL_SHARE)
    harness.organizations[CONSUMER] = "o-destination1"
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 0
    assert "status=MIGRATION_VALIDATED" in summary_line(capsys.readouterr().out)


def test_verify_consumer_still_in_its_baseline_organization_is_pending(harness, capsys, migration_record):
    applied(harness, migration_record)
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 0
    output = capsys.readouterr().out
    assert "status=PENDING_MIGRATION" in summary_line(output)
    assert "sharing_status=SHARING_READY migration_status=PENDING_MIGRATION" in output
    assert f"{CONSUMER} is still in its baseline organization o-sourceorg01" in output
    assert read_record(migration_record)["verifications"][-1]["migration_status"] == "PENDING_MIGRATION"


@pytest.mark.parametrize("organization", ["o-destination1", "STANDALONE"])
def test_verify_consumer_outside_its_baseline_organization_is_validated(
        harness, capsys, migration_record, organization):
    applied(harness, migration_record)
    harness.organizations[CONSUMER] = organization
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 0
    output = capsys.readouterr().out
    assert "status=MIGRATION_VALIDATED" in summary_line(output)
    assert "still in its baseline organization" not in output
    entry = read_record(migration_record)["verifications"][-1]
    assert entry["consumer_organizations"] == {CONSUMER: organization}
    assert (entry["baseline_status"], entry["migration_status"]) == ("INTACT", "MIGRATION_VALIDATED")


def test_verify_stays_pending_until_every_consumer_has_left(harness, capsys, migration_record):
    harness.source[OWNER, REGION][0].consumers = (CONSUMER, OTHER_CONSUMER)
    applied(harness, migration_record, args(consumers=f"{CONSUMER},{OTHER_CONSUMER}"))
    harness.organizations[CONSUMER] = "o-destination1"
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 0
    output = capsys.readouterr().out
    assert "status=PENDING_MIGRATION" in summary_line(output)
    assert f"{OTHER_CONSUMER} is still in its baseline organization" in output
    assert f"{CONSUMER} is still in its baseline organization" not in output
    harness.organizations[OTHER_CONSUMER] = "STANDALONE"
    assert main(mode_args("verify", migration_record)) == 0
    assert "status=MIGRATION_VALIDATED" in summary_line(capsys.readouterr().out)


@pytest.mark.parametrize("failure,detail", [
    (denied("DescribeOrganization"), "operation=DescribeOrganization"),
    ("", "Organization identity was not returned"),
])
def test_verify_organization_lookup_error_is_inconclusive(
        harness, capsys, migration_record, failure, detail):
    applied(harness, migration_record)
    harness.organizations[CONSUMER] = failure
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 3
    output = capsys.readouterr().out
    assert "status=INCONCLUSIVE" in summary_line(output)
    assert f"current organization of {CONSUMER} is unknown" in output
    assert f"account={CONSUMER} phase=organization status=BLOCKED" in output and detail in output
    assert read_record(migration_record)["verifications"][-1]["consumer_organizations"] == {}


def test_verify_organization_error_never_hides_a_baseline_loss(harness, capsys, migration_record):
    resolver_applied(harness, migration_record)
    harness.resolver_samples[CONSUMER, REGION] = [[]]
    harness.organizations[CONSUMER] = denied("DescribeOrganization")
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 1
    assert "status=FAILED" in summary_line(capsys.readouterr().out)
    drop, = read_record(migration_record)["drops"]
    assert drop["consumer_organization_at_detection"] == "UNKNOWN"


@pytest.mark.parametrize("state", ["intact", "added", "lost", "gaps", "migrated", "no-baseline"])
def test_verify_never_writes_or_replaces_the_baseline(harness, migration_record, state):
    resolver_applied(harness, migration_record)
    if state == "added":
        harness.resolver_samples[CONSUMER, REGION] = [[association(), association("association-new")]]
    elif state == "lost":
        harness.resolver_samples[CONSUMER, REGION] = [[]]
    elif state == "gaps":
        harness.collect_gaps = [gap()]
    elif state == "migrated":
        harness.organizations[CONSUMER] = "o-destination1"
    elif state == "no-baseline":
        rewrite(migration_record, baseline=None)
    before = read_record(migration_record)
    quietly(mode_args("verify", migration_record))
    after = read_record(migration_record)
    assert after["baseline"] == before["baseline"]
    assert after["shares"] == before["shares"]
    assert after["revision"] == before["revision"] + 1
    assert after["history"][-1]["mode"] == "verify"
    assert "BASELINE_CAPTURED" not in [h["status"] for h in after["history"] if h["mode"] == "verify"]


def test_verify_appends_one_verification_entry_per_run(harness, migration_record):
    record = applied(harness, migration_record)
    assert [entry["mode"] for entry in record["verifications"]] == ["apply"]
    assert quietly(mode_args("verify", migration_record)) == 0
    harness.organizations[CONSUMER] = "STANDALONE"
    assert quietly(mode_args("verify", migration_record)) == 0
    after = read_record(migration_record)
    assert after["verifications"][:1] == record["verifications"]
    assert [(e["mode"], e["migration_status"]) for e in after["verifications"]] == [
        ("apply", "PENDING_MIGRATION"), ("verify", "PENDING_MIGRATION"),
        ("verify", "MIGRATION_VALIDATED")]
    entry = after["verifications"][-1]
    assert (entry["sharing_status"], entry["baseline_status"]) == ("SHARING_READY", "INTACT")
    assert (entry["missing"], entry["degraded"], entry["gaps"]) == (0, 0, 0)
    assert entry["consumer_organizations"] == {CONSUMER: "STANDALONE"} and entry["reasons"] == []


@pytest.mark.parametrize("option,value", [
    ("--owners", OTHER_OWNER),
    ("--owners", f"{OWNER},{OTHER_OWNER}"),
    ("--consumers", OTHER_CONSUMER),
    ("--consumers", f"{CONSUMER},{OTHER_CONSUMER}"),
    ("--regions", "eu-west-1"),
    ("--regions", f"{REGION},eu-west-1"),
])
def test_verify_refuses_explicit_scope_that_disagrees_with_the_record(
        harness, capsys, migration_record, option, value):
    record = applied(harness, migration_record)
    capsys.readouterr()
    assert main(mode_args("verify", migration_record, option, value)) == 1
    assert f"{option} differs from the migration record scope" in capsys.readouterr().out
    assert [call[0] for call in harness.calls] == ["router"]
    assert read_record(migration_record)["revision"] == record["revision"]


def test_verify_accepts_explicit_scope_that_matches_the_record(harness, capsys, migration_record):
    applied(harness, migration_record)
    capsys.readouterr()
    assert main(with_record(args("verify"), migration_record)) == 0
    assert "status=PENDING_MIGRATION" in summary_line(capsys.readouterr().out)


def test_verify_blocks_when_a_recorded_share_is_missing_from_its_stack(harness, capsys, migration_record):
    harness.source[OWNER, REGION] = [pool_group("test"), pool_group("second", permission=OTHER_PERMISSION)]
    applied(harness, migration_record)
    removed = harness.stored[OWNER, REGION].pop()
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 1
    output = capsys.readouterr().out
    assert (f"phase=verification status=BLOCKED phase=reviewed-record recorded temporary share "
            f"{OWNER}/{REGION}/{removed.logical_id} is missing from its migration stack") in output
    assert "is not in the migration record" not in output
    assert not any(call[0] == "collect" for call in harness.calls)
    last = read_record(migration_record)["history"][-1]
    assert (last["mode"], last["status"]) == ("verify", "BLOCKED")


def test_verify_blocks_when_a_stack_entitlement_is_absent_from_the_record(
        harness, capsys, migration_record):
    applied(harness, migration_record)
    extra = pool_group("unrecorded", permission=OTHER_PERMISSION)
    harness.stored[OWNER, REGION].append(extra)
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 1
    output = capsys.readouterr().out
    assert (f"phase=verification status=BLOCKED phase=reviewed-record stack entitlement "
            f"{OWNER}/{REGION}/{extra.logical_id} is not in the migration record") in output
    assert "is missing from its migration stack" not in output
    assert not any(call[0] == "collect" for call in harness.calls)


def test_verify_reads_every_recorded_region_including_consumer_dependency_regions(
        harness, capsys, migration_record):
    harness.enabled_regions[CONSUMER].append({"RegionName": "ap-south-1", "OptInStatus": "opted-in"})
    harness.receive(region="ap-south-1")
    harness.source[OWNER, "ap-south-1"] = [group(region="ap-south-1")]
    record = applied(harness, migration_record)
    assert {share["region"] for share in record["shares"]} == {REGION, "ap-south-1"}
    assert "ap-south-1" not in record["scope"]["regions"]  # implied by a dependency, not --regions
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 0
    output = capsys.readouterr().out
    assert "sharing_status=SHARING_READY migration_status=PENDING_MIGRATION" in output
    assert ("persisted", OWNER, "ap-south-1") in harness.calls
    assert not any(call[0] in ("discovery", "received-shares") for call in harness.calls)


def baseline_without(path, consumer):
    """A record from a release whose apply could add a consumer after the baseline was
    captured: the baseline has no organization and no items for that consumer."""
    baseline = read_record(path)["baseline"]
    rewrite(path, baseline=dict(
        baseline, items=[i for i in baseline["items"] if i.get("consumer") != consumer],
        consumer_organizations={c: o for c, o in baseline["consumer_organizations"].items()
                                if c != consumer}))


def test_consumer_without_a_baseline_organization_is_never_validated(harness, capsys, migration_record):
    harness.source[OWNER, REGION].append(group(consumer=OTHER_CONSUMER))
    applied(harness, migration_record, args(consumers=f"{CONSUMER},{OTHER_CONSUMER}"))
    baseline_without(migration_record, OTHER_CONSUMER)
    assert read_record(migration_record)["baseline"]["consumer_organizations"] == {
        CONSUMER: "o-sourceorg01"}
    harness.organizations[CONSUMER] = "o-destination1"  # OTHER_CONSUMER never left
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 3
    output = capsys.readouterr().out
    assert "status=INCONCLUSIVE" in summary_line(output)
    assert f"{OTHER_CONSUMER} has no baseline organization" in output


# apply ----------------------------------------------------------------------
@pytest.mark.parametrize("after,reason", [
    ([], "missing"),
    ([association("association-replacement")], "missing"),
    ([association(status="FAILED")], "status FAILED"),
])
def test_resumed_apply_blocks_before_writes_when_a_baseline_item_is_lost(
        harness, capsys, migration_record, after, reason):
    record = resolver_applied(harness, migration_record)
    harness.resolver_samples[CONSUMER, REGION] = [after]
    capsys.readouterr()
    assert main(with_record(args("apply"), migration_record),
                input_fn=lambda _: pytest.fail("A lost baseline item blocks before confirmation")) == 1
    output = capsys.readouterr().out
    assert f"phase=baseline status=BLOCKED original {reason}: {ASSOCIATION_KEY}" in output
    assert "the recorded baseline is never replaced" in output
    assert not harness.writes() and not any(call[0] == "apply" for call in harness.calls)
    current = read_record(migration_record)
    assert current["baseline"] == record["baseline"]
    drop, = current["drops"]
    assert (drop["kind"], drop["severity"], drop["detected_by"], drop["subject"]) == (
        "association", "failure", "apply", ASSOCIATION_KEY)
    assert drop["last_present_at"] == record["baseline"]["captured_at"]
    last = current["history"][-1]
    assert (last["mode"], last["status"], last["drops"]) == ("apply", "BLOCKED", 1)


def test_resumed_apply_with_an_observation_gap_blocks_before_writes(harness, capsys, migration_record):
    record = applied(harness, migration_record)
    harness.collect_gaps = [gap()]
    capsys.readouterr()
    assert main(with_record(args("apply"), migration_record),
                input_fn=lambda _: pytest.fail("An incomplete observation blocks")) == 1
    assert "phase=baseline status=BLOCKED observation gap tgw" in capsys.readouterr().out
    assert not harness.writes()
    assert read_record(migration_record)["baseline"] == record["baseline"]


def test_baseline_is_captured_once_and_a_later_apply_never_replaces_it(harness, capsys, migration_record):
    first = resolver_applied(harness, migration_record)
    captured = [h for h in first["history"] if h["status"] == "BASELINE_CAPTURED"]
    assert len(captured) == 1 and first["baseline"]["captured_in_revision"] == captured[0]["revision"]
    added = f"resolver_association|{CONSUMER}|{REGION}|association-new"
    harness.resolver_samples[CONSUMER, REGION] = [[association(), association("association-new")]]
    capsys.readouterr()
    assert main(with_record(args("apply"), migration_record), input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    assert "phase=baseline status=CAPTURED" not in output
    assert "status=SHARING_READY" in summary_line(output) and "baseline_status=INTACT" in output
    record = read_record(migration_record)
    assert record["baseline"] == first["baseline"]
    assert added not in {item["key"] for item in record["baseline"]["items"]}
    assert [h["status"] for h in record["history"]].count("BASELINE_CAPTURED") == 1
    assert len(record["shares"]) == 1


@pytest.mark.parametrize("change,expected", [
    ("association-missing", f"original state changed during confirmation (missing): {ASSOCIATION_KEY}"),
    ("association-replaced", f"original state changed during confirmation (missing): {ASSOCIATION_KEY}"),
    ("association-moved", f"original state changed during confirmation (vpc_id changed): {ASSOCIATION_KEY}"),
    ("association-failed", "status=FAILED: not COMPLETE; capture requires a stable original state"),
    ("entitlement-lost", f"resource_arn={RULE} via_shares=0 via_temporary=0 via_other=0: "
                         "not visible to the consumer"),
])
def test_state_change_during_confirmation_blocks_at_the_write_gate(
        harness, capsys, migration_record, change, expected):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    harness.resolver_samples[CONSUMER, REGION] = [[association()]]
    assert quietly(with_record(args(), migration_record)) == 0
    after = {"association-missing": [], "association-replaced": [association("association-new")],
             "association-moved": [association(vpc="vpc-other")],
             "association-failed": [association(status="FAILED")]}

    def confirm(prompt):
        if change in after:
            harness.resolver_samples[CONSUMER, REGION] = [after[change]]
        else:
            harness.original_lost.add((CONSUMER, REGION, RULE))
        return harness.confirm(prompt)
    capsys.readouterr()
    assert main(with_record(args("apply"), migration_record), input_fn=confirm) == 1
    output = capsys.readouterr().out
    assert expected in output and "status=BLOCKED" in summary_line(output)
    assert "phase=baseline-preflight" in output and "phase=baseline kind=" in output
    assert not harness.writes() and not any(call[0] == "apply" for call in harness.calls)
    assert [call[0] for call in harness.calls].count("confirmation") == 1
    record = read_record(migration_record)
    assert record["baseline"] is None and record["drops"] == [] and record["shares"] == []
    last = record["history"][-1]
    assert (last["mode"], last["status"], last["phase"]) == ("apply", "BLOCKED", "post-confirmation")


@pytest.mark.parametrize("reply", ["no", f"APPLY {MIGRATION} ", f"COMPLETE {MIGRATION}", None])
def test_cancelled_confirmation_captures_no_baseline(harness, capsys, migration_record, reply):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    harness.resolver_samples[CONSUMER, REGION] = [[association()]]
    assert quietly(with_record(args(), migration_record)) == 0

    def answer(_prompt):
        if reply is None:
            raise EOFError
        return reply
    assert main(with_record(args("apply"), migration_record), input_fn=answer) == 2
    assert "status=CANCELLED" in capsys.readouterr().out
    record = read_record(migration_record)
    assert record["baseline"] is None and record["shares"] == []
    assert "BASELINE_CAPTURED" not in [h["status"] for h in record["history"]]
    assert not harness.writes()
    # The next apply captures the original state at its own write gate.
    harness.resolver_samples[CONSUMER, REGION] = [[association("association-later")]]
    assert quietly(with_record(args("apply"), migration_record), harness.confirm) == 0
    keys = {item["key"] for item in read_record(migration_record)["baseline"]["items"]}
    assert f"resolver_association|{CONSUMER}|{REGION}|association-later" in keys
    assert ASSOCIATION_KEY not in keys


def test_unassociated_rules_are_never_counted_as_missing_on_resume_verify_or_complete(
        harness, capsys, migration_record):
    record = resolver_applied(harness, migration_record, sample=[])
    assert not [item for item in record["baseline"]["items"] if item["kind"] == "resolver_association"]
    capsys.readouterr()
    assert main(with_record(args("apply"), migration_record), input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    assert f"consumer={CONSUMER} region={REGION} resource={RULE} phase=post-apply status=NOT_ASSOCIATED" \
        in output
    assert "baseline_missing=0" in output and "unassociated_resolver_rules=1" in output
    assert main(mode_args("verify", migration_record)) == 0
    output = capsys.readouterr().out
    assert "status=NOT_ASSOCIATED" in output and "baseline_missing=0" in output
    assert "status=PENDING_MIGRATION" in summary_line(output)
    assert main(complete_args(migration_record), input_fn=confirm_complete(harness)) == 0
    assert read_record(migration_record)["drops"] == []


def test_rule_unassociated_for_one_consumer_is_not_missing_for_either(harness, capsys, migration_record):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    harness.source[OWNER, REGION][0].consumers = (CONSUMER, OTHER_CONSUMER)
    harness.resolver_samples[CONSUMER, REGION] = [[association()]]
    applied(harness, migration_record, args(consumers=f"{CONSUMER},{OTHER_CONSUMER}"))
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 0
    output = capsys.readouterr().out
    assert f"consumer={OTHER_CONSUMER} region={REGION} resource={RULE} phase=verification " \
           "status=NOT_ASSOCIATED" in output
    assert f"consumer={CONSUMER} region={REGION} resource={RULE} phase=verification " \
           "status=NOT_ASSOCIATED" not in output
    line = summary_line(output)
    assert "baseline_missing=0" in line and "unassociated_resolver_rules=1" in line


def test_lost_baseline_association_is_reported_missing_never_as_unassociated(
        harness, capsys, migration_record):
    resolver_applied(harness, migration_record)
    harness.resolver_samples[CONSUMER, REGION] = [[]]
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 1
    output = capsys.readouterr().out
    assert f"status=BASELINE_MISSING key={ASSOCIATION_KEY}" in output
    assert "NOT_ASSOCIATED" not in output and "unassociated_resolver_rules" not in output
    assert "had none before migration" not in output


# complete -------------------------------------------------------------------
def refused(harness, path, capsys, *expected, extra=()):
    """complete must stop before its confirmation, delete nothing and record why."""
    before = read_record(path)
    deleted, stacks = list(harness.deleted_shares), list(harness.deleted_stacks)
    removed = set(harness.removed_principals)
    harness.calls.clear()
    assert main(complete_args(path, *extra),
                input_fn=lambda _: pytest.fail("A refused completion must not confirm")) == 1
    output = capsys.readouterr().out
    for text in expected:
        assert text in output
    assert f"status=BLOCKED migration={MIGRATION} phase=complete" in output
    assert "temporary shares retained" in output
    assert harness.deleted_shares == deleted and harness.deleted_stacks == stacks
    assert harness.removed_principals == removed
    assert not write_clients(harness)
    record = read_record(path)
    assert record["completion"] is None and record["shares"] == before["shares"]
    assert record["baseline"] == before["baseline"]
    assert record["retirements"] == before["retirements"]
    last = record["history"][-1]
    assert (last["mode"], last["status"]) == ("complete", "BLOCKED")
    return record


def test_complete_requires_the_record(harness, capsys):
    assert main(["complete", "--migration-id", MIGRATION, "--profile", "explicit-source"]) == 1
    assert "complete requires --record" in capsys.readouterr().out
    assert not harness.calls


def test_complete_refuses_without_a_baseline(harness, capsys, migration_record):
    applied(harness, migration_record)
    rewrite(migration_record, baseline=None)
    capsys.readouterr()
    refused(harness, migration_record, capsys,
            "a complete original baseline is required before the temporary path is retired")


def test_complete_refuses_with_an_incomplete_baseline(harness, capsys, migration_record):
    harness.collect_gaps = [gap("pca", "resource_checks_unavailable")]
    applied(harness, migration_record, code=1)
    harness.collect_gaps = []
    capsys.readouterr()
    refused(harness, migration_record, capsys,
            "a complete original baseline is required before the temporary path is retired")


@pytest.mark.parametrize("after,reason", [
    ([], "missing"),
    ([association(vpc="vpc-replacement")], "vpc_id changed"),
    ([association(status="FAILED")], "status FAILED"),
])
def test_complete_refuses_on_any_baseline_loss_and_records_the_drop(
        harness, capsys, migration_record, after, reason):
    resolver_applied(harness, migration_record)
    harness.resolver_samples[CONSUMER, REGION] = [after]
    capsys.readouterr()
    record = refused(harness, migration_record, capsys, f"original {reason}: {ASSOCIATION_KEY}")
    drop, = record["drops"]
    assert (drop["kind"], drop["severity"], drop["detected_by"], drop["subject"]) == (
        "association", "failure", "complete", ASSOCIATION_KEY)


def test_complete_refuses_with_a_recorded_failure_drop(harness, capsys, migration_record):
    resolver_applied(harness, migration_record)
    drop = recorded_drop(migration_record)  # the association recovered; the drop is permanent
    capsys.readouterr()
    record = refused(harness, migration_record, capsys,
                     f"failure drop recorded: association {ASSOCIATION_KEY} first absent "
                     f"{drop['first_absent_at']}")
    assert record["drops"] == [drop]


def test_complete_refuses_while_only_the_temporary_share_provides_access(
        harness, capsys, migration_record):
    applied(harness, migration_record)
    harness.original_lost.add((CONSUMER, REGION, POOL))  # no permanent replacement share yet
    capsys.readouterr()
    refused(harness, migration_record, capsys,
            f"phase=replacement consumer={CONSUMER} region={REGION} resource={POOL}: only the "
            "temporary share provides access; establish permanent replacement sharing first")


def test_complete_refuses_on_replacement_gaps(harness, capsys, migration_record):
    applied(harness, migration_record)
    harness.replacement_gaps = [gap("replacement", "AccessDeniedException operation=ListResources")]
    capsys.readouterr()
    refused(harness, migration_record, capsys,
            f"phase=replacement gap {CONSUMER} {REGION} AccessDeniedException operation=ListResources")


def test_complete_refuses_on_observation_gaps(harness, capsys, migration_record):
    applied(harness, migration_record)
    harness.collect_gaps = [gap()]
    capsys.readouterr()
    refused(harness, migration_record, capsys, f"observation gap tgw {CONSUMER} {REGION}")


@pytest.mark.parametrize("mismatch", ["recorded-only", "stack-only", "share-arn", "stack-absent"])
def test_complete_refuses_on_record_stack_mismatch(harness, capsys, migration_record, mismatch):
    first, second = pool_group("test"), pool_group("second", permission=OTHER_PERMISSION)
    harness.source[OWNER, REGION] = [first, second]
    record = applied(harness, migration_record)
    if mismatch == "recorded-only":
        harness.stored[OWNER, REGION] = [g for g in harness.stored[OWNER, REGION] if g.key != second.key]
        expected = (f"recorded temporary share {OWNER}/{REGION}/{second.logical_id} is missing "
                    "from its migration stack")
    elif mismatch == "stack-only":
        extra = pool_group("unrecorded", permission="arn:aws:ram::aws:permission/ThirdPermission")
        harness.stored[OWNER, REGION].append(extra)
        expected = f"stack entitlement {OWNER}/{REGION}/{extra.logical_id} is not in the migration record"
    elif mismatch == "share-arn":
        rewrite(migration_record, shares=[
            dict(entry, share_arn=entry["share_arn"] + "-replaced")
            if entry["logical_id"] == second.logical_id else entry for entry in record["shares"]])
        expected = (f"{OWNER}/{REGION}/{second.logical_id}: stack share {share_arn(second)} differs "
                    f"from recorded {share_arn(second)}-replaced")
    else:
        del harness.stored[OWNER, REGION]
        expected = f"owner={OWNER} region={REGION} phase=stored-plan"
    capsys.readouterr()
    refused(harness, migration_record, capsys, expected)


@pytest.mark.parametrize("failure", ["organization", "authentication"])
def test_complete_refuses_when_accounts_or_organizations_cannot_be_read(
        harness, capsys, migration_record, failure):
    applied(harness, migration_record)
    if failure == "organization":
        harness.organizations[CONSUMER] = denied("DescribeOrganization")
    else:
        harness.auth_errors[CONSUMER] = denied("GetCallerIdentity")
    capsys.readouterr()
    refused(harness, migration_record, capsys,
            f"account={CONSUMER} phase={failure} status=BLOCKED", "local-request-id")


def test_complete_refuses_a_record_without_temporary_shares(harness, capsys, migration_record):
    assert quietly(with_record(args(), migration_record)) == 0
    capsys.readouterr()
    refused(harness, migration_record, capsys, "the migration record has no temporary shares to retire")


def test_complete_refuses_a_consumer_the_baseline_never_covered(harness, capsys, migration_record):
    harness.source[OWNER, REGION].append(group(consumer=OTHER_CONSUMER))
    applied(harness, migration_record, args(consumers=f"{CONSUMER},{OTHER_CONSUMER}"))
    baseline_without(migration_record, OTHER_CONSUMER)
    capsys.readouterr()
    refused(harness, migration_record, capsys,
            f"consumer {OTHER_CONSUMER} is not covered by the original baseline")


@pytest.mark.parametrize("option,value", [("--owners", OTHER_OWNER), ("--regions", "eu-west-1")])
def test_complete_refuses_explicit_scope_that_disagrees_with_the_record(
        harness, capsys, migration_record, option, value):
    record = applied(harness, migration_record)
    capsys.readouterr()
    assert main(complete_args(migration_record, option, value),
                input_fn=lambda _: pytest.fail("must not confirm")) == 1
    assert f"{option} differs from the migration record scope" in capsys.readouterr().out
    assert [call[0] for call in harness.calls] == ["router"]
    assert read_record(migration_record)["revision"] == record["revision"]


def test_complete_refuses_a_selected_account_outside_the_record(harness, capsys, migration_record):
    record = applied(harness, migration_record)
    capsys.readouterr()
    assert main(mode_args("complete", migration_record, "--settle-seconds", "0",
                          "--consumers", OTHER_CONSUMER),
                input_fn=lambda _: pytest.fail("must not confirm")) == 1
    assert f"--consumers {OTHER_CONSUMER}: not a migrating account of this migration record" \
        in capsys.readouterr().out
    assert [call[0] for call in harness.calls] == ["router"]
    assert read_record(migration_record)["revision"] == record["revision"]


@pytest.mark.parametrize("reply", [
    "yes", f"APPLY {MIGRATION}", "COMPLETE another-migration", f"COMPLETE {MIGRATION} ",
    f"complete {MIGRATION}", None,
])
def test_complete_wrong_token_exits_2_without_deleting(harness, capsys, migration_record, reply):
    applied(harness, migration_record)
    prompts = []

    def answer(prompt):
        prompts.append(prompt)
        if reply is None:
            raise EOFError
        return reply
    assert main(complete_args(migration_record), input_fn=answer) == 2
    output = capsys.readouterr().out
    assert "status=CANCELLED" in output and f"COMPLETE {MIGRATION}" in prompts[0]
    assert "action=DELETE_SHARE" in output and "action=DELETE_STACK" in output
    assert not harness.deleted_shares and not harness.deleted_stacks and not write_clients(harness)
    record = read_record(migration_record)
    assert record["completion"] is None
    assert not [h for h in record["history"] if h["mode"] == "complete"]


def test_complete_deletes_smallest_share_first_and_stacks_last(harness, capsys, migration_record):
    large = pool_group("a1", "a2", "a3")
    small = pool_group("b1", permission=OTHER_PERMISSION)
    other = pool_group("c1", "c2", owner=OTHER_OWNER)
    harness.source = {(OWNER, REGION): [large, small], (OTHER_OWNER, REGION): [other]}
    applied(harness, migration_record, args(owners=f"{OWNER},{OTHER_OWNER}"))
    sites = {(CONSUMER, g.region, arn) for g in (large, small, other) for arn in g.resources}
    harness.original_lost |= sites  # the original organization share no longer applies,
    harness.replacement |= sites    # a permanent share from the new landing zone does
    harness.organizations[CONSUMER] = "o-destination1"
    recorded_drop(migration_record, kind="original_share", severity="informational",
                  subject=ORIGINAL_SHARE)
    capsys.readouterr()
    assert main(complete_args(migration_record), input_fn=confirm_complete(harness)) == 0
    output = capsys.readouterr().out
    order = [share_arn(g) for g in (small, other, large)]
    assert harness.deleted_shares == order
    assert completion_events(harness) == [
        "collect-3", "delete-share", "collect-1", "delete-share", "collect-1",
        "delete-share", "collect-1", "collect-3", "delete-stack", "delete-stack"]
    confirmation = harness.calls.index(("confirmation",))
    assert len(write_clients(harness)) == 3 and min(write_clients(harness)) > confirmation
    assert harness.deleted_stacks == [(OWNER, REGION), (OTHER_OWNER, REGION)]
    for index in (1, 2, 3):
        assert f"phase=complete-settle-{index} kind=entitlement" in output
    assert "phase=complete-final kind=entitlement" in output
    assert f"status=COMPLETED migration={MIGRATION} deleted_shares=3 deleted_stacks=2" in output
    record = read_record(migration_record)
    assert record["completion"]["deleted_shares"] == order
    assert record["completion"]["deleted_stacks"] == [f"local-stack-{OWNER}-{REGION}",
                                                      f"local-stack-{OTHER_OWNER}-{REGION}"]
    assert record["completion"]["consumer_organizations"] == {CONSUMER: "o-destination1"}
    assert [(h["status"], h.get("share")) for h in record["history"] if h["mode"] == "complete"] == [
        ("SHARE_DELETED", order[0]), ("SHARE_DELETED", order[1]), ("SHARE_DELETED", order[2]),
        ("COMPLETED", None)]
    assert len(record["shares"]) == 3 and not record_module.failure_drops(record)


def test_complete_stops_at_the_first_loss_after_a_deletion(harness, capsys, migration_record):
    small, large = pool_group("test"), pool_group("l1", "l2", permission=OTHER_PERMISSION)
    harness.source[OWNER, REGION] = [large, small]
    applied(harness, migration_record)

    def lose_access(h, arn):  # the consumer had no permanent path after all
        deleted = next(g for g in h.stored[OWNER, REGION] if share_arn(g) == arn)
        h.original_lost.update((c, deleted.region, r) for c in deleted.consumers for r in deleted.resources)
    harness.after_delete = lose_access
    capsys.readouterr()
    assert main(complete_args(migration_record), input_fn=confirm_complete(harness)) == 1
    output = capsys.readouterr().out
    assert harness.deleted_shares == [share_arn(small)] and not harness.deleted_stacks
    assert completion_events(harness) == ["collect-2", "delete-share", "collect-1"]
    assert f"status=FAILED phase=complete original not visible to the consumer: {entitlement_key(POOL)}" \
        in output
    assert f"status=FAILED phase=complete replacement access missing for {CONSUMER} {REGION} {POOL}" in output
    assert "Completion stopped; the remaining temporary shares are retained." in output
    record = read_record(migration_record)
    drop, = record["drops"]
    assert (drop["kind"], drop["severity"], drop["detected_by"], drop["subject"]) == (
        "entitlement", "failure", "complete", entitlement_key(POOL))
    assert drop["evidence"] == "complete-settle-1"
    assert record["completion"] is None
    assert [h["status"] for h in record["history"] if h["mode"] == "complete"] == [
        "SHARE_DELETED", "FAILED"]
    assert record["history"][-1]["deleted"] == [share_arn(small)]
    # The failure drop is permanent: restoring access does not re-enable completion.
    harness.after_delete = None
    harness.original_lost.clear()
    capsys.readouterr()
    refused(harness, migration_record, capsys, f"failure drop recorded: entitlement {entitlement_key(POOL)}")
    assert main(mode_args("verify", migration_record)) == 1
    assert "status=FAILED" in summary_line(capsys.readouterr().out)


def test_complete_settle_window_catches_a_delayed_loss(harness, capsys, migration_record, monkeypatch):
    applied(harness, migration_record)
    clock = [1000.0]
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])

    def sleep(seconds):
        clock[0] += seconds
        harness.original_lost.add((CONSUMER, REGION, POOL))  # fails after the first check
    monkeypatch.setattr(cli.time, "sleep", sleep)
    capsys.readouterr()
    assert main(mode_args("complete", migration_record, "--settle-seconds", "60"),
                input_fn=confirm_complete(harness)) == 1
    output = capsys.readouterr().out
    assert completion_events(harness) == ["collect-1", "delete-share", "collect-1", "collect-1"]
    assert f"original not visible to the consumer: {entitlement_key(POOL)}" in output
    assert not harness.deleted_stacks and read_record(migration_record)["completion"] is None


def test_complete_reverifies_for_the_whole_settle_window(harness, migration_record, monkeypatch):
    applied(harness, migration_record)
    clock = [1000.0]
    monkeypatch.setattr(cli.time, "monotonic", lambda: clock[0])
    monkeypatch.setattr(cli.time, "sleep", lambda seconds: clock.__setitem__(0, clock[0] + seconds))
    assert quietly(mode_args("complete", migration_record, "--settle-seconds", "60"),
                   confirm_complete(harness)) == 0
    # preflight, then at 0s/30s/60s after the deletion and again for the final check
    assert completion_events(harness) == ["collect-1", "delete-share"] + ["collect-1"] * 6 + ["delete-stack"]


def test_complete_share_deletion_failure_stops_and_keeps_the_rest(harness, capsys, migration_record,
                                                                  monkeypatch):
    harness.source[OWNER, REGION] = [pool_group("test"), pool_group("l1", "l2", permission=OTHER_PERMISSION)]
    applied(harness, migration_record)

    def failing(router, owner, region, arn, migration, timeout=600):
        harness.calls.append(("delete-share", owner, region, arn))
        router.client(owner, "ram", region, write=True)
        raise denied("DeleteResourceShare")
    monkeypatch.setattr(cli, "delete_share", failing)
    capsys.readouterr()
    assert main(complete_args(migration_record), input_fn=confirm_complete(harness)) == 1
    assert "phase=complete operation=DeleteResourceShare" in capsys.readouterr().out
    assert completion_events(harness) == ["collect-2", "delete-share"] and not harness.deleted_stacks
    record = read_record(migration_record)
    assert record["completion"] is None
    assert (record["history"][-1]["status"], record["history"][-1]["deleted"]) == ("FAILED", [])


def test_complete_stack_deletion_failure_records_no_completion(harness, capsys, migration_record,
                                                               monkeypatch):
    applied(harness, migration_record)

    def failing(self, owner, region):
        raise MigrationError("stack deletion did not finish before the timeout")
    monkeypatch.setattr(cli.Stacks, "delete", failing)
    capsys.readouterr()
    assert main(complete_args(migration_record), input_fn=confirm_complete(harness)) == 1
    assert "stack deletion did not finish" in capsys.readouterr().out
    record = read_record(migration_record)
    assert record["completion"] is None
    last = record["history"][-1]
    assert (last["status"], last["deleted"], last["stacks"]) == (
        "FAILED", [share_arn(harness.stored[OWNER, REGION][0])], [])


def test_already_complete_record_is_a_no_op(harness, capsys, migration_record):
    applied(harness, migration_record)
    assert quietly(complete_args(migration_record), confirm_complete(harness)) == 0
    record = read_record(migration_record)
    harness.calls.clear()
    capsys.readouterr()
    assert main(complete_args(migration_record), input_fn=lambda _: pytest.fail("nothing to confirm")) == 0
    assert (f"migration={MIGRATION} phase=complete status=ALREADY_COMPLETE "
            f"at={record['completion']['completed_at']}") in capsys.readouterr().out
    assert [call[0] for call in harness.calls] == ["router"]
    assert read_record(migration_record) == record


# ---------------------------------------------------------------------------
# Records and stacks from the permission-approval era, the locked write gate,
# per-stack recording, migrating owners found by their shares, Region exclusions,
# export safety, baseline coverage
# ---------------------------------------------------------------------------
from ram_migration_discovery import policy_semantics  # noqa: E402


def earlier_permission_approval():
    """What earlier versions wrote for an approved v2 -> v3 difference: a request and its
    approval in the record, and a PermissionChanges row naming that approval in the
    migration stack's template."""
    change = tgw_like_change()
    fields = {key: change[key] for key in ("permission_arn", "resource_type", "from_version",
                                           "to_version", "from_policy_sha256", "to_policy_sha256")}
    bound = {"migration_id": MIGRATION, **fields, "shares": [ORIGINAL_SHARE]}
    request = {"id": "pc-" + record_module.sha256(bound)[:16], **bound,
               "owners": [OWNER], "regions": [REGION],
               "difference": change["difference"], "from_policy": change["from_policy"],
               "to_policy": change["to_policy"]}
    approval = {"approval_id": request["id"], "migration_id": MIGRATION, **fields,
                "shares": [ORIGINAL_SHARE],
                "difference_sha256": record_module.sha256(change["difference"]),
                "approved_at": "2026-10-14T00:00:00+00:00",
                "approved_by": {"user": "approver", "host": "workstation"},
                "approved_in_revision": 2,
                "basis": "interactive confirmation of the displayed policy comparison"}
    row = {"SourceShareArn": ORIGINAL_SHARE, "PermissionArn": IPAM_PERMISSION,
           "ResourceType": IPAM, "FromVersion": "2", "ToVersion": "3",
           "FromPolicySha256": change["from_policy_sha256"],
           "ToPolicySha256": change["to_policy_sha256"], "ApprovalId": request["id"]}
    return request, approval, row


@pytest.mark.parametrize("held", [True, False])
def test_a_record_and_stack_with_earlier_permission_approvals_still_work_to_completion(
        harness, capsys, migration_record, monkeypatch, held):
    """Earlier versions recorded each permission difference as an approval in the record and
    as a PermissionChanges row naming it in the stack's template. Both are history: whether
    or not the record holds the approval the row names, the record plans, applies, verifies
    and completes, approve finds nothing to approve, and apply sees the deployed template
    unchanged, so it writes nothing and never reports that the plan changed."""
    harness.permission_changes[OWNER, REGION] = [tgw_like_change()]
    applied(harness, migration_record)
    request, approval, row = earlier_permission_approval()
    rewrite(migration_record, permission_change_requests=[request] if held else [],
            approvals={"permission_changes": [approval] if held else [], "owner_scope": []})
    stored, = harness.stored[OWNER, REGION]
    deployed = template_for([stored], MIGRATION)
    deployed["Resources"][stored.logical_id]["Metadata"]["PermissionChanges"] = [row]
    prepared = []

    class EarlierStacks(cli.Stacks):
        """The migration stack holds the template an earlier version wrote."""
        def prepare(self, owner, region, groups, fresh=False):
            body, old = super().prepare(owner, region, groups, fresh)
            prepared.append(additive_template(deployed, body, MIGRATION))
            return prepared[-1], old
    monkeypatch.setattr(cli, "Stacks", EarlierStacks)
    capsys.readouterr()
    assert main(with_record(args(), migration_record)) == 0
    assert "status=PLANNED" in summary_line(capsys.readouterr().out)
    assert main(["approve", "--record", str(migration_record)],
                input_fn=lambda _p: pytest.fail("nothing is pending")) == 0
    assert "status=NOTHING_PENDING" in capsys.readouterr().out
    harness.calls.clear()
    assert main(with_record(args("apply"), migration_record), input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    assert "status=SHARING_READY" in summary_line(output) and "plan changed" not in output
    assert not harness.writes()
    assert len(prepared) == 3 and all(body == deployed for body in prepared)
    assert main(mode_args("verify", migration_record)) == 0
    assert "status=PENDING_MIGRATION" in summary_line(capsys.readouterr().out)
    sites = {(CONSUMER, REGION, arn) for arn in stored.resources}
    harness.original_lost |= sites   # the original organization share no longer applies,
    harness.replacement |= sites     # a permanent share from the new landing zone does
    harness.organizations[CONSUMER] = "o-destination1"
    assert main(complete_args(migration_record), input_fn=confirm_complete(harness)) == 0
    record = read_record(migration_record)
    assert record["completion"] is not None
    assert record["permission_change_requests"] == ([request] if held else [])
    assert record["approvals"]["permission_changes"] == ([approval] if held else [])


def test_a_share_joining_an_existing_temporary_share_needs_no_approval_for_its_difference(
        harness, capsys, migration_record):
    """A second original share joins an existing temporary share, which keeps the version it
    was created with: the difference to that version is reported and apply proceeds."""
    kept_v3 = {"Arn": IPAM_PERMISSION, "Version": "3", "ResourceType": IPAM,
               "Policy": policy_semantics(V3), "DefaultVersion": True}
    first = ApprovedGroup(OWNER, REGION, (CONSUMER,), {IPAM: IPAM_PERMISSION}, {POOL: IPAM},
                          [ORIGINAL_SHARE], {IPAM: kept_v3}, [])
    harness.source[OWNER, REGION] = [first]
    applied(harness, migration_record)
    second = ORIGINAL_SHARE + "-second"
    joining = copy.deepcopy(first)
    joining.source_shares = [second]            # the same entitlement through another original
    harness.source[OWNER, REGION] = [first, joining]
    existing = f"existing temporary share {first.logical_id} (keeps version 3)"
    harness.permission_changes[OWNER, REGION] = [dict(tgw_like_change(), share=second,
                                                      applies_to=existing)]
    assert quietly(with_record(args(), migration_record)) == 0
    capsys.readouterr()
    assert main(with_record(args("apply"), migration_record), input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    assert f"  share={second} applies_to={existing}" in output
    assert "status=SHARING_READY" in summary_line(output)
    stored, = harness.stored[OWNER, REGION]
    assert stored.source_shares == [ORIGINAL_SHARE, second]
    assert stored.permission_snapshots == {IPAM: kept_v3}


@pytest.mark.parametrize("concurrent", ["blocked", "identical", "changed"])
def test_a_plan_recorded_while_apply_waits_for_confirmation_blocks_at_the_write_gate(
        harness, capsys, migration_record, concurrent):
    """Finding 7: apply rereads the record under its lock immediately before writing."""
    assert quietly(with_record(args(), migration_record)) == 0

    def confirm(prompt):                        # a second operator re-plans meanwhile
        saved = snapshot(harness)
        if concurrent == "blocked":
            harness.discovery_errors[OWNER, HOME] = "a blocker the second plan found"
        elif concurrent == "changed":
            harness.source[OWNER, REGION].append(pool_group("added", permission=OTHER_PERMISSION))
        quietly(with_record(args(), migration_record))
        restore(harness, saved)
        return harness.confirm(prompt)
    capsys.readouterr()
    assert main(with_record(args("apply"), migration_record), input_fn=confirm) == 1
    output = capsys.readouterr().out
    assert ("phase=preflight status=BLOCKED phase=reviewed-record the migration record changed "
            "while this apply waited for confirmation, and nothing was written: ") in output
    assert "category=reviewed-record-mismatch blockers=1 " in output
    assert not harness.writes() and not any(call[0] == "apply" for call in harness.calls)
    record = read_record(migration_record)
    assert record["baseline"] is None and record["shares"] == []
    assert [(h["mode"], h["status"]) for h in record["history"]] == [
        ("plan", "PLANNED"), ("plan", "BLOCKED" if concurrent == "blocked" else "PLANNED"),
        ("apply", "BLOCKED")]
    last = record["history"][-1]
    assert (last["phase"], last["plan_revision"]) == ("write-gate", 1)


def test_a_plan_recorded_while_apply_writes_is_kept_and_named_in_its_outcome(
        harness, capsys, migration_record, monkeypatch):
    assert quietly(with_record(args(), migration_record)) == 0

    class Stacks(cli.Stacks):
        def apply(self, owner, region, groups):
            quietly(with_record(args(), migration_record))  # re-plan while the stack is written
            return super().apply(owner, region, groups)
    monkeypatch.setattr(cli, "Stacks", Stacks)
    capsys.readouterr()
    assert main(with_record(args("apply"), migration_record), input_fn=harness.confirm) == 0
    assert ("phase=record status=PLAN_SUPERSEDED plan revision 3 was recorded while this apply "
            "ran; this apply applied reviewed revision 1 only") in capsys.readouterr().out
    entry = read_record(migration_record)["verifications"][-1]
    assert (entry["plan_revision"], entry["plan_superseded_by"]) == (1, 3)


def test_each_stack_is_recorded_as_soon_as_it_completes(harness, capsys, migration_record,
                                                        monkeypatch):
    """Finding 9: a run killed while a later stack is written keeps the earlier one."""
    harness.source[OTHER_OWNER, REGION] = [group(owner=OTHER_OWNER)]
    recorded_before = {}

    class Stacks(cli.Stacks):
        def apply(self, owner, region, groups):
            recorded_before[owner] = [s["owner"] for s in read_record(migration_record)["shares"]]
            return super().apply(owner, region, groups)
    monkeypatch.setattr(cli, "Stacks", Stacks)
    argv = args(owners=f"{OWNER},{OTHER_OWNER}") + ["--account-workers", "1"]
    assert quietly(with_record(argv, migration_record)) == 0
    capsys.readouterr()
    assert main(with_record(["apply", *argv], migration_record), input_fn=harness.confirm) == 0
    assert recorded_before == {OWNER: [], OTHER_OWNER: [OWNER]}
    assert f"owner={OWNER} region={REGION} phase=record status=STACK_COMPLETE revision=3 " \
           "stack_shares=1" in capsys.readouterr().out
    record = read_record(migration_record)
    assert [h["status"] for h in record["history"]] == [
        "PLANNED", "BASELINE_CAPTURED", "STACK_COMPLETE", "STACK_COMPLETE", "SHARING_READY"]
    assert {(h["owner"], h["plan_revision"]) for h in record["history"]
            if h["status"] == "STACK_COMPLETE"} == {(OWNER, 1), (OTHER_OWNER, 1)}


@pytest.mark.parametrize("error,raised", [(MigrationError("collector failed"), None),
                                          (KeyError("unexpected"), KeyError)])
def test_a_failure_after_the_write_gate_records_the_outcome_and_the_created_shares(
        harness, capsys, migration_record, monkeypatch, error, raised):
    """Findings 9 and 23: a failure that is not an interrupt is recorded too."""
    real = cli.observe

    def observe(router, groups, temporary, opts, report, phase):
        if phase == "post-apply":
            raise error
        return real(router, groups, temporary, opts, report, phase)
    monkeypatch.setattr(cli, "observe", observe)
    assert quietly(with_record(args(), migration_record)) == 0
    capsys.readouterr()
    argv = with_record(args("apply"), migration_record)
    if raised:
        with pytest.raises(raised):
            main(argv, input_fn=harness.confirm)
    else:
        assert main(argv, input_fn=harness.confirm) == 1
    output = capsys.readouterr().out
    text = "collector failed" if raised is None else "KeyError: 'unexpected'"
    assert f"status=INCOMPLETE {text}; successful temporary shares are retained" in output
    assert "phase=record status=INCOMPLETE record=" in output
    record = read_record(migration_record)
    last = record["history"][-1]
    assert (last["mode"], last["status"], last["failures"], last["plan_revision"]) == (
        "apply", "INCOMPLETE", [text], 1)
    assert "re-run apply with this record to resume" in last["retained"]
    share, = record["shares"]
    assert share["share_arn"] == share_arn(harness.stored[OWNER, REGION][0])


def test_a_recorded_share_that_differs_from_its_stack_never_discards_the_outcome(
        harness, capsys, migration_record):
    """Finding 9: one share-ARN conflict no longer loses the whole apply outcome."""
    first, second = pool_group("test"), pool_group("second", permission=OTHER_PERMISSION)
    harness.source[OWNER, REGION] = [first, second]
    record = applied(harness, migration_record)
    stale = share_arn(second) + "-before-the-stack-was-recreated"
    rewrite(migration_record, shares=[dict(entry, share_arn=stale)
                                      if entry["logical_id"] == second.logical_id else entry
                                      for entry in record["shares"]])
    capsys.readouterr()
    assert main(with_record(args("apply"), migration_record), input_fn=harness.confirm) == 1
    output = capsys.readouterr().out
    conflict = (f"{OWNER}/{REGION}/{second.logical_id}: recorded share {stale} differs from "
                f"{share_arn(second)}; the recorded share is kept, reconcile it explicitly")
    assert f"status=INCOMPLETE phase=record {conflict}" in output
    assert f"phase=record status=CONFLICT {conflict}" in output
    after = read_record(migration_record)
    assert {e["logical_id"]: e["share_arn"] for e in after["shares"]} == {
        first.logical_id: share_arn(first), second.logical_id: stale}
    assert (after["history"][-1]["mode"], after["history"][-1]["status"]) == ("apply", "INCOMPLETE")
    assert after["verifications"][-1]["mode"] == "apply"


def test_a_cancelled_apply_is_recorded_without_writes(harness, capsys, migration_record):
    """Finding 23: the CANCELLED return is history too."""
    assert quietly(with_record(args(), migration_record)) == 0
    assert main(with_record(args("apply"), migration_record), input_fn=lambda _p: "no") == 2
    last = read_record(migration_record)["history"][-1]
    assert (last["mode"], last["status"], last["writes"], last["plan_revision"]) == (
        "apply", "CANCELLED", "none", 1)
    assert not harness.writes()


def owned(harness, account=CONSUMER, region=REGION, suffix="owned", status="ACTIVE"):
    share = {"resourceShareArn": f"arn:aws:ram:{region}:{account}:resource-share/{suffix}",
             "owningAccountId": account, "status": status}
    harness.owned_shares[account, region].append(share)
    return share


def test_a_migrating_account_that_owns_shares_is_inspected_as_a_migrating_owner(
        harness, capsys, migration_record):
    """Finding 17: CONSUMER is given only in --consumers, but owns a share."""
    harness.enabled_regions[CONSUMER].append({"RegionName": "ap-south-1", "OptInStatus": "opted-in"})
    share = owned(harness, region="ap-south-1")
    assert main(with_record(args(), migration_record)) == 0
    output = capsys.readouterr().out
    assert (f"account={CONSUMER} region=ap-south-1 share={share['resourceShareArn']} "
            "phase=owned-audit status=OWNED share_status=ACTIVE") in output
    assert (f"account={CONSUMER} phase=owned-audit status=MIGRATING_OWNER owned_shares=1 "
            "regions=ap-south-1") in output
    owned_reads = {(call[1], call[2]) for call in harness.calls if call[0] == "owned-shares"}
    assert owned_reads == {(CONSUMER, HOME), (CONSUMER, REGION), (CONSUMER, "ap-south-1")}
    discovered = {(call[1], call[2]) for call in harness.calls if call[0] == "discovery"}
    assert {(CONSUMER, HOME), (CONSUMER, REGION), (CONSUMER, "ap-south-1")} <= discovered
    assert harness.discovery_kwargs["migrating_owners"] == {CONSUMER}
    scope = read_record(migration_record)["scope"]
    assert scope["migrating_owners"] == scope["detected_owners"] == [CONSUMER]
    assert scope["migrating_consumers"] == [] and scope["stationary_owners"] == [OWNER]
    # The migrating-owner rules apply to its shares: here one shares with a stationary account.
    harness.discovery_errors[CONSUMER, "ap-south-1"] = (
        f"{share['resourceShareArn']}: owner={CONSUMER} region=ap-south-1 migrating owner "
        f"{CONSUMER} shares with stationary consumers ['{OTHER_CONSUMER}']")
    assert main(with_record(args("apply"), migration_record),
                input_fn=lambda _: pytest.fail("blocked before confirmation")) == 1
    assert f"migrating owner {CONSUMER} shares with stationary consumers" in capsys.readouterr().out
    assert not harness.writes()


def test_verify_takes_a_detected_migrating_owner_from_the_record(harness, capsys, migration_record):
    owned(harness)
    applied(harness, migration_record)
    for owners, code in ((OWNER, 0), (f"{OWNER},{CONSUMER}", 0), (OTHER_OWNER, 1)):
        assert quietly(mode_args("verify", migration_record, "--owners", owners)) == code


def test_an_owned_share_read_failure_blocks_and_deleted_owned_shares_are_ignored(harness, capsys):
    owned(harness, status="DELETED")
    assert main(args()) == 0
    assert "status=MIGRATING_OWNER" not in capsys.readouterr().out
    harness.owned_errors[CONSUMER, HOME] = denied("GetResourceShares")
    assert main(args("apply"), input_fn=lambda _: pytest.fail("blocked before confirmation")) == 1
    assert (f"account={CONSUMER} region={HOME} phase=owned-audit status=BLOCKED "
            "operation=GetResourceShares") in capsys.readouterr().out
    assert not harness.writes()


def test_a_migrating_owner_is_inspected_in_every_region_it_has_enabled(harness, capsys):
    """Finding 18: not only in --regions and where other migrating accounts receive."""
    harness.enabled_regions[OTHER_OWNER] = [
        *harness.enabled_regions[CONSUMER], {"RegionName": "ap-south-1", "OptInStatus": "opted-in"},
        {"RegionName": "eu-west-1", "OptInStatus": "not-opted-in"}]
    argv = args(owners=f"{OWNER},{OTHER_OWNER}", consumers=f"{CONSUMER},{OTHER_OWNER}") + [
        "--profile-map", json.dumps({OTHER_OWNER: "other-owner"})]
    assert main(argv) == 0
    output = capsys.readouterr().out
    assert f"owner={OTHER_OWNER} phase=scope regions=ap-south-1,{HOME},{REGION}" in output
    assert f"owner={OWNER} phase=scope regions={HOME},{REGION}" in output   # stationary owner
    discovered = {(call[1], call[2]) for call in harness.calls if call[0] == "discovery"}
    assert (OTHER_OWNER, "ap-south-1") in discovered
    assert (OTHER_OWNER, "eu-west-1") not in discovered


EXCLUSION = ["--exclude-regions", "eu-central-1", "--exclude-reason", "Control Tower Region deny SCP"]
EXCLUDED = 'excluded_regions=eu-central-1 exclusion_reason="Control Tower Region deny SCP"'


def test_an_explicit_reasoned_region_exclusion_bounds_the_audit_and_is_recorded(
        harness, capsys, migration_record):
    """Finding 19: RAM reads are denied in a Region the landing zone does not govern."""
    harness.enabled_regions[CONSUMER].append({"RegionName": "eu-central-1",
                                              "OptInStatus": "opt-in-not-required"})
    harness.received_errors[CONSUMER, "eu-central-1"] = denied("GetResourceShares")
    assert main(with_record(args(), migration_record)) == 1          # never skipped implicitly
    assert f"account={CONSUMER} region=eu-central-1 phase=received-audit status=BLOCKED" in \
        capsys.readouterr().out
    harness.calls.clear()
    assert main(with_record(args() + EXCLUSION, migration_record)) == 0
    output = capsys.readouterr().out
    assert (f"account={CONSUMER} region=eu-central-1 phase=received-regions "
            'status=EXCLUDED_BY_OPERATOR reason="Control Tower Region deny SCP"') in output
    assert EXCLUDED in summary_line(output)
    assert "Regions eu-central-1 were excluded by the operator (Control Tower Region deny SCP)" in output
    assert not any(call[0] in ("received-shares", "owned-shares", "discovery") and
                   call[2] == "eu-central-1" for call in harness.calls)
    record = read_record(migration_record)
    assert record["scope"]["excluded_regions"] == {"regions": ["eu-central-1"],
                                                   "reason": "Control Tower Region deny SCP"}
    assert main(["approve", "--record", str(migration_record)]) == 0
    assert f"phase=approve scope=REGIONS_EXCLUDED {EXCLUDED}" in capsys.readouterr().out
    # apply consumes exactly the reviewed exclusion; verify and complete take it from the record
    assert main(with_record(args("apply"), migration_record),
                input_fn=lambda _: pytest.fail("the reviewed scope differs")) == 1
    assert "differ from reviewed plan revision 2" in capsys.readouterr().out
    assert main(with_record(args("apply") + EXCLUSION, migration_record), input_fn=harness.confirm) == 0
    assert EXCLUDED in summary_line(capsys.readouterr().out)
    assert main(mode_args("verify", migration_record)) == 0
    assert EXCLUDED in summary_line(capsys.readouterr().out)
    assert main(mode_args("verify", migration_record, "--exclude-regions", "eu-west-3",
                          "--exclude-reason", "another reason")) == 1
    assert "--exclude-regions/--exclude-reason differ from the migration record scope" in \
        capsys.readouterr().out
    assert main(complete_args(migration_record), input_fn=confirm_complete(harness)) == 0
    assert f"original baseline intact {EXCLUDED}" in capsys.readouterr().out


@pytest.mark.parametrize("extra,message", [
    (["--exclude-regions", "eu-central-1"], "requires --exclude-reason"),
    (["--exclude-regions", "eu-central-1", "--exclude-reason", "  "], "requires --exclude-reason"),
    (["--exclude-reason", "SCP"], "--exclude-reason requires --exclude-regions"),
    (["--exclude-regions", "eu-central-1", "--exclude-reason", "one\ntwo"], "one line"),
    (["--exclude-regions", HOME, "--exclude-reason", "SCP"], "cannot be excluded"),
    (["--exclude-regions", REGION, "--exclude-reason", "SCP"], "both requested"),
    (["--exclude-regions", "not-a-region", "--exclude-reason", "SCP"], "AWS Region names"),
])
def test_region_exclusions_need_a_reason_and_are_refused_before_authentication(
        harness, capsys, extra, message):
    assert main(args() + extra) == 1
    assert message in capsys.readouterr().out
    assert not harness.calls


@pytest.mark.parametrize("mode", ["approve", "monitor"])
def test_region_exclusions_are_refused_where_nothing_is_inspected(harness, capsys,
                                                                 migration_record, mode):
    argv = ["approve", "--record", str(migration_record)] if mode == "approve" else [
        "monitor", "--profile", "explicit-source", "--record", str(migration_record),
        "--migration-id", MIGRATION, "--all-accounts"]
    assert main(argv + EXCLUSION) == 1
    assert "supported only for plan, apply, verify and complete" in capsys.readouterr().out
    assert not harness.calls


@pytest.mark.parametrize("alias", ["same", "relative", "symlink", "hardlink", "lock", "temporary"])
@pytest.mark.parametrize("mode", ["plan", "apply"])
def test_the_plan_export_can_never_overwrite_the_record(harness, capsys, migration_record,
                                                        monkeypatch, alias, mode):
    """Finding 22: refused before any AWS call, so the record and its history survive."""
    import os
    from pathlib import Path
    assert quietly(with_record(args(), migration_record)) == 0
    before = migration_record.read_bytes()
    folder = migration_record.parent
    if alias == "same":
        export = migration_record
    elif alias == "relative":
        monkeypatch.chdir(folder.parent)
        export = Path(folder.name) / ".." / folder.name / migration_record.name
    elif alias == "symlink":
        export = folder / "export.json"
        export.symlink_to(migration_record)
    elif alias == "hardlink":
        export = folder / "export.json"
        os.link(migration_record, export)
    elif alias == "lock":
        export = folder / f".{migration_record.name}.lock"
    else:
        export = folder / f".{migration_record.name}.tmp-4242"
    harness.calls.clear()
    argv = with_record(args("apply" if mode == "apply" else None), migration_record)
    assert main(argv + ["--export-plan", str(export)],
                input_fn=lambda _: pytest.fail("refused before confirmation")) == 1
    assert "would overwrite the migration record" in capsys.readouterr().out
    assert not harness.calls and migration_record.read_bytes() == before


@pytest.mark.parametrize("addition", ["consumer", "resource"])
def test_apply_never_adds_an_entitlement_the_recorded_baseline_does_not_cover(
        harness, capsys, migration_record, addition):
    """A re-planned scope may add a consumer, or a resource for a covered consumer; the
    baseline is never extended, so apply blocks before writing, per entitlement."""
    record = applied(harness, migration_record)
    added = POOL + "-added"
    if addition == "consumer":
        harness.source[OWNER, REGION].append(group(consumer=OTHER_CONSUMER))
        argv, consumer, resource = args(consumers=f"{CONSUMER},{OTHER_CONSUMER}"), OTHER_CONSUMER, POOL
    else:
        harness.source[OWNER, REGION][0].resources[added] = IPAM
        argv, consumer, resource = args(), CONSUMER, added
    assert quietly(with_record(argv, migration_record)) == 0       # the plan itself is valid
    capsys.readouterr()
    assert main(with_record(["apply", *argv], migration_record),
                input_fn=lambda _: pytest.fail("blocked before confirmation")) == 1
    output = capsys.readouterr().out
    assert (f"phase=baseline-scope status=BLOCKED owner={OWNER} region={REGION} "
            f"consumer={consumer} resource={resource}: this entitlement is not in the recorded "
            f"original baseline (captured in revision {record['baseline']['captured_in_revision']})"
            ) in output
    assert (f"consumer {consumer} has no baseline organization" in output) == (addition == "consumer")
    assert output.count("phase=preflight status=BLOCKED phase=baseline-scope") == 1
    assert "category=baseline-scope blockers=1 " in output and "new migration record" in output
    assert not harness.writes() and not any(call[0] == "apply" for call in harness.calls)
    after = read_record(migration_record)
    assert after["baseline"] == record["baseline"] and after["shares"] == record["shares"]


def test_verify_and_complete_name_an_entitlement_the_baseline_never_covered(
        harness, capsys, migration_record):
    """A record from an earlier release: a covered consumer gained an uncovered entitlement."""
    added = POOL + "-added"
    harness.source[OWNER, REGION][0].resources[added] = IPAM
    applied(harness, migration_record)
    baseline = read_record(migration_record)["baseline"]
    rewrite(migration_record, baseline=dict(baseline, items=[
        item for item in baseline["items"] if item.get("resource_arn") != added]))
    harness.organizations[CONSUMER] = "o-destination1"
    reason = (f"entitlement owner={OWNER} region={REGION} consumer={CONSUMER} resource={added} "
              "is not covered by the original baseline")
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 3
    output = capsys.readouterr().out
    assert "status=INCONCLUSIVE" in summary_line(output) and reason in output
    refused(harness, migration_record, capsys, reason)


# ---------------------------------------------------------------------------
# large-estate discovery edge cases (case 022, case 030, case 032, case 114)
# ---------------------------------------------------------------------------
from ram_migration_discovery import feature_set_problem, share_blocker  # noqa: E402


def two_consumer_groups(harness):
    """Two temporary shares in one owner/Region stack, one per migrating consumer."""
    first, second = group(), group(consumer=OTHER_CONSUMER)
    harness.source[OWNER, REGION] = [first, second]
    return first, second, args(consumers=f"{CONSUMER},{OTHER_CONSUMER}")


def test_verify_reports_an_unproven_share_alone_and_still_verifies_its_sibling(
        harness, capsys, migration_record):
    """case 114: one failed logical share no longer aborts the readback of its siblings."""
    first, second, argv = two_consumer_groups(harness)
    applied(harness, migration_record, argv)
    harness.readback_failures[OWNER, REGION] = {
        first.logical_id: MigrationError("Migration resource ownership verification failed")}
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 1
    output = capsys.readouterr().out
    assert (f"{OWNER}/{REGION}/{first.key}: planned share could not be proven from its migration "
            "stack: Migration resource ownership verification failed") in output
    assert "planned share missing" not in output
    second_arn = harness.share(second)["resourceShareArn"]
    assert (f"share={second_arn} consumer={OTHER_CONSUMER} phase=verification "
            "status=VERIFIED") in output
    assert [call[1] for call in harness.calls if call[0] == "verify"] == [second.key]
    assert "sharing_status=SHARING_INCOMPLETE" in summary_line(output)   # never reported ready
    assert read_record(migration_record)["verifications"][-1]["sharing_status"] == \
        "SHARING_INCOMPLETE"


def test_apply_records_and_accepts_only_the_proven_share_of_a_partly_readable_stack(
        harness, capsys, migration_record):
    first, second, argv = two_consumer_groups(harness)
    assert quietly(with_record(argv, migration_record)) == 0
    harness.readback_failures[OWNER, REGION] = {
        first.logical_id: MigrationError("Migration share provenance differs from owning template")}
    capsys.readouterr()
    assert main(with_record(["apply", *argv], migration_record), input_fn=harness.confirm) == 1
    output = capsys.readouterr().out
    assert (f"owner={OWNER} region={REGION} logical_id={first.logical_id} phase=record "
            "status=INCOMPLETE share was not proven (Migration share provenance differs from "
            "owning template); it is not recorded") in output
    assert f"{OWNER}/{REGION}/{first.key}: planned share could not be proven" in output
    record = read_record(migration_record)
    assert [share["logical_id"] for share in record["shares"]] == [second.logical_id]
    assert [call[1] for call in harness.calls if call[0] == "accept-write"] == [
        f"local-invitation-{OTHER_CONSUMER}-{second.key}"]
    assert [entry["status"] for entry in record["history"]][-2:] == ["STACK_COMPLETE", "INCOMPLETE"]


def test_received_provenance_blocks_only_the_unproven_temporary_share(
        harness, capsys, migration_record):
    first, second, argv = two_consumer_groups(harness)
    applied(harness, migration_record, argv)
    for g, consumer in ((first, CONSUMER), (second, OTHER_CONSUMER)):
        arn = harness.share(g)["resourceShareArn"]
        harness.received_shares[consumer, REGION].append(
            {"resourceShareArn": arn, "owningAccountId": OWNER, "status": "ACTIVE"})
        harness.received_resources[consumer, REGION, arn] = [
            {"arn": POOL, "type": IPAM, "status": "AVAILABLE", "resourceShareArn": arn}]
    harness.readback_failures[OWNER, REGION] = {
        first.logical_id: MigrationError("Migration resource ownership verification failed")}
    capsys.readouterr()
    assert main(with_record(argv, migration_record)) == 1
    output = capsys.readouterr().out
    assert (f"{OWNER}/{REGION}/{first.key}: stored migration share ownership could not be "
            "proven: Migration resource ownership verification failed") in output
    assert (f"share={harness.share(second)['resourceShareArn']} phase=received-audit "
            "status=CURRENT_MIGRATION") in output


def restored(harness, consumer=CONSUMER):
    """An original re-added to a departed account: ASSOCIATED, external=true (case 030)."""
    share = harness.receive(receiver=consumer, suffix="restored-ec2")
    return share, {"owner": OWNER, "region": REGION, "share": share["resourceShareArn"],
                   "consumer": consumer, "status": "ASSOCIATED", "external": True}


def test_recovered_external_access_is_its_own_received_audit_status_and_is_recorded(
        harness, capsys, migration_record):
    harness.source = {}   # the account holds the original itself; nothing is bridged
    share, evidence = restored(harness)
    harness.external_access[OWNER, REGION] = [evidence]
    assert main(with_record(args(), migration_record)) == 0
    output = capsys.readouterr().out
    assert (f"share={share['resourceShareArn']} phase=received-audit status=RECOVERED_EXTERNAL "
            "share_status=ACTIVE resources=1 association_status=ASSOCIATED external=true") in output
    assert "status=EXCLUDED recovered external access: the owner's principal association" in output
    assert "not covered by any planned temporary share" not in output
    entry, = read_record(migration_record)["plan"]["received_entitlements"]["entries"]
    assert entry["status"] == "RECOVERED_EXTERNAL"
    assert entry["association"] == {"status": "ASSOCIATED", "external": True}
    assert not harness.writes()


@pytest.mark.parametrize("evidence_for", [None, OTHER_CONSUMER])
def test_a_receipt_without_its_own_external_evidence_still_blocks(harness, capsys, evidence_for):
    harness.source = {}
    restored(harness)
    if evidence_for:   # another account's external association covers nothing for this one
        harness.external_access[OWNER, REGION] = [restored(harness, evidence_for)[1]]
    assert main(args(consumers=f"{CONSUMER},{OTHER_CONSUMER}")) == 1
    output = capsys.readouterr().out
    assert (f"account={CONSUMER} owner={OWNER} region={REGION} share=arn:aws:ram:{REGION}:"
            f"{OWNER}:resource-share/restored-ec2 phase=received-audit status=NOT_COVERED") in output
    assert "category=received-dependency-not-covered blockers=1 " in output


def test_an_over_quota_temporary_share_blocks_plan_and_apply_before_any_write(
        harness, capsys, migration_record):
    """case 022: 5,000 resource associations per share is a fixed RAM quota."""
    big = group()
    big.resources = {f"arn:aws:ec2:{REGION}:{OWNER}:ipam-pool/ipam-pool-{index:05d}": IPAM
                     for index in range(5001)}
    harness.source[OWNER, REGION] = [big]
    assert main(with_record(args(), migration_record)) == 1
    output = capsys.readouterr().out
    assert (f"owner={OWNER} region={REGION} phase=stack-preflight {big.logical_id}: the temporary "
            "share would hold 5001 resource associations; AWS RAM allows at most 5000 resource "
            "associations per resource share and the quota is not adjustable") in output
    assert "category=ram-share-quota blockers=1 owners=1 next_action=" in output
    assert read_record(migration_record)["plan"]["status"] == "BLOCKED"
    assert main(with_record(["apply", *args()], migration_record),
                input_fn=lambda _: pytest.fail("blocked before confirmation")) == 1
    assert not harness.writes() and not any(call[0] == "apply" for call in harness.calls)


def test_a_policy_created_share_is_its_own_blocker_category_with_the_promotion_steps(
        harness, capsys, migration_record):
    """case 032: never inspected as a standard share; promote it, then plan again."""
    arn = f"arn:aws:ram:{REGION}:{OWNER}:resource-share/1f35643b"
    harness.discovery_errors[OWNER, REGION] = share_blocker(OWNER, REGION, arn, MigrationError(
        feature_set_problem(OWNER, REGION, arn, "CREATED_FROM_POLICY")))
    assert main(with_record(args(), migration_record)) == 1
    output = capsys.readouterr().out
    line, = [row for row in output.splitlines() if "category=policy-created-share" in row]
    assert "blockers=1 shares=1 owners=1 next_action=" in line
    assert "promote-resource-share-created-from-policy" in line
    assert line.endswith("then re-run plan --record")
    assert read_record(migration_record)["plan"]["status"] == "BLOCKED"


# Organization-policy preflight wiring (ram_migration_preflight; case 051/053/054)
# ---------------------------------------------------------------------------
GUARD = "p-coreguard1"
BLOCK_EXTERNAL_CREATE = {
    "Sid": "BlockExternalRAMCreate", "Effect": "Deny",
    "Action": ["ram:CreateResourceShare", "ram:UpdateResourceShare"], "Resource": "*",
    "Condition": {"Bool": {"ram:RequestedAllowsExternalPrincipals": "true"}}}
WORK_OU = "ou-local-work0001"
DESTINATION = f"arn:aws:organizations::{MANAGER}:ou/o-sourceorg01/{WORK_OU}"
OU_PRINCIPAL = f"arn:aws:organizations::{MANAGER}:ou/o-sourceorg01/ou-local-apps0001"


def guard(harness, *statements):
    """A root SCP beside FullAWSAccess, as the Core root's guardrail policy is."""
    harness.org_policies[GUARD] = ("Core guardrails", {
        "Version": "2012-10-17", "Statement": list(statements or [BLOCK_EXTERNAL_CREATE])})
    harness.org_attachments[ROOT, SCP] = [FULL_ACCESS, GUARD]


def blocker_summary(output):
    return [line for line in output.splitlines() if line.startswith("phase=blocker-summary")]


def test_plan_records_the_organization_policy_preflight(harness, capsys, migration_record):
    assert main(with_record(args(), migration_record)) == 0
    output = capsys.readouterr().out
    assert "phase=org-policy status=ALLOWED accounts=2 denies=0 gaps=0 unreadable=0" in output
    assert f"phase=org-policy account={OWNER} roles=owner status=EVALUATED " \
           f"organization=o-sourceorg01 path={ROOT}/{OWNER} scp=ENABLED rcp=NOT_ENABLED" in output
    record = read_record(migration_record)
    result = record["plan"]["organization_policy_preflight"]
    assert (result["status"], result["destination_ou"], result["blockers"]) == ("ALLOWED", None, [])
    assert [(a["account"], a["roles"]) for a in result["accounts"]] == [
        (OWNER, ["owner"]), (CONSUMER, ["consumer"])]
    assert len(result["organizations"]["o-sourceorg01"]["policies"][FULL_ACCESS]["sha256"]) == 64
    # Read-only reads through the management account; the plan digest does not change.
    reads = [call for call in harness.calls if call[0] == "org-read"]
    assert reads and {call[1] for call in reads} == {MANAGER}
    assert not any(call[0] == "client" and call[2] == "organizations" and call[4]
                   for call in harness.calls)
    assert record["plan"]["digest"] == record_module.plan_digest(harness.source[OWNER, REGION],
                                                                 record["scope"])


def test_a_denying_scp_blocks_plan_and_apply_before_confirmation(harness, capsys, migration_record):
    guard(harness)
    assert main(with_record(args(), migration_record)) == 1
    output = capsys.readouterr().out
    assert (f"phase=preflight status=BLOCKED phase=org-policy status=BLOCKED "
            f"decision=EXPLICIT_DENY account={OWNER} role=owner organization=o-sourceorg01 "
            f"regions={REGION} actions=ram:CreateResourceShare policy_type=SCP "
            f"target={ROOT} policy={GUARD} policy_name=\"Core guardrails\" "
            "sid=BlockExternalRAMCreate statement=1: ") in output
    header, deny = blocker_summary(output)
    assert header == "phase=blocker-summary status=BLOCKED blockers=1 categories=1"
    assert deny.startswith("phase=blocker-summary category=organization-policy-deny blockers=1 "
                           "accounts=1 policies=1 organizations=1 next_action=an SCP or RCP")
    assert "obtain an approved exception" in deny and deny.endswith(
        "then re-run plan --record; leaving the account out of this migration needs a new "
        "reviewed plan")
    record = read_record(migration_record)
    assert record["plan"]["status"] == "BLOCKED"
    assert record["plan"]["organization_policy_preflight"]["status"] == "BLOCKED"
    assert record["plan"]["organization_policy_preflight"]["findings"][0]["sid"] == \
        "BlockExternalRAMCreate"
    assert main(with_record(args("apply"), migration_record),
                input_fn=lambda _: pytest.fail("blocked before confirmation")) == 1
    assert not harness.writes()


def test_apply_rechecks_organization_policies_after_the_confirmation(
        harness, capsys, migration_record):
    """An SCP attached while the operator confirms blocks every write."""
    assert quietly(with_record(args(), migration_record)) == 0
    harness.calls.clear()
    harness.org_after_confirmation = guard
    assert main(with_record(args("apply"), migration_record), input_fn=harness.confirm) == 1
    output = capsys.readouterr().out
    assert not harness.writes() and not any(call[0] == "apply" for call in harness.calls)
    assert ("phase=preflight status=BLOCKED post-confirmation phase=org-policy status=BLOCKED "
            f"decision=EXPLICIT_DENY account={OWNER} role=owner") in output
    assert (f"phase=org-policy status=POLICY_CHANGED organization=o-sourceorg01 policy={GUARD} "
            "change=attached since the read before the confirmation; this run evaluated the "
            "current policies") in output
    reads = [call for call in harness.calls
             if call[:4] == ("org-read", MANAGER, "DescribePolicy", FULL_ACCESS)]
    assert len(reads) == 2  # before the confirmation, and fresh after it
    deny, = [line for line in blocker_summary(output) if "category=" in line]
    assert "category=organization-policy-deny" in deny
    assert "then re-run apply with the same --record" in deny and "plan --record" not in deny
    entry = read_record(migration_record)["history"][-1]
    assert (entry["mode"], entry["status"], entry["phase"]) == (
        "apply", "BLOCKED", "post-confirmation")


@pytest.mark.parametrize("error,category", [
    (denied("ListPoliciesForTarget"), "organization-policy-unreadable"),
    (ClientError({"Error": {"Code": "ExpiredTokenException",
                            "Message": "The security token included in the request is expired"},
                  "ResponseMetadata": {"RequestId": "local-request-id"}}, "ListPoliciesForTarget"),
     "authentication"),
])
def test_unreadable_organization_policies_are_named_blockers(harness, capsys, error, category):
    harness.org_errors["ListPoliciesForTarget", ROOT] = error
    assert main(args()) == 1
    output = capsys.readouterr().out
    code = error.response["Error"]["Code"]
    for account, role in ((OWNER, "owner"), (CONSUMER, "consumer")):
        assert (f"phase=org-policy status=BLOCKED decision=UNREADABLE account={account} "
                f"roles={role} organization=o-sourceorg01 management_account={MANAGER}: "
                f"operation=ListPoliciesForTarget {code}: ") in output
    assert "phase=org-policy status=ALLOWED" not in output
    unread, = [line for line in blocker_summary(output) if "category=" in line]
    assert unread.startswith(f"phase=blocker-summary category={category} blockers=2 accounts=2 ")
    if category == "organization-policy-unreadable":
        assert "organizations=1 next_action=" in unread and "--account-map" in unread
    # One failed read is not repeated for the second account.
    assert len([call for call in harness.calls
                if call[:4] == ("org-read", MANAGER, "ListPoliciesForTarget", ROOT)]) == 1


def test_an_undecidable_statement_blocks_as_a_gap_listed_for_review(harness, capsys):
    guard(harness, dict(BLOCK_EXTERNAL_CREATE, Condition={
        **BLOCK_EXTERNAL_CREATE["Condition"],
        "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/RamMigration"}}))
    assert main(args()) == 1
    output = capsys.readouterr().out
    assert "phase=org-policy status=GAP decision=UNDECIDED " in output
    assert "(condition key aws:PrincipalArn is not evaluated)" in output
    assert f"phase=org-policy status=REVIEW policy={GUARD} statement=1 text=" in output
    gap, = [line for line in blocker_summary(output) if "category=" in line]
    assert gap.startswith("phase=blocker-summary category=organization-policy-gap blockers=1 "
                          "accounts=1 policies=1 organizations=1 next_action=")


def test_destination_ou_is_validated_evaluated_recorded_and_must_match_at_apply(
        harness, capsys, migration_record):
    assert main(args() + ["--destination-ou", WORK_OU]) == 1
    assert "status=BLOCKED --destination-ou must be an OU or root ARN" in capsys.readouterr().out
    assert main(mode_args("verify", migration_record, "--destination-ou", DESTINATION)) == 1
    assert "--destination-ou is supported only for plan and apply" in capsys.readouterr().out
    harness.org_parents[WORK_OU] = (ROOT, "ROOT")
    # The Work OU's allow-list omits route53resolver: the migrated consumer's reads fail there.
    harness.org_policies["p-example0005"] = ("large_estate-work-deny-policy", {
        "Version": "2012-10-17", "Statement": [{
            "Effect": "Allow", "Resource": "*",
            "Action": ["ec2:*", "ram:*", "acm-pca:*", "organizations:Describe*"]}]})
    harness.org_attachments[WORK_OU, SCP] = ["p-example0005"]
    assert main(with_record(args(), migration_record) + ["--destination-ou", DESTINATION]) == 1
    output = capsys.readouterr().out
    assert (f"decision=NO_ALLOW account={CONSUMER} role=destination organization=o-sourceorg01 "
            f"regions={REGION} actions=route53resolver:") in output
    assert f"target={WORK_OU} policies=p-example0005(\"large_estate-work-deny-policy\")" in output
    assert "category=organization-policy-deny" in output
    del harness.org_attachments[WORK_OU, SCP]
    assert main(with_record(args(), migration_record) + ["--destination-ou", DESTINATION]) == 0
    output = capsys.readouterr().out
    assert f"phase=org-policy destination={DESTINATION} status=EVALUATED path={ROOT}/{WORK_OU}" \
        in output
    record = read_record(migration_record)
    assert record["plan"]["organization_policy_preflight"]["destination_ou"] == DESTINATION
    assert main(with_record(args("apply"), migration_record),
                input_fn=lambda _: pytest.fail("blocked before confirmation")) == 1
    output = capsys.readouterr().out
    assert (f"phase=reviewed-record --destination-ou none differs from the destination "
            f"{DESTINATION} that reviewed plan revision {record['revision']} evaluated") in output
    assert "category=reviewed-record-mismatch" in output and not harness.writes()
    assert main(with_record(args("apply"), migration_record) + ["--destination-ou", DESTINATION],
                input_fn=harness.confirm) == 0
    assert "status=SHARING_READY" in summary_line(capsys.readouterr().out)


def test_ou_principal_shares_check_the_ram_organization_prerequisites(
        harness, capsys, migration_record):
    harness.organization_principals = {
        ORIGINAL_SHARE: [OU_PRINCIPAL],
        f"arn:aws:ram:{REGION}:{OWNER}:resource-share/not-planned": [OU_PRINCIPAL]}
    harness.org_services = ["sso.amazonaws.com"]
    assert main(with_record(args(), migration_record)) == 1
    output = capsys.readouterr().out
    assert ("phase=ram-org-prerequisites status=BLOCKED organization=o-sourceorg01 "
            f"management_account={MANAGER} decision=NOT_MET prerequisite=ram-trusted-access "
            "shares=1: ") in output
    prerequisite, = [line for line in blocker_summary(output) if "category=" in line]
    assert prerequisite.startswith("phase=blocker-summary category=ram-organization-prerequisites "
                                   "blockers=1 organizations=1 next_action=")
    assert "never enables them" in prerequisite
    harness.org_services = ["ram.amazonaws.com"]
    assert main(with_record(args(), migration_record)) == 0
    entry, = read_record(migration_record)["plan"]["organization_policy_preflight"][
        "ram_organization_prerequisites"]
    assert (entry["organization"], entry["status"], entry["required_by"]) == (
        "o-sourceorg01", "MET", [ORIGINAL_SHARE])


def test_export_plan_includes_the_organization_policy_preflight(harness, tmp_path):
    exported = tmp_path / "plan.json"
    assert quietly(args() + ["--export-plan", str(exported)]) == 0
    assert json.loads(exported.read_text())["organization_policy_preflight"]["status"] == "ALLOWED"


@pytest.mark.parametrize("argv, message", [
    (["complete"], "complete acts on chosen migrating accounts: supply --consumers"),
    (["monitor"], "monitor acts on chosen migrating accounts: supply --consumers"),
    (["complete", "--all-accounts", "--consumers", CONSUMER],
     "complete acts on chosen migrating accounts: supply --consumers"),
    (["verify", "--force"], "--force is supported only for complete"),
    (["verify", "--all-accounts"], "--all-accounts is supported only for monitor and complete"),
])
def test_account_selection_options(harness, capsys, tmp_path, argv, message):
    record = tmp_path / "record.json"
    assert main([*argv, "--migration-id", MIGRATION, "--profile", "explicit-source",
                 "--record", str(record)]) == 1
    assert message in capsys.readouterr().out
    assert not harness.calls


def test_selected_consumers_must_be_migrating_accounts_of_the_record(tmp_path):
    args = cli.build_parser().parse_args(["complete", "--consumers", CONSUMER])
    opts = cli.Options(args, [], [CONSUMER, "444455556666"], [], [], {}, {}, None,
                       selected=[CONSUMER])
    assert cli.selected_consumers(opts, {}) == [CONSUMER]
    opts.selected = None
    assert cli.selected_consumers(opts, {}) == sorted([CONSUMER, "444455556666"])
    opts.selected = ["999988887777"]
    with pytest.raises(MigrationError, match="999988887777: not a migrating account"):
        cli.selected_consumers(opts, {})


# ---------------------------------------------------------------------------
# monitor: an on-demand report of what changed since the pre-migration baseline
# ---------------------------------------------------------------------------

def monitor_run(path, *extra, code=0):
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert main(mode_args("monitor", path, *extra)) == code
    return out.getvalue()


def test_monitor_right_after_apply_reports_no_change_and_writes_nothing(harness, migration_record):
    applied(harness, migration_record)
    output = monitor_run(migration_record)
    assert f"status=UNCHANGED migration={MIGRATION} phase=monitor consumers={CONSUMER}" in output
    assert "exit_code=0" in output and not harness.writes()
    record = read_record(migration_record)
    last = record["verifications"][-1]
    assert (last["mode"], last["monitor_status"], last["consumers"]) == ("monitor", "UNCHANGED", [CONSUMER])
    assert (record["history"][-1]["mode"], record["history"][-1]["status"]) == ("monitor", "UNCHANGED")


def test_monitor_records_an_original_share_drop_once(harness, migration_record):
    record = applied(harness, migration_record)
    original = f"arn:aws:ram:{REGION}:{OWNER}:resource-share/original"
    harness.original_lost.add((CONSUMER, REGION, POOL))  # the temporary share still grants it
    output = monitor_run(migration_record)
    assert (f"consumer={CONSUMER} region={REGION} owner={OWNER} resource={POOL} phase=monitor "
            f"change=ORIGINAL_SHARE_DROPPED share={original} access=TEMPORARY_ONLY") in output
    assert "status=CHANGED" in output and "original_share_drops=1" in output
    assert "recorded_drops=1" in output
    drops = read_record(migration_record)["drops"]
    assert [(d["kind"], d["severity"], d["subject"], d["resources"], d["detected_by"])
            for d in drops] == [("original_share", "informational", original, [POOL], "monitor")]
    again = monitor_run(migration_record)
    assert "recorded_drops=0" in again and len(read_record(migration_record)["drops"]) == 1
    assert record["shares"][0]["share_arn"] not in {d["subject"] for d in drops}


def test_monitor_reports_a_loss_with_exit_1_and_a_failure_drop(harness, migration_record):
    record = applied(harness, migration_record)
    harness.original_lost.add((CONSUMER, REGION, POOL))
    harness.deleted_shares.append(record["shares"][0]["share_arn"])  # nothing grants it now
    output = monitor_run(migration_record, code=1)
    assert f"phase=monitor change=DEGRADED key={entitlement_key(POOL)}" in output
    assert "status=LOSS" in output and "degraded=1" in output and "exit_code=1" in output
    failures = record_module.failure_drops(read_record(migration_record))
    assert [(d["kind"], d["subject"], d["detected_by"]) for d in failures] == [
        ("entitlement", entitlement_key(POOL), "monitor")]


def test_monitor_reports_the_consumer_organization_change(harness, migration_record):
    applied(harness, migration_record)
    harness.organizations[CONSUMER] = "o-destination1"
    output = monitor_run(migration_record)
    assert (f"consumer={CONSUMER} phase=monitor organization_at_baseline=o-sourceorg01 "
            "organization_now=o-destination1 organization_change=CHANGED") in output
    assert "status=CHANGED" in output
    assert read_record(migration_record)["verifications"][-1]["consumer_organizations"] == {
        CONSUMER: "o-destination1"}


def test_monitor_without_a_baseline_is_inconclusive_before_any_aws_read(harness, migration_record):
    assert quietly(with_record(args(), migration_record)) == 0
    harness.calls.clear()
    output = monitor_run(migration_record, code=3)
    assert "status=INCONCLUSIVE" in output and "no original baseline is recorded" in output
    assert [call[0] for call in harness.calls] == ["router"]
    assert read_record(migration_record)["verifications"][-1]["monitor_status"] == "INCONCLUSIVE"


def test_monitor_observes_only_the_chosen_accounts(harness, migration_record):
    harness.source[OWNER, REGION].append(group(consumer=OTHER_CONSUMER))
    applied(harness, migration_record, args(consumers=f"{CONSUMER},{OTHER_CONSUMER}"))
    harness.original_lost.add((OTHER_CONSUMER, REGION, POOL))
    output = monitor_run(migration_record, "--consumers", CONSUMER)
    assert "status=UNCHANGED" in output and OTHER_CONSUMER not in output
    collected = [call for call in harness.calls if call[0] == "collect"]
    assert [call[1] for call in collected] == [1]
    everyone = monitor_run(migration_record)
    assert f"consumer={OTHER_CONSUMER} region={REGION} owner={OWNER} resource={POOL}" in everyone
    assert f"consumers={CONSUMER},{OTHER_CONSUMER}" in everyone


def test_monitor_refuses_an_account_outside_the_record(harness, migration_record):
    applied(harness, migration_record)
    output = monitor_run(migration_record, "--consumers", "999988887777", code=1)
    assert "--consumers 999988887777: not a migrating account of this migration record" in output
    assert [call[0] for call in harness.calls] == ["router"]


def test_verify_records_original_share_drops_as_informational(harness, migration_record):
    applied(harness, migration_record)
    harness.original_lost.add((CONSUMER, REGION, POOL))
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert main(mode_args("verify", migration_record)) == 0
    assert "phase=verification change=ORIGINAL_SHARE_DROPPED" in out.getvalue()
    record = read_record(migration_record)
    assert [(d["kind"], d["severity"]) for d in record["drops"]] == [("original_share", "informational")]
    assert record["verifications"][-1]["migration_status"] == "PENDING_MIGRATION"


def test_monitor_that_cannot_record_still_reports_and_never_exits_0(harness, migration_record, monkeypatch):
    applied(harness, migration_record)
    revision = read_record(migration_record)["revision"]
    def refuse(*_args, **_kwargs):
        raise MigrationError("record changed concurrently")
    monkeypatch.setattr(cli, "update_record", refuse)
    output = monitor_run(migration_record, code=1)
    assert "phase=record status=NOT_RECORDED record changed concurrently" in output
    assert "status=UNCHANGED" in output and "recorded=false exit_code=1" in output
    assert read_record(migration_record)["revision"] == revision
# Per-account completion: chosen accounts, retirements, --force
# ---------------------------------------------------------------------------
BOTH = f"{CONSUMER},{OTHER_CONSUMER}"
FORCED = ("phase=complete status=NOT_OVERRIDDEN --force never overrides identity, "
          "record-versus-stack or ownership checks")


def shared_group(harness):
    """One temporary share serving both migrating accounts."""
    shared = pool_group("test", consumers=(CONSUMER, OTHER_CONSUMER))
    harness.source[OWNER, REGION] = [shared]
    return shared


def complete_for(path, *consumers, extra=()):
    return complete_args(path, "--consumers", *consumers, *extra)


def answering(token, prompts):
    def answer(prompt):
        prompts.append(prompt)
        return token
    return answer


def complete_history(path):
    return [entry for entry in read_record(path)["history"] if entry["mode"] == "complete"]


def lose_access_on_deletion(h, arn):
    """The consumer had no permanent path: deleting the share ends its access."""
    deleted = next(g for groups in h.stored.values() for g in groups if share_arn(g) == arn)
    h.original_lost.update((c, deleted.region, r) for c in deleted.consumers for r in deleted.resources)


def test_completing_one_account_of_a_shared_share_removes_only_its_principal(
        harness, capsys, migration_record):
    shared = shared_group(harness)
    applied(harness, migration_record, args(consumers=BOTH))
    arn = share_arn(shared)
    prompts = []
    capsys.readouterr()
    assert main(complete_for(migration_record, CONSUMER),
                input_fn=answering(f"COMPLETE {MIGRATION}", prompts)) == 0
    output = capsys.readouterr().out
    assert (f"owner={OWNER} region={REGION} phase=complete action=REMOVE_PRINCIPALS share={arn} "
            f"consumers={CONSUMER} resources=1 retained_consumers={OTHER_CONSUMER}") in output
    assert "action=DELETE_SHARE" not in output and "action=DELETE_STACK" not in output
    assert prompts == [f"Type COMPLETE {MIGRATION} to retire the temporary access of {CONSUMER} "
                       "with the actions above, re-verifying after each: "]
    assert completion_events(harness) == ["collect-1", "remove-principals", "collect-1", "collect-1"]
    assert harness.removed_principals == {(arn, CONSUMER)}
    assert not harness.deleted_shares and not harness.deleted_stacks
    # Only the chosen account and the share's owner are read; the other is not touched.
    assert {call[1] for call in harness.calls if call[0] == "authentication"} == {OWNER, CONSUMER}
    assert {call[1] for call in harness.calls if call[0] == "organization"} == {CONSUMER}
    assert summary_line(output) == (
        f"status=PARTIALLY_COMPLETED migration={MIGRATION} deleted_shares=0 deleted_stacks=0 "
        f"removed_principals=1 retired_accounts={CONSUMER} remaining_accounts={OTHER_CONSUMER} "
        "original baseline intact")
    record = read_record(migration_record)
    assert record["completion"] is None
    retirement, = record["retirements"]
    assert {key: entry for key, entry in retirement.items() if key != "at"} == {
        "consumer": CONSUMER, "owner": OWNER, "region": REGION, "logical_id": shared.logical_id,
        "share_arn": arn, "action": "PRINCIPAL_REMOVED", "forced": False}
    assert record_module.retired_consumers(record) == {CONSUMER}
    assert [(h["status"], h["retired"], h["consumers"]) for h in complete_history(migration_record)] \
        == [("PRINCIPALS_REMOVED", [CONSUMER], [CONSUMER]),
            ("PARTIALLY_COMPLETED", [CONSUMER], [CONSUMER])]


def test_completing_one_account_deletes_a_share_only_it_uses_and_keeps_the_stack(
        harness, capsys, migration_record):
    first, second, argv = two_consumer_groups(harness)
    applied(harness, migration_record, argv)
    capsys.readouterr()
    assert main(complete_for(migration_record, CONSUMER), input_fn=confirm_complete(harness)) == 0
    output = capsys.readouterr().out
    assert (f"owner={OWNER} region={REGION} phase=complete action=DELETE_SHARE "
            f"share={share_arn(first)} consumers={CONSUMER} resources=1") in output
    assert "REMOVE_PRINCIPALS" not in output and "action=DELETE_STACK" not in output
    assert harness.deleted_shares == [share_arn(first)] and not harness.deleted_stacks
    assert "status=PARTIALLY_COMPLETED" in summary_line(output)
    retirement, = read_record(migration_record)["retirements"]
    assert (retirement["consumer"], retirement["action"]) == (CONSUMER, "SHARE_DELETED")
    # RAM may no longer return the deleted share at all: the stack is still the recorded one.
    harness.readback_failures[OWNER, REGION] = {
        first.logical_id: MigrationError("Migration resource ownership verification failed")}
    assert main(complete_for(migration_record, OTHER_CONSUMER), input_fn=confirm_complete(harness)) == 0
    output = capsys.readouterr().out
    assert f"action=DELETE_SHARE share={share_arn(second)} consumers={OTHER_CONSUMER}" in output
    assert harness.deleted_stacks == [(OWNER, REGION)]
    assert "status=COMPLETED" in summary_line(output)


def test_a_stack_is_deleted_only_once_its_last_share_is(harness, capsys, migration_record):
    shared = pool_group("test", consumers=(CONSUMER, OTHER_CONSUMER))
    own = pool_group("c1", owner=OTHER_OWNER)
    harness.source = {(OWNER, REGION): [shared], (OTHER_OWNER, REGION): [own]}
    applied(harness, migration_record, args(owners=f"{OWNER},{OTHER_OWNER}", consumers=BOTH))
    capsys.readouterr()
    assert main(complete_for(migration_record, CONSUMER), input_fn=confirm_complete(harness)) == 0
    output = capsys.readouterr().out
    # CONSUMER's own share empties OTHER_OWNER's stack; the shared one keeps OWNER's.
    assert f"owner={OTHER_OWNER} region={REGION} phase=complete action=DELETE_STACK" in output
    assert f"owner={OWNER} region={REGION} phase=complete action=DELETE_STACK" not in output
    assert harness.removed_principals == {(share_arn(shared), CONSUMER)}
    assert harness.deleted_shares == [share_arn(own)]
    assert harness.deleted_stacks == [(OTHER_OWNER, REGION)]
    assert summary_line(output).startswith(
        f"status=PARTIALLY_COMPLETED migration={MIGRATION} deleted_shares=1 deleted_stacks=1 "
        f"removed_principals=1 retired_accounts={CONSUMER} remaining_accounts={OTHER_CONSUMER}")
    harness.calls.clear()
    assert main(complete_for(migration_record, OTHER_CONSUMER), input_fn=confirm_complete(harness)) == 0
    output = capsys.readouterr().out
    assert (f"owner={OWNER} region={REGION} phase=complete action=DELETE_SHARE "
            f"share={share_arn(shared)} consumers={OTHER_CONSUMER} resources=1") in output
    assert ("existing", OTHER_OWNER, REGION) in harness.calls  # emptied earlier, already gone
    assert harness.deleted_stacks == [(OTHER_OWNER, REGION), (OWNER, REGION)]
    assert summary_line(output) == (
        f"status=COMPLETED migration={MIGRATION} deleted_shares=1 deleted_stacks=1 "
        f"removed_principals=0 retired_accounts={BOTH} remaining_accounts=none "
        "original baseline intact")
    record = read_record(migration_record)
    assert record["completion"]["deleted_shares"] == [share_arn(shared)]
    assert record["completion"]["deleted_stacks"] == [f"local-stack-{OWNER}-{REGION}"]
    assert sorted((row["consumer"], row["share_arn"], row["action"]) for row in record["retirements"]) \
        == sorted([(CONSUMER, share_arn(shared), "PRINCIPAL_REMOVED"),
                   (CONSUMER, share_arn(own), "SHARE_DELETED"),
                   (OTHER_CONSUMER, share_arn(shared), "SHARE_DELETED")])


def test_all_accounts_deletes_a_shared_share_and_its_stack_as_before(harness, capsys, migration_record):
    shared = shared_group(harness)
    applied(harness, migration_record, args(consumers=BOTH))
    capsys.readouterr()
    assert main(complete_args(migration_record), input_fn=confirm_complete(harness)) == 0
    output = capsys.readouterr().out
    assert (f"action=DELETE_SHARE share={share_arn(shared)} consumers={BOTH} resources=1") in output
    assert "REMOVE_PRINCIPALS" not in output and not harness.removed_principals
    assert completion_events(harness) == ["collect-1", "delete-share", "collect-1", "collect-1",
                                          "delete-stack"]
    assert summary_line(output) == (
        f"status=COMPLETED migration={MIGRATION} deleted_shares=1 deleted_stacks=1 "
        f"removed_principals=0 retired_accounts={BOTH} remaining_accounts=none "
        "original baseline intact")
    record = read_record(migration_record)
    assert sorted((row["consumer"], row["action"]) for row in record["retirements"]) == [
        (CONSUMER, "SHARE_DELETED"), (OTHER_CONSUMER, "SHARE_DELETED")]
    assert (record["completion"]["forced"], record["completion"]["overridden"]) == (False, [])


def test_an_already_retired_account_is_skipped(harness, capsys, migration_record):
    shared = shared_group(harness)
    applied(harness, migration_record, args(consumers=BOTH))
    assert quietly(complete_for(migration_record, CONSUMER), confirm_complete(harness)) == 0
    record = read_record(migration_record)
    harness.calls.clear()
    capsys.readouterr()
    assert main(complete_for(migration_record, CONSUMER),
                input_fn=lambda _: pytest.fail("nothing to confirm")) == 0
    output = capsys.readouterr().out
    assert (f"consumer={CONSUMER} phase=complete status=ALREADY_RETIRED "
            f"at={record['retirements'][0]['at']}") in output
    assert summary_line(output) == (f"status=NOTHING_TO_RETIRE migration={MIGRATION} "
                                    f"retired_accounts={CONSUMER} remaining_accounts={OTHER_CONSUMER}")
    assert [call[0] for call in harness.calls] == ["router"]
    assert read_record(migration_record) == record
    # Named beside an account still to retire, it is skipped again and the other retired.
    assert main(complete_for(migration_record, CONSUMER, OTHER_CONSUMER),
                input_fn=confirm_complete(harness)) == 0
    output = capsys.readouterr().out
    assert f"consumer={CONSUMER} phase=complete status=ALREADY_RETIRED" in output
    assert (f"action=DELETE_SHARE share={share_arn(shared)} consumers={OTHER_CONSUMER} "
            "resources=1") in output
    assert "status=COMPLETED" in summary_line(output)


def test_force_overrides_missing_replacement_access_with_its_own_token_and_records_it(
        harness, capsys, migration_record):
    applied(harness, migration_record)
    arn = share_arn(harness.stored[OWNER, REGION][0])
    harness.original_lost.add((CONSUMER, REGION, POOL))  # only the temporary share provides access
    prompts = []
    capsys.readouterr()
    assert main(complete_args(migration_record, "--force"),
                input_fn=answering(f"FORCE-COMPLETE {MIGRATION}", prompts)) == 0
    output = capsys.readouterr().out
    missing = (f"phase=replacement consumer={CONSUMER} region={REGION} resource={POOL}: only the "
               "temporary share provides access; establish permanent replacement sharing first")
    assert f"phase=complete status=OVERRIDDEN {missing}" in output and "BLOCKED" not in output
    assert prompts == [f"Type FORCE-COMPLETE {MIGRATION} to retire the temporary access of "
                       f"{CONSUMER} with the actions above despite the failed safety checks "
                       "overridden above (1); these accounts may lose access to the resources "
                       "above: "]
    # Forced, a loss after the deletion is reported and recorded, and the run continues.
    lost = f"original not visible to the consumer: {entitlement_key(POOL)}"
    assert f"phase=complete status=OVERRIDDEN {lost}" in output
    assert harness.deleted_shares == [arn] and harness.deleted_stacks == [(OWNER, REGION)]
    assert summary_line(output) == (
        f"status=COMPLETED migration={MIGRATION} deleted_shares=1 deleted_stacks=1 "
        f"removed_principals=0 retired_accounts={CONSUMER} remaining_accounts=none "
        "forced=true overridden=5")
    record = read_record(migration_record)
    assert record["completion"]["forced"] is True
    assert record["completion"]["overridden"][0] == missing and lost in record["completion"]["overridden"]
    retirement, = record["retirements"]
    assert (retirement["action"], retirement["forced"]) == ("SHARE_DELETED", True)
    drop, = record["drops"]  # still lost at the final check: the same loss, recorded once
    assert (drop["kind"], drop["subject"], drop["detected_by"], drop["evidence"]) == (
        "entitlement", entitlement_key(POOL), "complete", "complete-settle-1")
    history = complete_history(migration_record)
    assert [h["status"] for h in history] == ["FORCED", "SHARE_DELETED", "OVERRIDDEN",
                                              "OVERRIDDEN", "COMPLETED"]
    assert history[0]["overridden"] == [missing] and all(h["forced"] for h in history)


def test_a_forced_completion_needs_the_force_token(harness, capsys, migration_record):
    applied(harness, migration_record)
    harness.original_lost.add((CONSUMER, REGION, POOL))
    capsys.readouterr()
    assert main(complete_args(migration_record, "--force"),
                input_fn=lambda _prompt: f"COMPLETE {MIGRATION}") == 2
    assert "status=CANCELLED Confirmation did not match; no AWS writes requested" in \
        capsys.readouterr().out
    assert not harness.deleted_shares and not harness.deleted_stacks and not write_clients(harness)
    record = read_record(migration_record)
    assert not complete_history(migration_record)
    assert (record["retirements"], record["drops"]) == ([], [])


def test_force_changes_nothing_when_every_check_passes(harness, capsys, migration_record):
    small, large = pool_group("test"), pool_group("l1", "l2", permission=OTHER_PERMISSION)
    harness.source[OWNER, REGION] = [large, small]
    applied(harness, migration_record)
    harness.after_delete = lose_access_on_deletion
    prompts = []
    capsys.readouterr()
    assert main(complete_args(migration_record, "--force"),
                input_fn=answering(f"COMPLETE {MIGRATION}", prompts)) == 1
    output = capsys.readouterr().out
    assert prompts[0].startswith(f"Type COMPLETE {MIGRATION} to retire")
    assert "OVERRIDDEN" not in output
    # Nothing to override, so a loss after the canary deletion still stops the run.
    assert harness.deleted_shares == [share_arn(small)] and not harness.deleted_stacks
    assert "Completion stopped; the remaining temporary shares are retained." in output
    history = complete_history(migration_record)
    assert [h["status"] for h in history] == ["SHARE_DELETED", "FAILED"]
    assert all(h["force"] == "unused" and "forced" not in h for h in history)
    assert read_record(migration_record)["retirements"][0]["forced"] is False


def test_forced_a_loss_after_an_action_is_recorded_and_the_run_continues(
        harness, capsys, migration_record):
    small, large = pool_group("test"), pool_group("l1", "l2", permission=OTHER_PERMISSION)
    harness.source[OWNER, REGION] = [large, small]
    applied(harness, migration_record)
    recorded_drop(migration_record)  # a recorded failure drop: refused without --force
    harness.after_delete = lose_access_on_deletion
    capsys.readouterr()
    assert main(complete_args(migration_record, "--force"),
                input_fn=lambda _prompt: f"FORCE-COMPLETE {MIGRATION}") == 0
    output = capsys.readouterr().out
    assert f"phase=complete status=OVERRIDDEN failure drop recorded: association {ASSOCIATION_KEY}" \
        in output
    for arn in (POOL, f"arn:aws:ec2:{REGION}:{OWNER}:ipam-pool/l1"):
        assert f"phase=complete status=OVERRIDDEN original not visible to the consumer: " \
               f"{entitlement_key(arn)}" in output
    # Forced, every action observes once and the run goes on past each loss.
    assert completion_events(harness) == ["collect-2", "delete-share", "collect-1", "delete-share",
                                          "collect-1", "collect-2", "delete-stack"]
    assert harness.deleted_shares == [share_arn(small), share_arn(large)]
    record = read_record(migration_record)
    assert sorted(drop["subject"] for drop in record["drops"] if drop["detected_by"] == "complete") \
        == sorted(entitlement_key(arn) for g in (small, large) for arn in g.resources)
    assert [h["status"] for h in complete_history(migration_record)] == [
        "FORCED", "SHARE_DELETED", "OVERRIDDEN", "SHARE_DELETED", "OVERRIDDEN", "OVERRIDDEN",
        "COMPLETED"]
    assert "status=COMPLETED" in summary_line(output) and "forced=true" in summary_line(output)


@pytest.mark.parametrize("mismatch", ["stack-only", "share-arn", "authentication"])
def test_force_never_overrides_identity_or_a_record_stack_mismatch(
        harness, capsys, migration_record, mismatch):
    first, second = pool_group("test"), pool_group("second", permission=OTHER_PERMISSION)
    harness.source[OWNER, REGION] = [first, second]
    record = applied(harness, migration_record)
    harness.original_lost.add((CONSUMER, REGION, POOL))  # an overridable check fails as well
    if mismatch == "stack-only":
        extra = pool_group("unrecorded", permission="arn:aws:ram::aws:permission/ThirdPermission")
        harness.stored[OWNER, REGION].append(extra)
        expected = f"stack entitlement {OWNER}/{REGION}/{extra.logical_id} is not in the migration record"
    elif mismatch == "share-arn":
        rewrite(migration_record, shares=[
            dict(entry, share_arn=entry["share_arn"] + "-replaced")
            if entry["logical_id"] == second.logical_id else entry for entry in record["shares"]])
        expected = f"{OWNER}/{REGION}/{second.logical_id}: stack share {share_arn(second)} differs"
    else:
        harness.auth_errors[CONSUMER] = denied("GetCallerIdentity")
        expected = f"account={CONSUMER} phase=authentication status=BLOCKED"
    capsys.readouterr()
    refused(harness, migration_record, capsys, expected, FORCED, extra=("--force",))
    assert not any(call[0] == "collect" for call in harness.calls)


@pytest.mark.parametrize("error,code,status", [
    (MigrationError("principal removal did not finish before the timeout"), 1, "FAILED"),
    (KeyboardInterrupt(), 130, "INTERRUPTED"),
])
def test_an_action_that_fails_after_aws_acted_records_what_aws_holds(
        harness, capsys, migration_record, monkeypatch, error, code, status):
    shared = shared_group(harness)
    applied(harness, migration_record, args(consumers=BOTH))
    arn = share_arn(shared)

    def removed_then_failed(router, owner, region, share, migration, consumers, timeout=600):
        router.client(owner, "ram", region, write=True)
        harness.removed_principals.update((share, consumer) for consumer in consumers)
        raise error
    monkeypatch.setattr(cli, "remove_principals", removed_then_failed)
    capsys.readouterr()
    assert main(complete_for(migration_record, CONSUMER), input_fn=confirm_complete(harness)) == code
    output = capsys.readouterr().out
    assert f"status={status} share={arn} phase=complete " in output
    assert f" retired={CONSUMER}" in output and ("readback", arn) in harness.calls
    record = read_record(migration_record)
    retirement, = record["retirements"]
    assert (retirement["consumer"], retirement["action"]) == (CONSUMER, "PRINCIPAL_REMOVED")
    last = record["history"][-1]
    assert (last["status"], last["retired"], last["principals_removed"]) == (status, [CONSUMER], 1)
    # The record holds what AWS holds: nothing is left to retire for that account.
    assert main(complete_for(migration_record, CONSUMER),
                input_fn=lambda _: pytest.fail("nothing to confirm")) == 0
    assert f"consumer={CONSUMER} phase=complete status=ALREADY_RETIRED" in capsys.readouterr().out


def test_a_stack_left_by_a_failed_deletion_is_deleted_by_the_next_run(
        harness, capsys, migration_record, monkeypatch):
    applied(harness, migration_record)
    delete, attempts = cli.Stacks.delete, []

    def failing_once(self, owner, region):
        attempts.append((owner, region))
        if len(attempts) == 1:
            raise MigrationError("stack deletion did not finish before the timeout")
        return delete(self, owner, region)
    monkeypatch.setattr(cli.Stacks, "delete", failing_once)
    assert quietly(complete_args(migration_record), confirm_complete(harness)) == 1
    record = read_record(migration_record)
    assert record["completion"] is None and record_module.retired_consumers(record) == {CONSUMER}
    harness.calls.clear()
    prompts = []
    capsys.readouterr()
    assert main(complete_args(migration_record),
                input_fn=answering(f"COMPLETE {MIGRATION}", prompts)) == 0
    output = capsys.readouterr().out
    assert f"consumer={CONSUMER} phase=complete status=ALREADY_RETIRED" in output
    assert f"owner={OWNER} region={REGION} phase=complete action=DELETE_STACK" in output
    assert prompts == [f"Type COMPLETE {MIGRATION} to delete the emptied migration stacks above: "]
    assert not any(call[0] in ("collect", "delete-share") for call in harness.calls)
    assert summary_line(output) == (
        f"status=COMPLETED migration={MIGRATION} deleted_shares=0 deleted_stacks=1 "
        f"removed_principals=0 retired_accounts={CONSUMER} remaining_accounts=none")
    assert read_record(migration_record)["completion"]["deleted_stacks"] == [
        f"local-stack-{OWNER}-{REGION}"]


def test_apply_refuses_once_an_account_is_retired_and_plan_still_runs(
        harness, capsys, migration_record):
    shared_group(harness)
    argv = args(consumers=BOTH)
    applied(harness, migration_record, argv)
    assert quietly(complete_for(migration_record, CONSUMER), confirm_complete(harness)) == 0
    assert quietly(with_record(argv, migration_record)) == 0
    before = read_record(migration_record)
    harness.calls.clear()
    capsys.readouterr()
    assert main(with_record(["apply", *argv], migration_record),
                input_fn=lambda _: pytest.fail("refused before confirmation")) == 1
    assert (f"status=BLOCKED this migration is being completed: complete has retired the "
            f"temporary access of {CONSUMER} under migration ID {MIGRATION}, so apply creates no "
            "further temporary shares for it; plan and apply them under a new --migration-id and "
            "--record") in capsys.readouterr().out
    assert [call[0] for call in harness.calls] == ["router"] and not harness.writes()
    assert read_record(migration_record) == before


def test_verify_leaves_a_retired_account_out_of_its_scope(harness, capsys, migration_record):
    shared = shared_group(harness)
    applied(harness, migration_record, args(consumers=BOTH))
    assert quietly(complete_for(migration_record, CONSUMER), confirm_complete(harness)) == 0
    at = read_record(migration_record)["retirements"][0]["at"]
    arn = share_arn(shared)
    # Neither the retired account's original path nor its organization counts any more.
    harness.original_lost.add((CONSUMER, REGION, POOL))
    harness.organizations[OTHER_CONSUMER] = "o-destination1"
    harness.calls.clear()
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 0
    output = capsys.readouterr().out
    assert output.count(f"consumer={CONSUMER} phase=verification status=RETIRED at={at}") == 1
    assert f"share={arn} consumer={OTHER_CONSUMER} phase=verification status=VERIFIED" in output
    assert f"consumer={CONSUMER} phase=verification status=VERIFIED" not in output
    assert ("verify-retired", shared.key, (CONSUMER,)) in harness.calls
    assert [call[1] for call in harness.calls if call[0] == "collect"] == [1]
    assert not any(call[0] in ("authentication", "organization") and call[1] == CONSUMER
                   for call in harness.calls)
    line = summary_line(output)
    assert line.startswith("status=MIGRATION_VALIDATED") and "baseline_missing=0" in line
    assert "expected_entitlements=1 planned_shares=1 " in line  # the share serves one account now
    entry = read_record(migration_record)["verifications"][-1]
    assert (entry["migration_status"], entry["consumer_organizations"]) == (
        "MIGRATION_VALIDATED", {OTHER_CONSUMER: "o-destination1"})


def test_verify_no_longer_expects_a_share_retired_from_every_consumer(
        harness, capsys, migration_record):
    first, second, argv = two_consumer_groups(harness)
    applied(harness, migration_record, argv)
    assert quietly(complete_for(migration_record, CONSUMER), confirm_complete(harness)) == 0
    harness.readback_failures[OWNER, REGION] = {  # RAM may no longer return the deleted share
        first.logical_id: MigrationError("Migration resource ownership verification failed")}
    harness.calls.clear()
    capsys.readouterr()
    assert main(mode_args("verify", migration_record)) == 0
    output = capsys.readouterr().out
    assert "is missing from its migration stack" not in output and "could not be proven" not in output
    assert [call[1] for call in harness.calls if call[0] == "verify"] == [second.key]
    assert "sharing_status=SHARING_READY migration_status=PENDING_MIGRATION" in output
    assert "expected_entitlements=1 planned_shares=1 " in summary_line(output)
    assert f"{OTHER_CONSUMER} is still in its baseline organization" in output
    assert f"{CONSUMER} is still in its baseline organization" not in output


def test_verify_of_a_completed_migration_reports_it_without_aws_reads(harness, migration_record):
    applied(harness, migration_record)
    harness.replacement.add((CONSUMER, REGION, POOL))
    assert quietly(complete_args(migration_record), confirm_complete(harness)) == 0
    assert read_record(migration_record)["completion"]
    harness.calls.clear()
    out = io.StringIO()
    with contextlib.redirect_stdout(out):
        assert main(mode_args("verify", migration_record)) == 0
    assert f"status=ALREADY_COMPLETE migration={MIGRATION} phase=verification" in out.getvalue()
    assert [call[0] for call in harness.calls] == ["router"]
