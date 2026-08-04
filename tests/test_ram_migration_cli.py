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
from ram_migration_discovery import ApprovedGroup, approved_change, permission_change
from ram_migration_record import approval_for
import ram_migration_record as record_module
from ram_migration_stacks import template_for

OWNER = "000000000001"
CONSUMER = "000000000002"
OTHER_CONSUMER = "000000000003"
OTHER_OWNER = "000000000004"
REGION = "us-west-2"
HOME = "us-east-1"
MIGRATION = "local-test"
IPAM = "ec2:IpamPool"
RESOLVER = "route53resolver:ResolverRule"


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
        assert kwargs["resourceOwner"] == "OTHER-ACCOUNTS"
        self.harness.calls.append(("received-shares", self.account, self.region, kwargs))
        key = self.account, self.region
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

    def list_resolver_rule_associations(self, **_kwargs):
        samples = self.harness.resolver_samples[self.account, self.region]
        sample = samples.pop(0) if len(samples) > 1 else samples[0]
        return {"ResolverRuleAssociations": copy.deepcopy(sample)}


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
        self.share_states = {}
        self.share_reads = Counter()
        self.prepare_counts = Counter()
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
        self.region_errors = {}
        self.enabled_regions = defaultdict(lambda: [
            {"RegionName": HOME, "OptInStatus": "opt-in-not-required"},
            {"RegionName": REGION, "OptInStatus": "opt-in-not-required"},
        ])
        self.catalog = {IPAM.lower(): True, RESOLVER.lower(): True}
        self.permission_changes = {}
        self.discovery_kwargs = {}
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

            def inspect(self, owner, region):
                harness.calls.append(("discovery", owner, region))
                error = harness.discovery_errors.get((owner, region))
                if error:
                    return Plan(self.migration, blocked=[str(error)])
                plan = Plan(self.migration, groups=copy.deepcopy(harness.source.get((owner, region), [])),
                            excluded=["local empty share"] if region == HOME else [])
                approvals = harness.discovery_kwargs.get("approved_changes", [])
                for change in harness.permission_changes.get((owner, region), []):
                    granted = approval_for(approvals, self.migration, change)
                    item = dict(change, status="APPROVED" if granted else "APPROVAL_REQUIRED")
                    plan.permission_changes.append(item)
                    if granted:
                        item["approval_id"] = granted["approval_id"]
                        for g in plan.groups:
                            if change["share"] in g.source_shares:
                                g.permission_changes = [approved_change(item)]
                    else:
                        plan.groups = [g for g in plan.groups if change["share"] not in g.source_shares]
                        plan.blocked.append(f"{change['share']}: Non-default permission differs "
                                            "from the current default and requires approval")
                return plan

        class LocalStacks:
            def __init__(self, router, migration, timeout):
                self.router, self.migration = router, migration
                harness.calls.append(("stacks-inputs", timeout))

            def existing(self, owner, region):
                harness.calls.append(("existing", owner, region))
                return {"StackId": "local-stored-stack"} if (owner, region) in harness.stored else None

            def persisted_groups(self, owner, region):
                harness.calls.append(("persisted", owner, region))
                return copy.deepcopy(harness.stored[owner, region])

            def prepare(self, owner, region, groups):
                key = owner, region
                harness.calls.append(("prepare", owner, region))
                harness.prepare_counts[key] += 1
                if key in harness.prepare_errors:
                    raise harness.prepare_errors[key]
                body = template_for(groups, self.migration)
                if key in harness.drift and harness.prepare_counts[key] > 1:
                    body["Description"] = "changed after confirmation"
                return body, self.existing(owner, region)

            def apply(self, owner, region, groups):
                harness.calls.append(("apply", owner, region))
                if (owner, region) in harness.apply_errors:
                    raise harness.apply_errors[owner, region]
                self.router.client(owner, "cloudformation", region, write=True).create_change_set()
                harness.stored[owner, region] = copy.deepcopy(groups)
                for g in groups:
                    for consumer in g.consumers:
                        rows = harness.invitations[consumer, region]
                        arn = harness.share(g)["resourceShareArn"]
                        if not any(row["resourceShareArn"] == arn for row in rows):
                            rows.append(harness.invitation(g, consumer))
                return "local-migration-stack"

            def shares(self, owner, region):
                harness.calls.append(("shares", owner, region))
                harness.share_reads[owner, region] += 1
                if (owner, region) not in harness.stored:
                    raise MigrationError("Migration stack does not exist")
                states = harness.share_states.get((owner, region), ["ACTIVE"])
                state = states.pop(0) if len(states) > 1 else states[0]
                return {g.logical_id: dict(harness.share(g), status=state)
                        for g in harness.stored[owner, region] if g.key not in harness.missing_shares}

        def local_verify(router, g, share, migration):
            harness.calls.append(("verify", g.key, share["resourceShareArn"], migration))
            if harness.verify_hook:
                harness.verify_hook(router, g, share)
            if g.key in harness.verify_errors:
                error = harness.verify_errors[g.key]
                if callable(error):
                    error = error(router, g)
                if error:
                    raise error
            router.client(g.owner, "ram", g.region)

        monkeypatch.setattr(cli, "Router", LocalRouter)
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
        return f"APPLY {MIGRATION}"

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
_UNSNAPSHOTTED = {"router"}


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
    assert "status=READY" in capsys.readouterr().out
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
    assert "status=READY" in output and "accepted_invitations=1" in output
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
    assert "status=READY" in capsys.readouterr().out


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


def test_apply_resolver_snapshot_uses_actual_ids_and_preserves_them(harness, capsys):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    harness.resolver_samples[CONSUMER, REGION] = [[association()], [association()]]
    assert main(args("apply"), input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    assert "association=association-original" in output
    assert "rule=actual-owner-rule-id" in output
    assert "phase=resolver-before" in output and "phase=resolver-after" in output
    assert "status=READY" in output


@pytest.mark.parametrize("after", [
    [],
    [association("association-replacement")],
    [association(vpc="vpc-replacement")],
    [association(status="FAILED")],
])
def test_resolver_changes_fail_even_when_counts_match(harness, after, capsys):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    harness.resolver_samples[CONSUMER, REGION] = [[association()], after]
    assert main(args("apply"), input_fn=harness.confirm) == 1
    output = capsys.readouterr().out
    assert "association state changed" in output
    assert "status=INCOMPLETE" in output and "status=READY" not in output


def test_missing_preexisting_associations_are_not_claimed_as_preserved(harness, capsys):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    assert main(args("apply"), input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    assert "missing_preexisting_associations=1" in output and "continuity is unproven" in output
    assert "status=MISSING_ASSOCIATION" in output
    assert "PASS" not in output and "no association repair was performed" in output


def test_unhealthy_resolver_baseline_blocks_before_confirmation(harness):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    harness.resolver_samples[CONSUMER, REGION] = [[association(status="CREATING")]]
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Baseline is blocked")) == 1
    assert not harness.writes()


def test_resolver_snapshot_access_denial_blocks_before_writes(harness, capsys):
    harness.source[OWNER, REGION] = [group(kind=RESOLVER)]
    harness.resolver_error = denied("ListResolverRules")
    assert main(args("apply"), input_fn=lambda _: pytest.fail("Baseline is blocked")) == 1
    assert "operation=ListResolverRules" in capsys.readouterr().out
    assert not harness.writes()


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


@pytest.mark.parametrize("return_code", [0, 1, 2])
def test_monitor_delegates_config_and_exit_code_without_share_work(harness, monkeypatch, return_code):
    config = {"scope": {"consumer": CONSUMER}, "evidence_directory": "local-evidence"}
    calls = []
    def monitor(router, received):
        calls.append((router, received))
        return return_code
    monkeypatch.setitem(sys.modules, "ram_migration_monitor", SimpleNamespace(monitor=monitor))
    assert main(["monitor", "--profile", "explicit-source",
                     "--monitor-config", json.dumps(config)]) == return_code
    assert calls == [(harness.router, config)]
    assert [call[0] for call in harness.calls] == ["router"]


def test_monitor_missing_configuration_fails_before_authentication(harness, capsys):
    assert main(["monitor", "--profile", "explicit-source"]) == 1
    assert "monitor requires --monitor-config" in capsys.readouterr().out
    assert not harness.calls


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
# Reviewed record and permission-change approvals (v0.2.0)
# ---------------------------------------------------------------------------
IPAM_PERMISSION = f"arn:aws:ram::aws:permission/{IPAM}"
ORIGINAL_SHARE = f"arn:aws:ram:{REGION}:{OWNER}:resource-share/original"
V2 = {"Effect": "Allow", "Action": ["ec2:DescribeTransitGateways"]}
V3 = {"Effect": "Allow", "Action": ["ec2:DescribeTransitGateways", "ec2:CreateClientVpnEndpoint"]}


def tgw_like_change():
    from ram_migration_discovery import policy_semantics
    prior = {"Arn": IPAM_PERMISSION, "Version": "2", "ResourceType": IPAM,
             "Policy": policy_semantics(V2), "DefaultVersion": False}
    default = {"Arn": IPAM_PERMISSION, "Version": "3", "ResourceType": IPAM,
               "Policy": policy_semantics(V3), "DefaultVersion": True}
    return permission_change(OWNER, REGION, ORIGINAL_SHARE, prior, default)


def with_record(argv, path):
    return list(argv) + ["--record", str(path)]


@pytest.fixture
def revalidations(monkeypatch):
    seen = []
    monkeypatch.setattr(cli, "revalidate_change", lambda client, change: seen.append(change))
    return seen


def plan_and_approve(harness, path, capsys):
    harness.permission_changes[OWNER, REGION] = [tgw_like_change()]
    assert main(with_record(args(), path)) == 1
    request, = record_module.load(path, MIGRATION)["permission_change_requests"]
    token = f"APPROVE {MIGRATION} {request['id']}"
    assert main(["approve", "--record", str(path)], input_fn=lambda _prompt: token) == 0
    assert main(with_record(args(), path)) == 0
    capsys.readouterr()
    return request


def test_plan_record_shows_comparison_and_blocks_until_approved(harness, capsys, migration_record):
    harness.permission_changes[OWNER, REGION] = [tgw_like_change()]
    assert main(with_record(args(), migration_record)) == 1
    output = capsys.readouterr().out
    assert "phase=permission-change" in output and "status=APPROVAL_REQUIRED" in output
    assert "version=2->3" in output
    assert "actions added: Allow ec2:CreateClientVpnEndpoint" in output
    assert f"share={ORIGINAL_SHARE}" in output
    assert not harness.writes()
    record = record_module.load(migration_record, MIGRATION)
    assert record["plan"]["status"] == "BLOCKED" and record["revision"] == 1
    request, = record["permission_change_requests"]
    assert request["shares"] == [ORIGINAL_SHARE] and request["to_version"] == "3"
    assert record["approvals"]["permission_changes"] == []


def test_approve_needs_the_exact_token_and_no_aws_access(harness, capsys, migration_record):
    harness.permission_changes[OWNER, REGION] = [tgw_like_change()]
    assert main(with_record(args(), migration_record)) == 1
    harness.calls.clear()
    assert main(["approve", "--record", str(migration_record)],
                input_fn=lambda _prompt: f"APPROVE {MIGRATION}") == 2
    assert "status=NOT_APPROVED" in capsys.readouterr().out
    assert record_module.load(migration_record, MIGRATION)["approvals"]["permission_changes"] == []
    request, = record_module.load(migration_record, MIGRATION)["permission_change_requests"]
    prompts = []
    token = f"APPROVE {MIGRATION} {request['id']}"
    assert main(["approve", "--record", str(migration_record)],
                input_fn=lambda prompt: prompts.append(prompt) or token) == 0
    output = capsys.readouterr().out
    assert "actions added: Allow ec2:CreateClientVpnEndpoint" in output
    assert "Original shares are not modified" in output and token in prompts[0]
    assert not any(call[0] in ("router", "authentication", "client") for call in harness.calls)
    approval, = record_module.load(migration_record, MIGRATION)["approvals"]["permission_changes"]
    assert approval["shares"] == [ORIGINAL_SHARE] and approval["migration_id"] == MIGRATION
    assert (approval["from_version"], approval["to_version"]) == ("2", "3")
    assert main(["approve", "--record", str(migration_record)],
                input_fn=lambda _p: pytest.fail("nothing left to approve")) == 0


def test_approved_change_is_revalidated_then_applied_and_recorded(harness, capsys, migration_record,
                                                                 revalidations):
    request = plan_and_approve(harness, migration_record, capsys)
    record = record_module.load(migration_record, MIGRATION)
    assert record["plan"]["status"] == "PLANNED"
    template = record["plan"]["migration_stacks"][0]["template"]
    row, = next(iter(template["Resources"].values()))["Metadata"]["PermissionChanges"]
    assert row["ApprovalId"] == request["id"] and row["SourceShareArn"] == ORIGINAL_SHARE
    assert main(with_record(args("apply"), migration_record), input_fn=harness.confirm) == 0
    output = capsys.readouterr().out
    assert "phase=permission-revalidation status=VERIFIED" in output
    assert [c["approval_id"] for c in revalidations] == [request["id"]]
    confirmation = harness.calls.index(("confirmation",))
    first_write = harness.calls.index(next(c for c in harness.calls if c[0] == "write"))
    assert confirmation < first_write
    record = record_module.load(migration_record, MIGRATION)
    assert [h["mode"] for h in record["history"]] == ["plan", "approve", "plan", "apply"]
    share, = record["shares"]
    assert share["share_arn"].startswith(f"arn:aws:ram:{REGION}:{OWNER}:resource-share/temporary-")


def test_permission_drift_after_approval_blocks_every_write(harness, capsys, migration_record,
                                                            monkeypatch):
    plan_and_approve(harness, migration_record, capsys)

    def drifted(_client, change):
        raise cli.MigrationError(f"{change['permission_arn']}: permission changed since approval")
    monkeypatch.setattr(cli, "revalidate_change", drifted)
    assert main(with_record(args("apply"), migration_record), input_fn=harness.confirm) == 1
    assert "post-confirmation permission revalidation" in capsys.readouterr().out
    assert not harness.writes()
    last = record_module.load(migration_record, MIGRATION)["history"][-1]
    assert (last["mode"], last["status"], last["phase"]) == ("apply", "BLOCKED", "post-confirmation")


def test_apply_refuses_a_blocked_reviewed_plan(harness, capsys, migration_record):
    harness.permission_changes[OWNER, REGION] = [tgw_like_change()]
    assert main(with_record(args(), migration_record)) == 1
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
        f"{ORIGINAL_SHARE}: Non-default permission differs and requires approval")
    harness.receive()
    assert main(args()) == 1
    output = capsys.readouterr().out
    assert "requires approval" in output and "not covered by any planned" not in output


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
