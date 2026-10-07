"""Owner-transfer regression checks with synthetic clients; no AWS calls."""
import copy
import sys
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from ram_migration_common import Group, MigrationError, Plan
from ram_migration_discovery import ApprovedGroup, Discovery, LookupCache
from ram_migration_preflight import (
    ENABLED, EVALUATED, RCP, SCP, Governance, Policy, organization_preflight,
)
from ram_migration_record import plan_digest
from ram_migration_stacks import _validate_template, additive_template, template_for
from ram_migration_verification import Observation, _item, compare
from temporary_migration_ram_shares import (
    account_scope, baseline_scope_problems, build_parser, fill_scope_from_record,
    consumer_exclusion_scope, consumer_scope_problem, excluded_group_problems,
    migration_status, new_baseline, options, selected_consumers,
    validate_discovered_consumers,
)

OWNER = "400000000005"
MOVING = "400000000008"
STAYING = "400000000010"
OTHER = "400000000001"
REGION = "us-east-1"
SOURCE_ORG = "o-example0004x"
DEST_ORG = "o-example0003x"
DEST_OU = "arn:aws:organizations::400000000012:ou/o-example0003x/ou-exa3-example003"
SHARE = f"arn:aws:ram:{REGION}:{OWNER}:resource-share/11111111-1111-1111-1111-111111111111"
RESOURCE = f"arn:aws:ec2:{REGION}:{OWNER}:transit-gateway/tgw-00000000000000001"
KIND = "ec2:TransitGateway"
PERMISSION = "arn:aws:ram::aws:permission/AWSRAMDefaultPermissionTransitGateway"
SNAPSHOT = {
    "Arn": PERMISSION, "ResourceType": KIND, "Version": "1", "DefaultVersion": True,
    "Policy": {"Version": "2012-10-17", "Statement": [
        {"Effect": "Allow", "Action": ["ec2:CreateTransitGatewayVpcAttachment"],
         "Resource": "*"}]},
}


class Client:
    def __init__(self, **handlers):
        self.handlers = handlers
        self.calls = []
        self.meta = SimpleNamespace(partition="aws", region_name=REGION)

    def __getattr__(self, name):
        def invoke(**kwargs):
            self.calls.append((name, copy.deepcopy(kwargs)))
            if name not in self.handlers:
                raise AssertionError(f"Unexpected API operation {name}")
            handler = self.handlers[name]
            if isinstance(handler, Exception):
                raise handler
            return copy.deepcopy(handler(**kwargs) if callable(handler) else handler)
        return invoke


class Router:
    def __init__(self, **clients):
        self.clients = clients
        self.calls = []

    def client(self, account, service, region, write=False):
        self.calls.append((account, service, region, write))
        if write:
            raise AssertionError("Owner-continuity discovery requested a writable client")
        return self.clients[service]


def opts(mode="plan"):
    argv = [mode, "--migration-id", "test-owner-wave",
            "--owners", OWNER, "--consumers", OWNER, MOVING, "--regions", REGION]
    if mode != "plan":
        argv += ["--record", "unused-synthetic-record.json"]
    if mode in ("monitor", "complete"):
        argv = [mode, "--migration-id", "test-owner-wave",
                "--record", "unused-synthetic-record.json", "--all-accounts"]
    argv += ["--profile", "synthetic-unused", "--sso-role", "1-global-admin"]
    return options(build_parser().parse_args(argv),
                   lambda _prompt: (_ for _ in ()).throw(AssertionError("Unexpected prompt")))


def approved(consumers=(STAYING,), stationary=(STAYING,)):
    return ApprovedGroup(OWNER, REGION, tuple(sorted(consumers)), {KIND: PERMISSION},
                         {RESOURCE: KIND}, [SHARE], {KIND: copy.deepcopy(SNAPSHOT)}, [],
                         tuple(sorted(stationary)))


class OwnerContinuityDiscovery(unittest.TestCase):
    def setUp(self):
        self.share = {"resourceShareArn": SHARE, "owningAccountId": OWNER,
                      "status": "ACTIVE", "featureSet": "STANDARD", "tags": []}
        self.ram = Client(
            list_resources={"resources": [{"arn": RESOURCE, "type": KIND}]},
            get_resource_share_associations={"resourceShareAssociations": [
                {"associatedEntity": STAYING, "status": "ASSOCIATED", "external": False}]},
            list_resource_share_permissions={"permissions": [
                {"arn": PERMISSION, "resourceType": KIND, "version": "1"}]},
        )
        self.router = Router()
        self.discovery = Discovery(self.router, {OWNER, MOVING}, "test-owner-wave", {},
                                   {KIND.lower(): True}, migrating_owners={OWNER})
        self.configured = None

    def inspect(self):
        source = None
        if self.configured is not None:
            source = ({"StackId": "synthetic-source-stack"}, {},
                      {"Properties": {"Principals": self.configured}}, {}, {}, {})
        with patch.object(self.discovery, "_stack_source", return_value=source), \
                patch("ram_migration_discovery.cached_permission",
                      return_value=copy.deepcopy(SNAPSHOT)):
            part, group = self.discovery._inspect_share(
                OWNER, REGION, self.ram, self.share, LookupCache())
        self.assertTrue(all(not call[3] for call in self.router.calls))
        self.assertTrue(all(name.startswith(("get_", "list_", "describe_"))
                            for name, _ in self.ram.calls))
        return part, group

    def test_stationary_only_share_is_bridged_without_a_moving_recipient(self):
        part, group = self.inspect()
        self.assertEqual(part.blocked, [])
        self.assertEqual(group.consumers, (STAYING,))
        self.assertEqual(group.stationary_consumers, (STAYING,))
        self.assertEqual(group.resources, {RESOURCE: KIND})
        self.assertEqual(part.owner_continuity[0]["stationary_consumers"], [STAYING])
        validate_discovered_consumers([group], {OWNER, MOVING}, {OWNER})

    def test_mixed_share_keeps_both_populations_and_excludes_owning_account(self):
        rows = self.ram.handlers["get_resource_share_associations"]["resourceShareAssociations"]
        rows += [{"associatedEntity": MOVING, "status": "ASSOCIATED", "external": False},
                 {"associatedEntity": OWNER, "status": "FAILED", "external": False}]
        self.configured = [OWNER, MOVING, STAYING]
        part, group = self.inspect()
        self.assertEqual(part.blocked, [])
        self.assertEqual(group.consumers, tuple(sorted((MOVING, STAYING))))
        self.assertEqual(group.stationary_consumers, (STAYING,))
        self.assertNotIn(OWNER, group.consumers)

    def test_override_cannot_hide_live_stationary_recipient(self):
        self.discovery.overrides[SHARE] = [MOVING]
        part, group = self.inspect()
        self.assertEqual(part.blocked, [])
        self.assertEqual(group.consumers, tuple(sorted((MOVING, STAYING))))

    def test_empty_override_cannot_hide_stationary_recipient(self):
        self.discovery.overrides[SHARE] = []
        part, group = self.inspect()
        self.assertEqual(part.blocked, [])
        self.assertEqual(group.consumers, (STAYING,))

    def test_explicit_exclusion_skips_stationary_recipient_and_unsettled_invitation(self):
        self.discovery.excluded_consumers = {STAYING}
        self.discovery.consumer_exclusion_reason = "Excluded wave; no recovery requested"
        row = self.ram.handlers["get_resource_share_associations"]["resourceShareAssociations"][0]
        row.update(status="ASSOCIATING", external=True)
        self.configured = [STAYING, MOVING]
        part, group = self.inspect()
        self.assertEqual(part.blocked, [])
        self.assertEqual(group.consumers, (MOVING,))
        self.assertEqual(group.stationary_consumers, ())
        self.assertEqual(part.owner_continuity, [])
        self.assertEqual(part.external_access, [])
        self.assertTrue(any("explicitly excluded" in note for note in part.excluded))

    def test_excluded_stationary_only_share_creates_no_group(self):
        self.discovery.excluded_consumers = {STAYING}
        self.discovery.consumer_exclusion_reason = "Excluded wave; no recovery requested"
        part, group = self.inspect()
        self.assertEqual(part.blocked, [])
        self.assertIsNone(group)
        self.assertEqual(part.owner_continuity, [])
        self.assertTrue(any("explicitly excluded" in note for note in part.excluded))

    def test_override_does_not_restore_explicitly_excluded_recipient(self):
        self.discovery.excluded_consumers = {STAYING}
        self.discovery.consumer_exclusion_reason = "Excluded wave; no recovery requested"
        self.discovery.overrides[SHARE] = [MOVING, STAYING]
        part, group = self.inspect()
        self.assertEqual(part.blocked, [])
        self.assertEqual(group.consumers, (MOVING,))

    def test_discovery_rejects_excluded_migrating_account_or_missing_reason(self):
        for excluded, reason in (({MOVING}, "Excluded"), ({STAYING}, None)):
            with self.subTest(excluded=excluded), self.assertRaises(MigrationError):
                Discovery(self.router, {OWNER, MOVING}, "test-owner-wave", {},
                          {KIND.lower(): True}, migrating_owners={OWNER},
                          excluded_consumers=excluded, consumer_exclusion_reason=reason)

    def test_a_template_only_stationary_recipient_blocks_instead_of_gaining_access(self):
        """Review finding: continuity keeps current access; a recipient only the owning
        template names holds no ASSOCIATED association and would gain new access."""
        self.configured = [STAYING, OTHER]
        self.discovery.overrides[SHARE] = [MOVING]
        part, group = self.inspect()
        self.assertIsNone(group)
        self.assertIn(f"stationary recipients ['{OTHER}'] hold no ASSOCIATED principal association",
                      part.blocked[0])
        self.assertIn("--exclude-consumers", part.blocked[0])

    def test_override_cannot_invent_stationary_recipient(self):
        self.discovery.overrides[SHARE] = [OTHER]
        part, group = self.inspect()
        self.assertIsNone(group)
        self.assertIn("no live or owning-template", part.blocked[0])

    def test_organization_principal_expands_only_active_members(self):
        organization = f"arn:aws:organizations::400000000004:organization/{SOURCE_ORG}"
        self.ram.handlers["get_resource_share_associations"] = {
            "resourceShareAssociations": [
                {"associatedEntity": organization, "status": "ASSOCIATED"}]}
        org = Client(list_accounts={"Accounts": [
            {"Id": OWNER, "State": "ACTIVE"}, {"Id": MOVING, "State": "ACTIVE"},
            {"Id": STAYING, "State": "ACTIVE"}, {"Id": OTHER, "State": "SUSPENDED"}]})
        with patch.object(self.discovery, "_org", return_value=(org, {"Id": SOURCE_ORG})):
            part, group = self.inspect()
        self.assertEqual(part.blocked, [])
        self.assertEqual(group.stationary_consumers, (STAYING,))
        self.assertNotIn(OTHER, group.consumers)

    def test_unknown_organization_membership_still_blocks(self):
        organization = f"arn:aws:organizations::400000000004:organization/{SOURCE_ORG}"
        self.configured = [organization]
        with patch.object(self.discovery, "_org", side_effect=MigrationError("denied membership")):
            part, group = self.inspect()
        self.assertIsNone(group)
        self.assertIn("denied membership", part.blocked[0])

    def test_restricted_role_principal_cannot_be_broadened_by_override(self):
        self.configured = [f"arn:aws:iam::{STAYING}:role/Restricted"]
        self.discovery.overrides[SHARE] = [STAYING]
        part, group = self.inspect()
        self.assertIsNone(group)
        self.assertIn("cannot broaden restricted access", part.blocked[0])

    def test_existing_external_access_is_not_duplicated(self):
        self.ram.handlers["get_resource_share_associations"]["resourceShareAssociations"][0][
            "external"] = True
        part, group = self.inspect()
        self.assertEqual(part.blocked, [])
        self.assertIsNone(group)
        self.assertEqual(part.external_access[0]["consumer"], STAYING)
        self.assertEqual(part.owner_continuity, [])

    def test_unaccepted_original_external_invitation_still_blocks(self):
        row = self.ram.handlers["get_resource_share_associations"]["resourceShareAssociations"][0]
        row.update(status="ASSOCIATING", external=True)
        part, group = self.inspect()
        self.assertIsNone(group)
        self.assertIn("not settled", part.blocked[0])

    def test_external_capability_restriction_still_blocks(self):
        self.discovery.capabilities[KIND.lower()] = False
        part, group = self.inspect()
        self.assertIsNone(group)
        self.assertIn("external-sharing capability", part.blocked[0])
        self.assertEqual(part.owner_continuity, [])

    def test_stationary_owner_does_not_expand_the_moving_population(self):
        self.discovery.migrating_owners.clear()
        self.discovery.consumers = {MOVING}
        part, group = self.inspect()
        self.assertIsNone(group)
        self.assertEqual(part.blocked, [])
        self.assertEqual(part.owner_continuity, [])

    def test_merged_source_shares_keep_continuity_evidence(self):
        part, group = self.inspect()
        plan = Plan("test-owner-wave")
        self.discovery._merge(plan, OWNER, REGION, SHARE, part, group)
        second = copy.deepcopy(group)
        second.source_shares = [SHARE.replace("11111111", "22222222")]
        second.resources = {RESOURCE.replace("00001", "00002"): KIND}
        second_part = copy.deepcopy(part)
        second_part.owner_continuity[0]["share"] = second.source_shares[0]
        self.discovery._merge(plan, OWNER, REGION, second.source_shares[0], second_part, second)
        self.assertEqual(plan.blocked, [])
        self.assertEqual(len(plan.groups), 1)
        self.assertEqual(len(plan.groups[0].resources), 2)
        self.assertEqual(plan.groups[0].stationary_consumers, (STAYING,))
        self.assertEqual(len(plan.owner_continuity), 2)


class ContinuityScopeAndLifecycle(unittest.TestCase):
    def excluded_options(self, mode="plan"):
        values = opts(mode)
        values.excluded_consumers = [OTHER]
        values.consumer_exclusion_reason = "Excluded wave; no recovery requested"
        return values

    def test_cli_recipient_exclusion_requires_reason_and_disjoint_accounts(self):
        base = ["plan", "--migration-id", "test-owner-wave", "--owners", OWNER,
                "--consumers", MOVING, "--regions", REGION, "--profile", "unused"]
        for extra in (
                ["--exclude-consumers", OTHER],
                ["--exclude-consumers-reason", "Excluded"],
                ["--exclude-consumers", MOVING, "--exclude-consumers-reason", "Excluded"],
                ["--exclude-consumers", "58264495998",
                 "--exclude-consumers-reason", "Excluded"]):
            with self.subTest(extra=extra), self.assertRaises(MigrationError):
                options(build_parser().parse_args(base + extra), lambda _prompt: "")
        valid = options(build_parser().parse_args(
            base + ["--exclude-consumers", OTHER, "--exclude-consumers-reason", "Excluded"]),
            lambda _prompt: "")
        self.assertEqual(consumer_exclusion_scope(valid),
                         {"accounts": [OTHER], "reason": "Excluded"})

    def test_recipient_exclusion_is_digest_bound_and_inherited(self):
        values = self.excluded_options()
        scope = account_scope(values)
        self.assertNotEqual(plan_digest([], scope), plan_digest([], account_scope(opts())))
        record = {"scope": scope, "shares": [], "baseline": None}
        monitoring = opts("monitor")
        fill_scope_from_record(monitoring, record)
        self.assertEqual(consumer_exclusion_scope(monitoring), scope["excluded_consumers"])
        self.assertNotIn(OTHER, selected_consumers(monitoring, record))
        monitoring.selected = [OTHER]
        with self.assertRaises(MigrationError):
            selected_consumers(monitoring, record)

    def test_exclusion_cannot_change_after_baseline_capture_or_hide_recorded_access(self):
        excluded = consumer_exclusion_scope(self.excluded_options())
        observed = Observation("synthetic-now", [], [])
        record = {"baseline": new_baseline(observed, {}, 1, None, excluded)}
        self.assertIsNone(consumer_scope_problem(record, excluded))
        self.assertIn("differ", consumer_scope_problem(record, None))
        record["baseline"]["consumer_organizations"][OTHER] = SOURCE_ORG
        self.assertIn("cannot hide", consumer_scope_problem(record, excluded))

    def test_record_rejects_excluded_account_still_in_stationary_scope_or_old_shares(self):
        scope = account_scope(self.excluded_options())
        for record in (
                {"scope": {**scope, "stationary_consumers": [OTHER]}, "shares": []},
                {"scope": scope, "shares": [{"consumers": [OTHER]}]},
                {"scope": scope, "plan": {"groups": [{"consumers": [OTHER]}]}}):
            with self.subTest(record=record), self.assertRaises(MigrationError):
                fill_scope_from_record(opts("monitor"), record)

    def test_persisted_excluded_grant_blocks_additive_replanning(self):
        group = approved(consumers=(OTHER,), stationary=(OTHER,))
        problems = excluded_group_problems([group], {OTHER})
        self.assertEqual(len(problems), 1)
        self.assertIn("retire that access", problems[0])
        self.assertEqual(excluded_group_problems([approved()], {OTHER}), [])

    def test_stationary_accounts_are_recorded_separately_and_selectable(self):
        values = opts()
        values.stationary_consumers = [STAYING]
        scope = account_scope(values)
        self.assertEqual(scope["migrating_owners"], [OWNER])
        self.assertEqual(scope["migrating_consumers"], [MOVING])
        self.assertEqual(scope["stationary_consumers"], [STAYING])
        record = {"scope": scope, "shares": [], "baseline": None}
        monitoring = opts("monitor")
        fill_scope_from_record(monitoring, record)
        self.assertEqual(set(selected_consumers(monitoring, record)), {OWNER, MOVING, STAYING})
        monitoring.selected = [STAYING]
        self.assertEqual(selected_consumers(monitoring, record), [STAYING])

    def test_unproven_discovered_consumer_and_wrong_owner_role_are_rejected(self):
        for group in (approved(stationary=()), approved()):
            with self.subTest(stationary=group.stationary_consumers), \
                    self.assertRaises(MigrationError):
                validate_discovered_consumers([group], {OWNER, MOVING}, set())

    def test_review_digest_binds_stationary_role_metadata(self):
        group = approved()
        scope = account_scope(opts())
        original = plan_digest([group], scope)
        group.stationary_consumers = ()
        self.assertNotEqual(original, plan_digest([group], scope))

    def test_retained_template_contains_only_proven_account_principals(self):
        group = approved()
        template = template_for([group], "test-owner-wave")
        _validate_template(template, "test-owner-wave", OWNER)
        resource = template["Resources"][group.logical_id]
        self.assertEqual(resource["Properties"]["Principals"], [STAYING])
        self.assertTrue(resource["Properties"]["AllowExternalPrincipals"])
        self.assertEqual(resource["Properties"]["ResourceShareConfiguration"],
                         {"RetainSharingOnAccountLeaveOrganization": True})
        self.assertEqual(resource["Metadata"]["StationaryConsumers"], [STAYING])
        self.assertEqual(resource["DeletionPolicy"], "Retain")
        merged = additive_template(template, copy.deepcopy(template), "test-owner-wave")
        self.assertEqual(merged, template)

    def test_template_rejects_stationary_metadata_outside_principals(self):
        group = approved()
        template = template_for([group], "test-owner-wave")
        template["Resources"][group.logical_id]["Metadata"]["StationaryConsumers"] = [OTHER]
        with self.assertRaises(MigrationError):
            _validate_template(template, "test-owner-wave", OWNER)

    def record_and_comparison(self):
        values = opts()
        values.stationary_consumers = [STAYING]
        record = {
            "scope": account_scope(values), "drops": [],
            "baseline": {"complete": True, "gaps": [], "items": [],
                         "consumer_organizations": {
                             OWNER: SOURCE_ORG, MOVING: SOURCE_ORG, STAYING: SOURCE_ORG}}}
        return record, compare([], Observation("synthetic-now", [], []))

    def test_stationary_org_does_not_keep_migration_pending(self):
        record, comparison = self.record_and_comparison()
        result, reasons = migration_status(record, comparison, {
            OWNER: DEST_ORG, MOVING: DEST_ORG, STAYING: SOURCE_ORG}, [])
        self.assertEqual((result, reasons), ("MIGRATION_VALIDATED", []))

    def test_owner_with_no_received_resource_must_still_move(self):
        record, comparison = self.record_and_comparison()
        result, reasons = migration_status(record, comparison, {
            OWNER: SOURCE_ORG, MOVING: DEST_ORG, STAYING: SOURCE_ORG}, [])
        self.assertEqual(result, "PENDING_MIGRATION")
        self.assertEqual(len(reasons), 1)
        self.assertIn(OWNER, reasons[0])

    def test_missing_owner_baseline_org_cannot_validate_migration(self):
        record, comparison = self.record_and_comparison()
        del record["baseline"]["consumer_organizations"][OWNER]
        result, reasons = migration_status(record, comparison, {
            MOVING: DEST_ORG, STAYING: SOURCE_ORG}, [])
        self.assertEqual(result, "INCONCLUSIVE")
        self.assertIn(OWNER, reasons[0])

    def test_original_baseline_is_not_extended_for_new_stationary_grants(self):
        baseline = {"items": [], "consumer_organizations": {MOVING: SOURCE_ORG}}
        problems = baseline_scope_problems(baseline, [approved()], [], [OWNER])
        self.assertEqual(len(problems), 2)
        self.assertIn("baseline", problems[0])
        self.assertIn("original organization", problems[1])
        self.assertEqual(baseline, {"items": [], "consumer_organizations": {MOVING: SOURCE_ORG}})

    def test_stationary_resource_loss_fails_migration_validation(self):
        record, _ = self.record_and_comparison()
        item = _item("entitlement", [STAYING, REGION, RESOURCE], STAYING, OWNER,
                     REGION, RESOURCE, type=KIND, via_shares=[SHARE],
                     via_temporary=[], via_other=[SHARE])
        record["baseline"]["items"] = [item]
        comparison = compare([item], Observation("synthetic-now", [], []))
        result, reasons = migration_status(record, comparison, {
            OWNER: DEST_ORG, MOVING: DEST_ORG, STAYING: SOURCE_ORG}, [approved()])
        self.assertEqual(result, "FAILED")
        self.assertTrue(reasons)


class StationaryConsumerPolicies(unittest.TestCase):
    def run_preflight(self, source_deny=None, destination_deny=None, include_routes=False):
        allow = {"Effect": "Allow", "Action": "*", "Resource": "*"}

        def governance(account):
            scp = Policy("p-source-scp", "Source", SCP, False, "synthetic",
                         [allow, *([source_deny] if account == STAYING and source_deny else [])])
            rcp = Policy("p-source-rcp", "Source", RCP, False, "synthetic", [allow])
            return Governance(
                account, EVALUATED, organization=SOURCE_ORG, manager="400000000004",
                enabled={SCP: ENABLED, RCP: ENABLED}, path=["r-source"],
                attached={SCP: [("r-source", [scp])], RCP: [("r-source", [rcp])]},
                principal_arn=f"arn:aws:iam::{account}:role/VerifiedGlobalAdmin")

        destination = Governance(
            None, EVALUATED, organization=DEST_ORG, manager="400000000012",
            enabled={SCP: ENABLED, RCP: ENABLED}, path=["r-target"],
            attached={
                SCP: [("r-target", [Policy("p-target-scp", "Target", SCP, False,
                                        "synthetic", [allow])])],
                RCP: [("r-target", [Policy("p-target-rcp", "Target", RCP, False,
                                        "synthetic", [allow, *(
                                            [destination_deny] if destination_deny else [])])])],
            })
        ca = f"arn:aws:acm-pca:{REGION}:{OWNER}:certificate-authority/synthetic"
        group = Group(OWNER, REGION, (STAYING,), {}, {ca: "acm-pca:CertificateAuthority"})
        with patch("ram_migration_preflight._govern",
                   side_effect=lambda _reader, account: governance(account)), \
                patch("ram_migration_preflight._destination", return_value=destination):
            return organization_preflight(
                Router(), [group], [OWNER], destination=DEST_OU,
                include_tgw_routes=include_routes)

    def test_destination_checks_only_the_moving_owner(self):
        result = self.run_preflight()
        self.assertEqual(result["status"], "ALLOWED")
        self.assertEqual(result["destination"]["accounts"], [OWNER])
        self.assertEqual(result["owner_continuity"][0]["consumer"], STAYING)

    def test_destination_owner_rcp_can_deny_stationary_recipient(self):
        result = self.run_preflight(destination_deny={
            "Effect": "Deny", "Action": "acm-pca:GetCertificateAuthorityCertificate",
            "Resource": "*", "Condition": {
                "StringNotEquals": {"aws:PrincipalOrgID": DEST_ORG}}})
        self.assertEqual(result["status"], "BLOCKED")
        self.assertTrue(any(row["account"] == STAYING and row["role"] == "owner-continuity"
                            for row in result["findings"]))

    def test_stationary_scp_resource_org_condition_is_rechecked_after_owner_move(self):
        result = self.run_preflight(source_deny={
            "Effect": "Deny", "Action": "acm-pca:GetCertificateAuthorityCertificate",
            "Resource": "*", "Condition": {
                "StringEquals": {"aws:ResourceOrgID": DEST_ORG}}})
        self.assertEqual(result["status"], "BLOCKED")
        rows = [row for row in result["findings"] if row["account"] == STAYING]
        self.assertTrue(any(row["role"] == "owner-continuity" for row in rows))
        self.assertFalse(any(row["role"] == "stationary-consumer" for row in rows))


if __name__ == "__main__":
    unittest.main()
