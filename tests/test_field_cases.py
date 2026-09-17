"""Offline checks for the scoped field updates; no AWS calls."""
import ast
import copy
import hashlib
import io
import os
import sys
import unittest
import zipfile
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from botocore.exceptions import ClientError
from ram_migration_common import Api, Group, MigrationError, Plan
from ram_migration_discovery import Discovery, LookupCache
from ram_migration_preflight import (
    ABSENT, ENABLED, EVALUATED, EXPLICIT_DENY, SCP, UNDECIDED,
    Action, Governance, Policy, _context, _evaluate, _Findings, _govern,
    _Reader, statement_applies, STANDALONE, organization_preflight,
)
from ram_migration_record import plan_digest, tool_identity
from ram_migration_verification import _allocations, _Task, collect, Observation
from temporary_migration_ram_shares import (
    account_scope, build_parser, capture_problems, fill_scope_from_record, new_baseline,
    observe, options, recorded_verification_exclusions, reviewed_plan_problem, summary,
    verification_exclusions, verification_scope_problem, WriteGate,
)

ACCOUNT = "400000000013"
REGION = "us-east-1"
ORG = "o-example0004x"
ROLE_NAME = "AWSReservedSSO_1-global-admin_1234567890abcdef"
ROLE_ID = "AROAEXAMPLEVERIFIED"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/sso.amazonaws.com/{ROLE_NAME}"
STS_ARN = f"arn:aws:sts::{ACCOUNT}:assumed-role/{ROLE_NAME}/e142018"
ROOT_DENY = {
    "Sid": "RootBlock", "Effect": "Deny", "Action": "*", "Resource": "*",
    "Condition": {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::*:root"}},
}


def api_error(operation, code="AccessDeniedException"):
    return ClientError({"Error": {"Code": code, "Message": "synthetic test response"}},
                       operation)


class Client:
    def __init__(self, **handlers):
        self.handlers = handlers
        self.calls = []
        self.meta = SimpleNamespace(partition="aws", region_name=REGION)

    def __getattr__(self, name):
        def invoke(**kwargs):
            self.calls.append((name, copy.deepcopy(kwargs)))
            if name not in self.handlers:
                raise AssertionError(f"Unexpected API call: {name}")
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
            raise AssertionError("Read-only fix requested a writable client")
        return self.clients[service]


class PrincipalConditions(unittest.TestCase):
    def decision(self, arn=None, statement=ROOT_DENY):
        context = {} if arn is None else {"aws:principalarn": arn}
        return statement_applies(statement, "ram:CreateResourceShare", context)

    def test_root_deny_applies_to_root_and_not_role(self):
        self.assertEqual(self.decision(f"arn:aws:iam::{ACCOUNT}:root"), (True, []))
        self.assertEqual(self.decision(ROLE_ARN), (False, []))

    def test_unknown_principal_remains_gap(self):
        value, reasons = self.decision()
        self.assertIsNone(value)
        self.assertIn("no known value", " ".join(reasons))

    def test_arn_wildcards_cannot_cross_components(self):
        arn = f"arn:aws:iam::{ACCOUNT}:role/path:root"
        self.assertEqual(self.decision(arn), (False, []))

    def test_arn_aliases_negations_case_and_multiple_patterns(self):
        for operator, expected in (("ArnLike", True), ("ArnEquals", True),
                                   ("ArnNotLike", False), ("ArnNotEquals", False)):
            statement = {**ROOT_DENY, "Condition": {operator: {"AWS:PrincipalArn": [
                "arn:aws:iam::*:root", f"arn:aws:iam::{ACCOUNT}:role/aws-reserved/*"]}}}
            with self.subTest(operator=operator):
                self.assertEqual(self.decision(ROLE_ARN, statement), (expected, []))
        self.assertEqual(self.decision(f"arn:aws:iam::{ACCOUNT}:ROOT"), (False, []))

    def test_malformed_arns_and_unsupported_keys_remain_gaps(self):
        for value in ("not-an-arn", "arn:aws:iam", True, ["unknown"]):
            with self.subTest(value=value):
                self.assertIsNone(self.decision(value)[0])
        statement = {**ROOT_DENY, "Condition": {"ArnLike": {"aws:PrincipalAccount": ACCOUNT}}}
        self.assertIsNone(statement_applies(
            statement, "ram:CreateResourceShare", {"aws:principalaccount": ACCOUNT})[0])
        statement = {**ROOT_DENY, "Condition": {"ArnLike": {"aws:PrincipalArn": "*"}}}
        self.assertIsNone(self.decision(ROLE_ARN, statement)[0])

    def test_unknown_is_not_absent_even_with_ifexists_or_null(self):
        for operator, value in (("ArnLikeIfExists", "arn:aws:iam::*:root"),
                                ("ArnNotLikeIfExists", "arn:aws:iam::*:root"),
                                ("Null", "false")):
            statement = {**ROOT_DENY, "Condition": {operator: {"aws:PrincipalArn": value}}}
            with self.subTest(operator=operator):
                self.assertIsNone(self.decision(statement=statement)[0])
        for operator, expected in (("ArnLike", False), ("ArnNotLike", True),
                                   ("ArnLikeIfExists", True),
                                   ("ForAnyValue:ArnLike", False),
                                   ("ForAllValues:ArnLike", True)):
            statement = {**ROOT_DENY, "Condition": {
                operator: {"aws:PrincipalArn": "arn:aws:iam::*:root"}}}
            self.assertEqual(statement_applies(
                statement, "ram:CreateResourceShare", {"aws:principalarn": ABSENT}),
                (expected, []))

    def test_current_context_cannot_be_reused_for_future_destination_role(self):
        principal = Governance(ACCOUNT, EVALUATED, organization=ORG, principal_arn=ROLE_ARN)
        current = _context(Action("ram:CreateResourceShare"), REGION, principal, ORG, None)
        future = _context(Action("ram:GetResourceShares"), REGION, principal,
                          "o-example0003x", None)
        self.assertEqual(statement_applies(ROOT_DENY, "ram:CreateResourceShare", current),
                         (False, []))
        self.assertIsNone(statement_applies(ROOT_DENY, "ram:GetResourceShares", future)[0])

    def test_policy_path_keeps_real_root_deny_and_unknown_gap(self):
        allow = {"Effect": "Allow", "Action": "*", "Resource": "*"}
        policy = Policy("p-example1", "Root guard", SCP, False, "test", [allow, ROOT_DENY])
        governance = Governance(ACCOUNT, EVALUATED, organization=ORG,
                                enabled={SCP: ENABLED},
                                attached={SCP: [("r-example", [policy])]})
        for arn, decision in ((ROLE_ARN, None),
                              (f"arn:aws:iam::{ACCOUNT}:root", EXPLICIT_DENY),
                              (None, UNDECIDED)):
            findings = _Findings()
            _evaluate(findings, governance, SCP, ACCOUNT, "owner", "ram:CreateResourceShare",
                      REGION, {} if arn is None else {"aws:principalarn": arn})
            rows = findings.to_list()
            self.assertEqual([row["decision"] for row in rows], [] if decision is None
                             else [decision])


class AuthenticatedPrincipal(unittest.TestCase):
    def setup_reader(self, identity=None, role=None):
        identity = identity or {"Account": ACCOUNT, "Arn": STS_ARN,
                                "UserId": f"{ROLE_ID}:e142018"}
        role = role or {"Arn": ROLE_ARN, "RoleName": ROLE_NAME, "RoleId": ROLE_ID}
        sts = Client(get_caller_identity=identity)
        iam = Client(get_role={"Role": role})
        self.router = Router(sts=sts, iam=iam)
        return _Reader(self.router)

    def test_actual_role_path_and_unique_id_are_verified(self):
        reader = self.setup_reader()
        self.assertEqual(reader.principal_arn(ACCOUNT), ROLE_ARN)
        self.assertEqual(reader.principal_arn(ACCOUNT), ROLE_ARN)
        self.assertEqual(len(self.router.clients["iam"].calls), 1)
        self.assertTrue(all(not call[3] for call in self.router.calls))

    def test_wrong_account_role_name_partition_and_id_are_rejected(self):
        variants = [
            {"identity": {"Account": "400000000005", "Arn": STS_ARN,
                          "UserId": f"{ROLE_ID}:e142018"}},
            {"role": {"Arn": ROLE_ARN.replace("aws:iam", "aws-cn:iam"),
                      "RoleName": ROLE_NAME, "RoleId": ROLE_ID}},
            {"role": {"Arn": ROLE_ARN.replace(ACCOUNT, "400000000005"),
                      "RoleName": ROLE_NAME, "RoleId": ROLE_ID}},
            {"role": {"Arn": ROLE_ARN, "RoleName": "AnotherRole", "RoleId": ROLE_ID}},
            {"role": {"Arn": ROLE_ARN, "RoleName": ROLE_NAME, "RoleId": "AROAOTHER"}},
            {"identity": {"Account": ACCOUNT, "Arn": STS_ARN}},
        ]
        for values in variants:
            with self.subTest(values=values), self.assertRaises(MigrationError):
                self.setup_reader(**values).principal_arn(ACCOUNT)

    def test_denied_getrole_is_not_a_guessed_arn(self):
        reader = self.setup_reader()
        self.router.clients["iam"].handlers["get_role"] = api_error("GetRole")
        with self.assertRaises(ClientError):
            reader.principal_arn(ACCOUNT)

    def test_direct_root_and_user_are_recognized_but_federated_user_is_unknown(self):
        for suffix in ("root", "user/path/e142018"):
            arn = f"arn:aws:iam::{ACCOUNT}:{suffix}"
            reader = self.setup_reader(identity={"Account": ACCOUNT, "Arn": arn})
            self.assertEqual(reader.principal_arn(ACCOUNT), arn)
            self.assertEqual(self.router.clients["iam"].calls, [])
        with self.assertRaises(MigrationError):
            self.setup_reader(identity={"Account": ACCOUNT,
                                        "Arn": f"arn:aws:sts::{ACCOUNT}:federated-user/example"}
                              ).principal_arn(ACCOUNT)

    def test_identity_read_error_is_retained_without_making_up_context(self):
        reader = SimpleNamespace(
            principal_arn=lambda account: (_ for _ in ()).throw(api_error("GetRole")),
            member=lambda account: None)
        governance = _govern(reader, ACCOUNT)
        self.assertIsNone(governance.principal_arn)
        self.assertIn("GetRole", governance.principal_arn_problem)
        context = _context(Action("ram:GetResourceShares"), REGION, governance, None, None)
        self.assertIsNone(statement_applies(ROOT_DENY, "ram:GetResourceShares", context)[0])


class OrphanPolicyCA(unittest.TestCase):
    def setUp(self):
        self.owner = "400000000015"
        self.share_arn = f"arn:aws:ram:{REGION}:{self.owner}:resource-share/" \
                         "1f35643b-6c62-49d6-adbe-9140cbc74c75"
        self.ca = f"arn:aws:acm-pca:{REGION}:{self.owner}:certificate-authority/" \
                  "4fd43b41-84f0-4f96-8daf-0269141f4d39"
        self.other_ca = self.ca.replace("4fd43b41-84f0-4f96-8daf-0269141f4d39",
                                       "7338071c-fbf2-46f2-8733-2913ec051297")
        self.share = {"resourceShareArn": self.share_arn, "owningAccountId": self.owner,
                      "status": "ACTIVE", "featureSet": "CREATED_FROM_POLICY"}
        self.ram = Client(get_resource_share_associations={"resourceShareAssociations": []},
                          list_resources={"resources": [
                              {"type": "acm-pca:CertificateAuthority", "arn": self.ca}]})
        self.pca = Client(
            describe_certificate_authority=api_error("DescribeCertificateAuthority",
                                                    "ResourceNotFoundException"),
            list_certificate_authorities={"CertificateAuthorities": [
                {"Arn": self.other_ca, "Status": "ACTIVE"}]})
        self.router = Router(**{"acm-pca": self.pca})
        self.discovery = Discovery(self.router, {"400000000008"}, "test-wave", {}, {},
                                   cache=LookupCache())

    def inspect(self):
        return self.discovery._inspect_share(self.owner, REGION, self.ram, self.share,
                                             LookupCache())

    def assert_blocked(self):
        part, group = self.inspect()
        self.assertIsNone(group)
        self.assertTrue(part.blocked)
        self.assertEqual(part.excluded, [])

    def test_two_independent_reads_prove_missing_and_create_no_group(self):
        part, group = self.inspect()
        self.assertIsNone(group)
        self.assertEqual(part.blocked, [])
        self.assertEqual(len(part.excluded), 1)
        self.assertIn(self.ca, part.excluded[0])
        self.assertIn("ResourceNotFoundException", part.excluded[0])
        self.assertIn("complete ListCertificateAuthorities", part.excluded[0])
        self.assertEqual(self.pca.calls[-1][1]["ResourceOwner"], "SELF")
        self.assertTrue(all(not call[3] for call in self.router.calls))
        self.assertTrue(all(name.startswith(("get_", "list_", "describe_"))
                            for name, _ in self.ram.calls + self.pca.calls))

    def test_active_and_restorable_deleted_ca_remain_blocked(self):
        for status in ("ACTIVE", "DELETED"):
            with self.subTest(status=status):
                self.pca.handlers["describe_certificate_authority"] = {
                    "CertificateAuthority": {"Arn": self.ca, "Status": status}}
                self.assert_blocked()

    def test_any_principal_association_remains_blocked(self):
        for status in ("ASSOCIATED", "ASSOCIATING", "DISASSOCIATED", "FAILED", "UNKNOWN"):
            with self.subTest(status=status):
                self.ram.handlers["get_resource_share_associations"] = {
                    "resourceShareAssociations": [
                        {"associatedEntity": "400000000008", "status": status}]}
                self.assert_blocked()

    def test_mixed_empty_and_wrong_owner_resource_inventories_remain_blocked(self):
        for resources in ([], [{"type": "ec2:TransitGateway", "arn": "other"}],
                          [{"type": "acm-pca:CertificateAuthority",
                            "arn": self.ca.replace(self.owner, "400000000005")}],
                          [{"type": "acm-pca:CertificateAuthority",
                            "arn": self.ca.replace(REGION, "eu-west-1")}],
                          [{"type": "acm-pca:CertificateAuthority", "arn": self.ca},
                           {"type": "ec2:TransitGateway", "arn": "other"}]):
            with self.subTest(resources=resources):
                self.ram.handlers["list_resources"] = {"resources": resources}
                self.assert_blocked()

    def test_denied_or_missing_evidence_never_proves_absence(self):
        for client, operation in ((self.ram, "get_resource_share_associations"),
                                  (self.ram, "list_resources"),
                                  (self.pca, "describe_certificate_authority"),
                                  (self.pca, "list_certificate_authorities")):
            original = client.handlers[operation]
            for response in (api_error(operation), {}):
                with self.subTest(operation=operation, response=response):
                    client.handlers[operation] = response
                    self.assert_blocked()
            client.handlers[operation] = original

    def test_ca_present_on_later_inventory_page_blocks(self):
        def inventory(**kwargs):
            if kwargs.get("NextToken") == "page-two":
                return {"CertificateAuthorities": [{"Arn": self.ca, "Status": "DELETED"}]}
            return {"CertificateAuthorities": [], "NextToken": "page-two"}
        self.pca.handlers["list_certificate_authorities"] = inventory
        self.assert_blocked()
        self.assertEqual(len([c for c in self.pca.calls if c[0] ==
                              "list_certificate_authorities"]), 2)

    def test_inventory_later_page_failure_and_repeated_token_block(self):
        def denied(**kwargs):
            if kwargs.get("NextToken"):
                raise api_error("ListCertificateAuthorities")
            return {"CertificateAuthorities": [], "NextToken": "page-two"}
        self.pca.handlers["list_certificate_authorities"] = denied
        self.assert_blocked()
        self.pca.handlers["list_certificate_authorities"] = {
            "CertificateAuthorities": [], "NextToken": "repeated"}
        self.assert_blocked()

    def test_incomplete_inventory_rows_and_wrong_client_region_block(self):
        self.pca.handlers["list_certificate_authorities"] = {"CertificateAuthorities": [{}]}
        self.assert_blocked()
        self.pca.meta.region_name = "eu-west-1"
        self.assert_blocked()

    def test_malformed_pagination_tokens_are_not_end_of_inventory(self):
        for token in (False, 0, [], {}):
            with self.subTest(token=token):
                self.pca.handlers["list_certificate_authorities"] = {
                    "CertificateAuthorities": [], "NextToken": token}
                self.assert_blocked()

    def test_nonactive_or_promoting_share_is_not_excluded(self):
        for changes in ({"status": "DELETING"}, {"status": "FAILED"},
                        {"featureSet": "PROMOTING_TO_STANDARD"}):
            with self.subTest(changes=changes):
                share = copy.deepcopy(self.share)
                self.share.update(changes)
                self.assert_blocked()
                self.share = share


class WriteAndRecordGuards(unittest.TestCase):
    def record(self, status="PLANNED", sources=None):
        plan = Plan("test-wave")
        scope = {"migrating_consumers": ["400000000008"]}
        record = {"plan": {"status": status, "digest": plan_digest(plan.groups, scope)},
                  "history": [{"mode": "plan", "revision": 1, "status": status,
                               "tool_sources_digest": sources or
                               tool_identity()["sources_digest"]}]}
        return record, plan, scope

    def test_blocked_revision_and_old_sources_cannot_be_applied(self):
        record, plan, scope = self.record(status="BLOCKED")
        self.assertIn("BLOCKED", reviewed_plan_problem(record, plan, scope))
        record, plan, scope = self.record(sources="old-release-source-digest")
        self.assertIn("tool sources changed", reviewed_plan_problem(record, plan, scope))

    def test_only_matching_reviewed_scope_can_be_applied(self):
        record, plan, scope = self.record()
        self.assertIsNone(reviewed_plan_problem(record, plan, scope))
        self.assertIn("differ", reviewed_plan_problem(
            record, plan, {"migrating_consumers": ["400000000002"]}))

    def test_write_boundary_stays_closed(self):
        client = Client(create_resource_share={})
        api = Api(client)
        with self.assertRaises(MigrationError):
            api.create_resource_share(name="must-never-run")
        self.assertEqual(client.calls, [])
        gate = WriteGate(Router(ram=client))
        with self.assertRaises(MigrationError):
            gate.client(ACCOUNT, "ram", REGION, write=True)


class IpamLocaleReads(unittest.TestCase):
    def setUp(self):
        self.owner = "400000000013"
        self.consumer = "400000000016"
        self.pool = "ipam-pool-0cc12a562b9dfecd5"
        self.arn = f"arn:aws:ec2::{self.owner}:ipam-pool/{self.pool}"
        self.metadata = {"OwnerId": self.owner, "IpamPoolId": self.pool,
                         "IpamPoolArn": self.arn, "Locale": "eu-west-1",
                         "IpamRegion": "us-east-1"}
        self.allocation = {"IpamPoolAllocationId": "ipam-pool-alloc-example",
                           "ResourceOwner": self.consumer, "ResourceType": "vpc",
                           "ResourceId": "vpc-example", "Cidr": "172.16.9.0/24"}
        self.home = Client(describe_ipam_pools={"IpamPools": [self.metadata]})
        self.locale = Client(get_ipam_pool_allocations={
            "IpamPoolAllocations": [self.allocation]})
        self.locale.meta.region_name = "eu-west-1"
        self.clients = {"us-east-1": self.home, "eu-west-1": self.locale}
        self.calls = []

        def client(account, service, region, write=False):
            self.calls.append((account, service, region, write))
            if account != self.owner or service != "ec2" or write:
                raise AssertionError("Unexpected or writable IPAM client")
            return self.clients[region]
        self.router = SimpleNamespace(client=client)
        self.task = _Task(self.router, self.owner, REGION, {REGION, "eu-west-1"})

    def observe(self):
        _allocations(self.task, self.arn, {self.consumer})

    def test_verified_locale_is_used_and_ram_scope_keys_are_preserved(self):
        self.observe()
        self.assertEqual(self.task.gaps, [])
        self.assertEqual(len(self.task.items), 1)
        item = self.task.items[0]
        self.assertEqual(item["region"], "us-east-1")
        self.assertEqual(item["allocation_region"], "eu-west-1")
        self.assertIn(f"|{self.owner}|us-east-1|{self.pool}|", item["key"])
        self.assertEqual(self.calls, [(self.owner, "ec2", "us-east-1", False),
                                     (self.owner, "ec2", "eu-west-1", False)])
        self.assertEqual(self.home.calls, [("describe_ipam_pools", {"IpamPoolIds": [self.pool]})])

    def test_same_locale_uses_existing_read_client(self):
        self.metadata["Locale"] = "us-east-1"
        self.home.handlers["get_ipam_pool_allocations"] = {
            "IpamPoolAllocations": [self.allocation]}
        self.observe()
        self.assertEqual(self.task.gaps, [])
        self.assertEqual(self.task.items[0]["allocation_region"], "us-east-1")
        self.assertEqual(len(self.calls), 1)

    def test_unknown_or_wrong_pool_metadata_is_a_gap(self):
        for change in ({"Locale": None}, {"OwnerId": "400000000005"},
                       {"IpamPoolId": "ipam-pool-other"}, {"IpamPoolArn": "wrong"}):
            with self.subTest(change=change):
                metadata = {**self.metadata, **change}
                self.home.handlers["describe_ipam_pools"] = {"IpamPools": [metadata]}
                self.task = _Task(self.router, self.owner, REGION, {REGION, "eu-west-1"})
                self.observe()
                self.assertTrue(self.task.gaps)
                self.assertEqual(self.task.items, [])
                self.assertEqual(self.locale.calls, [])
        self.home.handlers["describe_ipam_pools"] = api_error("DescribeIpamPools")
        self.task = _Task(self.router, self.owner, REGION, {REGION, "eu-west-1"})
        self.observe()
        self.assertIn("operation=DescribeIpamPools", self.task.gaps[0]["reason"])

    def test_locale_outside_cli_scope_is_never_read(self):
        self.metadata["Locale"] = "ap-south-1"
        self.observe()
        self.assertEqual(self.task.items, [])
        self.assertIn("RegionOutsideVerificationScope", self.task.gaps[0]["reason"])
        self.assertEqual(self.calls, [(self.owner, "ec2", REGION, False)])

    def test_later_allocation_page_denial_is_not_an_empty_inventory(self):
        def allocations(**kwargs):
            if kwargs.get("NextToken"):
                raise api_error("GetIpamPoolAllocations")
            return {"IpamPoolAllocations": [self.allocation], "NextToken": "page-two"}
        self.locale.handlers["get_ipam_pool_allocations"] = allocations
        self.observe()
        self.assertEqual(self.task.items, [])
        self.assertIn("operation=GetIpamPoolAllocations", self.task.gaps[0]["reason"])

    def test_malformed_allocation_page_is_a_gap(self):
        self.locale.handlers["get_ipam_pool_allocations"] = {}
        self.observe()
        self.assertEqual(self.task.items, [])
        self.assertTrue(self.task.gaps)

    def test_explicit_region_scope_must_include_group_regions(self):
        group = Group(self.owner, REGION, (self.consumer,), {}, {self.arn: "ec2:IpamPool"})
        for regions in ({"eu-west-1"}, "us-east-1", {"us-east-1", "invalid-region"}):
            with self.subTest(regions=regions), self.assertRaises(MigrationError):
                collect(self.router, [group], allowed_regions=regions)
        self.assertEqual(self.calls, [])

    def test_existing_blackhole_routes_still_block_capture(self):
        tables = ("rtb-0311c0f5daf5b3fe3", "rtb-0de2834b36db8c3b3",
                  "rtb-0ebb044c3afc21cd6")
        items = [{"kind": "tgw_route", "key": f"tgw_route|{self.consumer}|{REGION}|{table}|0.0.0.0/0",
                  "consumer": self.consumer, "owner": "400000000005", "region": REGION,
                  "resource_arn": "arn:aws:ec2:us-east-1:400000000005:transit-gateway/tgw-example",
                  "tgw_id": "tgw-example", "route_table_id": table,
                  "destination": "0.0.0.0/0", "state": "blackhole"} for table in tables]
        problems = capture_problems({"items": items, "gaps": []})
        self.assertEqual(len(problems), 3)
        self.assertTrue(all("capture requires a stable original state" in p for p in problems))


class TgwRouteExclusion(unittest.TestCase):
    owner = "400000000005"
    consumer = "400000000016"
    reason = "User requested RAM sharing verification; TGW routes are outside scope"

    def setUp(self):
        self.tgw = "tgw-example"
        self.arn = f"arn:aws:ec2:{REGION}:{self.owner}:transit-gateway/{self.tgw}"
        self.share = f"arn:aws:ram:{REGION}:{self.owner}:resource-share/example"
        self.attachment = "tgw-attach-example"
        self.group = Group(self.owner, REGION, (self.consumer,), {},
                           {self.arn: "ec2:TransitGateway"})
        self.owner_ec2 = Client(describe_transit_gateway_attachments={
            "TransitGatewayAttachments": [{
                "TransitGatewayAttachmentId": self.attachment, "TransitGatewayId": self.tgw,
                "ResourceOwnerId": self.consumer, "Association": {"State": "associated"},
            }]})
        self.consumer_ec2 = Client(
            describe_transit_gateway_vpc_attachments={"TransitGatewayVpcAttachments": [{
                "TransitGatewayAttachmentId": self.attachment, "TransitGatewayId": self.tgw,
                "VpcOwnerId": self.consumer, "VpcId": "vpc-example", "State": "available",
            }]},
            describe_route_tables={"RouteTables": [{
                "RouteTableId": "rtb-example", "OwnerId": self.consumer, "Routes": [{
                    "DestinationCidrBlock": "0.0.0.0/0", "TransitGatewayId": self.tgw,
                    "State": "blackhole",
                }],
            }]})
        self.ram = Client(
            get_resource_shares={"resourceShares": [{
                "resourceShareArn": self.share, "owningAccountId": self.owner, "status": "ACTIVE",
            }]},
            list_resources={"resources": [{
                "arn": self.arn, "resourceShareArn": self.share, "status": "AVAILABLE",
            }]})
        self.client_calls = []

        def client(account, service, region, write=False):
            self.client_calls.append((account, service, region, write))
            if write or region != REGION:
                raise AssertionError("Unexpected verification scope or write")
            if service == "ram" and account == self.consumer:
                return self.ram
            if service == "ec2":
                return {self.owner: self.owner_ec2, self.consumer: self.consumer_ec2}[account]
            raise AssertionError("Unexpected client")

        self.router = SimpleNamespace(client=client)

    def opts(self, mode="plan", excluded=True, reason=None):
        argv = [mode, "--migration-id", "test-wave", "--source-profile", "synthetic",
                "--sso-role", "1-global-admin"]
        if mode in ("plan", "apply"):
            argv += ["--owners", self.owner, "--consumers", self.consumer, "--regions", REGION]
        if mode != "plan":
            argv += ["--record", "synthetic-unused.json"]
        if mode in ("monitor", "complete"):
            argv += ["--all-accounts"]
        if excluded:
            argv += ["--exclude-tgw-routes", "--exclude-tgw-routes-reason", reason or self.reason]
        return options(build_parser().parse_args(argv), lambda _prompt: self.fail("Unexpected prompt"))

    def test_default_still_observes_and_blocks_blackhole_routes(self):
        observed = collect(self.router, [self.group])
        routes = [item for item in observed.items if item["kind"] == "tgw_route"]
        self.assertEqual([item["state"] for item in routes], ["blackhole"])
        self.assertEqual(len(capture_problems(observed)), 1)

    def test_cli_exclusion_skips_route_api_and_retains_entitlement_and_attachment(self):
        lines = []
        observed = observe(self.router, [self.group], frozenset(), self.opts(),
                           SimpleNamespace(emit=lines.append), "baseline-preflight")
        self.assertEqual(observed.gaps, [])
        self.assertEqual(capture_problems(observed), [])
        self.assertEqual({item["kind"] for item in observed.items},
                         {"entitlement", "tgw_attachment"})
        self.assertNotIn("describe_route_tables", [name for name, _ in self.consumer_ec2.calls])
        self.assertIn("get_resource_shares", [name for name, _ in self.ram.calls])
        self.assertIn("describe_transit_gateway_attachments",
                      [name for name, _ in self.owner_ec2.calls])
        self.assertTrue(all(not call[3] for call in self.client_calls))

    def test_excluded_route_api_denial_is_never_called(self):
        self.consumer_ec2.handlers["describe_route_tables"] = api_error("DescribeRouteTables")
        observed = collect(self.router, [self.group], include_tgw_routes=False)
        self.assertEqual(observed.gaps, [])
        self.assertEqual(capture_problems(observed), [])
        self.assertNotIn("describe_route_tables", [name for name, _ in self.consumer_ec2.calls])

    def test_attachment_read_denial_still_blocks_with_routes_excluded(self):
        self.consumer_ec2.handlers["describe_transit_gateway_vpc_attachments"] = api_error(
            "DescribeTransitGatewayVpcAttachments")
        observed = collect(self.router, [self.group], include_tgw_routes=False)
        self.assertTrue(any(gap["collector"] == "tgw_attachments" for gap in observed.gaps))
        self.assertTrue(capture_problems(observed))

    def test_owner_attachment_read_denial_still_blocks(self):
        self.owner_ec2.handlers["describe_transit_gateway_attachments"] = api_error(
            "DescribeTransitGatewayAttachments")
        observed = collect(self.router, [self.group], include_tgw_routes=False)
        self.assertTrue(any(gap["collector"] == "tgw_owner_attachments" for gap in observed.gaps))
        self.assertTrue(capture_problems(observed))

    def test_unhealthy_existing_attachment_still_blocks(self):
        row = self.consumer_ec2.handlers[
            "describe_transit_gateway_vpc_attachments"]["TransitGatewayVpcAttachments"][0]
        row["State"] = "deleting"
        observed = collect(self.router, [self.group], include_tgw_routes=False)
        self.assertTrue(capture_problems(observed))

    def test_missing_ram_visibility_still_blocks(self):
        self.ram.handlers["list_resources"] = {"resources": []}
        observed = collect(self.router, [self.group], include_tgw_routes=False)
        entitlement = next(item for item in observed.items if item["kind"] == "entitlement")
        self.assertEqual(entitlement["via_shares"], [])
        self.assertTrue(capture_problems(observed))

    def test_visible_tgw_does_not_invent_a_vpc_attachment(self):
        self.owner_ec2.handlers["describe_transit_gateway_attachments"] = {
            "TransitGatewayAttachments": []}
        self.consumer_ec2.handlers["describe_transit_gateway_vpc_attachments"] = {
            "TransitGatewayVpcAttachments": []}
        observed = collect(self.router, [self.group], include_tgw_routes=False)
        self.assertEqual([item["kind"] for item in observed.items], ["entitlement"])
        self.assertEqual(capture_problems(observed), [])

    def test_reason_is_mandatory_and_cannot_inject_output(self):
        base = ["plan", "--exclude-tgw-routes"]
        for extra in ([], ["--exclude-tgw-routes-reason", ""],
                      ["--exclude-tgw-routes-reason", "reason\nstatus=READY"],
                      ["--exclude-tgw-routes-reason", "x" * 501]):
            with self.subTest(extra=extra), self.assertRaises(MigrationError):
                options(build_parser().parse_args(base + extra), lambda _prompt: "")
        with self.assertRaises(MigrationError):
            options(build_parser().parse_args(["plan", "--exclude-tgw-routes-reason", "reason"]),
                    lambda _prompt: "")

    def test_scope_change_requires_a_new_reviewed_plan(self):
        plan = Plan("test-wave")
        strict_scope = account_scope(self.opts(excluded=False))
        excluded_scope = account_scope(self.opts())
        record = {"plan": {"status": "PLANNED",
                           "digest": plan_digest(plan.groups, strict_scope)},
                  "history": [{"mode": "plan", "revision": 1, "status": "PLANNED",
                               "tool_sources_digest": tool_identity()["sources_digest"]}]}
        self.assertIsNone(reviewed_plan_problem(record, plan, strict_scope))
        self.assertIn("differ", reviewed_plan_problem(record, plan, excluded_scope))

    def test_scope_is_frozen_after_capture(self):
        excluded = verification_exclusions(self.opts())
        observed = Observation("2026-10-16T00:00:00+00:00")
        strict = {"baseline": new_baseline(observed, {}, 1)}
        scoped = {"baseline": new_baseline(observed, {}, 1, excluded)}
        self.assertIsNone(verification_scope_problem(strict, None))
        self.assertIn("cannot change", verification_scope_problem(strict, excluded))
        self.assertIsNone(verification_scope_problem(scoped, excluded))
        self.assertIn("cannot change", verification_scope_problem(scoped, None))
        changed = {**excluded, "reason": "Different reason"}
        self.assertIn("cannot change", verification_scope_problem(scoped, changed))

    def test_verify_monitor_complete_inherit_recorded_scope_and_reject_mismatch(self):
        scope = account_scope(self.opts())
        record = {"scope": scope, "plan": {"groups": []}, "shares": [],
                  "baseline": new_baseline(Observation("2026-10-16T00:00:00+00:00"), {}, 1,
                                           verification_exclusions(self.opts()))}
        for mode in ("verify", "monitor", "complete"):
            with self.subTest(mode=mode):
                opts = self.opts(mode, excluded=False)
                fill_scope_from_record(opts, record)
                self.assertEqual(verification_exclusions(opts), scope["verification_exclusions"])
                with self.assertRaises(MigrationError):
                    fill_scope_from_record(self.opts(mode, reason="Different reason"), record)

    def test_record_cannot_exclude_entitlements_or_hide_recorded_routes(self):
        excluded = verification_exclusions(self.opts())
        for changes in ({"collectors": ["entitlement"]}, {"item_kinds": ["tgw_attachment"]},
                        {"unexpected": True}):
            with self.subTest(changes=changes), self.assertRaises(MigrationError):
                recorded_verification_exclusions({"verification_exclusions": {**excluded, **changes}})
        record = {"baseline": {"verification_exclusions": excluded,
                               "items": [{"kind": "tgw_route", "key": "old-route"}]}}
        self.assertIn("cannot hide", verification_scope_problem(record, excluded))

    def test_summary_reports_selected_verification_scope(self):
        lines = []
        summary(Plan("test-wave"), SimpleNamespace(emit=lines.append), "PLANNED",
                mode="plan", recorded=False,
                verification_exclusions=verification_exclusions(self.opts()))
        self.assertIn("excluded_verification_collectors=tgw_routes", lines[0])
        self.assertIn(self.reason, lines[0])

    def test_nonboolean_collector_scope_is_rejected_before_any_reads(self):
        for invalid in ("false", 0, None):
            with self.subTest(invalid=invalid), self.assertRaises(MigrationError):
                collect(self.router, [self.group], include_tgw_routes=invalid)
        self.assertEqual(self.client_calls, [])


class RouteScopedPolicyPreflight(unittest.TestCase):
    def run_preflight(self, denied, include_routes):
        owner, consumer = "400000000005", "400000000016"
        policy = Policy("p-example", "Synthetic guard", SCP, False, "synthetic", [
            {"Effect": "Allow", "Action": "*", "Resource": "*"},
            {"Effect": "Deny", "Action": denied, "Resource": "*"},
        ])
        target = Governance(None, EVALUATED, organization="o-example0003x", manager="400000000012",
                            enabled={SCP: ENABLED}, path=["r-example"],
                            attached={SCP: [("r-example", [policy])]})
        group = Group(owner, REGION, (consumer,), {}, {})
        with patch("ram_migration_preflight._govern",
                   side_effect=lambda _reader, account: Governance(account, STANDALONE)), \
                patch("ram_migration_preflight._destination", return_value=target):
            return organization_preflight(
                Router(), [group], [consumer], include_tgw_routes=include_routes,
                destination="arn:aws:organizations::400000000012:ou/o-example0003x/ou-exa3-example003")

    def test_route_deny_blocks_only_when_that_read_is_in_scope(self):
        strict = self.run_preflight("ec2:DescribeRouteTables", True)
        excluded = self.run_preflight("ec2:DescribeRouteTables", False)
        self.assertEqual(strict["status"], "BLOCKED")
        self.assertEqual(excluded["status"], "ALLOWED")
        self.assertIn("ec2:DescribeRouteTables", strict["evaluator"]["destination_actions"])
        self.assertNotIn("ec2:DescribeRouteTables", excluded["evaluator"]["destination_actions"])

    def test_attachment_deny_still_blocks_with_routes_excluded(self):
        result = self.run_preflight("ec2:DescribeTransitGatewayVpcAttachments", False)
        self.assertEqual(result["status"], "BLOCKED")
        self.assertIn("ec2:DescribeTransitGatewayVpcAttachments",
                      result["evaluator"]["destination_actions"])


class MonitorPresentation(unittest.TestCase):
    """Exercise the packaged console adapter without unpacking or calling AWS."""

    @classmethod
    def setUpClass(cls):
        # The launcher source that packaging/build.sh packages as the zipapp __main__.py.
        launcher = Path(__file__).resolve().parents[1] / "packaging" / "launcher_main.py"
        tree = ast.parse(launcher.read_text())
        names = {"_event_fields", "HumanMonitorReporter", "_launch"}
        nodes = [
            node for node in tree.body
            if (isinstance(node, ast.Import)
                and all(alias.name != "temporary_migration_ram_shares" for alias in node.names))
            or isinstance(node, ast.ImportFrom)
            or (isinstance(node, (ast.FunctionDef, ast.ClassDef)) and node.name in names)
            or (isinstance(node, ast.Assign)
                and any(isinstance(target, ast.Name) and target.id == "MONITOR_COUNTS"
                        for target in node.targets))
        ]
        namespace = {"__name__": "ramshift_console_test"}
        exec(compile(ast.Module(body=nodes, type_ignores=[]), "<console-adapter>", "exec"),
             namespace)
        cls.presentation = SimpleNamespace(**namespace)

    def setUp(self):
        self.report = self.presentation.HumanMonitorReporter()
        self.report.context = SimpleNamespace(
            regions=["eu-west-1", "us-east-1"],
            args=SimpleNamespace(record=Path("wave1.json")))

    def render(self, *events):
        output = io.StringIO()
        with redirect_stdout(output):
            for event in events:
                self.report.emit(event)
        return output.getvalue()

    def start(self):
        return (
            'phase=verification-scope status=EXCLUDED collector=tgw_routes kind=tgw_route '
            'reason="Routes outside this scope"',
            "TGW route health and network reachability are outside this verification scope.",
            "migration=wave1 phase=monitor status=STARTED "
            "consumers=400000000002,400000000008,400000000016 "
            "baseline_captured_at=2026-10-16T13:44:00.123456+00:00 baseline_items=172",
        )

    @staticmethod
    def counts(account="400000000002", **changes):
        values = dict(original_share_drops=0, shares_added=0, lost=0, degraded=0,
                      added=0, unobserved=0)
        values.update(changes)
        return (f"consumer={account} phase=monitor "
                + " ".join(f"{name}={value}" for name, value in values.items()))

    @staticmethod
    def finish(status="UNCHANGED", gaps=0, code=0, recorded=True, **changes):
        values = dict(original_share_drops=0, shares_added=0, lost=0, degraded=0,
                      added=0, unobserved=0)
        values.update(changes)
        return (
            f"status={status} migration=wave1 phase=monitor "
            "consumers=400000000002,400000000008,400000000016 "
            + " ".join(f"{name}={value}" for name, value in values.items())
            + f" gaps={gaps} "
            + ("recorded_drops=0 revision=19" if recorded else "recorded=false")
            + f" exit_code={code}")

    def test_unchanged_summary_keeps_account_id_scope_and_baseline(self):
        events = list(self.start())
        for account in ("400000000002", "400000000008", "400000000016"):
            events.extend((
                f"consumer={account} phase=monitor organization_at_baseline=o-source "
                "organization_now=o-source organization_change=UNCHANGED",
                self.counts(account)))
        output = self.render(*events, self.finish())
        self.assertIn("Result: UNCHANGED", output)
        self.assertIn("No changes detected in the monitored baseline", output)
        self.assertIn("400000000002", output)
        self.assertIn("Regions: eu-west-1, us-east-1", output)
        self.assertIn("Baseline: 2026-10-16 13:44:00 UTC", output)
        self.assertIn("TGW route checks excluded: Routes outside this scope", output)
        self.assertEqual(output.count("network reachability"), 1)
        self.assertIn("Lost: 0   Degraded: 0   Unobserved: 0   Read gaps: 0", output)
        self.assertIn("wave1.json (revision 19)", output)
        self.assertNotIn("phase=monitor", output)

    def test_routine_progress_is_condensed_and_owner_read_gap_remains_visible(self):
        output = self.render(
            *self.start(),
            "account=400000000005 phase=authentication status=VERIFIED",
            "account=400000000002 phase=authentication status=VERIFIED",
            "phase=progress stage=observation:monitor status=STARTED accounts=6 tasks=6",
            "phase=progress stage=observation:monitor account=400000000005 "
            "done=1/1 overall=1/6 elapsed_seconds=32.0 items=4 gaps=1",
            self.counts(unobserved=1),
            self.finish("INCONCLUSIVE", gaps=1, code=3, unobserved=1))
        self.assertEqual(output.count("Checking account access"), 1)
        self.assertIn("Result: INCONCLUSIVE", output)
        self.assertIn("400000000005: 1 read gap", output)
        self.assertNotIn("No changes detected", output)
        self.assertNotIn("done=1/1", output)

    def test_changed_organization_and_access_are_distinguished_from_losses(self):
        output = self.render(
            *self.start(),
            "consumer=400000000002 phase=monitor organization_at_baseline=o-source "
            "organization_now=o-destination organization_change=CHANGED",
            "consumer=400000000002 region=eu-west-1 owner=400000000005 "
            "resource=arn:aws:ec2:eu-west-1:400000000005:transit-gateway/tgw-example "
            "phase=monitor change=ORIGINAL_SHARE_DROPPED share=share-example access=AVAILABLE",
            self.counts(original_share_drops=1),
            self.finish("CHANGED", original_share_drops=1))
        self.assertIn("Result: CHANGED", output)
        self.assertIn("o-destination", output)
        self.assertIn("Original share access removed", output)
        self.assertIn("current access=AVAILABLE", output)
        self.assertIn("Lost: 0", output)
        self.assertNotIn("Baseline items were lost", output)

    def test_loss_and_degradation_evidence_is_preserved(self):
        reason = "AttachmentStateNotAvailable operation=DescribeTransitGatewayVpcAttachments"
        output = self.render(
            *self.start(),
            "phase=monitor change=LOST key=entitlement|400000000002|resource-one",
            f'phase=monitor change=DEGRADED key=attachment|example reasons=["{reason}"] '
            "consumer=400000000002 resource=attachment-example",
            self.counts(lost=1, degraded=1),
            self.finish("LOSS", code=1, lost=1, degraded=1))
        self.assertIn("Result: LOSS", output)
        self.assertIn("Lost: 1   Degraded: 1", output)
        self.assertIn("resource-one", output)
        self.assertIn("AttachmentStateNotAvailable", output)
        self.assertIn("DescribeTransitGatewayVpcAttachments", output)
        self.assertIn("Exit code: 1", output)
        self.assertNotIn("No changes detected", output)

    def test_unobserved_items_and_auth_failure_are_never_shown_as_success(self):
        output = self.render(
            *self.start(),
            'phase=monitor change=UNOBSERVED key=example reasons=["AccessDenied"]',
            "phase=monitor status=INCONCLUSIVE current organization of 400000000002 is unknown",
            self.finish("INCONCLUSIVE", gaps=1, code=3, unobserved=1))
        self.assertIn("Could not observe", output)
        self.assertIn("AccessDenied", output)
        self.assertIn("current organization of 400000000002 is unknown", output)
        self.assertIn("Exit code: 3", output)
        blocked = self.render("status=BLOCKED Error when retrieving token from sso: Token has expired")
        self.assertIn("Monitor could not run", blocked)
        self.assertIn("Token has expired", blocked)
        self.assertNotIn("No changes detected", blocked)

    def test_missing_account_evidence_is_unknown_instead_of_zero(self):
        output = self.render(*self.start(), self.finish("INCONCLUSIVE", code=3))
        account_row = next(line for line in output.splitlines() if line.startswith("400000000002"))
        self.assertIn("UNKNOWN", account_row)
        self.assertEqual(account_row.count("?"), 4)

    def test_failed_record_write_is_visible(self):
        output = self.render(self.finish(recorded=False, code=1))
        self.assertIn("result could not be saved", output)
        self.assertIn("Exit code: 1", output)
        self.assertNotIn("(revision", output)

    def test_unknown_and_malformed_events_are_passed_through(self):
        diagnostic = "phase=new-collector status=GAP AccessDenied operation=NewAPI"
        malformed = 'phase=monitor reason="unterminated'
        self.assertEqual(self.render(diagnostic, malformed), diagnostic + "\n" + malformed + "\n")
        summary = self.finish().replace("lost=0", "lost=not-a-number")
        self.assertEqual(self.render(summary), summary + "\n")

    def fake_cli(self, return_code=0):
        original_reporter = SimpleNamespace
        fake = SimpleNamespace(build_parser=build_parser, Reporter=original_reporter)

        def monitor(router, opts, report):
            return return_code

        fake.run_monitor = monitor
        fake.seen = []

        def main(argv):
            fake.seen.append(list(argv))
            fake.active_reporter = fake.Reporter
            return return_code

        fake.main = main
        return fake, original_reporter, monitor

    def test_human_adapter_preserves_all_native_arguments_and_exit_code(self):
        fake, reporter, monitor = self.fake_cli(return_code=3)
        argv = ["monitor", "--record", "wave1.json", "--all-accounts",
                "--sso-role", "1-global-admin"]
        code = self.presentation._launch(fake, argv)
        self.assertEqual(code, 3)
        self.assertEqual(fake.seen, [argv])
        self.assertIs(fake.active_reporter, self.presentation.HumanMonitorReporter)
        self.assertIs(fake.Reporter, reporter)
        self.assertIs(fake.run_monitor, monitor)

    def test_raw_output_and_other_modes_use_original_reporter(self):
        for mode, flag in (("monitor", ["--raw-output"]), ("plan", []),
                           ("apply", []), ("verify", []), ("complete", [])):
            with self.subTest(mode=mode):
                fake, reporter, _ = self.fake_cli(return_code=1)
                argv = [mode, "--record", "example.json", *flag]
                self.assertEqual(self.presentation._launch(fake, argv), 1)
                self.assertIs(fake.active_reporter, reporter)
                self.assertEqual(fake.seen, [[mode, "--record", "example.json"]])

    def test_failed_native_main_restores_original_handlers(self):
        fake, reporter, monitor = self.fake_cli()

        def fail(argv):
            raise RuntimeError("synthetic native failure")

        fake.main = fail
        with self.assertRaisesRegex(RuntimeError, "synthetic native failure"):
            self.presentation._launch(fake, ["monitor", "--all-accounts"])
        self.assertIs(fake.Reporter, reporter)
        self.assertIs(fake.run_monitor, monitor)

    def test_application_modules_and_recorded_source_identity_are_unchanged(self):
        package = os.environ.get("RAMSHIFT_PACKAGE")
        if not package:
            self.skipTest("set RAMSHIFT_PACKAGE to a built .pyz to check its modules")
        identity = tool_identity()
        with zipfile.ZipFile(package) as bundle:
            self.assertEqual(bundle.read("BUILD_ID").decode().strip(), identity["sources_digest"])
            for name, checksum in identity["sources_sha256"].items():
                with self.subTest(name=name):
                    self.assertEqual(hashlib.sha256(bundle.read(f"lib/{name}")).hexdigest(),
                                     checksum)


if __name__ == "__main__":
    unittest.main()
