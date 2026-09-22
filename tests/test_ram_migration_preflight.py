"""Organization-policy preflight (ram_migration_preflight) against Stubber-backed
AWS Organizations clients. Offline: every response is stubbed in the order the
preflight reads, each Stubber must be fully consumed, and only read-only
organizations clients in us-east-1 may be requested. These are not live evidence
of any organization's policies."""
from __future__ import annotations

import json
import urllib.request

import boto3
import botocore.session
import pytest
from botocore.stub import Stubber

import ram_migration_preflight as preflight
from ram_migration_common import Api, Group, MigrationError

REGION, OTHER_REGION, HOME = "eu-west-1", "us-west-2", "us-east-1"
CORE, MNA = "o-core000001", "o-mna0000001"
CORE_ROOT, MNA_ROOT = "r-core", "r-mna0"
WORK_OU, CNPF_OU, APPS_OU = "ou-core-work0001", "ou-core-cnpf0001", "ou-mna0-apps0001"
CORE_MANAGER, MNA_MANAGER = "111111111111", "222222222222"
OWNER, CONSUMER, OUTSIDER = "333333333333", "444444444444", "555555555555"
SCP, RCP = preflight.SCP, preflight.RCP
FULL, RCP_FULL = "p-FullAWSAccess", "p-RCPFullAWSAccess"
WORK_DESTINATION = f"arn:aws:organizations::{CORE_MANAGER}:ou/{CORE}/{WORK_OU}"
SHARE = f"arn:aws:ram:{REGION}:{OWNER}:resource-share/original"
RAM = "ram.amazonaws.com"

BLOCK_EXTERNAL_CREATE = {
    "Sid": "BlockExternalRAMCreate", "Effect": "Deny",
    "Action": ["ram:CreateResourceShare", "ram:UpdateResourceShare"], "Resource": "*",
    "Condition": {"Bool": {"ram:RequestedAllowsExternalPrincipals": "true"}}}
BLOCK_EXTERNAL_ACCEPT = {
    "Sid": "BlockExternalRAMAccept", "Effect": "Deny",
    "Action": "ram:AcceptResourceShareInvitation", "Resource": "*",
    "Condition": {"StringNotEquals": {"aws:ResourceOrgID": [CORE, MNA]}}}
RESOLVER_READS = ["route53resolver:GetResolverEndpoint",
                  "route53resolver:ListResolverEndpointIpAddresses",
                  "route53resolver:ListResolverRuleAssociations",
                  "route53resolver:ListResolverRules"]


def _forbidden(*_args, **_kwargs):
    raise AssertionError("preflight tests must not use credentials or the network")


@pytest.fixture(autouse=True)
def offline(monkeypatch, tmp_path):
    monkeypatch.setenv("AWS_CONFIG_FILE", str(tmp_path / "config"))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(tmp_path / "credentials"))
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID",
                 "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setattr(urllib.request, "urlopen", _forbidden)
    monkeypatch.setattr(boto3, "Session", _forbidden)


class Router:
    """One Stubber-backed organizations client per mapped account. An account
    without a client is unmapped, as the CLI Router reports it."""
    def __init__(self):
        self.session = botocore.session.Session()
        self.clients: dict[str, object] = {}
        self.stubs: dict[str, Stubber] = {}
        self.requests: list[tuple] = []

    def stub(self, account: str) -> Stubber:
        if account not in self.stubs:
            client = self.session.create_client(
                "organizations", region_name=HOME, aws_access_key_id="testing",
                aws_secret_access_key="testing")
            self.clients[account], self.stubs[account] = client, Stubber(client)
            self.stubs[account].activate()
        return self.stubs[account]

    def client(self, account, service, region, write=False):
        self.requests.append((account, service, region, write))
        assert (service, region, write) == ("organizations", HOME, False)
        if account not in self.clients:
            raise MigrationError(f"{account}: supply an account/profile or role mapping; "
                                 "explicit-source: no access to this account")
        return Api(self.clients[account])  # the read-only boundary the CLI uses

    def done(self):
        for stub in self.stubs.values():
            stub.assert_no_pending_responses()


def document(*statements) -> dict:
    return {"Version": "2012-10-17", "Statement": list(statements)}


ALLOW_ALL = {"Effect": "Allow", "Action": "*", "Resource": "*"}
RCP_ALLOW_ALL = {"Effect": "Allow", "Principal": "*", "Action": "*", "Resource": "*"}


class Organization:
    """One stubbed organization, read through its management account's client in
    the order the preflight reads: FullAWSAccess is attached everywhere unless a
    target says otherwise, and RCPFullAWSAccess too once RCPs are enabled."""
    def __init__(self, router: Router, manager: str, identifier: str, root: str, *,
                 feature_set: str = "ALL", rcps: bool = False, services=(RAM,)):
        self.router, self.manager, self.id, self.root = router, manager, identifier, root
        self.feature_set, self.rcps, self.services = feature_set, rcps, list(services)
        self.parents: dict[str, str] = {}
        self.attachments: dict[tuple[str, str], list[str]] = {}
        self.documents = {FULL: ("FullAWSAccess", json.dumps(document(ALLOW_ALL)), True),
                          RCP_FULL: ("RCPFullAWSAccess", json.dumps(document(RCP_ALLOW_ALL)), True)}
        self.read: set[tuple] = set()
        self.stub = router.stub(manager)

    def place(self, child: str, parent: str) -> "Organization":
        self.parents[child] = parent
        return self

    def attach(self, target: str, kind: str, *policies: str) -> "Organization":
        self.attachments[target, kind] = list(policies)
        return self

    def define(self, policy: str, name: str, *statements, raw: str | None = None) -> "Organization":
        self.documents[policy] = (name, raw if raw is not None else json.dumps(document(*statements)),
                                  False)
        return self

    def described(self) -> dict:
        return {"Organization": {"Id": self.id, "FeatureSet": self.feature_set,
                                 "MasterAccountId": self.manager,
                                 "Arn": f"arn:aws:organizations::{self.manager}:organization/{self.id}"}}

    def path(self, start: str) -> list[str]:
        chain = [start]
        while chain[-1] != self.root:
            chain.append(self.parents.get(chain[-1], self.root))
        return chain[::-1]

    def attached(self, target: str, kind: str) -> list[str]:
        if (target, kind) in self.attachments:
            return self.attachments[target, kind]
        return [FULL] if kind == SCP else [RCP_FULL] if self.rcps else []

    # Expected reads ----------------------------------------------------------
    def expect_member(self, account: str) -> None:
        self.router.stub(account).add_response("describe_organization", self.described(), {})

    def expect_organization(self) -> None:
        if ("organization",) not in self.read:
            self.read.add(("organization",))
            self.stub.add_response("describe_organization", self.described(), {})

    def expect_walk(self, start: str) -> None:
        chain = self.path(start)[::-1]
        for child, parent in zip(chain, chain[1:]):
            if ("parent", child) not in self.read:
                self.read.add(("parent", child))
                kind = "ROOT" if parent == self.root else "ORGANIZATIONAL_UNIT"
                self.stub.add_response("list_parents", {"Parents": [{"Id": parent, "Type": kind}]},
                                       {"ChildId": child})

    def expect_policies(self, path: list[str]) -> None:
        if self.feature_set != "ALL":
            return
        for kind in (SCP, RCP):
            for target in path:
                if ("attached", target, kind) in self.read:
                    continue
                self.read.add(("attached", target, kind))
                identifiers = self.attached(target, kind)
                self.stub.add_response("list_policies_for_target", {"Policies": [
                    {"Id": i, "Name": self.documents[i][0], "Type": kind,
                     "AwsManaged": self.documents[i][2]} for i in identifiers]},
                    {"TargetId": target, "Filter": kind})
                for identifier in identifiers:
                    if ("document", identifier) not in self.read:
                        self.read.add(("document", identifier))
                        name, content, managed = self.documents[identifier]
                        self.stub.add_response("describe_policy", {"Policy": {
                            "PolicySummary": {"Id": identifier, "Name": name, "Type": kind,
                                              "AwsManaged": managed},
                            "Content": content}}, {"PolicyId": identifier})

    def expect_account(self, account: str) -> None:
        self.expect_member(account)
        if account == self.manager:
            return
        self.expect_organization()
        self.expect_walk(account)
        self.expect_policies(self.path(account))

    def expect_destination(self, target: str) -> None:
        self.expect_organization()
        if target != self.root:
            self.expect_walk(target)
        self.expect_policies(self.path(target))

    def expect_prerequisites(self) -> None:
        self.expect_organization()
        self.stub.add_response("list_aws_service_access_for_organization", {
            "EnabledServicePrincipals": [{"ServicePrincipal": s} for s in self.services]}, {})


def standalone(router: Router, account: str) -> None:
    router.stub(account).add_client_error(
        "describe_organization", "AWSOrganizationsNotInUseException",
        "Your account is not a member of an organization.", expected_params={})


def share(owner=OWNER, consumers=(CONSUMER,), region=REGION) -> Group:
    return Group(owner, region, tuple(consumers), {"ec2:IpamPool": "arn:aws:ram::aws:permission/x"},
                 {f"arn:aws:ec2:{region}:{owner}:ipam-pool/ipam-pool-1": "ec2:IpamPool"},
                 [f"arn:aws:ram:{region}:{owner}:resource-share/original"])


def run(router: Router, groups, migrating=(CONSUMER,), **kwargs) -> tuple[dict, list[str]]:
    lines: list[str] = []
    result = preflight.organization_preflight(router, groups, migrating, emit=lines.append, **kwargs)
    router.done()
    assert not any(write for *_rest, write in router.requests)
    json.dumps(result)  # recorded as is in the migration record
    return result, lines


def rows(result: dict, **match) -> list[dict]:
    return [row for row in result["findings"] if all(row.get(k) == v for k, v in match.items())]


# ---------------------------------------------------------------------------
# case 051: the Core SCP BlockExternalRAMCreate
# ---------------------------------------------------------------------------

def test_block_external_ram_create_blocks_an_owner_in_core_naming_policy_statement_and_action():
    router = Router()
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT)
    core.define("p-coreguard1", "Core guardrails", BLOCK_EXTERNAL_CREATE, BLOCK_EXTERNAL_ACCEPT)
    core.attach(CORE_ROOT, SCP, FULL, "p-coreguard1")
    mna = Organization(router, MNA_MANAGER, MNA, MNA_ROOT)
    core.expect_account(OWNER)
    mna.expect_account(CONSUMER)
    result, lines = run(router, [share()])
    assert result["status"] == "BLOCKED"
    blocker, = result["blockers"]
    assert blocker == (
        f"phase=org-policy status=BLOCKED decision=EXPLICIT_DENY account={OWNER} role=owner "
        f"organization={CORE} regions={REGION} actions=ram:CreateResourceShare policy_type=SCP "
        f"target={CORE_ROOT} policy=p-coreguard1 policy_name=\"Core guardrails\" "
        "sid=BlockExternalRAMCreate statement=1: this Deny statement applies to these requests; "
        "the tool never edits organization policies and an administrator role does not "
        "override them")
    # The key is absent from TagResource and every other request, and the consumer is
    # in M&A, whose policies allow everything; an acceptance is not a creation.
    finding, = result["findings"]
    assert finding["statement_text"] == json.dumps(BLOCK_EXTERNAL_CREATE, sort_keys=True,
                                                   separators=(",", ":"))
    assert f"phase=org-policy status=REVIEW policy=p-coreguard1 statement=1 text=" \
           f"{finding['statement_text']}" in lines
    owner, consumer = result["accounts"]
    assert (owner["account"], owner["roles"], owner["path"]) == (OWNER, ["owner"], [CORE_ROOT, OWNER])
    assert owner["attachments"][CORE_ROOT] == {SCP: [FULL, "p-coreguard1"], RCP: []}
    assert (owner["service_control_policies"], owner["resource_control_policies"]) == (
        "ENABLED", "NOT_ENABLED")
    assert (consumer["account"], consumer["organization"]) == (CONSUMER, MNA)
    guard = result["organizations"][CORE]["policies"]["p-coreguard1"]
    assert guard["name"] == "Core guardrails" and len(guard["sha256"]) == 64
    assert result["organizations"][MNA]["management_account"] == MNA_MANAGER
    assert lines[-1] == ("phase=org-policy status=BLOCKED accounts=2 denies=1 gaps=0 unreadable=0 "
                         "prerequisites_not_met=0")
    assert {request[0] for request in router.requests} == {OWNER, CONSUMER, CORE_MANAGER, MNA_MANAGER}


def test_acceptance_exception_for_mna_resource_orgs_is_decided_per_share_owner():
    """A Core consumer may accept shares from M&A owners; from an owner outside any
    organization, the request has no aws:ResourceOrgID and StringNotEquals denies it."""
    router = Router()
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT)
    core.define("p-coreguard1", "Core guardrails", BLOCK_EXTERNAL_CREATE, BLOCK_EXTERNAL_ACCEPT)
    core.attach(CORE_ROOT, SCP, FULL, "p-coreguard1")
    mna = Organization(router, MNA_MANAGER, MNA, MNA_ROOT)
    mna.expect_account(OWNER)
    core.expect_account(CONSUMER)
    standalone(router, OUTSIDER)
    result, lines = run(router, [share(), share(owner=OUTSIDER)])
    finding, = result["findings"]
    assert (finding["decision"], finding["account"], finding["role"], finding["share_owner"],
            finding["sid"], finding["actions"]) == (
        "EXPLICIT_DENY", CONSUMER, "consumer", OUTSIDER, "BlockExternalRAMAccept",
        ["ram:AcceptResourceShareInvitation"])
    assert f"share_owner={OUTSIDER} regions={REGION} " in result["blockers"][0]
    assert f"phase=org-policy status=NOTE account={OUTSIDER} is in no organization: no SCPs or " \
           "RCPs apply" in lines


# ---------------------------------------------------------------------------
# case 053: the destination path
# ---------------------------------------------------------------------------

def test_work_ou_allow_list_omitting_a_namespace_denies_the_destination_reads():
    router = Router()
    mna = Organization(router, MNA_MANAGER, MNA, MNA_ROOT)
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT)
    core.place(WORK_OU, CORE_ROOT).attach(WORK_OU, SCP, "p-example0005")
    core.define("p-example0005", "large_estate-work-deny-policy", {
        "Sid": "AllowListedServices", "Effect": "Allow", "Resource": "*",
        "Action": ["ec2:*", "ram:*", "kms:*", "ecr:*", "acm-pca:*", "organizations:Describe*"]})
    mna.expect_account(OWNER)
    mna.expect_account(CONSUMER)
    core.expect_destination(WORK_OU)
    result, lines = run(router, [share()], destination=WORK_DESTINATION)
    blocker, = result["blockers"]
    assert blocker.startswith(
        f"phase=org-policy status=BLOCKED decision=NO_ALLOW account={CONSUMER} role=destination "
        f"organization={CORE} regions={REGION} actions={','.join(RESOLVER_READS)} "
        f"policy_type=SCP target={WORK_OU} "
        "policies=p-example0005(\"large_estate-work-deny-policy\"): no statement in the SCPs "
        "attached at this target allows these actions")
    destination = result["destination"]
    assert destination["path"] == [CORE_ROOT, WORK_OU] and destination["accounts"] == [CONSUMER]
    assert destination["attachments"][WORK_OU] == {SCP: ["p-example0005"], RCP: []}
    assert result["destination_ou"] == WORK_DESTINATION
    assert f"phase=org-policy destination={WORK_DESTINATION} status=EVALUATED " \
           f"path={CORE_ROOT}/{WORK_OU} scp=ENABLED rcp=NOT_ENABLED accounts=1" in lines
    assert any("policies attached directly to each account after it joins" in n
               for n in result["notes"])
    # The owner stays in M&A: only migrating accounts are evaluated on the destination path.
    assert not rows(result, account=OWNER)


def test_path_dependent_root_denies_are_decided_by_region_and_left_open_by_org_path():
    router = Router()
    mna = Organization(router, MNA_MANAGER, MNA, MNA_ROOT)
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT)
    core.place(WORK_OU, CORE_ROOT).attach(CORE_ROOT, SCP, FULL, "p-rootdeny01")
    core.define("p-rootdeny01", "root guardrails", {
        "Sid": "DenyOutsideApprovedRegions", "Effect": "Deny", "Resource": "*",
        "NotAction": ["organizations:*", "iam:*", "sts:*"],
        "Condition": {"StringNotEquals": {"aws:RequestedRegion": [HOME, REGION]}},
    }, {
        "Sid": "DenyNetworkOutsideCnpf", "Effect": "Deny", "Resource": "*",
        "Action": ["ec2:*", "route53resolver:*"],
        "Condition": {"ForAnyValue:StringNotLike": {
            "aws:PrincipalOrgPaths": [f"{CORE}/{CORE_ROOT}/{CNPF_OU}/*"]}},
    }, {"Sid": "DenyLogDeletion", "Effect": "Deny", "Action": "logs:DeleteLogGroup",
        "Resource": "*"})
    mna.expect_account(OWNER)
    mna.expect_account(CONSUMER)
    core.expect_destination(WORK_OU)
    result, _ = run(router, [share(), share(region=OTHER_REGION)], destination=WORK_DESTINATION)
    regional, = rows(result, sid="DenyOutsideApprovedRegions")
    assert (regional["decision"], regional["regions"]) == ("EXPLICIT_DENY", [OTHER_REGION])
    assert "organizations:DescribeOrganization" not in regional["actions"]
    assert "ec2:DescribeRegions" not in regional["actions"]  # read in us-east-1
    assert {"ram:GetResourceShares", "acm-pca:GetCertificateAuthorityCertificate",
            *RESOLVER_READS} <= set(regional["actions"])
    network, = rows(result, sid="DenyNetworkOutsideCnpf")
    assert network["decision"] == "UNDECIDED"
    assert network["regions"] == sorted([REGION, HOME, OTHER_REGION])  # DescribeRegions: us-east-1
    assert network["reasons"] == ["condition key aws:PrincipalOrgPaths is not evaluated"]
    assert all(action.split(":")[0] in ("ec2", "route53resolver") for action in network["actions"])
    assert not rows(result, sid="DenyLogDeletion")
    gap = next(b for b in result["blockers"] if "sid=DenyNetworkOutsideCnpf" in b)
    assert gap.startswith("phase=org-policy status=GAP decision=UNDECIDED ")
    assert "listed for human review, and the run stays blocked while it is undecided" in gap


def test_destination_prerequisites_and_policies_are_read_through_the_destination_manager():
    """case 054: an original OU share relies on RAM sharing with AWS Organizations: its
    own organization meets the prerequisites, the destination has no RAM trusted access."""
    router = Router()
    mna = Organization(router, MNA_MANAGER, MNA, MNA_ROOT)
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT, services=["sso.amazonaws.com"])
    core.place(WORK_OU, CORE_ROOT)
    mna.expect_account(OWNER)
    mna.expect_account(CONSUMER)
    core.expect_destination(WORK_OU)
    core.expect_prerequisites()
    mna.expect_prerequisites()
    organization_principal = f"arn:aws:organizations::{MNA_MANAGER}:ou/{MNA}/{APPS_OU}"
    result, lines = run(router, [share()], destination=WORK_DESTINATION,
                        organization_shares={SHARE: [organization_principal]})
    assert result["blockers"] == [] and result["status"] == "ALLOWED"
    warning, = result["warnings"]
    assert warning == (
        f"phase=ram-org-prerequisites status=WARNING organization={CORE} "
        f"management_account={CORE_MANAGER} decision=NOT_MET prerequisite=ram-trusted-access "
        "shares=1: ram.amazonaws.com trusted access, which RAM's sharing with AWS Organizations "
        "enables, is not enabled; the temporary shares do not need it, so this never blocks; "
        "this tool never enables it")
    assert warning in lines
    destination, source = result["ram_organization_prerequisites"]
    assert (destination["organization"], destination["scope"], destination["status"]) == (
        CORE, ["destination"], "NOT_MET")
    assert (destination["all_features"], destination["ram_trusted_access"]) == (True, False)
    assert (source["organization"], source["scope"], source["status"]) == (MNA, ["source"], "MET")
    assert source["required_by"] == [SHARE]
    assert f"phase=ram-org-prerequisites organization={MNA} status=MET all_features=true " \
           "ram_trusted_access=true shares=1" in lines
    assert ("the RAM service-linked role is not read; IAM is read only to verify the "
            "authenticated caller's role ARN") in result["notes"]


def test_a_consolidated_billing_destination_has_no_policies_and_fails_all_features():
    router = Router()
    mna = Organization(router, MNA_MANAGER, MNA, MNA_ROOT)
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT, feature_set="CONSOLIDATED_BILLING",
                        services=[])
    core.place(WORK_OU, CORE_ROOT)
    mna.expect_account(OWNER)
    mna.expect_account(CONSUMER)
    core.expect_destination(WORK_OU)   # no policy listing: no policy type can be enabled
    core.expect_prerequisites()
    mna.expect_prerequisites()
    result, _ = run(router, [share()], destination=WORK_DESTINATION, organization_shares={
        SHARE: [f"arn:aws:organizations::{MNA_MANAGER}:organization/{MNA}"]})
    assert result["destination"]["service_control_policies"] == "NOT_ENABLED"
    assert result["blockers"] == []
    all_features, trusted = result["warnings"]
    assert "prerequisite=all-features feature_set=CONSOLIDATED_BILLING shares=1" in all_features
    assert "prerequisite=ram-trusted-access" in trusted


def test_no_prerequisites_are_read_when_no_original_share_uses_ou_or_org_principals():
    router = Router()
    mna = Organization(router, MNA_MANAGER, MNA, MNA_ROOT)
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT, services=[])
    core.place(WORK_OU, CORE_ROOT)
    mna.expect_account(OWNER)
    mna.expect_account(CONSUMER)
    core.expect_destination(WORK_OU)
    result, _ = run(router, [share()], destination=WORK_DESTINATION, organization_shares={})
    assert result["status"] == "ALLOWED" and result["ram_organization_prerequisites"] == []


def test_an_unmapped_destination_manager_is_a_named_blocker():
    router = Router()
    mna = Organization(router, MNA_MANAGER, MNA, MNA_ROOT)
    mna.expect_account(OWNER)
    mna.expect_account(CONSUMER)
    result, _ = run(router, [share()], destination=WORK_DESTINATION)
    blocker, = result["blockers"]
    assert blocker.startswith(
        f"phase=org-policy status=BLOCKED decision=UNREADABLE destination={WORK_DESTINATION} "
        f"organization={CORE} management_account={CORE_MANAGER}: {CORE_MANAGER}: supply an "
        "account/profile or role mapping")
    assert blocker.endswith("could not be read, and unread policies never pass")
    assert result["destination"]["status"] == "UNREADABLE"


@pytest.mark.parametrize("arn", [
    "ou-core-work0001",
    f"arn:aws:organizations::{CORE_MANAGER}:account/{CORE}/{CONSUMER}",
    f"arn:aws:organizations::12345:ou/{CORE}/{WORK_OU}",
    f"arn:aws:organizations::{CORE_MANAGER}:ou/{CORE}/{WORK_OU}/extra",
    f"arn:aws:iam::{CORE_MANAGER}:ou/{CORE}/{WORK_OU}",
])
def test_destination_must_be_an_ou_or_root_arn(arn):
    with pytest.raises(MigrationError, match="--destination-ou must be an OU or root ARN"):
        preflight.destination_target(arn)


def test_destination_root_arn_names_its_management_account_and_organization():
    target = preflight.destination_target(
        f"arn:aws:organizations::{CORE_MANAGER}:root/{CORE}/{CORE_ROOT}")
    assert (target["manager"], target["organization"], target["target"]) == (
        CORE_MANAGER, CORE, CORE_ROOT)


# ---------------------------------------------------------------------------
# RCPs
# ---------------------------------------------------------------------------

def test_owner_rcps_govern_the_consumers_acceptance_of_the_owners_invitation():
    router = Router()
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT, rcps=True)
    core.attach(CORE_ROOT, RCP, RCP_FULL, "p-perimeter1")
    core.define("p-perimeter1", "data perimeter", {
        "Sid": "DenyAcceptanceOutsideCore", "Effect": "Deny", "Principal": "*",
        "Action": "ram:AcceptResourceShareInvitation", "Resource": "*",
        "Condition": {"StringNotEqualsIfExists": {"aws:PrincipalOrgID": CORE}},
    }, {
        "Sid": "EnforcePerimeter", "Effect": "Deny", "Principal": "*", "Action": "*",
        "Resource": "*",
        "Condition": {"StringNotEqualsIfExists": {"aws:PrincipalOrgID": CORE},
                      "BoolIfExists": {"aws:PrincipalIsAWSService": "false"}},
    })
    mna = Organization(router, MNA_MANAGER, MNA, MNA_ROOT)
    core.expect_account(OWNER)
    mna.expect_account(CONSUMER)
    result, _ = run(router, [share()])
    denied, = rows(result, decision="EXPLICIT_DENY")
    assert (denied["account"], denied["role"], denied["share_owner"], denied["policy_type"],
            denied["target"], denied["policy"], denied["sid"], denied["actions"]) == (
        CONSUMER, "consumer", OWNER, RCP, CORE_ROOT, "p-perimeter1", "DenyAcceptanceOutsideCore",
        ["ram:AcceptResourceShareInvitation"])
    gap, = rows(result, decision="UNDECIDED")
    assert (gap["sid"], gap["share_owner"], gap["reasons"]) == (
        "EnforcePerimeter", OWNER, ["condition key aws:PrincipalIsAWSService is not evaluated"])
    # The owner's own requests come from inside Core: the perimeter decides them,
    # whatever aws:PrincipalIsAWSService holds.
    assert not rows(result, account=OWNER)
    owner, consumer = result["accounts"]
    assert owner["resource_control_policies"] == "ENABLED"
    assert consumer["resource_control_policies"] == "NOT_ENABLED"
    assert "policy_type=RCP target=r-core policy=p-perimeter1" in result["blockers"][0]


def test_a_target_without_rcps_on_an_rcp_path_is_a_gap():
    router = Router()
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT, rcps=True)
    core.attach(OWNER, RCP)  # nothing attached to the account itself
    mna = Organization(router, MNA_MANAGER, MNA, MNA_ROOT)
    core.expect_account(OWNER)
    mna.expect_account(CONSUMER)
    result, _ = run(router, [share()])
    blocker, = result["blockers"]
    assert blocker.startswith(f"phase=org-policy status=GAP decision=UNDECIDED account={OWNER} "
                              f"role=owner organization={CORE} policy_type=RCP "
                              f"targets_without_policies={OWNER}: ")
    assert result["accounts"][0]["resource_control_policies"] == "INCOMPLETE"


# ---------------------------------------------------------------------------
# Conditions, resources and statements it can and cannot decide
# ---------------------------------------------------------------------------

CREATE = {"aws:requestedregion": REGION, "aws:principalaccount": OWNER,
          "aws:principalorgid": CORE, "ram:requestedallowsexternalprincipals": True}
TAG = dict(CREATE, **{"ram:requestedallowsexternalprincipals": preflight.ABSENT})
ACCEPT = {"aws:requestedregion": REGION, "aws:principalaccount": CONSUMER,
          "aws:principalorgid": MNA, "ram:requestedallowsexternalprincipals": preflight.ABSENT,
          "aws:resourceaccount": OWNER, "aws:resourceorgid": preflight.ABSENT}


def deny(condition=None, **elements):
    statement = {"Effect": "Deny", "Action": "ram:*", "Resource": "*", **elements}
    if condition is not None:
        statement["Condition"] = condition
    return statement


@pytest.mark.parametrize("statement,action,context,expected", [
    (deny({"Bool": {"ram:RequestedAllowsExternalPrincipals": "true"}}),
     "ram:CreateResourceShare", CREATE, True),
    (deny({"Bool": {"ram:RequestedAllowsExternalPrincipals": True}}), "ram:TagResource", TAG, False),
    (deny({"BoolIfExists": {"ram:RequestedAllowsExternalPrincipals": "false"}}),
     "ram:TagResource", TAG, True),
    (deny({"StringNotEquals": {"aws:PrincipalOrgID": [CORE, MNA]}}),
     "ram:CreateResourceShare", CREATE, False),
    (deny({"StringNotEquals": {"aws:PrincipalOrgID": MNA}}), "ram:CreateResourceShare", CREATE, True),
    (deny({"StringEqualsIgnoreCase": {"aws:PrincipalOrgID": CORE.upper()}}),
     "ram:CreateResourceShare", CREATE, True),
    (deny({"StringNotEquals": {"aws:ResourceOrgID": CORE}}),
     "ram:AcceptResourceShareInvitation", ACCEPT, True),          # absent: negated holds
    (deny({"StringEquals": {"aws:ResourceOrgID": CORE}}),
     "ram:AcceptResourceShareInvitation", ACCEPT, False),         # absent: positive fails
    (deny({"Null": {"aws:ResourceOrgID": "true"}}), "ram:AcceptResourceShareInvitation", ACCEPT, True),
    (deny({"ForAnyValue:StringEquals": {"aws:ResourceOrgID": CORE}}),
     "ram:AcceptResourceShareInvitation", ACCEPT, False),
    (deny({"ForAllValues:StringNotLike": {"aws:ResourceOrgID": "o-*"}}),
     "ram:AcceptResourceShareInvitation", ACCEPT, True),
    (deny({"StringLike": {"aws:RequestedRegion": "eu-*"}}), "ram:CreateResourceShare", CREATE, True),
    (deny({"StringNotLike": {"aws:RequestedRegion": ["eu-*", "us-east-1"]}}),
     "ram:CreateResourceShare", CREATE, False),
    (deny({"StringEquals": {"aws:PrincipalAccount": OWNER}}), "ram:CreateResourceShare", CREATE, True),
    (deny(NotAction="ram:*", Action=None), "ram:CreateResourceShare", CREATE, False),
    (deny(Resource="arn:aws:s3:::bucket/*"), "ram:CreateResourceShare", CREATE, False),
    (deny(Resource=["arn:aws:s3:::bucket/*", "*"]), "ram:CreateResourceShare", CREATE, True),
    (deny(Resource=None, NotResource="arn:aws:s3:::bucket/*"), "ram:CreateResourceShare", CREATE, True),
    (deny(Resource=None, NotResource="*"), "ram:CreateResourceShare", CREATE, False),
    (deny(Principal="*"), "ram:CreateResourceShare", CREATE, True),
    (deny(Action="cloudformation:*"), "ram:CreateResourceShare", CREATE, False),
    ({"Effect": "Deny", "NotAction": ["ram:Get*", "ram:List*"], "Resource": "*"},
     "ram:CreateResourceShare", CREATE, True),
    ({"Effect": "Deny", "NotAction": ["ram:Get*", "ram:List*"], "Resource": "*"},
     "ram:GetResourceShares", CREATE, False),
    ({"Effect": "Deny", "Action": "RAM:create*", "Resource": "*"},
     "ram:CreateResourceShare", CREATE, True),                     # actions match any case
    # An undecidable clause beside a false one is decided: the statement does not apply.
    (deny({"Bool": {"ram:RequestedAllowsExternalPrincipals": "true"},
           "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/Migration"}}),
     "ram:TagResource", TAG, False),
])
def test_statements_it_can_decide(statement, action, context, expected):
    statement = {k: v for k, v in statement.items() if v is not None}
    value, reasons = preflight.statement_applies(statement, action, context)
    assert value is expected
    assert (reasons == []) == (expected is not None)


@pytest.mark.parametrize("statement,context,reason", [
    (deny({"ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/Migration"}}), CREATE,
     "condition key aws:PrincipalArn has no known value for this request"),
    (deny({"StringNotEquals": {"aws:PrincipalAccount": "${aws:ResourceAccount}"}}), CREATE,
     "condition values of aws:PrincipalAccount use a policy variable"),
    (deny({"ArnLike": {"aws:PrincipalOrgID": "o-*"}}), CREATE,
     "condition operator ArnLike is not evaluated for aws:PrincipalOrgID"),
    (deny({"StringEquals": {"ram:RequestedAllowsExternalPrincipals": "true"}}), CREATE,
     "condition operator StringEquals is not evaluated for ram:RequestedAllowsExternalPrincipals"),
    (deny({"NumericLessThan": {"aws:MultiFactorAuthAge": 3600}}), CREATE,
     "condition key aws:MultiFactorAuthAge is not evaluated"),
    (deny({"DateGreaterThan": {"aws:RequestedRegion": "2026-01-01T00:00:00Z"}}), CREATE,
     "condition operator DateGreaterThan is not evaluated"),
    (deny({"StringEquals": {"aws:CalledVia": "cloudformation.amazonaws.com"}}), CREATE,
     "condition key aws:CalledVia is not evaluated"),
    (deny({"StringEquals": {"aws:ResourceOrgID": CORE}}), CREATE,
     "condition key aws:ResourceOrgID has no known value for this request"),
    (deny(Resource="arn:aws:ram:*:*:resource-share/*"), CREATE,
     "Resource arn:aws:ram:*:*:resource-share/* is not resolved for ram:CreateResourceShare"),
    (deny(Resource=None, NotResource="arn:*:ram:*:*:resource-share/*"), CREATE,
     "NotResource arn:*:ram:*:*:resource-share/* is not resolved for ram:CreateResourceShare"),
    (deny(NotPrincipal={"AWS": "arn:aws:iam::111111111111:root"}), CREATE,
     "NotPrincipal is not evaluated"),
    (deny(Resource=None), CREATE, "the statement has no Resource element"),
    (deny(Unexpected=True), CREATE, "element Unexpected is not evaluated"),
])
def test_statements_it_cannot_decide_are_gaps_with_their_reason(statement, context, reason):
    statement = {k: v for k, v in statement.items() if v is not None}
    value, reasons = preflight.statement_applies(statement, "ram:CreateResourceShare", context)
    assert value is None and reasons == [reason]


def test_a_principal_exception_the_evaluator_cannot_resolve_blocks_as_a_reviewed_gap():
    """BlockExternalRAMCreate with an exception for a migration role: whether the
    caller is that role is not evaluated, so creation is a gap, never a pass."""
    router = Router()
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT)
    exempt = dict(BLOCK_EXTERNAL_CREATE, Condition={
        **BLOCK_EXTERNAL_CREATE["Condition"],
        "ArnNotLike": {"aws:PrincipalArn": "arn:aws:iam::*:role/RamMigration"}})
    core.define("p-coreguard1", "Core guardrails", exempt).attach(CORE_ROOT, SCP, FULL, "p-coreguard1")
    mna = Organization(router, MNA_MANAGER, MNA, MNA_ROOT)
    core.expect_account(OWNER)
    mna.expect_account(CONSUMER)
    result, lines = run(router, [share()])
    assert result["status"] == "BLOCKED"
    gap, = result["blockers"]
    assert gap.startswith(f"phase=org-policy status=GAP decision=UNDECIDED account={OWNER} "
                          "role=owner ")
    assert "actions=ram:CreateResourceShare " in gap and "sid=BlockExternalRAMCreate" in gap
    assert "(condition key aws:PrincipalArn has no known value for this request)" in gap
    assert any(line.startswith("phase=org-policy status=REVIEW policy=p-coreguard1 statement=1 ")
               for line in lines)


def test_an_unanalyzable_policy_document_is_a_gap_and_no_allow():
    router = Router()
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT)
    core.define("p-broken001", "broken", raw="{\"Statement\": \"not a list\"}")
    core.attach(OWNER, SCP, "p-broken001")  # the only SCP on the account
    mna = Organization(router, MNA_MANAGER, MNA, MNA_ROOT)
    core.expect_account(OWNER)
    mna.expect_account(CONSUMER)
    result, _ = run(router, [share()])
    document_gap = rows(result, policy="p-broken001")
    allow_gap = [row for row in rows(result, target=OWNER) if "undecided_allows" in row]
    assert document_gap and document_gap[0]["reasons"] == ["the policy document has no Statement"]
    assert allow_gap and allow_gap[0]["undecided_allows"] == [
        "p-broken001 document (the policy document has no Statement)"]
    assert all(b.startswith("phase=org-policy status=GAP ") for b in result["blockers"])


# ---------------------------------------------------------------------------
# Missing read permission is a named blocker, never a silent pass
# ---------------------------------------------------------------------------

def denial(stub: Stubber, operation: str, expected: dict) -> None:
    stub.add_client_error(operation, "AccessDeniedException",
                          "You don't have permissions to access this resource.",
                          expected_params=expected, response_meta={"RequestId": "req-denied"})


@pytest.mark.parametrize("failing", [
    "member", "unmapped-manager", "list-parents", "list-policies", "describe-policy",
])
def test_missing_permission_to_read_policies_is_a_named_blocker(failing):
    router = Router()
    member = router.stub(OWNER)
    described = {"Organization": {"Id": CORE, "FeatureSet": "ALL", "MasterAccountId": CORE_MANAGER}}
    if failing == "member":
        denial(member, "describe_organization", {})
        operation = "operation=DescribeOrganization AccessDeniedException"
    else:
        member.add_response("describe_organization", described, {})
    if failing not in ("member", "unmapped-manager"):
        manager = router.stub(CORE_MANAGER)
        manager.add_response("describe_organization", described, {})
        if failing == "list-parents":
            denial(manager, "list_parents", {"ChildId": OWNER})
            operation = "operation=ListParents AccessDeniedException"
        else:
            manager.add_response("list_parents", {"Parents": [{"Id": CORE_ROOT, "Type": "ROOT"}]},
                                 {"ChildId": OWNER})
        if failing == "list-policies":
            denial(manager, "list_policies_for_target", {"TargetId": CORE_ROOT, "Filter": SCP})
            operation = "operation=ListPoliciesForTarget AccessDeniedException"
        elif failing == "describe-policy":
            manager.add_response("list_policies_for_target", {"Policies": [
                {"Id": FULL, "Name": "FullAWSAccess", "Type": SCP, "AwsManaged": True}]},
                {"TargetId": CORE_ROOT, "Filter": SCP})
            denial(manager, "describe_policy", {"PolicyId": FULL})
            operation = "operation=DescribePolicy AccessDeniedException"
    if failing == "unmapped-manager":
        operation = f"{CORE_MANAGER}: supply an account/profile or role mapping"
    standalone(router, CONSUMER)
    result, lines = run(router, [share()])
    assert result["status"] == "BLOCKED" and result["findings"] == []
    blocker, = result["blockers"]
    expected = f"phase=org-policy status=BLOCKED decision=UNREADABLE account={OWNER} roles=owner"
    if failing != "member":
        expected += f" organization={CORE} management_account={CORE_MANAGER}"
    assert blocker.startswith(expected + ": " + operation)
    if failing != "unmapped-manager":
        assert "(request req-denied)" in blocker
    assert blocker.endswith("the organization policies that govern this account could not be "
                            "read, and unread policies never pass")
    assert result["accounts"][0]["status"] == "UNREADABLE"
    assert "status=ALLOWED" not in "\n".join(lines)


def test_one_unreadable_policy_is_read_once_and_blocks_every_account_it_governs():
    router = Router()
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT)
    core.expect_member(OWNER)
    core.expect_organization()
    core.expect_walk(OWNER)
    core.stub.add_response("list_policies_for_target", {"Policies": [
        {"Id": FULL, "Name": "FullAWSAccess", "Type": SCP, "AwsManaged": True}]},
        {"TargetId": CORE_ROOT, "Filter": SCP})
    denial(core.stub, "describe_policy", {"PolicyId": FULL})
    core.expect_member(CONSUMER)
    core.expect_walk(CONSUMER)       # the root's attachments and its policy are not re-read
    result, _ = run(router, [share()])
    assert [b.split(":")[0] for b in result["blockers"]] == [
        f"phase=org-policy status=BLOCKED decision=UNREADABLE account={OWNER} roles=owner "
        f"organization={CORE} management_account={CORE_MANAGER}",
        f"phase=org-policy status=BLOCKED decision=UNREADABLE account={CONSUMER} roles=consumer "
        f"organization={CORE} management_account={CORE_MANAGER}"]


# ---------------------------------------------------------------------------
# Accounts no policy governs, and drift
# ---------------------------------------------------------------------------

def test_the_management_account_and_standalone_accounts_are_not_governed():
    router = Router()
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT)
    core.expect_account(CORE_MANAGER)   # the owner is the management account
    standalone(router, CONSUMER)
    result, lines = run(router, [share(owner=CORE_MANAGER)])
    assert result["status"] == "ALLOWED" and result["blockers"] == [] and result["findings"] == []
    assert [entry["status"] for entry in result["accounts"]] == ["MANAGEMENT_ACCOUNT", "STANDALONE"]
    assert f"account={CORE_MANAGER} is the management account of {CORE}: SCPs and RCPs do not " \
           "apply to it" in result["notes"]
    assert lines[-1].startswith("phase=org-policy status=ALLOWED accounts=2 denies=0 gaps=0 ")


def test_full_access_everywhere_allows_every_request_and_records_policy_hashes():
    router = Router()
    core = Organization(router, CORE_MANAGER, CORE, CORE_ROOT)
    core.place(OWNER, CNPF_OU).place(CNPF_OU, CORE_ROOT)
    core.expect_account(OWNER)
    core.expect_account(CONSUMER)
    result, lines = run(router, [share()], migrating=[])
    assert result["status"] == "ALLOWED" and result["blockers"] == []
    assert result["accounts"][0]["path"] == [CORE_ROOT, CNPF_OU, OWNER]
    # This fake router serves no STS, so the caller's role ARN stays unknown; no
    # statement here conditions on it.
    assert any(line.startswith(
        f"phase=org-policy account={OWNER} roles=owner status=EVALUATED organization={CORE} "
        f"path={CORE_ROOT}/{CNPF_OU}/{OWNER} scp=ENABLED rcp=NOT_ENABLED principal_arn=UNKNOWN")
        for line in lines)
    policies = result["organizations"][CORE]["policies"]
    assert set(policies) == {FULL} and policies[FULL]["aws_managed"] is True
    assert result["evaluator"]["sha256"] == preflight.EVALUATOR_SHA256
    assert "ram:CreateResourceShare" in result["evaluator"]["owner_actions"]
    assert result["evaluator"]["consumer_actions"] == [
        "ram:AcceptResourceShareInvitation", "ram:GetResourceShareInvitations"]


def test_policy_changes_since_the_reviewed_plan_are_reported():
    before = {"organizations": {CORE: {"policies": {FULL: {"sha256": "a"},
                                                    "p-coreguard1": {"sha256": "b"},
                                                    "p-removed01": {"sha256": "c"}}}}}
    after = {"organizations": {CORE: {"policies": {FULL: {"sha256": "a"},
                                                   "p-coreguard1": {"sha256": "B"},
                                                   "p-added0001": {"sha256": "d"}}}}}
    assert [line.split(" since")[0] for line in preflight.policy_changes(before, after)] == [
        f"phase=org-policy status=POLICY_CHANGED organization={CORE} policy=p-added0001 "
        "change=attached",
        f"phase=org-policy status=POLICY_CHANGED organization={CORE} policy=p-coreguard1 "
        "change=content",
        f"phase=org-policy status=POLICY_CHANGED organization={CORE} policy=p-removed01 "
        "change=detached"]
    assert preflight.policy_changes(None, after) == []
    assert preflight.recorded_destination({"destination_ou": WORK_DESTINATION}) == WORK_DESTINATION
    assert preflight.recorded_destination(None) is None
