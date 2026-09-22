"""Offline RAM/CFN fidelity tests: unsigned clients, strict stubs, no credentials."""
import copy
import json
from contextlib import ExitStack
from pathlib import Path

import botocore.session
import pytest
import yaml
from botocore import UNSIGNED
from botocore.config import Config
from botocore.stub import Stubber

from ram_migration_common import PURPOSE, Api, Group, MigrationError, check_sdk
from ram_migration_discovery import (
    ApprovedGroup, CfnLoader, Discovery, external_catalog, permission_snapshot,
    policy_semantics, resolve,
)
from ram_migration_stacks import (
    Stacks, accept, additive_template, stack_name, template_for, validate_changes,
    verify_group,
)

OWNER, CONSUMER, OTHER, DEPARTED = ("000000000001", "000000000002",
                                    "000000000003", "000000000004")
REGION, MIGRATION = "us-east-1", "offline-canary"
KIND = "route53resolver:ResolverRule"
PERMISSION = "arn:aws:ram::aws:permission/AWSRAMDefaultPermissionRoute53ResolverRule"
SOURCE = f"arn:aws:ram:{REGION}:{OWNER}:resource-share/source"
TEMP = f"arn:aws:ram:{REGION}:{OWNER}:resource-share/temporary"
RESOURCE = f"arn:aws:route53resolver:{REGION}:{OWNER}:resolver-rule/rslvr-rr-offline1"
STACK_ID = f"arn:aws:cloudformation:{REGION}:{OWNER}:stack/offline/identifier"
CHANGE_ID = f"arn:aws:cloudformation:{REGION}:{OWNER}:changeSet/offline/identifier"
POLICY = {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Action": ["route53resolver:GetResolverRule",
                                "route53resolver:AssociateResolverRule"], "Resource": "*"}]}


@pytest.fixture(autouse=True)
def prohibit_authentication_and_network(monkeypatch):
    monkeypatch.setenv("AWS_CONFIG_FILE", "/dev/null")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.delenv("AWS_PROFILE", raising=False)

    def forbidden(*args, **kwargs):
        raise AssertionError("Offline core tests must not load credentials or send requests")

    monkeypatch.setattr("botocore.session.Session.get_credentials", forbidden)
    monkeypatch.setattr("botocore.endpoint.Endpoint._send", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)


@pytest.fixture
def clients():
    with ExitStack() as stack:
        clients, stubs = {}, {}
        session = botocore.session.get_session()
        for name in ("ram", "cloudformation", "organizations"):
            clients[name] = session.create_client(name, region_name=REGION,
                                                  config=Config(signature_version=UNSIGNED))
            stubs[name] = stack.enter_context(Stubber(clients[name]))
        yield clients, stubs
        for stub in stubs.values():
            stub.assert_no_pending_responses()


class OfflineRouter:
    def __init__(self, clients, readonly=False, consumer=None):
        self.clients, self.readonly, self.consumer = clients, readonly, consumer

    def client(self, account, service, region, write=False):
        assert account in (OWNER, CONSUMER, OTHER, DEPARTED)
        assert region == REGION
        client = self.consumer if account != OWNER and service == "ram" else self.clients[service]
        assert client is not None
        return Api(client, write and not self.readonly)


def permission(version="2", policy=None, default=True, arn=PERMISSION, kind=KIND):
    return {"arn": arn, "version": version, "defaultVersion": default,
            "resourceType": kind, "permission": json.dumps(policy or POLICY),
            "status": "ATTACHABLE", "featureSet": "STANDARD", "permissionType": "AWS_MANAGED"}


def snapshot():
    return {"Arn": PERMISSION, "Version": "2", "ResourceType": KIND,
            "Policy": policy_semantics(POLICY), "DefaultVersion": True}


def group(resources=None, consumers=(CONSUMER,), sources=None, approved=False):
    args = (OWNER, REGION, consumers, {KIND: PERMISSION},
            resources or {RESOURCE: KIND}, sources or [SOURCE])
    if approved:
        return ApprovedGroup(*args, {KIND: snapshot()}, [STACK_ID])
    return Group(*args)


def resource(arn=RESOURCE, kind=KIND):
    return {"arn": arn, "type": kind, "status": "AVAILABLE"}


def migration_share(g=None):
    g = g or group()
    props = template_for([g], MIGRATION)["Resources"][g.logical_id]["Properties"]
    return {"resourceShareArn": TEMP, "owningAccountId": OWNER,
            "name": props["Name"], "status": "ACTIVE", "allowExternalPrincipals": True,
            "resourceShareConfiguration": {"retainSharingOnAccountLeaveOrganization": True},
            "tags": [{"key": tag["Key"], "value": tag["Value"]} for tag in props["Tags"]]}


def association(entity, kind, status="ASSOCIATED", share=TEMP):
    return {"resourceShareArn": share, "associatedEntity": entity,
            "associationType": kind, "status": status}


def stack_info(state="CREATE_COMPLETE"):
    return {"StackId": STACK_ID, "StackName": stack_name(MIGRATION, OWNER, REGION),
            "CreationTime": "2026-10-13T00:00:00Z", "StackStatus": state,
            "Tags": [{"Key": "Purpose", "Value": PURPOSE},
                     {"Key": "MigrationId", "Value": MIGRATION},
                     {"Key": "OwnerAccount", "Value": OWNER}]}


def no_stack(stub, physical=False, arn=SOURCE):
    kwargs = {"PhysicalResourceId": arn} if physical else {
        "StackName": stack_name(MIGRATION, OWNER, REGION)}
    stub.add_client_error("describe_stack_resources" if physical else "describe_stacks",
                          service_error_code="ValidationError",
                          service_message="Stack for the requested resource does not exist",
                          expected_params=kwargs)


def owning_stack(stub, template, logical, arn, stack=None):
    stub.add_response("describe_stack_resources", {"StackResources": [{
        "StackId": STACK_ID, "StackName": "offline", "LogicalResourceId": logical,
        "PhysicalResourceId": arn, "ResourceType": "AWS::RAM::ResourceShare",
        "Timestamp": "2026-10-13T00:00:00Z", "ResourceStatus": "CREATE_COMPLETE"}]},
        {"PhysicalResourceId": arn})
    stub.add_response("describe_stacks", {"Stacks": [stack or stack_info()]},
                      {"StackName": STACK_ID})
    stub.add_response("get_template", {"TemplateBody": json.dumps(template)},
                      {"StackName": STACK_ID, "TemplateStage": "Processed"})


def stub_discovery(stubs, shares=None, principals=None, kinds=None,
                   attached_version="2", attached_policy=None, read_permissions=None,
                   principal_status="ASSOCIATED"):
    shares = shares or [(SOURCE, RESOURCE)]
    kinds = kinds or {}
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [
        {"resourceShareArn": arn, "owningAccountId": OWNER, "status": "ACTIVE", "tags": []}
        for arn, _ in shares]}, {"resourceOwner": "SELF"})
    for arn, resource_arn in shares:
        kind = kinds.get(resource_arn, KIND)
        stubs["ram"].add_response("list_resources", {"resources": [resource(resource_arn, kind)]},
                                 {"resourceOwner": "SELF", "resourceShareArns": [arn]})
        ids = (principals or {}).get(arn, [CONSUMER])
        stubs["ram"].add_response("get_resource_share_associations",
                                 {"resourceShareAssociations": [
                                     association(p, "PRINCIPAL", status=principal_status, share=arn)
                                     for p in ids]},
                                 {"associationType": "PRINCIPAL", "resourceShareArns": [arn]})
        no_stack(stubs["cloudformation"], physical=True, arn=arn)
        # An empty/service-only inventory stops before permission discovery.
        if read_permissions is False or (read_permissions is None and
                (not ids or all(p.endswith(".amazonaws.com") for p in ids))):
            continue
        stubs["ram"].add_response("list_resource_share_permissions", {"permissions": [{
            "arn": PERMISSION, "version": attached_version, "resourceType": kind,
            "defaultVersion": attached_version == "2"}]}, {"resourceShareArn": arn})
        stubs["ram"].add_response("get_permission", {"permission": permission(kind=kind)},
                                 {"permissionArn": PERMISSION})
        if attached_version != "2":
            stubs["ram"].add_response(
                "get_permission", {"permission": permission(attached_version, attached_policy,
                                                           default=False, kind=kind)},
                {"permissionArn": PERMISSION, "permissionVersion": int(attached_version)})


def inspect(clients, consumers=None, capabilities=None, overrides=None):
    return Discovery(OfflineRouter(clients), consumers or {CONSUMER}, MIGRATION,
                     overrides or {}, capabilities if capabilities is not None else {
                         KIND.lower(): True}).inspect(OWNER, REGION)


def stub_original_principals(stubs, live, configured):
    stub = stubs["ram"]
    stub.add_response("get_resource_shares", {"resourceShares": [{
        "resourceShareArn": SOURCE, "owningAccountId": OWNER, "status": "ACTIVE", "tags": []}]},
        {"resourceOwner": "SELF"})
    stub.add_response("list_resources", {"resources": [resource()]},
                      {"resourceOwner": "SELF", "resourceShareArns": [SOURCE]})
    stub.add_response("get_resource_share_associations", {"resourceShareAssociations": [
        association(p, "PRINCIPAL", share=SOURCE) for p in live]},
        {"associationType": "PRINCIPAL", "resourceShareArns": [SOURCE]})
    original = {"Resources": {"Original": {"Type": "AWS::RAM::ResourceShare",
                                          "Properties": {"Principals": configured}}}}
    owning_stack(stubs["cloudformation"], original, "Original", SOURCE,
                 {**stack_info(), "Tags": []})


def test_installed_sdk_supports_retention_without_authentication():
    check_sdk()
    model = botocore.session.get_session().get_service_model("cloudformation")
    assert "DisableRollback" in model.operation_model("ExecuteChangeSet").input_shape.members
    assert "IncludePropertyValues" in model.operation_model("DescribeChangeSet").input_shape.members


@pytest.mark.parametrize("name,value", [
    ("Principal", {"AWS": f"arn:aws:iam::{CONSUMER}:root"}),
    ("Principal", "*"),
    ("NotPrincipal", {"AWS": f"arn:aws:iam::{OTHER}:role/Restricted"}),
    ("Condition", {"StringEquals": {"aws:PrincipalOrgID": "o-offline123"}}),
    ("Condition", {"Bool": {"aws:SecureTransport": True}}),
    ("Condition", {"NumericEquals": {"service:Limit": 1}}),
])
def test_policy_semantics_scalar_and_list_values_are_equivalent_and_idempotent(name, value):
    scalar = copy.deepcopy(POLICY)
    scalar["Statement"][0][name] = value
    listed = copy.deepcopy(scalar)
    if name == "Condition":
        operator = next(iter(value))
        condition_key = next(iter(value[operator]))
        listed["Statement"][0][name][operator][condition_key] = [value[operator][condition_key]]
    elif isinstance(value, dict):
        key = next(iter(value))
        listed["Statement"][0][name][key] = [value[key]]
    else:
        listed["Statement"][0][name] = [value]
    normalized = policy_semantics(scalar)
    assert normalized == policy_semantics(listed)
    assert policy_semantics(normalized) == normalized
    assert policy_semantics(json.dumps(scalar)) == normalized


def test_policy_semantics_preserves_principal_and_condition_restrictions():
    original = copy.deepcopy(POLICY)
    original["Statement"][0]["Principal"] = {
        "AWS": [f"arn:aws:iam::{CONSUMER}:root", f"arn:aws:iam::{OTHER}:root"]}
    original["Statement"][0]["Condition"] = {
        "StringEquals": {"aws:PrincipalOrgID": ["o-first", "o-second"]}}
    reordered = copy.deepcopy(original)
    reordered["Statement"][0]["Principal"]["AWS"].reverse()
    reordered["Statement"][0]["Condition"]["StringEquals"]["aws:PrincipalOrgID"].reverse()
    assert policy_semantics(original) == policy_semantics(reordered)
    different_principal = copy.deepcopy(original)
    different_principal["Statement"][0]["Principal"]["AWS"] = [f"arn:aws:iam::{DEPARTED}:root"]
    different_condition = copy.deepcopy(original)
    different_condition["Statement"][0]["Condition"]["StringEquals"]["aws:PrincipalOrgID"] = "o-third"
    different_operator = copy.deepcopy(original)
    different_operator["Statement"][0]["Condition"] = {
        "StringLike": {"aws:PrincipalOrgID": ["o-first", "o-second"]}}
    assert policy_semantics(original) != policy_semantics(different_principal)
    assert policy_semantics(original) != policy_semantics(different_condition)
    assert policy_semantics(original) != policy_semantics(different_operator)


def test_permission_snapshot_supports_scalar_principal_and_string_equals(clients):
    cs, stubs = clients
    conditional = copy.deepcopy(POLICY)
    conditional["Statement"][0]["Principal"] = {"AWS": f"arn:aws:iam::{CONSUMER}:root"}
    conditional["Statement"][0]["Condition"] = {"StringEquals": {
        "ram:ResourceShareOwnerAccountId": OWNER}}
    stubs["ram"].add_response("get_permission", {"permission": permission(policy=conditional)},
                             {"permissionArn": PERMISSION})
    captured = permission_snapshot(Api(cs["ram"]), PERMISSION)
    statement = captured["Policy"]["Statement"][0]
    assert statement["Principal"]["AWS"] == [f"arn:aws:iam::{CONSUMER}:root"]
    assert statement["Condition"]["StringEquals"]["ram:ResourceShareOwnerAccountId"] == [OWNER]
    assert policy_semantics(captured["Policy"]) == captured["Policy"]


def test_catalogue_multicode_and_conditional_rows():
    text = """| `network-firewall:StatefulRuleGroup` and `network-firewall:StatelessRuleGroup` | a | b | ![Yes](images/icon-yes.png) | d | e |
| `route53resolver:ResolverRule` | a | b | ![Yes](images/icon-yes.png) | d | e |
| `ec2:CapacityReservation` | a | b | ![Yes](images/icon-yes.png) reservations; ![No](images/icon-no.png) Capacity Blocks | d | e |
| `ec2:Subnet` | a | b | ![No](images/icon-no.png) | d | e |
| `service:Qualified` | a | b | ![Yes](images/icon-yes.png) except some resources | d | e |"""
    values = external_catalog(text)
    assert values["network-firewall:statefulrulegroup"] is True
    assert values["network-firewall:statelessrulegroup"] is True
    assert values[KIND.lower()] is True
    assert values["ec2:subnet"] is False
    assert "ec2:capacityreservation" not in values
    assert "service:qualified" not in values


def test_catalogue_conflicting_rows_fail_closed():
    with pytest.raises(MigrationError, match="Conflicting"):
        external_catalog("""| `ec2:Subnet` | a | b | ![Yes](images/icon-yes.png) | d | e |
| `ec2:Subnet` | a | b | ![No](images/icon-no.png) | d | e |""")


def test_qualified_catalogue_row_overrides_unqualified_row_conservatively():
    values = external_catalog("""| `ec2:CapacityReservation` | a | b | ![Yes](images/icon-yes.png) | d | e |
| `ec2:CapacityReservation` | a | b | ![Yes](images/icon-yes.png) except Capacity Blocks | d | e |
| `route53resolver:ResolverRule` | a | b | ![Yes](images/icon-yes.png) | d | e |""")
    assert "ec2:capacityreservation" not in values
    assert values[KIND.lower()] is True


def test_principal_resolution_preserves_leading_zeros():
    template = yaml.load(
        "Parameters:\n  Consumers:\n    Type: CommaDelimitedList\n"
        "Resources:\n  Share:\n    Properties:\n      Principals: !Ref Consumers\n", Loader=CfnLoader)
    assert resolve(template["Resources"]["Share"]["Properties"]["Principals"],
                   {"Consumers": CONSUMER + "," + OTHER}, template, {}) == [CONSUMER, OTHER]
    assert group().consumers == (CONSUMER,)


@pytest.mark.parametrize("expression", [
    {"Ref": "Missing"}, {"Ref": "Consumers", "Fn::Sub": "anything"},
    {"Fn::Join": ["", [2]]}, {"Fn::Split": [",", 2]},
    {"Fn::Sub": ["${Consumer}", {"Consumer": 2}]},
])
def test_ambiguous_or_numeric_principal_resolution_fails(expression):
    with pytest.raises(MigrationError):
        resolve(expression, {"Consumers": CONSUMER}, {}, {})


def test_native_non_cfn_share_stack_not_found(clients):
    cs, stubs = clients
    no_stack(stubs["cloudformation"], physical=True)
    discovery = Discovery(OfflineRouter(cs), {CONSUMER}, MIGRATION, {}, {})
    assert discovery._stack_principals(OWNER, REGION, SOURCE) is None


def test_native_missing_consumers_block_instead_of_service_exclusion(clients):
    cs, stubs = clients
    stub_discovery(stubs, principals={SOURCE: []})
    result = inspect(cs)
    assert not result.groups and not result.excluded
    assert "consumers are unresolved" in result.blocked[0]


def test_owning_template_recovers_missing_live_principals_and_stack_lineage(clients):
    cs, stubs = clients
    stub = stubs["ram"]
    stub.add_response("get_resource_shares", {"resourceShares": [{
        "resourceShareArn": SOURCE, "owningAccountId": OWNER, "status": "ACTIVE", "tags": []}]},
        {"resourceOwner": "SELF"})
    stub.add_response("list_resources", {"resources": [resource()]},
                      {"resourceOwner": "SELF", "resourceShareArns": [SOURCE]})
    stub.add_response("get_resource_share_associations", {"resourceShareAssociations": []},
                      {"associationType": "PRINCIPAL", "resourceShareArns": [SOURCE]})
    original = {"Parameters": {"Consumers": {"Type": "CommaDelimitedList"}},
                "Resources": {"Original": {"Type": "AWS::RAM::ResourceShare", "Properties": {
                    "Principals": {"Ref": "Consumers"}}}}}
    original_stack = {**stack_info(), "Tags": [],
                      "Parameters": [{"ParameterKey": "Consumers", "ParameterValue": CONSUMER}]}
    owning_stack(stubs["cloudformation"], original, "Original", SOURCE, original_stack)
    stub.add_response("list_resource_share_permissions", {"permissions": [{
        "arn": PERMISSION, "version": "2", "resourceType": KIND}]}, {"resourceShareArn": SOURCE})
    stub.add_response("get_permission", {"permission": permission()}, {"permissionArn": PERMISSION})
    result = inspect(cs)
    assert not result.blocked
    assert result.groups[0].consumers == (CONSUMER,)
    assert result.groups[0].source_stacks == [STACK_ID]


def test_service_only_is_excluded_without_organizations_calls(clients):
    cs, stubs = clients
    stub_discovery(stubs, principals={SOURCE: ["service.amazonaws.com"]})
    result = inspect(cs)
    assert not result.blocked
    assert "service-principal-only" in result.excluded[0]


@pytest.mark.parametrize("principal", [
    f"arn:aws:iam::{CONSUMER}:role/Restricted", f"arn:aws:iam::{CONSUMER}:user/Restricted",
])
def test_restricted_principals_are_not_converted_to_account_wide_grants(clients, principal):
    cs, _ = clients
    with pytest.raises(MigrationError, match="Unsupported account-level principal conversion"):
        Discovery(OfflineRouter(cs), {CONSUMER}, MIGRATION, {}, {})._expand(OWNER, principal)


@pytest.mark.parametrize("override", [False, True])
@pytest.mark.parametrize("principal", [
    f"arn:aws:iam::{CONSUMER}:role/Restricted",
    f"arn:aws:iam::{CONSUMER}:user/Restricted",
    f"arn:aws:iam::{CONSUMER}:role/logs.amazonaws.com",
])
def test_override_cannot_broaden_live_role_or_user_restrictions(clients, override, principal):
    cs, stubs = clients
    stub_discovery(stubs, principals={SOURCE: [principal]}, read_permissions=False)
    result = inspect(cs, overrides={SOURCE: [CONSUMER]} if override else {})
    assert not result.groups
    assert "overrides cannot broaden restricted access" in result.blocked[0]
    assert principal in result.blocked[0]


@pytest.mark.parametrize("principal_status", ["DISASSOCIATING", "FAILED", "DISASSOCIATED"])
def test_override_cannot_hide_observed_role_restrictions_outside_active_inventory(
        clients, principal_status):
    cs, stubs = clients
    principal = f"arn:aws:iam::{CONSUMER}:role/Restricted"
    stub_discovery(stubs, principals={SOURCE: [principal]}, read_permissions=False,
                   principal_status=principal_status)
    result = inspect(cs, overrides={SOURCE: [CONSUMER]})
    assert not result.groups
    assert "overrides cannot broaden restricted access" in result.blocked[0]


@pytest.mark.parametrize("live", [[], [CONSUMER]])
@pytest.mark.parametrize("restriction", ["role/Restricted", "user/Restricted"])
def test_override_cannot_hide_resolved_owning_template_restrictions(clients, live, restriction):
    cs, stubs = clients
    principal = f"arn:aws:iam::{CONSUMER}:{restriction}"
    stub_original_principals(stubs, live, [principal])
    result = inspect(cs, overrides={SOURCE: [CONSUMER]})
    assert not result.groups
    assert principal in result.blocked[0]
    assert "overrides cannot broaden restricted access" in result.blocked[0]


def test_override_cannot_hide_live_restriction_when_template_is_account_scoped(clients):
    cs, stubs = clients
    principal = f"arn:aws:iam::{CONSUMER}:role/Restricted"
    stub_original_principals(stubs, [principal], [CONSUMER])
    result = inspect(cs, overrides={SOURCE: [CONSUMER]})
    assert not result.groups
    assert "overrides cannot broaden restricted access" in result.blocked[0]


def test_override_cannot_skip_unresolved_template_principal_expression(clients):
    cs, stubs = clients
    stub_original_principals(stubs, [CONSUMER], {"Fn::GetAtt": ["PrincipalRole", "Arn"]})
    result = inspect(cs, overrides={SOURCE: [CONSUMER]})
    assert not result.groups
    assert "Unresolved principal intrinsic" in result.blocked[0]


def test_override_cannot_convert_service_only_share_to_account_wide_access(clients):
    cs, stubs = clients
    stub_discovery(stubs, principals={SOURCE: ["service.amazonaws.com"]})
    result = inspect(cs, overrides={SOURCE: [CONSUMER]})
    assert not result.groups
    assert "cannot broaden a service-principal-only share" in result.blocked[0]


@pytest.mark.parametrize("partition", ["aws", "aws-us-gov", "aws-cn"])
def test_root_principal_preserves_account_id_in_the_same_partition(clients, partition):
    cs, _ = clients
    root = f"arn:{partition}:iam::{CONSUMER}:root"
    discovery = Discovery(OfflineRouter(cs), {CONSUMER}, MIGRATION, {}, {})
    assert discovery._expand(OWNER, root, partition=partition) == {CONSUMER}


@pytest.mark.parametrize("partition", [None, "aws-us-gov", "aws-cn"])
def test_root_principal_rejects_unproven_or_mismatched_partition(clients, partition):
    cs, _ = clients
    root = f"arn:aws:iam::{CONSUMER}:root"
    with pytest.raises(MigrationError, match="partition"):
        Discovery(OfflineRouter(cs), {CONSUMER}, MIGRATION, {}, {})._expand(
            OWNER, root, partition=partition)


@pytest.mark.parametrize("principal", [
    f"arn:aws:iam:us-east-1:{CONSUMER}:root", f"arn:aws:iam::{CONSUMER}:root/path",
    "arn:aws:iam::123:root", f"arn:aws:iam::{CONSUMER}:role/root",
    f"arn:aws:iam::{CONSUMER}:user/root",
])
def test_only_exact_account_root_arns_can_be_normalized(clients, principal):
    cs, _ = clients
    with pytest.raises(MigrationError, match="Unsupported account-level principal conversion"):
        Discovery(OfflineRouter(cs), {CONSUMER}, MIGRATION, {}, {})._expand(
            OWNER, principal, partition="aws")


def test_live_root_and_account_id_principals_have_identical_entitlement_identity(clients):
    cs, stubs = clients
    stub_discovery(stubs)
    first = inspect(cs)
    stub_discovery(stubs, principals={SOURCE: [f"arn:aws:iam::{CONSUMER}:root", CONSUMER]})
    second = inspect(cs)
    assert not first.blocked and not second.blocked
    assert first.groups == second.groups
    assert second.groups[0].consumers == (CONSUMER,)


def test_mixed_ou_and_departed_root_principal_proves_direct_account_entitlement(clients, monkeypatch):
    cs, stubs = clients
    organization = {"Id": "o-offline123", "ManagementAccountId": OWNER}
    ou = f"arn:aws:organizations::{OWNER}:ou/o-offline123/ou-offline-first"
    root = f"arn:aws:iam::{DEPARTED}:root"
    discovery = Discovery(OfflineRouter(cs), {CONSUMER, DEPARTED}, MIGRATION, {},
                          {KIND.lower(): True})
    monkeypatch.setattr(discovery, "_org", lambda owner: (Api(cs["organizations"]), organization))
    stub_discovery(stubs, principals={SOURCE: [ou, root]})
    stubs["organizations"].add_response("list_accounts_for_parent", {
        "Accounts": [{"Id": CONSUMER, "State": "ACTIVE"}]}, {"ParentId": "ou-offline-first"})
    stubs["organizations"].add_response("list_organizational_units_for_parent", {
        "OrganizationalUnits": []}, {"ParentId": "ou-offline-first"})
    stubs["organizations"].add_response("list_accounts", {"Accounts": [
        {"Id": OWNER, "State": "ACTIVE"}, {"Id": CONSUMER, "State": "ACTIVE"}]}, {})
    result = discovery.inspect(OWNER, REGION)
    assert not result.blocked
    assert result.groups[0].consumers == (CONSUMER, DEPARTED)


def test_discovery_records_the_ou_and_organization_principals_of_original_shares(
        clients, monkeypatch):
    """The organization-policy preflight checks the RAM organization prerequisites
    only where an original share relies on them; account principals are not recorded."""
    cs, stubs = clients
    organization = {"Id": "o-offline123", "ManagementAccountId": OWNER}
    ou = f"arn:aws:organizations::{OWNER}:ou/o-offline123/ou-offline-first"
    discovery = Discovery(OfflineRouter(cs), {CONSUMER, DEPARTED}, MIGRATION, {},
                          {KIND.lower(): True})
    monkeypatch.setattr(discovery, "_org", lambda owner: (Api(cs["organizations"]), organization))
    stub_discovery(stubs, principals={SOURCE: [ou, f"arn:aws:iam::{DEPARTED}:root"]})
    stubs["organizations"].add_response("list_accounts_for_parent", {
        "Accounts": [{"Id": CONSUMER, "State": "ACTIVE"}]}, {"ParentId": "ou-offline-first"})
    stubs["organizations"].add_response("list_organizational_units_for_parent", {
        "OrganizationalUnits": []}, {"ParentId": "ou-offline-first"})
    stubs["organizations"].add_response("list_accounts", {"Accounts": [
        {"Id": OWNER, "State": "ACTIVE"}, {"Id": CONSUMER, "State": "ACTIVE"}]}, {})
    assert not discovery.inspect(OWNER, REGION).blocked
    assert discovery.organization_principals == {SOURCE: [ou]}
    direct = Discovery(OfflineRouter(cs), {CONSUMER}, MIGRATION, {}, {KIND.lower(): True})
    stub_discovery(stubs)
    assert not direct.inspect(OWNER, REGION).blocked
    assert direct.organization_principals == {}


@pytest.mark.parametrize("capabilities", [{}, {KIND.lower(): False}])
def test_unsupported_or_unknown_external_type_blocks(clients, capabilities):
    cs, stubs = clients
    stub_discovery(stubs)
    result = inspect(cs, capabilities=capabilities)
    assert not result.groups
    assert "external-sharing capability" in result.blocked[0]


def test_semantically_equivalent_permission_versions_are_supported(clients):
    cs, stubs = clients
    reordered = copy.deepcopy(POLICY)
    reordered["Statement"][0]["Action"].reverse()
    reordered["Statement"][0]["Sid"] = "AnInertIdentifier"
    reordered["Statement"][0]["Resource"] = ["*"]
    stub_discovery(stubs, attached_version="1", attached_policy=reordered)
    result = inspect(cs)
    assert not result.blocked
    assert result.groups[0].permission_snapshots[KIND]["Version"] == "2"


def test_a_broader_default_permission_is_attached_and_the_difference_reported(clients):
    """AWS attaches only the default to a new share. A broader default is used, never an
    older version pinned, and the difference never blocks: the share is temporary."""
    cs, stubs = clients
    narrower = copy.deepcopy(POLICY)
    narrower["Statement"][0]["Action"] = ["route53resolver:GetResolverRule"]
    stub_discovery(stubs, attached_version="1", attached_policy=narrower)
    result = inspect(cs)
    assert not result.blocked
    assert result.groups[0].permission_snapshots[KIND]["Version"] == "2"
    change, = result.permission_changes
    assert (change["from_version"], change["to_version"]) == ("1", "2")
    assert change["difference"]["summary"] == \
        "grants more: Allow route53resolver:AssociateResolverRule"


def test_compatible_grouping_merges_resources_and_preserves_sources(clients):
    cs, stubs = clients
    second_source, second_resource = SOURCE + "2", RESOURCE + "2"
    stub_discovery(stubs, shares=[(SOURCE, RESOURCE), (second_source, second_resource)])
    result = inspect(cs)
    assert not result.blocked and len(result.groups) == 1
    assert set(result.groups[0].resources) == {RESOURCE, second_resource}
    assert result.groups[0].source_shares == [SOURCE, second_source]
    assert result.groups[0].consumers == (CONSUMER,)


def test_different_consumers_are_never_grouped_together(clients):
    cs, stubs = clients
    second_source, second_resource = SOURCE + "2", RESOURCE + "2"
    stub_discovery(stubs, shares=[(SOURCE, RESOURCE), (second_source, second_resource)],
                   principals={SOURCE: [CONSUMER], second_source: [OTHER]})
    result = inspect(cs, consumers={CONSUMER, OTHER})
    assert not result.blocked
    assert {(g.consumers, tuple(g.resources)) for g in result.groups} == {
        ((CONSUMER,), (RESOURCE,)), ((OTHER,), (second_resource,))}


def test_ou_members_in_other_ous_are_unrelated_but_departed_accounts_block(clients, monkeypatch):
    cs, stubs = clients
    organization = {"Id": "o-offline123", "ManagementAccountId": OWNER}
    ou = f"arn:aws:organizations::{OWNER}:ou/o-offline123/ou-offline-first"
    discovery = Discovery(OfflineRouter(cs), {CONSUMER, OTHER}, MIGRATION, {},
                          {KIND.lower(): True})
    monkeypatch.setattr(discovery, "_org", lambda owner: (Api(cs["organizations"]), organization))
    stub_discovery(stubs, principals={SOURCE: [ou]})
    stubs["organizations"].add_response("list_accounts_for_parent", {
        "Accounts": [{"Id": CONSUMER, "State": "ACTIVE"}]}, {"ParentId": "ou-offline-first"})
    stubs["organizations"].add_response("list_organizational_units_for_parent", {
        "OrganizationalUnits": []}, {"ParentId": "ou-offline-first"})
    stubs["organizations"].add_response("list_accounts", {"Accounts": [
        {"Id": OWNER, "State": "ACTIVE"}, {"Id": CONSUMER, "State": "ACTIVE"},
        {"Id": OTHER, "State": "ACTIVE"}]}, {})
    result = discovery.inspect(OWNER, REGION)
    assert not result.blocked and result.groups[0].consumers == (CONSUMER,)
    assert OTHER in result.excluded[0] and "outside this principal scope" in result.excluded[0]

    discovery.consumers.add(DEPARTED)
    # Discovery stops at historical resolution, before permission reads.
    stub = stubs["ram"]
    stub.add_response("get_resource_shares", {"resourceShares": [{
        "resourceShareArn": SOURCE, "owningAccountId": OWNER, "status": "ACTIVE", "tags": []}]},
        {"resourceOwner": "SELF"})
    stub.add_response("list_resources", {"resources": [resource()]},
                      {"resourceOwner": "SELF", "resourceShareArns": [SOURCE]})
    stub.add_response("get_resource_share_associations", {"resourceShareAssociations": [
        association(ou, "PRINCIPAL", share=SOURCE)]},
        {"associationType": "PRINCIPAL", "resourceShareArns": [SOURCE]})
    no_stack(stubs["cloudformation"], physical=True)
    stubs["organizations"].add_response("list_accounts_for_parent", {
        "Accounts": [{"Id": CONSUMER, "State": "ACTIVE"}]}, {"ParentId": "ou-offline-first"})
    stubs["organizations"].add_response("list_organizational_units_for_parent", {
        "OrganizationalUnits": []}, {"ParentId": "ou-offline-first"})
    stubs["organizations"].add_response("list_accounts", {"Accounts": [
        {"Id": CONSUMER, "State": "ACTIVE"}, {"Id": OTHER, "State": "ACTIVE"}]}, {})
    result = discovery.inspect(OWNER, REGION)
    assert not result.groups
    assert DEPARTED in result.blocked[0] and OTHER not in result.blocked[0]


def test_two_source_ous_do_not_cross_grant_and_active_members_are_cached(clients, monkeypatch):
    cs, stubs = clients
    organization = {"Id": "o-offline123", "ManagementAccountId": OWNER}
    second_source, second_resource = SOURCE + "2", RESOURCE + "2"
    ou_ids = ("ou-offline-first", "ou-offline-second")
    ou_arns = [f"arn:aws:organizations::{OWNER}:ou/o-offline123/{ou}" for ou in ou_ids]
    discovery = Discovery(OfflineRouter(cs), {CONSUMER, OTHER}, MIGRATION, {},
                          {KIND.lower(): True})
    monkeypatch.setattr(discovery, "_org", lambda owner: (Api(cs["organizations"]), organization))
    stub_discovery(stubs, shares=[(SOURCE, RESOURCE), (second_source, second_resource)],
                   principals={SOURCE: [ou_arns[0]], second_source: [ou_arns[1]]})
    org = stubs["organizations"]
    for index, (ou, consumer) in enumerate(zip(ou_ids, (CONSUMER, OTHER))):
        org.add_response("list_accounts_for_parent", {"Accounts": [
            {"Id": consumer, "State": "ACTIVE"}]}, {"ParentId": ou})
        org.add_response("list_organizational_units_for_parent", {"OrganizationalUnits": []},
                         {"ParentId": ou})
        if index == 0:
            # Only one all-member lookup is permitted for the whole inspection.
            org.add_response("list_accounts", {"Accounts": [
                {"Id": CONSUMER, "State": "ACTIVE"}, {"Id": OTHER, "State": "ACTIVE"}]}, {})
    result = discovery.inspect(OWNER, REGION)
    assert not result.blocked
    assert {(g.consumers, tuple(g.resources)) for g in result.groups} == {
        ((CONSUMER,), (RESOURCE,)), ((OTHER,), (second_resource,))}


def test_historical_override_is_explicit_account_inventory(clients):
    cs, stubs = clients
    stub_discovery(stubs)
    result = inspect(cs, consumers={CONSUMER, DEPARTED}, overrides={
        SOURCE: [CONSUMER, DEPARTED]})
    assert not result.blocked
    assert result.groups[0].consumers == (CONSUMER, DEPARTED)


def test_historical_override_recovers_missing_live_account_inventory(clients):
    cs, stubs = clients
    stub_discovery(stubs, principals={SOURCE: []}, read_permissions=True)
    result = inspect(cs, consumers={CONSUMER, DEPARTED}, overrides={SOURCE: [CONSUMER, DEPARTED]})
    assert not result.blocked
    assert result.groups[0].consumers == (CONSUMER, DEPARTED)


def test_historical_ou_override_does_not_require_current_ou_membership(clients):
    cs, stubs = clients
    ou = f"arn:aws:organizations::{OWNER}:ou/o-offline123/ou-offline-first"
    stub_discovery(stubs, principals={SOURCE: [ou]})
    result = inspect(cs, consumers={CONSUMER, DEPARTED}, overrides={SOURCE: [CONSUMER, DEPARTED]})
    assert not result.blocked
    assert result.groups[0].consumers == (CONSUMER, DEPARTED)


def test_migration_tags_alone_do_not_authorize_recursive_exclusion(clients):
    cs, stubs = clients
    forged = migration_share()
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [forged]},
                             {"resourceOwner": "SELF"})
    no_stack(stubs["cloudformation"], physical=True, arn=TEMP)
    result = inspect(cs)
    assert not result.existing
    assert "no proven owning migration stack" in result.blocked[0]


def test_proven_migration_share_with_lowercase_tags_is_not_replicated(clients):
    cs, stubs = clients
    g = group(approved=True)
    share = migration_share(g)
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [share]},
                             {"resourceOwner": "SELF"})
    owning_stack(stubs["cloudformation"], template_for([g], MIGRATION), g.logical_id, TEMP)
    result = inspect(cs)
    assert not result.blocked and not result.groups
    assert result.existing == [share]


def test_additive_merge_is_idempotent_and_preserves_prior_entitlements_and_lineage():
    before_group = group(approved=True)
    after_group = group(resources={RESOURCE + "2": KIND}, sources=[SOURCE + "2"], approved=True)
    prior = template_for([before_group], MIGRATION)
    fresh = template_for([after_group], MIGRATION)
    merged = additive_template(prior, fresh, MIGRATION)
    item = merged["Resources"][before_group.logical_id]
    assert item["Properties"]["ResourceArns"] == [RESOURCE, RESOURCE + "2"]
    assert item["Properties"]["Principals"] == [CONSUMER]
    assert item["Metadata"]["SourceShareArns"] == [SOURCE, SOURCE + "2"]
    assert item["DeletionPolicy"] == item["UpdateReplacePolicy"] == "Retain"
    assert additive_template(merged, fresh, MIGRATION) == merged
    assert additive_template(merged, template_for([], MIGRATION), MIGRATION) == merged
    assert prior["Resources"][before_group.logical_id]["Properties"]["ResourceArns"] == [RESOURCE]


@pytest.mark.parametrize("mutation", ["owner", "permission", "principal", "retain", "policy"])
def test_unsafe_template_merges_fail_closed(mutation):
    g = group(approved=True)
    prior = template_for([g], MIGRATION)
    fresh = copy.deepcopy(prior)
    item = fresh["Resources"][g.logical_id]
    if mutation == "owner":
        item["Properties"]["Tags"][2]["Value"] = OTHER
    elif mutation == "permission":
        item["Properties"]["PermissionArns"] = [PERMISSION + "Different"]
    elif mutation == "principal":
        item["Properties"]["Principals"].append(OTHER)
    elif mutation == "retain":
        item["DeletionPolicy"] = "Delete"
    else:
        item["Metadata"]["PermissionSnapshots"][KIND]["Policy"]["Statement"][0]["Action"].append("*")
    with pytest.raises(MigrationError):
        additive_template(prior, fresh, MIGRATION)


def change(g, action="Modify", replacement="False", field="ResourceArns"):
    return {"Type": "Resource", "ResourceChange": {
        "Action": action, "LogicalResourceId": g.logical_id,
        "ResourceType": "AWS::RAM::ResourceShare", "Replacement": replacement,
        "Scope": ["Properties"], "Details": [{
            "Target": {"Attribute": "Properties", "Name": field, "RequiresRecreation": "Never"},
            "Evaluation": "Static"}]}}


@pytest.mark.parametrize("action,replacement,field", [
    ("Remove", "False", "ResourceArns"), ("Import", "False", "ResourceArns"),
    ("Modify", "True", "ResourceArns"), ("Modify", "Conditional", "ResourceArns"),
    ("Modify", "False", "PermissionArns"), ("Modify", "False", "Principals"),
    ("Modify", "False", "AllowExternalPrincipals"),
])
def test_unsafe_change_set_rejected(action, replacement, field):
    g = group(approved=True)
    prior = template_for([g], MIGRATION)
    proposed = additive_template(prior, template_for([
        group(resources={RESOURCE + "2": KIND}, approved=True)], MIGRATION), MIGRATION)
    with pytest.raises(MigrationError):
        validate_changes([change(g, action, replacement, field)], proposed, prior)


def test_only_nonreplacing_additive_change_can_execute():
    g = group(approved=True)
    prior = template_for([g], MIGRATION)
    proposed = additive_template(prior, template_for([
        group(resources={RESOURCE + "2": KIND}, approved=True)], MIGRATION), MIGRATION)
    validate_changes([change(g)], proposed, prior)
    removal = copy.deepcopy(proposed)
    removal["Resources"][g.logical_id]["Properties"]["ResourceArns"] = [RESOURCE + "2"]
    with pytest.raises(MigrationError, match="removal"):
        validate_changes([change(g)], removal, prior)


@pytest.mark.parametrize("mutate", ["policy_action", "dynamic", "path", "no_details", "omission"])
def test_ambiguous_or_destructive_change_details_are_rejected(mutate):
    g = group(approved=True)
    prior = template_for([g], MIGRATION)
    proposed = additive_template(prior, template_for([
        group(resources={RESOURCE + "2": KIND}, approved=True)], MIGRATION), MIGRATION)
    row = change(g)
    if mutate == "policy_action":
        row["ResourceChange"]["PolicyAction"] = "ReplaceAndRetain"
    elif mutate == "dynamic":
        row["ResourceChange"]["Details"][0]["Evaluation"] = "Dynamic"
    elif mutate == "path":
        row["ResourceChange"]["Details"][0]["Target"]["Path"] = "/Properties/PermissionArns"
    elif mutate == "no_details":
        row["ResourceChange"]["Details"] = []
    else:
        proposed["Resources"] = {}
    with pytest.raises(MigrationError):
        validate_changes([row], proposed, prior)


def test_create_failed_stack_blocks_before_any_write_or_permission_lookup(clients):
    cs, stubs = clients
    stubs["cloudformation"].add_response("describe_stacks", {"Stacks": [stack_info("CREATE_FAILED")]},
        {"StackName": stack_name(MIGRATION, OWNER, REGION)})
    with pytest.raises(MigrationError, match="cannot be retried automatically"):
        Stacks(OfflineRouter(cs), MIGRATION).apply(OWNER, REGION, [group()])


def test_readonly_api_prevents_changeset_creation(clients):
    cs, stubs = clients
    no_stack(stubs["cloudformation"])
    stubs["ram"].add_response("get_permission", {"permission": permission()},
                             {"permissionArn": PERMISSION})
    with pytest.raises(MigrationError, match="Read-only"):
        Stacks(OfflineRouter(cs, readonly=True), MIGRATION).apply(OWNER, REGION, [group()])


def test_changed_managed_policy_blocks_before_changeset_creation(clients):
    cs, stubs = clients
    no_stack(stubs["cloudformation"])
    approved = group(approved=True)
    broader = copy.deepcopy(POLICY)
    broader["Statement"][0]["Action"] = "*"
    stubs["ram"].add_response("get_permission", {"permission": permission("3", broader)},
                             {"permissionArn": PERMISSION})
    with pytest.raises(MigrationError, match="default managed permission changed since "
                                             "discovery read it"):
        Stacks(OfflineRouter(cs), MIGRATION).apply(OWNER, REGION, [approved])


@pytest.mark.parametrize("unsafe", [False, True])
def test_apply_stubber_preserves_rollback_setting_and_rejects_unsafe_execution(
        clients, monkeypatch, unsafe):
    cs, stubs = clients
    g = group(approved=True)
    body = template_for([g], MIGRATION)
    no_stack(stubs["cloudformation"])
    stubs["ram"].add_response("get_permission", {"permission": permission()},
                             {"permissionArn": PERMISSION})
    monkeypatch.setattr("ram_migration_stacks.time.time_ns", lambda: 7)
    from ram_migration_common import digest
    name = stack_name(MIGRATION, OWNER, REGION)
    stubs["cloudformation"].add_response("create_change_set", {"Id": CHANGE_ID}, {
        "StackName": name, "ChangeSetName": "ram-" + digest(body) + "-7",
        "ChangeSetType": "CREATE", "TemplateBody": json.dumps(body, sort_keys=True),
        "Description": "Additive RAM migration shares",
        "Tags": [{"Key": "Purpose", "Value": PURPOSE},
                 {"Key": "MigrationId", "Value": MIGRATION},
                 {"Key": "OwnerAccount", "Value": OWNER},
                 {"Key": "RetirementPolicy", "Value": "VerifyReplacementAccessFirst"}]})
    status = {"Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE"}
    stubs["cloudformation"].add_response("describe_change_set", status,
                                        {"ChangeSetName": CHANGE_ID, "StackName": name})
    row = change(g, action="Remove" if unsafe else "Add")
    stubs["cloudformation"].add_response("describe_change_set", {**status, "Changes": [row]}, {
        "ChangeSetName": CHANGE_ID, "StackName": name, "IncludePropertyValues": True})
    if unsafe:
        with pytest.raises(MigrationError, match="Unsafe"):
            Stacks(OfflineRouter(cs), MIGRATION).apply(OWNER, REGION, [g])
    else:
        stubs["cloudformation"].add_response("execute_change_set", {}, {
            "ChangeSetName": CHANGE_ID, "StackName": name, "DisableRollback": True})
        stubs["cloudformation"].add_response("describe_stacks", {"Stacks": [stack_info()]},
                                            {"StackName": name})
        assert Stacks(OfflineRouter(cs), MIGRATION).apply(OWNER, REGION, [g]) == name


def test_persisted_groups_uses_template_permission_and_actual_ram_types(clients):
    cs, stubs = clients
    # This type cannot be inferred by splitting the ARN's service/resource name.
    actual_kind = "ec2:IpamPool"
    actual_arn = f"arn:aws:ec2:{REGION}:{OWNER}:ipam-pool/ipam-pool-offline"
    actual_permission = "arn:aws:ram::aws:permission/AWSRAMDefaultPermissionIpamPool"
    approved = {**snapshot(), "Arn": actual_permission, "ResourceType": actual_kind}
    g = ApprovedGroup(OWNER, REGION, (CONSUMER,), {actual_kind: actual_permission},
                      {actual_arn: actual_kind}, [SOURCE], {actual_kind: approved}, [STACK_ID])
    body = template_for([g], MIGRATION)
    stubs["cloudformation"].add_response("describe_stacks", {"Stacks": [stack_info()]},
        {"StackName": stack_name(MIGRATION, OWNER, REGION)})
    stubs["cloudformation"].add_response("get_template", {"TemplateBody": json.dumps(body)},
                                        {"StackName": STACK_ID, "TemplateStage": "Processed"})
    stubs["ram"].add_response("get_permission", {
        "permission": permission(arn=actual_permission, kind=actual_kind)},
        {"permissionArn": actual_permission, "permissionVersion": 2})
    stubs["ram"].add_response("list_resources", {"resources": [resource(actual_arn, actual_kind)]},
                             {"resourceOwner": "SELF", "resourceArns": [actual_arn]})
    recovered = Stacks(OfflineRouter(cs), MIGRATION).persisted_groups(OWNER, REGION)
    assert recovered == [g]
    assert recovered[0].permissions == {actual_kind: actual_permission}
    assert recovered[0].source_shares == [SOURCE]


def test_persisted_groups_rejects_wrong_entitlement_hash_before_ram_reads(clients):
    cs, stubs = clients
    g = group(approved=True)
    body = template_for([g], MIGRATION)
    body["Resources"][g.logical_id]["Properties"]["Principals"].append(OTHER)
    stubs["cloudformation"].add_response("describe_stacks", {"Stacks": [stack_info()]},
        {"StackName": stack_name(MIGRATION, OWNER, REGION)})
    stubs["cloudformation"].add_response("get_template", {"TemplateBody": json.dumps(body)},
                                        {"StackName": STACK_ID, "TemplateStage": "Processed"})
    with pytest.raises(MigrationError, match="identity"):
        Stacks(OfflineRouter(cs), MIGRATION).persisted_groups(OWNER, REGION)


def test_existing_template_without_policy_approval_is_an_explicit_blocker(clients):
    cs, stubs = clients
    body = template_for([group()], MIGRATION)
    stubs["cloudformation"].add_response("describe_stacks", {"Stacks": [stack_info()]},
        {"StackName": stack_name(MIGRATION, OWNER, REGION)})
    stubs["cloudformation"].add_response("get_template", {"TemplateBody": json.dumps(body)},
                                        {"StackName": STACK_ID, "TemplateStage": "Processed"})
    with pytest.raises(MigrationError, match="permission approval missing"):
        Stacks(OfflineRouter(cs), MIGRATION).persisted_groups(OWNER, REGION)


def stub_verification(stub, g, extra=None, principals=None):
    permission_rows = [{"arn": PERMISSION, "version": "2", "resourceType": KIND}]
    if extra == "permission":
        permission_rows.append({"arn": PERMISSION + "Extra", "version": "2",
                                "resourceType": "ec2:Subnet"})
    stub.add_response("list_resource_share_permissions", {"permissions": permission_rows},
                      {"resourceShareArn": TEMP})
    stub.add_response("get_permission", {"permission": permission()},
                      {"permissionArn": PERMISSION, "permissionVersion": 2})
    if extra == "permission":
        return
    rows = [association(RESOURCE, "RESOURCE")]
    if extra == "resource":
        rows.append(association(RESOURCE + "Extra", "RESOURCE"))
    stub.add_response("get_resource_share_associations", {"resourceShareAssociations": rows},
                      {"associationType": "RESOURCE", "resourceShareArns": [TEMP]})
    if extra == "resource":
        return
    stub.add_response("list_resources", {"resources": [resource()]},
                      {"resourceOwner": "SELF", "resourceShareArns": [TEMP]})
    rows = list(principals) if principals is not None else [association(CONSUMER, "PRINCIPAL")]
    if extra == "principal":
        rows.append(association(OTHER, "PRINCIPAL"))
    stub.add_response("get_resource_share_associations", {"resourceShareAssociations": rows},
                      {"associationType": "PRINCIPAL", "resourceShareArns": [TEMP]})


@pytest.mark.parametrize("extra", ["permission", "resource", "principal"])
def test_exact_verification_rejects_extra_entitlements(clients, extra):
    cs, stubs = clients
    g = group(approved=True)
    stub_verification(stubs["ram"], g, extra)
    with pytest.raises(MigrationError):
        verify_group(OfflineRouter(cs), g, migration_share(g), MIGRATION)


def test_complete_exact_verification_with_lowercase_ram_tags(clients):
    cs, stubs = clients
    g = group(approved=True)
    stub_verification(stubs["ram"], g)
    session = botocore.session.get_session()
    consumer = session.create_client("ram", region_name=REGION,
                                     config=Config(signature_version=UNSIGNED))
    with Stubber(consumer) as stub:
        stub.add_response("list_resources", {"resources": [resource()]},
                          {"resourceOwner": "OTHER-ACCOUNTS", "resourceShareArns": [TEMP]})
        verify_group(OfflineRouter(cs, consumer=consumer), g, migration_share(g), MIGRATION)
        stub.assert_no_pending_responses()


def test_verification_rejects_broader_attached_permission_version(clients):
    cs, stubs = clients
    stubs["ram"].add_response("list_resource_share_permissions", {"permissions": [{
        "arn": PERMISSION, "version": "3", "resourceType": KIND}]}, {"resourceShareArn": TEMP})
    broader = copy.deepcopy(POLICY)
    broader["Statement"][0]["Action"] = "*"
    stubs["ram"].add_response("get_permission", {"permission": permission("3", broader)},
                             {"permissionArn": PERMISSION, "permissionVersion": 3})
    approved = group(approved=True)
    with pytest.raises(MigrationError, match="policy/version differs"):
        verify_group(OfflineRouter(cs), approved, migration_share(approved), MIGRATION)


def test_verification_rejects_extra_consumer_visible_resources(clients):
    cs, stubs = clients
    approved = group(approved=True)
    stub_verification(stubs["ram"], approved)
    consumer = botocore.session.get_session().create_client(
        "ram", region_name=REGION, config=Config(signature_version=UNSIGNED))
    with Stubber(consumer) as stub:
        stub.add_response("list_resources", {"resources": [resource(), resource(RESOURCE + "Extra")]},
                          {"resourceOwner": "OTHER-ACCOUNTS", "resourceShareArns": [TEMP]})
        with pytest.raises(MigrationError, match="inventory differs"):
            verify_group(OfflineRouter(cs, consumer=consumer), approved,
                         migration_share(approved), MIGRATION)
        stub.assert_no_pending_responses()


@pytest.mark.parametrize("version", ["0", "01", "-1", "latest", 2, True])
def test_permission_versions_are_validated_before_sdk_reads(clients, version):
    cs, _ = clients
    with pytest.raises(MigrationError, match="invalid managed permission version"):
        permission_snapshot(Api(cs["ram"]), PERMISSION, version)


# ---------------------------------------------------------------------------
# Per-account completion: principal removal, retired principals, share deletion
# ---------------------------------------------------------------------------
from ram_migration_stacks import delete_share, remove_principals, unserved_consumers  # noqa: E402

SHARE_QUERY = {"resourceOwner": "SELF", "resourceShareArns": [TEMP]}
PRINCIPAL_QUERY = {"associationType": "PRINCIPAL", "resourceShareArns": [TEMP]}


def principal_rows(*rows):
    return {"resourceShareAssociations": [association(entity, "PRINCIPAL", status)
                                          for entity, status in rows]}


def shared_share(**changes):
    """This migration's temporary share for CONSUMER and OTHER, as RAM returns it."""
    return dict(migration_share(group(consumers=(CONSUMER, OTHER))), **changes)


def test_verification_of_a_partly_retired_share_expects_only_the_other_principals(clients):
    cs, stubs = clients
    g = group(consumers=(CONSUMER, OTHER), approved=True)
    stub_verification(stubs["ram"], g, principals=[
        association(CONSUMER, "PRINCIPAL", "DISASSOCIATED"), association(OTHER, "PRINCIPAL")])
    consumer = botocore.session.get_session().create_client(
        "ram", region_name=REGION, config=Config(signature_version=UNSIGNED))
    with Stubber(consumer) as stub:  # visibility is read for OTHER only
        stub.add_response("list_resources", {"resources": [resource()]},
                          {"resourceOwner": "OTHER-ACCOUNTS", "resourceShareArns": [TEMP]})
        verify_group(OfflineRouter(cs, consumer=consumer), g, migration_share(g), MIGRATION,
                     retired={CONSUMER})
        stub.assert_no_pending_responses()


def test_verification_fails_while_a_retired_consumer_is_still_a_principal(clients):
    cs, stubs = clients
    g = group(consumers=(CONSUMER, OTHER), approved=True)
    stub_verification(stubs["ram"], g, principals=[
        association(CONSUMER, "PRINCIPAL"), association(OTHER, "PRINCIPAL")])
    with pytest.raises(MigrationError, match="unexpected or missing principal entitlements"):
        verify_group(OfflineRouter(cs), g, migration_share(g), MIGRATION, retired={CONSUMER})


@pytest.mark.parametrize("change", ["another-migration", "another-owner", "not-tool-named", "absent"])
def test_principal_removal_refuses_a_share_that_is_not_this_migrations(clients, change):
    cs, stubs = clients
    share = shared_share()
    if change == "another-migration":
        share["tags"] = [dict(tag, value="another-migration") if tag["key"] == "MigrationId"
                         else tag for tag in share["tags"]]
    elif change == "another-owner":
        share["owningAccountId"] = DEPARTED
    elif change == "not-tool-named":
        share["name"] = "original-dns-share"
    stubs["ram"].add_response("get_resource_shares",
                              {"resourceShares": [] if change == "absent" else [share]}, SHARE_QUERY)
    with pytest.raises(MigrationError, match="refusing to remove principals from a share that is "
                                             "not this migration's temporary share"):
        remove_principals(OfflineRouter(cs), OWNER, REGION, TEMP, MIGRATION, [CONSUMER])


def test_principal_removal_needs_an_active_share_and_never_names_the_owner(clients):
    cs, stubs = clients
    with pytest.raises(MigrationError, match="never the owner"):
        remove_principals(OfflineRouter(cs), OWNER, REGION, TEMP, MIGRATION, [OWNER])
    stubs["ram"].add_response("get_resource_shares",
                              {"resourceShares": [shared_share(status="DELETING")]}, SHARE_QUERY)
    with pytest.raises(MigrationError, match="principals are removed only from an ACTIVE share"):
        remove_principals(OfflineRouter(cs), OWNER, REGION, TEMP, MIGRATION, [CONSUMER])


@pytest.mark.parametrize("rows", [
    [(CONSUMER, "DISASSOCIATED"), (OTHER, "ASSOCIATED")],
    [(OTHER, "ASSOCIATED")],
], ids=["disassociated", "never-associated"])
def test_principal_removal_is_a_no_op_for_a_principal_already_gone(clients, rows):
    cs, stubs = clients
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [shared_share()]}, SHARE_QUERY)
    stubs["ram"].add_response("get_resource_share_associations", principal_rows(*rows),
                              PRINCIPAL_QUERY)
    remove_principals(OfflineRouter(cs), OWNER, REGION, TEMP, MIGRATION, [CONSUMER])


def test_principal_removal_disassociates_only_the_named_principal_and_waits(clients, monkeypatch):
    cs, stubs = clients
    monkeypatch.setattr("ram_migration_stacks.time.sleep", lambda _seconds: None)
    ram = stubs["ram"]
    ram.add_response("get_resource_shares", {"resourceShares": [shared_share()]}, SHARE_QUERY)
    ram.add_response("get_resource_share_associations",
                     principal_rows((CONSUMER, "ASSOCIATED"), (OTHER, "ASSOCIATED")), PRINCIPAL_QUERY)
    # Exactly the named principal: never the other one, never a resource.
    ram.add_response("disassociate_resource_share", principal_rows((CONSUMER, "DISASSOCIATING")),
                     {"resourceShareArn": TEMP, "principals": [CONSUMER]})
    ram.add_response("get_resource_share_associations",
                     principal_rows((CONSUMER, "DISASSOCIATING"), (OTHER, "ASSOCIATED")),
                     PRINCIPAL_QUERY)
    ram.add_response("get_resource_share_associations",
                     principal_rows((CONSUMER, "DISASSOCIATED"), (OTHER, "ASSOCIATED")),
                     PRINCIPAL_QUERY)
    remove_principals(OfflineRouter(cs), OWNER, REGION, TEMP, MIGRATION, [CONSUMER])


def test_principal_removal_waits_for_a_disassociation_already_under_way(clients, monkeypatch):
    cs, stubs = clients
    monkeypatch.setattr("ram_migration_stacks.time.sleep", lambda _seconds: None)
    ram = stubs["ram"]
    ram.add_response("get_resource_shares", {"resourceShares": [shared_share()]}, SHARE_QUERY)
    ram.add_response("get_resource_share_associations",
                     principal_rows((CONSUMER, "DISASSOCIATING"), (OTHER, "ASSOCIATED")),
                     PRINCIPAL_QUERY)
    ram.add_response("get_resource_share_associations", principal_rows((OTHER, "ASSOCIATED")),
                     PRINCIPAL_QUERY)
    remove_principals(OfflineRouter(cs), OWNER, REGION, TEMP, MIGRATION, [CONSUMER])


def test_principal_removal_that_does_not_finish_times_out(clients):
    cs, stubs = clients
    ram = stubs["ram"]
    ram.add_response("get_resource_shares", {"resourceShares": [shared_share()]}, SHARE_QUERY)
    ram.add_response("get_resource_share_associations", principal_rows((CONSUMER, "ASSOCIATED")),
                     PRINCIPAL_QUERY)
    ram.add_response("disassociate_resource_share", principal_rows((CONSUMER, "DISASSOCIATING")),
                     {"resourceShareArn": TEMP, "principals": [CONSUMER]})
    ram.add_response("get_resource_share_associations",
                     principal_rows((CONSUMER, "DISASSOCIATING")), PRINCIPAL_QUERY)
    with pytest.raises(MigrationError, match="principal removal did not finish before the timeout"):
        remove_principals(OfflineRouter(cs), OWNER, REGION, TEMP, MIGRATION, [CONSUMER], timeout=0)


def test_unserved_consumers_reads_what_the_share_now_holds(clients):
    cs, stubs = clients
    ram, router = stubs["ram"], OfflineRouter(cs, readonly=True)
    ram.add_response("get_resource_shares", {"resourceShares": [shared_share()]}, SHARE_QUERY)
    ram.add_response("get_resource_share_associations",
                     principal_rows((CONSUMER, "DISASSOCIATED"), (OTHER, "DISASSOCIATING")),
                     PRINCIPAL_QUERY)
    assert unserved_consumers(router, OWNER, REGION, TEMP, [CONSUMER, OTHER]) == {CONSUMER}
    for rows in ([shared_share(status="DELETED")], []):  # a deleted share serves no one
        ram.add_response("get_resource_shares", {"resourceShares": rows}, SHARE_QUERY)
        assert unserved_consumers(router, OWNER, REGION, TEMP, [CONSUMER, OTHER]) == {CONSUMER, OTHER}


def test_share_deletion_refuses_a_share_that_is_not_this_migrations(clients, monkeypatch):
    cs, stubs = clients
    monkeypatch.setattr("ram_migration_stacks.time.sleep", lambda _seconds: None)
    ram = stubs["ram"]
    ram.add_response("get_resource_shares",
                     {"resourceShares": [shared_share(name="original-dns-share")]}, SHARE_QUERY)
    with pytest.raises(MigrationError, match="refusing to delete a share that is not this "
                                             "migration's temporary share"):
        delete_share(OfflineRouter(cs), OWNER, REGION, TEMP, MIGRATION)
    ram.add_response("get_resource_shares", {"resourceShares": [shared_share()]}, SHARE_QUERY)
    ram.add_response("delete_resource_share", {"returnValue": True}, {"resourceShareArn": TEMP})
    ram.add_response("get_resource_shares", {"resourceShares": [shared_share(status="DELETED")]},
                     SHARE_QUERY)
    delete_share(OfflineRouter(cs), OWNER, REGION, TEMP, MIGRATION)


def invitation(share=TEMP, sender=OWNER, status="PENDING"):
    return {"resourceShareArn": share, "resourceShareInvitationArn": share + "/invitation",
            "senderAccountId": sender, "receiverAccountId": CONSUMER, "status": status}


def test_unrelated_invitations_are_excluded_and_accepted_invitations_are_reused(clients):
    cs, stubs = clients
    stubs["ram"].add_response("get_resource_share_invitations", {
        "resourceShareInvitations": [invitation(SOURCE), invitation(status="ACCEPTED"),
                                    invitation(TEMP + "Other", sender=OTHER)]}, {})
    accept(OfflineRouter(cs, consumer=cs["ram"]), CONSUMER, REGION, {TEMP: OWNER})


def test_invitation_wrong_expected_sender_is_rejected_before_acceptance(clients):
    cs, stubs = clients
    stubs["ram"].add_response("get_resource_share_invitations", {
        "resourceShareInvitations": [invitation(sender=OTHER)]}, {})
    with pytest.raises(MigrationError, match="owner/receiver mismatch"):
        accept(OfflineRouter(cs, consumer=cs["ram"]), CONSUMER, REGION, {TEMP: OWNER})


def test_only_approved_pending_invitation_is_accepted(clients):
    cs, stubs = clients
    stubs["ram"].add_response("get_resource_share_invitations", {
        "resourceShareInvitations": [invitation(SOURCE), invitation()]}, {})
    stubs["ram"].add_response("accept_resource_share_invitation", {}, {
        "resourceShareInvitationArn": TEMP + "/invitation"})
    accept(OfflineRouter(cs, consumer=cs["ram"]), CONSUMER, REGION, {TEMP: OWNER})


def test_expired_invitation_blocks_without_revoking_principal(clients):
    cs, stubs = clients
    stubs["ram"].add_response("get_resource_share_invitations", {
        "resourceShareInvitations": [invitation(status="EXPIRED")]}, {})
    with pytest.raises(MigrationError, match="reissue"):
        accept(OfflineRouter(cs, consumer=cs["ram"]), CONSUMER, REGION, {TEMP: OWNER})


# Regression tests for response shapes observed read-only against live AWS on
# 2026-10-14 (sandbox owners); account IDs are replaced by the offline test IDs.
TGW = "ec2:TransitGateway"
TGW_RESOURCE = f"arn:aws:ec2:{REGION}:{OWNER}:transit-gateway/tgw-079bc008585f3d5de"
# GetPermission's "permission" text for AWS managed permissions: one bare statement.
LIVE_PERMISSIONS = {
    KIND: ("arn:aws:ram::aws:permission/AWSRAMDefaultPermissionResolverRule", "1",
           '{"Effect":"Allow","Action":["route53resolver:GetResolverRule",'
           '"route53resolver:AssociateResolverRule","route53resolver:DisassociateResolverRule",'
           '"route53resolver:ListResolverRules","route53resolver:ListResolverRuleAssociations"]}'),
    TGW: ("arn:aws:ram::aws:permission/AWSRAMDefaultPermissionTransitGateway", "3",
          '{"Effect":"Allow","Action":["ec2:DescribeTransitGateways",'
          '"ec2:CreateTransitGatewayVpcAttachment","ec2:ModifyTransitGatewayVpcAttachment",'
          '"ec2:DeleteTransitGatewayVpcAttachment","network-firewall:CreateFirewall",'
          '"ec2:CreateClientVpnEndpoint"]}'),
}
LIVE_STATEMENT = json.loads(LIVE_PERMISSIONS[KIND][2])
LIVE_CATALOGUE = Path(__file__).parent / "fixtures" / "ram-shareable-20261014.md"
YES_ICON = "![](https://docs.aws.amazon.com/ram/latest/userguide/images/icon-yes.png)"
NO_ICON = "![](https://docs.aws.amazon.com/ram/latest/userguide/images/icon-no.png)"
# Live shareable.md rows, verbatim except for the abbreviated (unparsed) use-case column.
LIVE_ROWS = "\n".join([
    f"| Resolver\xa0rules<br />`route53resolver:ResolverRule` | Share Resolver rules. "
    f"|  {NO_ICON} No  |  {YES_ICON} Yes <br />Can share with **any** AWS account. "
    f"|  {NO_ICON} No  |  {NO_ICON} No  | ",
    f"| Transit gateways<br />`ec2:TransitGateway` | Share transit gateways. "
    f"|  {NO_ICON} No  |  {YES_ICON} Yes <br />Can share with **any** AWS account. "
    f"|  {NO_ICON} No  |  {NO_ICON} No  | ",
    f"| Bedrock Custom Model<br />`bedrock:CustomModel` | Share custom models. "
    f"|  {YES_ICON} Yes  |  {NO_ICON} No <br />Can share with **only** AWS accounts in its own "
    f"organization. |  {YES_ICON} Yes  |  {NO_ICON} No  | ",
    f"| Capacity\xa0reservations<br />`ec2:CapacityReservation` | Share reservations and blocks. "
    f"|  {NO_ICON} No  | Yes for Capacity Reservations (Can share with **any** AWS account).<br />"
    f"No for Capacity Blocks (Can share with **only** AWS accounts in its own organization). "
    f"|  {NO_ICON} No  |  {NO_ICON} No  | ",
])


def live_permission(kind=KIND):
    arn, version, text = LIVE_PERMISSIONS[kind]
    return {"arn": arn, "version": version, "defaultVersion": True,
            "name": arn.rsplit("/", 1)[1], "resourceType": kind, "permission": text,
            "creationTime": "2022-06-30T20:04:14.774000Z",
            "lastUpdatedTime": "2022-06-30T20:04:14.774000Z", "isResourceTypeDefault": True,
            "permissionType": "AWS_MANAGED", "featureSet": "STANDARD", "status": "ATTACHABLE"}


def live_share(arn, status="ACTIVE"):
    """GetResourceShares(resourceOwner=SELF) row, including a DELETED share's shape."""
    return {"resourceShareArn": arn, "name": "tf-logs-us-east-1-sim-resolver-rule-share",
            "owningAccountId": OWNER, "allowExternalPrincipals": True, "status": status,
            "tags": [{"key": "resource-managed-by", "value": "iac"},
                     {"key": "environment", "value": "sandbox"},
                     {"key": "Purpose", "value": "example"},
                     {"key": "CreatedVia", "value": "CloudFormation"}],
            "creationTime": "2026-10-14T04:42:04.556000Z",
            "lastUpdatedTime": "2026-10-14T05:04:32.995000Z", "featureSet": "STANDARD",
            "resourceShareConfiguration": {"retainSharingOnAccountLeaveOrganization": False}}


def live_resource(arn=RESOURCE, share=SOURCE, kind=KIND, **extra):
    """ListResources(resourceOwner=SELF) row: the owner's view carries no status field."""
    return {"arn": arn, "type": kind, "resourceShareArn": share,
            "creationTime": "2026-10-14T05:02:25.452000Z",
            "lastUpdatedTime": "2026-10-14T05:02:26.097000Z", "resourceRegionScope": "REGIONAL",
            **extra}


def live_group():
    arn, version, text = LIVE_PERMISSIONS[KIND]
    approved = {"Arn": arn, "Version": version, "ResourceType": KIND,
                "Policy": policy_semantics(text), "DefaultVersion": True}
    return ApprovedGroup(OWNER, REGION, (CONSUMER,), {KIND: arn}, {RESOURCE: KIND}, [SOURCE],
                         {KIND: approved}, [STACK_ID])


def stub_live_source(stubs, share, rows, kind=KIND):
    """Owner-side reads for one ACTIVE source share, in Discovery.inspect order."""
    arn, version, _ = LIVE_PERMISSIONS[kind]
    ram = stubs["ram"]
    ram.add_response("list_resources", {"resources": rows},
                     {"resourceOwner": "SELF", "resourceShareArns": [share]})
    ram.add_response("get_resource_share_associations", {"resourceShareAssociations": [
        association(CONSUMER, "PRINCIPAL", share=share)]},
        {"associationType": "PRINCIPAL", "resourceShareArns": [share]})
    no_stack(stubs["cloudformation"], physical=True, arn=share)
    ram.add_response("list_resource_share_permissions", {"permissions": [{
        "arn": arn, "version": version, "resourceType": kind, "defaultVersion": True}]},
        {"resourceShareArn": share})
    ram.add_response("get_permission", {"permission": live_permission(kind)}, {"permissionArn": arn})


def test_policy_semantics_accepts_live_bare_statement_and_statement_lists():
    normalized = policy_semantics(LIVE_PERMISSIONS[KIND][2])
    assert normalized == {"Statement": [{"Action": sorted(LIVE_STATEMENT["Action"]),
                                         "Effect": "Allow"}]}
    assert policy_semantics(LIVE_STATEMENT) == policy_semantics([LIVE_STATEMENT]) == normalized
    assert policy_semantics({"Statement": LIVE_STATEMENT}) == normalized
    assert policy_semantics(normalized) == normalized
    # Wrapping never relaxes comparison: any action/effect/scope change still differs.
    for different in ({**LIVE_STATEMENT, "Action": LIVE_STATEMENT["Action"][:-1]},
                      {**LIVE_STATEMENT, "Action": LIVE_STATEMENT["Action"] + ["route53resolver:*"]},
                      {**LIVE_STATEMENT, "Effect": "Deny"},
                      {**LIVE_STATEMENT, "Resource": "arn:aws:route53resolver:*:*:resolver-rule/*"},
                      [LIVE_STATEMENT, {"Effect": "Allow", "Action": "ec2:*"}]):
        assert policy_semantics(different) != normalized


@pytest.mark.parametrize("document", [
    {}, {"Version": "2012-10-17"}, {"Effect": "Allow"}, [], [{"Effect": "Allow"}],
    [LIVE_STATEMENT, "Allow"], "[]", '"Allow"',
])
def test_policy_semantics_still_rejects_documents_without_statements(document):
    with pytest.raises(MigrationError, match="no Statement"):
        policy_semantics(document)


@pytest.mark.parametrize("kind", [KIND, TGW])
def test_permission_snapshot_accepts_live_get_permission_response(clients, kind):
    cs, stubs = clients
    arn, version, text = LIVE_PERMISSIONS[kind]
    stubs["ram"].add_response("get_permission", {"permission": live_permission(kind)},
                             {"permissionArn": arn})
    assert permission_snapshot(Api(cs["ram"]), arn) == {
        "Arn": arn, "Version": version, "ResourceType": kind,
        "Policy": {"Statement": [{"Action": sorted(json.loads(text)["Action"]), "Effect": "Allow"}]},
        "DefaultVersion": True}


def test_live_catalogue_rows_parse_standard_qualifiers_and_keep_conditional_rows_unknown():
    assert external_catalog(LIVE_ROWS) == {
        KIND.lower(): True, TGW.lower(): True, "bedrock:custommodel": False}


@pytest.mark.parametrize("cell", [
    f"{YES_ICON} Yes <br />Can share with **only** AWS accounts in its own organization.",
    f"{NO_ICON} No <br />Can share with **any** AWS account.",
    f"{YES_ICON} Yes <br />Can share with **any** AWS account, except Capacity Blocks.",
    f"{YES_ICON} Yes <br />Can share with **any** AWS account.<br />No for Capacity Blocks.",
    "Yes <br />Can share with **any** AWS account.",
])
def test_catalogue_qualifier_must_restate_the_icon_answer(cell):
    rows = f"| `{KIND}` | a | b | {cell} | d | e |\n| `ec2:Subnet` | a | b | {NO_ICON} No | d | e |"
    assert external_catalog(rows) == {"ec2:subnet": False}


@pytest.mark.skipif(not LIVE_CATALOGUE.exists(), reason="needs a saved copy of the AWS RAM "
                    "shareable-resources page as tests/fixtures/ram-shareable-20261014.md")
def test_live_catalogue_fixture_keeps_every_unconditional_row():
    values = external_catalog(LIVE_CATALOGUE.read_text(encoding="utf-8"))
    # 86 rows name 87 types; only the Capacity Reservations/Blocks row is conditional.
    assert len(values) == 86 and sum(values.values()) == 72
    assert values[KIND.lower()] is True and values[TGW.lower()] is True
    assert values["ec2:subnet"] is False and values["bedrock:custommodel"] is False
    assert "ec2:capacityreservation" not in values


def test_live_owner_shapes_plan_and_deleted_share_is_an_exclusion(clients):
    cs, stubs = clients
    deleted, tgw_share = SOURCE + "-deleted", SOURCE + "-tgw"
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [
        live_share(deleted, "DELETED"), live_share(SOURCE), live_share(tgw_share)]},
        {"resourceOwner": "SELF"})
    # The DELETED share needs no further reads; strict stubs reject any extra call.
    stub_live_source(stubs, SOURCE, [live_resource()])
    stub_live_source(stubs, tgw_share, [live_resource(TGW_RESOURCE, tgw_share, TGW)], TGW)
    result = inspect(cs, capabilities=external_catalog(LIVE_ROWS))
    assert not result.blocked and not result.existing
    assert result.excluded == [f"{deleted}: deleted share (status DELETED)"]
    assert {kind: (g.resources, g.source_shares, g.consumers)
            for g in result.groups for kind in g.permissions} == {
        KIND: ({RESOURCE: KIND}, [SOURCE], (CONSUMER,)),
        TGW: ({TGW_RESOURCE: TGW}, [tgw_share], (CONSUMER,))}
    for g in result.groups:
        kind, = g.permissions
        assert g.permission_snapshots[kind]["Policy"] == policy_semantics(LIVE_PERMISSIONS[kind][2])


def test_deleted_migration_tagged_share_is_excluded_without_provenance_reads(clients):
    cs, stubs = clients
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [
        {**migration_share(), "status": "DELETED"}]}, {"resourceOwner": "SELF"})
    result = inspect(cs)
    assert not result.blocked and not result.groups and not result.existing
    assert result.excluded == [f"{TEMP}: deleted share (status DELETED)"]


def test_a_pending_source_share_still_blocks(clients):
    cs, stubs = clients
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [
        live_share(SOURCE, "PENDING")]}, {"resourceOwner": "SELF"})
    result = inspect(cs)
    assert not result.groups and not result.excluded
    assert result.blocked == [f"{SOURCE}: owner={OWNER} region={REGION} source status PENDING"]


@pytest.mark.parametrize("status", ["DELETING", "FAILED"])
def test_a_source_share_that_grants_nothing_now_is_excluded_not_blocked(clients, status):
    """The migration cannot change access a share does not give."""
    cs, stubs = clients
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [
        live_share(SOURCE, status)]}, {"resourceOwner": "SELF"})
    result = inspect(cs)
    assert not result.groups and not result.blocked
    assert result.excluded == [f"{SOURCE}: source status {status}; it grants no access now, so "
                               "the migration does not change it"]


def test_an_owner_side_resource_being_added_still_blocks(clients):
    cs, stubs = clients
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [live_share(SOURCE)]},
                             {"resourceOwner": "SELF"})
    stub_live_source(stubs, SOURCE, [live_resource(status="PENDING")])
    result = inspect(cs)
    assert not result.groups
    assert result.blocked == [f"{SOURCE}: owner={OWNER} region={REGION} {RESOURCE}: resource status PENDING"]


@pytest.mark.parametrize("status", ["UNAVAILABLE", "ZONAL_RESOURCE_INACCESSIBLE", "LIMIT_EXCEEDED"])
def test_an_owner_side_resource_the_share_cannot_provide_now_is_left_out(clients, status):
    cs, stubs = clients
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [live_share(SOURCE)]},
                             {"resourceOwner": "SELF"})
    stub_live_source(stubs, SOURCE, [live_resource(status=status)])
    result = inspect(cs)
    assert not result.groups and not result.blocked
    assert result.excluded == [
        f"{SOURCE}: resource {RESOURCE} status {status}; it is not available through this share "
        "now, so the migration does not change it",
        f"{SOURCE}: no resource is available through this share now; the migration does not "
        "change it"]


@pytest.mark.parametrize("status", [None, "UNAVAILABLE"])
def test_persisted_groups_accept_live_owner_rows_but_not_explicit_unavailability(clients, status):
    cs, stubs = clients
    g = live_group()
    arn, version, _ = LIVE_PERMISSIONS[KIND]
    stubs["cloudformation"].add_response("describe_stacks", {"Stacks": [stack_info()]},
        {"StackName": stack_name(MIGRATION, OWNER, REGION)})
    stubs["cloudformation"].add_response("get_template", {
        "TemplateBody": json.dumps(template_for([g], MIGRATION))},
        {"StackName": STACK_ID, "TemplateStage": "Processed"})
    stubs["ram"].add_response("get_permission", {"permission": live_permission()},
                             {"permissionArn": arn, "permissionVersion": int(version)})
    row = live_resource(share=TEMP, **({"status": status} if status else {}))
    stubs["ram"].add_response("list_resources", {"resources": [row]},
                             {"resourceOwner": "SELF", "resourceArns": [RESOURCE]})
    stacks = Stacks(OfflineRouter(cs), MIGRATION)
    if status is None:
        assert stacks.persisted_groups(OWNER, REGION) == [g]
    else:
        with pytest.raises(MigrationError, match="approved available resources"):
            stacks.persisted_groups(OWNER, REGION)


@pytest.mark.parametrize("consumer_status", ["AVAILABLE", None, "PENDING"])
def test_verification_accepts_live_owner_rows_but_consumer_view_must_be_available(
        clients, consumer_status):
    cs, stubs = clients
    g = live_group()
    arn, version, _ = LIVE_PERMISSIONS[KIND]
    ram = stubs["ram"]
    ram.add_response("list_resource_share_permissions", {"permissions": [{
        "arn": arn, "version": version, "resourceType": KIND}]}, {"resourceShareArn": TEMP})
    ram.add_response("get_permission", {"permission": live_permission()},
                     {"permissionArn": arn, "permissionVersion": int(version)})
    ram.add_response("get_resource_share_associations", {"resourceShareAssociations": [
        association(RESOURCE, "RESOURCE")]}, {"associationType": "RESOURCE", "resourceShareArns": [TEMP]})
    ram.add_response("list_resources", {"resources": [live_resource(share=TEMP)]},
                     {"resourceOwner": "SELF", "resourceShareArns": [TEMP]})
    ram.add_response("get_resource_share_associations", {"resourceShareAssociations": [
        association(CONSUMER, "PRINCIPAL")]}, {"associationType": "PRINCIPAL", "resourceShareArns": [TEMP]})
    consumer = botocore.session.get_session().create_client(
        "ram", region_name=REGION, config=Config(signature_version=UNSIGNED))
    visible = live_resource(share=TEMP, **({"status": consumer_status} if consumer_status else {}))
    with Stubber(consumer) as stub:
        stub.add_response("list_resources", {"resources": [visible]},
                          {"resourceOwner": "OTHER-ACCOUNTS", "resourceShareArns": [TEMP]})
        router = OfflineRouter(cs, consumer=consumer)
        if consumer_status == "AVAILABLE":
            verify_group(router, g, migration_share(g), MIGRATION)
        else:
            with pytest.raises(MigrationError, match="approved available resources"):
                verify_group(router, g, migration_share(g), MIGRATION)
        stub.assert_no_pending_responses()


# ---------------------------------------------------------------------------
# Managed-permission differences: reported, never approved; earlier versions' stack rows
# ---------------------------------------------------------------------------
from ram_migration_discovery import (  # noqa: E402
    describe_difference, grants_less, permission_change, policy_difference, policy_sha256,
)
from ram_migration_stacks import _validate_template  # noqa: E402

TGW_ACTIONS = ["ec2:CreateTransitGatewayVpcAttachment", "ec2:DeleteTransitGatewayVpcAttachment",
               "ec2:DescribeTransitGateways", "ec2:ModifyTransitGatewayVpcAttachment",
               "network-firewall:CreateFirewall"]
TGW_V2 = {"Effect": "Allow", "Action": TGW_ACTIONS}            # GetPermission's bare shape
TGW_V3 = {"Effect": "Allow", "Action": TGW_ACTIONS + ["ec2:CreateClientVpnEndpoint"]}
NARROWER = {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Action": ["route53resolver:GetResolverRule"], "Resource": "*"}]}


def test_tgw_v2_to_v3_comparison_shows_only_client_vpn_endpoint():
    difference = policy_difference(TGW_V2, TGW_V3)
    assert difference["actions_added"] == ["Allow ec2:CreateClientVpnEndpoint"]
    lines = describe_difference(difference)
    assert lines[0] == "grants more: Allow ec2:CreateClientVpnEndpoint"
    assert lines[-1] == "actions added: Allow ec2:CreateClientVpnEndpoint"
    assert policy_sha256(TGW_V2) != policy_sha256(TGW_V3)
    assert policy_sha256(TGW_V3) == policy_sha256({"Statement": [TGW_V3]})  # shape-independent


def test_comparison_reports_removed_actions_resources_and_conditions_per_effect():
    before = {"Statement": [{"Effect": "Allow", "Action": ["a:One", "a:Two"], "Resource": "*",
                             "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-first"}}}]}
    after = {"Statement": [{"Effect": "Allow", "Action": ["a:One"], "Resource": "arn:x",
                            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-other"}}},
                           {"Effect": "Deny", "Action": ["a:Two"], "Resource": "*"}]}
    difference = policy_difference(before, after)
    assert difference["actions_removed"] == ["Allow a:Two"]
    assert difference["actions_added"] == ["Deny a:Two"]          # a deny is never shown as a grant
    assert difference["resources_added"] == ["Allow arn:x", "Deny *"]
    assert "Allow *" in difference["resources_removed"]
    assert any("o-other" in c for c in difference["conditions_added"])
    assert any("o-first" in c for c in difference["conditions_removed"])


def stub_changed_share(stubs):
    stub_discovery(stubs, attached_version="1", attached_policy=NARROWER)


def expected_change():
    prior = {"Arn": PERMISSION, "Version": "1", "ResourceType": KIND,
             "Policy": policy_semantics(NARROWER), "DefaultVersion": False}
    default = {"Arn": PERMISSION, "Version": "2", "ResourceType": KIND,
               "Policy": policy_semantics(POLICY), "DefaultVersion": True}
    return permission_change(OWNER, REGION, SOURCE, prior, default)


def test_a_permission_difference_plans_the_default_and_is_reported_without_approval(clients):
    """The original attaches v1. The temporary share receives the default, v2; the
    difference is the plan's information, never a blocker or an approval request."""
    cs, stubs = clients
    stub_changed_share(stubs)
    result = inspect(cs)
    assert not result.blocked
    g, = result.groups
    assert g.permission_snapshots[KIND]["Version"] == "2"      # temporary share gets the default
    assert not hasattr(g, "permission_changes")                 # a group carries no approval
    change, = result.permission_changes
    assert change == dict(expected_change(),
                          applies_to="new temporary share (receives the current default)")
    assert describe_difference(change["difference"])[:2] == [
        "grants more: Allow route53resolver:AssociateResolverRule",
        "BROADENED Allow route53resolver:AssociateResolverRule: before not granted; "
        "after on * unconditionally"]
    assert grants_less(change["difference"]) == []


def test_a_share_blocked_after_its_comparison_reports_no_difference(clients):
    """Only a planned share reports a difference; this one fails its capability check."""
    cs, stubs = clients
    stub_changed_share(stubs)
    result = inspect(cs, capabilities={})
    assert not result.groups and "external-sharing capability" in result.blocked[0]
    assert not result.permission_changes


def test_permission_type_mismatch_still_blocks(clients):
    cs, stubs = clients
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [
        {"resourceShareArn": SOURCE, "owningAccountId": OWNER, "status": "ACTIVE", "tags": []}]},
        {"resourceOwner": "SELF"})
    stubs["ram"].add_response("list_resources", {"resources": [resource()]},
                              {"resourceOwner": "SELF", "resourceShareArns": [SOURCE]})
    stubs["ram"].add_response("get_resource_share_associations", {"resourceShareAssociations": [
        association(CONSUMER, "PRINCIPAL", share=SOURCE)]},
        {"associationType": "PRINCIPAL", "resourceShareArns": [SOURCE]})
    no_stack(stubs["cloudformation"], physical=True)
    stubs["ram"].add_response("list_resource_share_permissions", {"permissions": [{
        "arn": PERMISSION, "version": "1", "resourceType": KIND, "defaultVersion": False}]},
        {"resourceShareArn": SOURCE})
    stubs["ram"].add_response("get_permission", {"permission": permission()}, {"permissionArn": PERMISSION})
    stubs["ram"].add_response("get_permission", {"permission": permission(
        "1", NARROWER, default=False, kind="ec2:TransitGateway")},
        {"permissionArn": PERMISSION, "permissionVersion": 1})
    result = inspect(cs)
    assert not result.groups and "type differs" in result.blocked[0]
    assert not result.permission_changes


def earlier_template(g):
    """The template an earlier version wrote for a share created under an approved v1 -> v2
    difference: its metadata also holds a PermissionChanges row naming that approval (the ID
    that version derived for expected_change)."""
    template = template_for([g], MIGRATION)
    change = expected_change()
    template["Resources"][g.logical_id]["Metadata"]["PermissionChanges"] = [{
        "SourceShareArn": SOURCE, "PermissionArn": PERMISSION, "ResourceType": KIND,
        "FromVersion": "1", "ToVersion": "2", "FromPolicySha256": change["from_policy_sha256"],
        "ToPolicySha256": change["to_policy_sha256"], "ApprovalId": "pc-7e317668eab8c023"}]
    return template


def test_a_template_records_what_a_share_attaches_and_no_permission_difference():
    g = group(approved=True)
    metadata = template_for([g], MIGRATION)["Resources"][g.logical_id]["Metadata"]
    assert set(metadata) == {"SourceShareArns", "SourceStackIds", "OwnerRegion",
                             "ResourceTypes", "PermissionTypes", "PermissionSnapshots"}


def test_earlier_permission_change_rows_are_kept_verbatim_and_never_change_a_template():
    """The rows are history: never read, so never validated or rewritten. This version's
    template of the same share merges into the deployed one without any change, and the rows
    stay as they are when the share grows."""
    g = group(approved=True)
    deployed = earlier_template(g)
    _validate_template(deployed, MIGRATION)
    assert additive_template(deployed, template_for([g], MIGRATION), MIGRATION) == deployed
    grown = additive_template(deployed, template_for([group(
        resources={RESOURCE + "2": KIND}, sources=[SOURCE + "2"], approved=True)], MIGRATION),
        MIGRATION)
    item = grown["Resources"][g.logical_id]
    assert item["Properties"]["ResourceArns"] == [RESOURCE, RESOURCE + "2"]
    assert item["Metadata"]["SourceShareArns"] == [SOURCE, SOURCE + "2"]
    assert item["Metadata"]["PermissionChanges"] == \
        deployed["Resources"][g.logical_id]["Metadata"]["PermissionChanges"]
    unread = copy.deepcopy(deployed)
    unread["Resources"][g.logical_id]["Metadata"]["PermissionChanges"][0]["ToVersion"] = "9"
    _validate_template(unread, MIGRATION)


def test_a_stack_with_earlier_permission_change_rows_is_read_verified_and_not_rewritten(clients):
    """persisted_groups recovers the group without the rows, the share verifies against the
    version it keeps, prepare returns the deployed template unchanged, and apply finds
    nothing to write (strict stubs: no change set is created)."""
    cs, stubs = clients
    g = group(approved=True)
    deployed = earlier_template(g)
    cfn, ram, name = stubs["cloudformation"], stubs["ram"], stack_name(MIGRATION, OWNER, REGION)
    read = {"StackName": STACK_ID, "TemplateStage": "Processed"}
    stacks = Stacks(OfflineRouter(cs), MIGRATION)

    def deployed_stack():
        cfn.add_response("describe_stacks", {"Stacks": [stack_info()]}, {"StackName": name})
        cfn.add_response("get_template", {"TemplateBody": json.dumps(deployed)}, read)
        ram.add_response("get_permission", {"permission": permission()},  # the kept version
                         {"permissionArn": PERMISSION, "permissionVersion": 2})
    deployed_stack()
    ram.add_response("list_resources", {"resources": [resource()]},
                     {"resourceOwner": "SELF", "resourceArns": [RESOURCE]})
    recovered, = stacks.persisted_groups(OWNER, REGION)
    assert recovered == g and not hasattr(recovered, "permission_changes")
    stub_verification(ram, recovered)
    consumer = botocore.session.get_session().create_client(
        "ram", region_name=REGION, config=Config(signature_version=UNSIGNED))
    with Stubber(consumer) as stub:
        stub.add_response("list_resources", {"resources": [resource()]},
                          {"resourceOwner": "OTHER-ACCOUNTS", "resourceShareArns": [TEMP]})
        verify_group(OfflineRouter(cs, consumer=consumer), recovered, migration_share(recovered),
                     MIGRATION)
        stub.assert_no_pending_responses()
    deployed_stack()
    body, old = stacks.prepare(OWNER, REGION, [recovered], fresh=True)
    assert body == deployed and old["StackId"] == STACK_ID
    deployed_stack()
    cfn.add_response("get_template", {"TemplateBody": json.dumps(deployed)}, read)  # apply's reread
    assert stacks.apply(OWNER, REGION, [recovered]) == name


# ---------------------------------------------------------------------------
# Account roles: migrating owners (v0.2.0)
# ---------------------------------------------------------------------------

def test_stationary_owner_with_unrelated_consumers_only_excludes_them(clients):
    cs, stubs = clients
    stub_discovery(stubs, principals={SOURCE: [CONSUMER, OTHER]})
    result = Discovery(OfflineRouter(cs), {CONSUMER}, MIGRATION, {}, {KIND.lower(): True},
                       migrating_owners=set()).inspect(OWNER, REGION)
    assert not result.blocked and result.groups[0].consumers == (CONSUMER,)
    assert any("unrelated consumers outside migration population" in e for e in result.excluded)


# ---------------------------------------------------------------------------
# Statement-level permission comparison: bindings, wildcards, Deny
# ---------------------------------------------------------------------------
ORG = {"StringEquals": {"aws:PrincipalOrgID": "o-abc123"}}
ORG_TEXT = '{"StringEquals":{"aws:PrincipalOrgID":["o-abc123"]}}'
DESCRIBE, ATTACH = "ec2:DescribeTransitGateways", "ec2:CreateTransitGatewayVpcAttachment"
ONLY = "arn:aws:a:us-east-1:000000000001:thing/only"
FACETS = ("actions", "not_actions", "resources", "not_resources", "conditions", "principals")
STRUCTURE_ONLY = ("statements differ only in structure; every action keeps the same "
                  "resources and conditions")


def allow(action, **extra):
    return {"Effect": "Allow", "Action": action, **extra}


def deny(action, **extra):
    return {"Effect": "Deny", "Action": action, **extra}


def access(before, after):
    """{(effect, action): status} for every (effect, action) the comparison reports."""
    return {(e["effect"], e["action"]): e["status"]
            for e in policy_difference(before, after)["access"]}


def changes(before, after):
    return {k: v for k, v in access(before, after).items() if v != "UNCHANGED"}


def comparison(before, after):
    return describe_difference(policy_difference(before, after))


def test_real_tgw_v2_to_v3_reports_exactly_client_vpn_endpoint_as_a_broadening():
    v3 = LIVE_PERMISSIONS[TGW][2]                         # GetPermission's live v3 text
    v2 = json.dumps({"Effect": "Allow", "Action": [
        a for a in json.loads(v3)["Action"] if a != "ec2:CreateClientVpnEndpoint"]})
    assert (policy_sha256(v2), policy_sha256(v3)) == (policy_sha256(TGW_V2), policy_sha256(TGW_V3))
    difference = policy_difference(v2, v3)
    assert changes(v2, v3) == {("Allow", "ec2:CreateClientVpnEndpoint"): "BROADENED"}
    assert difference["summary"] == "grants more: Allow ec2:CreateClientVpnEndpoint"
    assert describe_difference(difference) == [
        "grants more: Allow ec2:CreateClientVpnEndpoint",
        "BROADENED Allow ec2:CreateClientVpnEndpoint: before not granted; "
        "after on the shared resources unconditionally",
        "unchanged access: Allow ec2:CreateTransitGatewayVpcAttachment, "
        "Allow ec2:DeleteTransitGatewayVpcAttachment, Allow ec2:DescribeTransitGateways, "
        "Allow ec2:ModifyTransitGatewayVpcAttachment, Allow network-firewall:CreateFirewall",
        "actions added: Allow ec2:CreateClientVpnEndpoint"]


def test_dropped_condition_is_shown_as_a_broadening_with_both_bindings():
    before = [allow([DESCRIBE], Condition=ORG), allow([ATTACH], Condition=ORG)]
    after = [allow([DESCRIBE], Condition=ORG), allow([ATTACH])]
    assert comparison(before, after) == [
        f"grants more: Allow {ATTACH}",
        f"BROADENED Allow {ATTACH}: before on the shared resources when {ORG_TEXT}; "
        "after on the shared resources unconditionally",
        f"unchanged access: Allow {DESCRIBE}"]


@pytest.mark.parametrize("before,after,expected", [
    # The second statement drops the organization condition.
    ([allow([DESCRIBE], Condition=ORG), allow([ATTACH], Condition=ORG)],
     [allow([DESCRIBE], Condition=ORG), allow([ATTACH])], {("Allow", ATTACH): "BROADENED"}),
    # An action moves out of its conditioned statement into an unconditioned one.
    (allow([DESCRIBE, ATTACH], Condition=ORG),
     [allow([DESCRIBE], Condition=ORG), allow([ATTACH])], {("Allow", ATTACH): "BROADENED"}),
    # An unconditioned twin joins the conditioned statement.
    (allow("a:X", Condition=ORG), [allow("a:X", Condition=ORG), allow("a:X")],
     {("Allow", "a:X"): "BROADENED"}),
    # The condition moves from a:Write to a:Read.
    ([allow("a:Write", Condition=ORG), allow("a:Read")],
     [allow("a:Read", Condition=ORG), allow("a:Write")],
     {("Allow", "a:Write"): "BROADENED", ("Allow", "a:Read"): "NARROWED"}),
])
def test_moved_conditions_are_compared_per_action_not_reported_as_structure(
        before, after, expected):
    difference = policy_difference(before, after)
    assert policy_sha256(before) != policy_sha256(after)
    # Pooled facets cannot see these changes at all.
    assert not any(difference[f"{facet}_{verb}"] for facet in FACETS for verb in ("added", "removed"))
    assert changes(before, after) == expected
    lines = describe_difference(difference)
    assert lines[0].startswith("grants more: ")
    assert not any("structure" in line or "no facet-level" in line for line in lines)


def test_resource_widening_for_one_action_is_a_broadening_not_a_removal():
    before = [allow("a:Read", Resource="*"), allow("a:Write", Resource=ONLY)]
    after = allow(["a:Read", "a:Write"], Resource="*")
    difference = policy_difference(before, after)
    assert difference["resources_removed"] == [f"Allow {ONLY}"]    # alone, reads as a narrowing
    assert changes(before, after) == {("Allow", "a:Write"): "BROADENED"}
    assert describe_difference(difference) == [
        "grants more: Allow a:Write",
        f"BROADENED Allow a:Write: before on {ONLY} unconditionally; after on * unconditionally",
        "unchanged access: Allow a:Read",
        f"resources removed: Allow {ONLY}"]


@pytest.mark.parametrize("narrow,wide", [
    (ONLY, "arn:aws:a:us-east-1:000000000001:thing/*"),
    (ONLY, "arn:aws:a:*:000000000001:thing/only"),
    ("arn:aws:a:us-east-1:000000000001:thing/*", "*"),
])
def test_resource_wildcards_widen_and_narrow_one_action(narrow, wide):
    assert changes(allow("a:X", Resource=narrow), allow("a:X", Resource=wide)) == {
        ("Allow", "a:X"): "BROADENED"}
    assert changes(allow("a:X", Resource=wide), allow("a:X", Resource=narrow)) == {
        ("Allow", "a:X"): "NARROWED"}


@pytest.mark.parametrize("wildcard", ["ec2:*", "*", "ec2:Describe*", "ec2:*TransitGateway*"])
def test_a_new_wildcard_action_is_a_broadening_and_the_covered_action_stays_granted(wildcard):
    before, after = allow([DESCRIBE]), allow([wildcard])
    assert access(before, after) == {("Allow", wildcard): "BROADENED",
                                     ("Allow", DESCRIBE): "UNCHANGED"}
    lines = comparison(before, after)
    assert lines[:3] == [
        f"grants more: Allow {wildcard}",
        f"BROADENED Allow {wildcard}: before not granted as a whole; "
        "after on the shared resources unconditionally",
        f"unchanged access: Allow {DESCRIBE}"]
    assert f"actions removed: Allow {DESCRIBE}" in lines          # the facet line is kept


def test_not_action_grant_is_a_broadening_although_the_listed_actions_disappear():
    before = allow([DESCRIBE, ATTACH])
    after = {"Effect": "Allow", "NotAction": ["ec2:DeleteTransitGateway"]}
    difference = policy_difference(before, after)
    assert difference["actions_removed"] == [f"Allow {ATTACH}", f"Allow {DESCRIBE}"]
    assert changes(before, after) == {
        ("Allow", "NotAction [ec2:DeleteTransitGateway]"): "BROADENED"}
    assert describe_difference(difference)[:3] == [
        "grants more: Allow NotAction [ec2:DeleteTransitGateway]",
        "BROADENED Allow NotAction [ec2:DeleteTransitGateway]: before not granted as a whole; "
        "after on the shared resources unconditionally",
        f"unchanged access: Allow {ATTACH}, Allow {DESCRIBE}"]


@pytest.mark.parametrize("before,after,expected", [
    # A NotAction that excludes less grants more.
    ({"Effect": "Allow", "NotAction": ["iam:*", "ec2:Delete*"]},
     {"Effect": "Allow", "NotAction": ["iam:*"]},
     {("Allow", "NotAction [iam:*]"): "BROADENED",
      ("Allow", "NotAction [ec2:Delete*, iam:*]"): "UNCHANGED"}),
    # NotResource replaces one named resource.
    (allow("a:X", Resource=ONLY),
     allow("a:X", NotResource="arn:aws:a:us-east-1:000000000001:thing/secret"),
     {("Allow", "a:X"): "BROADENED"}),
    # NotResource replaces the share's own resources, which it never provably covers.
    (allow("a:X"), allow("a:X", NotResource=ONLY), {("Allow", "a:X"): "CHANGED"}),
])
def test_not_action_and_not_resource_are_treated_conservatively(before, after, expected):
    assert access(before, after) == expected
    assert comparison(before, after)[0].startswith("grants more: ")


def test_removing_a_deny_is_a_broadening():
    granted = allow("ec2:*TransitGateway*")
    before = [granted, deny("ec2:Delete*")]
    difference = policy_difference(before, granted)
    assert difference["actions_removed"] == ["Deny ec2:Delete*"]      # the only facet line
    assert changes(before, granted) == {("Deny", "ec2:Delete*"): "BROADENED"}
    assert describe_difference(difference) == [
        "grants more: Deny ec2:Delete* (deny removed)",
        "BROADENED Deny ec2:Delete*: before on the shared resources unconditionally; "
        "after not denied as a whole",
        "unchanged access: Allow ec2:*TransitGateway*",
        "actions removed: Deny ec2:Delete*"]


@pytest.mark.parametrize("after,expected,first", [
    # The Deny gains a condition, so it denies less.
    ([allow("ec2:*"), deny("ec2:Delete*", Condition=ORG)],
     {("Deny", "ec2:Delete*"): "BROADENED"}, "grants more: Deny ec2:Delete* (deny weakened)"),
    # The Deny shrinks to one action: ec2:Delete* as a whole is no longer denied.
    ([allow("ec2:*"), deny("ec2:DeleteTransitGateway")],
     {("Deny", "ec2:Delete*"): "BROADENED"}, "grants more: Deny ec2:Delete* (deny removed)"),
    ([allow("ec2:*")], {("Deny", "ec2:Delete*"): "BROADENED"},
     "grants more: Deny ec2:Delete* (deny removed)"),
])
def test_a_deny_that_applies_to_less_grants_more(after, expected, first):
    before = [allow("ec2:*"), deny("ec2:Delete*")]
    assert changes(before, after) == expected
    assert comparison(before, after)[0] == first


@pytest.mark.parametrize("condition,status", [
    (None, "BROADENED"),                                                        # removed
    ({"StringEquals": {"aws:PrincipalOrgID": ["o-abc123", "o-other"]}}, "BROADENED"),
    ({"StringLike": {"aws:PrincipalOrgID": "o-*"}}, "CHANGED"),                  # other operator
    ({"StringEquals": {"aws:PrincipalOrgID": "o-other"}}, "CHANGED"),             # other value
    ({"StringEqualsIfExists": {"aws:PrincipalOrgID": "o-abc123"}}, "CHANGED"),    # passes if absent
    ({"StringEquals": {"aws:principalorgid": "o-abc123"}}, "UNCHANGED"),          # key case
    ({**ORG, "Bool": {"aws:SecureTransport": "true"}}, "NARROWED"),              # one more clause
])
def test_allow_condition_changes_are_classified_by_what_they_admit(condition, status):
    before = allow("a:X", Condition=ORG)
    after = allow("a:X", **({"Condition": condition} if condition else {}))
    assert access(before, after) == {("Allow", "a:X"): status}
    assert comparison(before, after)[0] == {
        "BROADENED": "grants more: Allow a:X",
        "CHANGED": "grants more: Allow a:X; grants less: Allow a:X",
        "NARROWED": "grants less: Allow a:X",
        "UNCHANGED": "no semantic change"}[status]


def test_negated_condition_values_are_exclusions():
    fewer = allow("a:X", Condition={"StringNotEquals": {"aws:PrincipalOrgID": ["o-x"]}})
    more = allow("a:X", Condition={"StringNotEquals": {"aws:PrincipalOrgID": ["o-x", "o-y"]}})
    assert access(fewer, more) == {("Allow", "a:X"): "NARROWED"}
    assert access(more, fewer) == {("Allow", "a:X"): "BROADENED"}


def test_principal_widening_is_a_broadening():
    one = allow("a:X", Principal={"AWS": f"arn:aws:iam::{CONSUMER}:root"})
    everyone = allow("a:X", Principal="*")
    assert access(one, everyone) == {("Allow", "a:X"): "BROADENED"}
    assert access(everyone, one) == {("Allow", "a:X"): "NARROWED"}


def test_reordering_and_sid_changes_are_no_semantic_change():
    before = {"Version": "2012-10-17", "Id": "first", "Statement": [
        {"Sid": "Read", "Effect": "Allow", "Action": ["a:Read", "a:List"], "Resource": "*",
         "Condition": ORG},
        {"Sid": "Write", "Effect": "Allow", "Action": "a:Write", "Resource": ONLY}]}
    after = {"Version": "2012-10-17", "Id": "second", "Statement": [
        {"Sid": "W", "Resource": [ONLY], "Action": ["a:Write"], "Effect": "Allow"},
        {"Sid": "R", "Condition": {"StringEquals": {"aws:PrincipalOrgID": ["o-abc123"]}},
         "Action": ["a:List", "a:Read"], "Resource": ["*"], "Effect": "Allow"}]}
    difference = policy_difference(before, after)
    assert difference["summary"] == "no semantic change"
    assert describe_difference(difference) == [
        "no semantic change", "unchanged access: Allow a:List, Allow a:Read, Allow a:Write"]


@pytest.mark.parametrize("after", [
    # The statement is split per action.
    [allow("a:Read", Resource="*", Condition=ORG), allow("a:List", Resource="*", Condition=ORG),
     allow("a:Write", Resource=ONLY)],
    # A redundant, narrower statement is added.
    [allow(["a:Read", "a:List"], Resource="*", Condition=ORG), allow("a:Write", Resource=ONLY),
     allow("a:Read", Resource=ONLY, Condition=ORG)],
])
def test_structure_only_changes_are_no_semantic_change(after):
    before = [allow(["a:Read", "a:List"], Resource="*", Condition=ORG),
              allow("a:Write", Resource=ONLY)]
    assert policy_sha256(before) != policy_sha256(after)
    lines = comparison(before, after)
    assert (lines[0], lines[-1]) == ("no semantic change", STRUCTURE_ONLY)


@pytest.mark.parametrize("before,after", [
    (allow([DESCRIBE]), allow(["EC2:describeTransitGateways"])),   # action names ignore case
    (allow(["ec2:*"]), allow(["ec2:*", "ec2:CreateClientVpnEndpoint"])),   # already covered
])
def test_equivalent_action_lists_are_no_semantic_change(before, after):
    assert comparison(before, after)[0] == "no semantic change"


@pytest.mark.parametrize("before,after,expected,first", [
    (TGW_V3, TGW_V2, {("Allow", "ec2:CreateClientVpnEndpoint"): "NARROWED"},
     "grants less: Allow ec2:CreateClientVpnEndpoint"),
    (allow("ec2:*"), allow("ec2:Describe*"), {("Allow", "ec2:*"): "NARROWED"},
     "grants less: Allow ec2:*"),
    (allow("*"), {"Effect": "Allow", "NotAction": "iam:*"}, {("Allow", "*"): "NARROWED"},
     "grants less: Allow *"),
    (allow("a:X", Resource="*"), allow("a:X", Resource=ONLY), {("Allow", "a:X"): "NARROWED"},
     "grants less: Allow a:X"),
    (allow("a:X"), allow("a:X", Condition=ORG), {("Allow", "a:X"): "NARROWED"},
     "grants less: Allow a:X"),
    (allow("a:X", Condition={"StringEquals": {"aws:PrincipalOrgID": ["o-abc123", "o-other"]}}),
     allow("a:X", Condition=ORG), {("Allow", "a:X"): "NARROWED"}, "grants less: Allow a:X"),
    (allow("ec2:*"), [allow("ec2:*"), deny("ec2:Delete*")],
     {("Deny", "ec2:Delete*"): "NARROWED"}, "grants less: Deny ec2:Delete* (deny added)"),
    # A Deny that loses its condition denies everywhere.
    ([allow("ec2:*"), deny("ec2:Delete*", Condition=ORG)], [allow("ec2:*"), deny("ec2:Delete*")],
     {("Deny", "ec2:Delete*"): "NARROWED"}, "grants less: Deny ec2:Delete* (deny strengthened)"),
])
def test_narrowings_are_reported_as_grants_less(before, after, expected, first):
    assert changes(before, after) == expected
    assert comparison(before, after)[0] == first


def test_mixed_change_lists_what_it_grants_more_and_less():
    before = {"Statement": [{"Effect": "Allow", "Action": ["a:One", "a:Two"], "Resource": "*",
                             "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-first"}}}]}
    after = {"Statement": [{"Effect": "Allow", "Action": ["a:One"], "Resource": "arn:x",
                            "Condition": {"StringEquals": {"aws:PrincipalOrgID": "o-other"}}},
                           {"Effect": "Deny", "Action": ["a:Two"], "Resource": "*"}]}
    assert access(before, after) == {("Allow", "a:One"): "CHANGED", ("Allow", "a:Two"): "NARROWED",
                                     ("Deny", "a:Two"): "NARROWED"}
    assert comparison(before, after)[0] == (
        "grants more: Allow a:One; grants less: Allow a:One, Allow a:Two, Deny a:Two (deny added)")


def test_statements_outside_the_analysis_count_as_possible_broadenings():
    plain = {"Statement": [allow("a:X")]}
    odd = {"Statement": [allow("a:X"), {"Effect": "Allow", "Action": "a:Y", "Condition": "o-x"}]}
    assert access(plain, odd) == {("Allow", "a:X"): "UNCHANGED",
                                  ("Allow", "(unanalyzed statements)"): "CHANGED"}
    assert comparison(plain, odd)[0].startswith("grants more: Allow (unanalyzed statements)")
    assert comparison(odd, odd)[0] == "no semantic change"


def test_a_comparison_without_statement_analysis_never_claims_no_difference():
    # A difference made without the statement-level analysis has facets only.
    first = ("grants more: not ruled out; this comparison has no statement-level analysis, "
             "re-run plan --record")
    assert describe_difference({"actions_added": [], "statements_added": [allow("a:X")]}) == [first]
    assert describe_difference({"actions_added": ["Allow a:X"]}) == [
        first, "actions added: Allow a:X"]
    assert grants_less({"actions_added": ["Allow a:X"]}) == [
        "not ruled out without the statement-level analysis"]


def test_grants_less_lists_what_the_later_policy_narrows_or_changes():
    before = {"Statement": [allow(["a:One", "a:Two", "a:Three"])]}
    after = {"Statement": [allow(["a:One"]), allow(["a:Three"], Condition=ORG),
                           allow(["a:Four"])]}
    assert grants_less(policy_difference(before, after)) == ["Allow a:Three", "Allow a:Two"]
    assert grants_less(policy_difference(after, after)) == []
    assert grants_less(policy_difference(TGW_V2, TGW_V3)) == []


def test_statement_analysis_leaves_the_policy_hashes_unchanged():
    # Pinned before the statement-level analysis existed; plan shows and records them.
    assert (policy_sha256(TGW_V2), policy_sha256(TGW_V3)) == (
        "64e8120f3145bc9c1c1e1a7bc2d8e128279857821fabbc992da813be98c778e3",
        "365d19f67b097460189056474e8d18cdf27c8330f733e28f2ec5a397b74dd08c")
    change = expected_change()
    assert (change["from_policy_sha256"], change["to_policy_sha256"]) == (
        "44ddeb77e186963124f751a3a4f51f4f4017d9adeeaf7c34a424e7250b55a27c",
        "5a209dca3e4277c7d7b835f1b1aed878897e3da43ce1134cff256444c235fd1f")
    assert change["difference"]["summary"] == \
        "grants more: Allow route53resolver:AssociateResolverRule"



# ---------------------------------------------------------------------------
# Scale: one run cache for planning reads; rechecks and writes read fresh
# ---------------------------------------------------------------------------
from botocore.awsrequest import AWSResponse  # noqa: E402
from botocore.exceptions import ClientError  # noqa: E402

from ram_migration_common import CONFIG, pages  # noqa: E402
from ram_migration_discovery import LookupCache  # noqa: E402


def stub_shared_stack_shares(stubs, count=2):
    """Shares from one owning stack with one managed permission: each read once."""
    arns = [f"{SOURCE}-{index}" for index in range(count)]
    resources = [f"{RESOURCE}-{index}" for index in range(count)]
    ram, cfn = stubs["ram"], stubs["cloudformation"]
    ram.add_response("get_resource_shares", {"resourceShares": [
        {"resourceShareArn": arn, "owningAccountId": OWNER, "status": "ACTIVE", "tags": []}
        for arn in arns]}, {"resourceOwner": "SELF"})
    template = {"Resources": {f"Share{index}": {"Type": "AWS::RAM::ResourceShare",
                                                "Properties": {"Principals": [CONSUMER]}}
                              for index in range(count)}}
    for index, (arn, resource_arn) in enumerate(zip(arns, resources)):
        ram.add_response("list_resources", {"resources": [resource(resource_arn)]},
                         {"resourceOwner": "SELF", "resourceShareArns": [arn]})
        ram.add_response("get_resource_share_associations", {"resourceShareAssociations": [
            association(CONSUMER, "PRINCIPAL", share=arn)]},
            {"associationType": "PRINCIPAL", "resourceShareArns": [arn]})
        cfn.add_response("describe_stack_resources", {"StackResources": [{
            "StackId": STACK_ID, "StackName": "offline", "LogicalResourceId": f"Share{index}",
            "PhysicalResourceId": arn, "ResourceType": "AWS::RAM::ResourceShare",
            "Timestamp": "2026-10-13T00:00:00Z", "ResourceStatus": "CREATE_COMPLETE"}]},
            {"PhysicalResourceId": arn})
        cfn.add_response("describe_stacks", {"Stacks": [stack_info()]}, {"StackName": STACK_ID})
        if index == 0:
            cfn.add_response("get_template", {"TemplateBody": json.dumps(template)},
                             {"StackName": STACK_ID, "TemplateStage": "Processed"})
        ram.add_response("list_resource_share_permissions", {"permissions": [{
            "arn": PERMISSION, "version": "2", "resourceType": KIND, "defaultVersion": True}]},
            {"resourceShareArn": arn})
        if index == 0:
            ram.add_response("get_permission", {"permission": permission()},
                             {"permissionArn": PERMISSION})
    return resources


def test_run_cache_reads_each_permission_and_owning_template_once(clients):
    cs, stubs = clients
    resources = stub_shared_stack_shares(stubs)
    cache = LookupCache()
    result = Discovery(OfflineRouter(cs), {CONSUMER}, MIGRATION, {}, {KIND.lower(): True},
                       cache=cache).inspect(OWNER, REGION)
    assert not result.blocked
    g, = result.groups
    assert set(g.resources) == set(resources) and g.source_stacks == [STACK_ID]
    for fresh in (False, True):  # stack preflight always rereads the current default
        no_stack(stubs["cloudformation"])
        stubs["ram"].add_response("get_permission", {"permission": permission()},
                                  {"permissionArn": PERMISSION})
        Stacks(OfflineRouter(cs), MIGRATION, cache=cache).prepare(OWNER, REGION, [g], fresh=fresh)


def test_default_permission_drift_after_discovery_blocks_plan_preflight_and_recheck(clients):
    """What the template would attach is reread, never taken from discovery's cached read: a
    default changed after this run's discovery blocks the preflight and the recheck."""
    cs, stubs = clients
    stub_changed_share(stubs)
    cache = LookupCache()
    result = Discovery(OfflineRouter(cs), {CONSUMER}, MIGRATION, {}, {KIND.lower(): True},
                       cache=cache).inspect(OWNER, REGION)
    g, = result.groups
    # SetDefaultPermissionVersion after discovery; the cache still holds discovery's read.
    for fresh in (False, True):  # the plan-time preflight, then the post-confirmation recheck
        no_stack(stubs["cloudformation"])
        stubs["ram"].add_response("get_permission", {"permission": permission(policy=TGW_V3)},
                                  {"permissionArn": PERMISSION})
        with pytest.raises(MigrationError, match="the default managed permission changed since "
                                                 "discovery read it"):
            Stacks(OfflineRouter(cs), MIGRATION, cache=cache).prepare(OWNER, REGION, [g],
                                                                     fresh=fresh)


def test_repeated_apply_of_an_up_to_date_stack_writes_nothing(clients):
    cs, stubs = clients
    g = group(approved=True)
    body = json.dumps(template_for([g], MIGRATION))
    cfn, name = stubs["cloudformation"], stack_name(MIGRATION, OWNER, REGION)
    read = {"StackName": STACK_ID, "TemplateStage": "Processed"}
    stacks = Stacks(OfflineRouter(cs), MIGRATION, cache=LookupCache())
    # The share exists, so it is checked against the version it keeps, not the default.
    attached = {"permissionArn": PERMISSION, "permissionVersion": 2}
    cfn.add_response("describe_stacks", {"Stacks": [stack_info()]}, {"StackName": name})
    cfn.add_response("get_template", {"TemplateBody": body}, read)
    stubs["ram"].add_response("get_permission", {"permission": permission()}, attached)
    stacks.prepare(OWNER, REGION, [g])  # planning reads the template once ...
    stacks._template(OWNER, REGION, stack_info())  # ... and reuses it for that stack version
    cfn.add_response("describe_stacks", {"Stacks": [stack_info()]}, {"StackName": name})
    stubs["ram"].add_response("get_permission", {"permission": permission()}, attached)
    cfn.add_response("get_template", {"TemplateBody": body}, read)  # prepare: fresh
    cfn.add_response("get_template", {"TemplateBody": body}, read)  # apply: fresh
    assert stacks.apply(OWNER, REGION, [g]) == name  # strict stubs: no change set at all


def stack_resource(logical, arn):
    return {"LogicalResourceId": logical, "PhysicalResourceId": arn,
            "ResourceType": "AWS::RAM::ResourceShare", "ResourceStatus": "CREATE_COMPLETE",
            "LastUpdatedTimestamp": "2026-10-14T00:00:00Z"}


def test_an_updated_stack_misses_the_template_cache_so_readback_sees_its_resources(clients):
    """A StackId survives updates: another writer's update must never be checked against
    the template planning cached, or readback reports false ownership failures."""
    cs, stubs = clients
    first = group(approved=True)
    second = group(resources={f"{RESOURCE}-2": KIND}, consumers=(OTHER,), approved=True)
    cfn, name = stubs["cloudformation"], stack_name(MIGRATION, OWNER, REGION)
    read = {"StackName": STACK_ID, "TemplateStage": "Processed"}
    stacks = Stacks(OfflineRouter(cs), MIGRATION, cache=LookupCache())
    cfn.add_response("get_template", {"TemplateBody": json.dumps(template_for([first], MIGRATION))},
                     read)
    for _ in range(2):  # one GetTemplate per stack version
        assert list(stacks._template(OWNER, REGION, stack_info())["Resources"]) == [first.logical_id]
    updated = {**stack_info("UPDATE_COMPLETE"), "LastUpdatedTime": "2026-10-14T00:00:00Z"}
    arns = {first.logical_id: TEMP, second.logical_id: f"{TEMP}-2"}
    cfn.add_response("describe_stacks", {"Stacks": [updated]}, {"StackName": name})
    cfn.add_response("get_template", {"TemplateBody": json.dumps(
        template_for([first, second], MIGRATION))}, read)
    cfn.add_response("list_stack_resources", {"StackResourceSummaries": [
        stack_resource(logical, arn) for logical, arn in arns.items()]}, {"StackName": STACK_ID})
    for g in (first, second):
        arn = arns[g.logical_id]
        stubs["ram"].add_response("get_resource_shares", {"resourceShares": [
            dict(migration_share(g), resourceShareArn=arn)]},
            {"resourceOwner": "SELF", "resourceShareArns": [arn]})
    assert set(stacks.shares(OWNER, REGION)) == set(arns)


class RawBody:
    def __init__(self, body):
        self.body = body

    def stream(self, **_kwargs):
        yield self.body


@pytest.mark.parametrize("code", ["Throttling", "TooManyRequestsException"])
def test_sdk_retries_throttled_reads_with_a_bounded_attempt_count(monkeypatch, code):
    """Discovery reads rely on the SDK's adaptive retries, which are bounded."""
    sent, delays, throttled = [], [], [2]

    def send(_endpoint, request):
        sent.append(request.url)
        if len(sent) <= throttled[0]:
            error = json.dumps({"__type": code, "message": "Rate exceeded"}).encode()
            return AWSResponse(request.url, 400, {"x-amzn-ErrorType": code}, RawBody(error))
        return AWSResponse(request.url, 200, {}, RawBody(b'{"resourceShares": []}'))
    monkeypatch.setattr("botocore.endpoint.Endpoint._send", send)
    monkeypatch.setattr("botocore.endpoint.time.sleep", delays.append)
    monkeypatch.setattr("botocore.retries.adaptive.ClientRateLimiter.on_sending_request",
                        lambda *_args, **_kwargs: None)
    client = botocore.session.get_session().create_client(
        "ram", region_name=REGION, config=CONFIG.merge(Config(signature_version=UNSIGNED)))
    assert pages(Api(client), "get_resource_shares", "resourceShares", resourceOwner="SELF") == []
    assert len(sent) == 3 and len(delays) == 2 and all(0 <= d <= 20 for d in delays)
    sent.clear()
    throttled[0] = 99
    with pytest.raises(ClientError) as raised:
        pages(Api(client), "get_resource_shares", "resourceShares", resourceOwner="SELF")
    assert raised.value.response["Error"]["Code"] == code
    assert len(sent) == 9  # the initial attempt plus CONFIG's 8 retries, then fail closed


# ---------------------------------------------------------------------------
# Existing temporary shares keep their version; overrides never hide a migrating
# owner's stationary consumers
# ---------------------------------------------------------------------------
BROADER = {"Version": "2012-10-17", "Statement": [{
    "Effect": "Allow", "Action": ["route53resolver:GetResolverRule",
                                "route53resolver:AssociateResolverRule",
                                "route53resolver:DisassociateResolverRule"], "Resource": "*"}]}


def kept(version="2", policy=None):
    """What an existing temporary share's template records that it attaches."""
    return {"Arn": PERMISSION, "Version": version, "ResourceType": KIND,
            "Policy": policy_semantics(policy or POLICY), "DefaultVersion": True}


def stub_attached_share(stubs, attached="2", default="3", default_policy=None):
    """One source share for CONSUMER attaching ``attached``; the default is ``default``."""
    ram = stubs["ram"]
    ram.add_response("get_resource_shares", {"resourceShares": [
        {"resourceShareArn": SOURCE, "owningAccountId": OWNER, "status": "ACTIVE", "tags": []}]},
        {"resourceOwner": "SELF"})
    ram.add_response("list_resources", {"resources": [resource()]},
                     {"resourceOwner": "SELF", "resourceShareArns": [SOURCE]})
    ram.add_response("get_resource_share_associations", {"resourceShareAssociations": [
        association(CONSUMER, "PRINCIPAL", share=SOURCE)]},
        {"associationType": "PRINCIPAL", "resourceShareArns": [SOURCE]})
    no_stack(stubs["cloudformation"], physical=True)
    ram.add_response("list_resource_share_permissions", {"permissions": [{
        "arn": PERMISSION, "version": attached, "resourceType": KIND,
        "defaultVersion": attached == default}]}, {"resourceShareArn": SOURCE})
    ram.add_response("get_permission", {"permission": permission(default, default_policy or BROADER)},
                     {"permissionArn": PERMISSION})


def stub_version(stubs, version, policy):
    stubs["ram"].add_response("get_permission", {"permission": permission(
        version, policy, default=False)}, {"permissionArn": PERMISSION,
                                           "permissionVersion": int(version)})


def discover_with(clients, deployed=None):
    cs, _ = clients
    return Discovery(OfflineRouter(cs), {CONSUMER}, MIGRATION, {}, {KIND.lower(): True},
                     deployed=deployed).inspect(OWNER, REGION)


def test_a_newer_default_is_not_a_change_to_an_existing_temporary_share(clients):
    """Finding 3: the original and the temporary share both attach v2; AWS publishes v3."""
    _, stubs = clients
    stub_attached_share(stubs, attached="2", default="3")
    result = discover_with(clients, deployed={group().key: {KIND: kept("2")}})
    assert not result.blocked and not result.permission_changes
    g, = result.groups
    assert g.key == group().key and g.permission_snapshots == {KIND: kept("2")}
    note, = result.notes  # reported explicitly, as a note and never a blocker
    assert f"{SOURCE}: owner={OWNER} region={REGION} permission={PERMISSION} " \
           "status=DEFAULT_CHANGED" in note
    assert f"existing temporary share {g.logical_id} keeps version 2" in note
    assert "the current default is version 3 and the original share attaches version 2" in note
    assert "so the default change does not affect it" in note


def test_a_new_share_receives_a_newer_default_and_reports_the_difference(clients):
    """Control for finding 3: nothing is deployed, so a new share receives v3."""
    _, stubs = clients
    stub_attached_share(stubs, attached="2", default="3")
    stub_version(stubs, "2", POLICY)
    result = discover_with(clients)
    assert not result.blocked and not result.notes
    g, = result.groups
    assert g.permission_snapshots[KIND]["Version"] == "3"
    change, = result.permission_changes
    assert (change["from_version"], change["to_version"]) == ("2", "3")
    assert change["applies_to"] == "new temporary share (receives the current default)"
    assert change["difference"]["summary"] == \
        "grants more: Allow route53resolver:DisassociateResolverRule"


def test_an_original_upgraded_past_its_temporary_share_is_compared_with_the_kept_version(clients):
    """The owner moved the original to v3 after its temporary share was created at v2. The
    temporary share keeps v2, which grants less; the share still joins it, and plan says so."""
    _, stubs = clients
    stub_attached_share(stubs, attached="3", default="3")
    stub_version(stubs, "3", BROADER)
    result = discover_with(clients, deployed={group().key: {KIND: kept("2")}})
    assert not result.blocked
    g, = result.groups
    assert g.permission_snapshots == {KIND: kept("2")}
    change, = result.permission_changes
    assert (change["from_version"], change["to_version"]) == ("3", "2")
    assert change["to_policy_sha256"] == policy_sha256(POLICY)
    assert change["applies_to"] == f"existing temporary share {g.logical_id} (keeps version 2)"
    assert grants_less(change["difference"]) == ["Allow route53resolver:DisassociateResolverRule"]


def existing_stack(stubs, groups):
    cfn = stubs["cloudformation"]
    cfn.add_response("describe_stacks", {"Stacks": [stack_info()]},
                     {"StackName": stack_name(MIGRATION, OWNER, REGION)})
    cfn.add_response("get_template", {"TemplateBody": json.dumps(template_for(groups, MIGRATION))},
                     {"StackName": STACK_ID, "TemplateStage": "Processed"})


def test_preflight_checks_an_existing_share_against_its_kept_version_not_the_default(clients):
    """Finding 3: prepare never reports a changed default permission for a deployed share
    whose version is no longer the default; it rereads that version instead."""
    cs, stubs = clients
    g = group(approved=True)              # the deployed snapshot is v2
    existing_stack(stubs, [g])
    stub_version(stubs, "2", POLICY)      # never the current default
    body, old = Stacks(OfflineRouter(cs), MIGRATION).prepare(OWNER, REGION, [g], fresh=True)
    assert body == template_for([g], MIGRATION) and old["StackId"] == STACK_ID
    stale = group(approved=True)
    stale.permission_snapshots = {KIND: kept("3", BROADER)}
    existing_stack(stubs, [g])
    with pytest.raises(MigrationError, match=r"permission evidence differs from existing "
                                             r"temporary share .*keeps version 2"):
        Stacks(OfflineRouter(cs), MIGRATION).prepare(OWNER, REGION, [stale], fresh=True)

