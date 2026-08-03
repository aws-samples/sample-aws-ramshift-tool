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


def test_broader_default_permission_is_not_substituted(clients):
    cs, stubs = clients
    narrower = copy.deepcopy(POLICY)
    narrower["Statement"][0]["Action"] = ["route53resolver:GetResolverRule"]
    stub_discovery(stubs, attached_version="1", attached_policy=narrower)
    result = inspect(cs)
    assert not result.groups
    assert "Non-default permission differs" in result.blocked[0]


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
    with pytest.raises(MigrationError, match="changed since plan approval"):
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


def stub_verification(stub, g, extra=None):
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
    rows = [association(CONSUMER, "PRINCIPAL")]
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


@pytest.mark.parametrize("status", ["DELETING", "PENDING", "FAILED"])
def test_unsettled_or_failed_source_shares_still_block(clients, status):
    cs, stubs = clients
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [
        live_share(SOURCE, status)]}, {"resourceOwner": "SELF"})
    result = inspect(cs)
    assert not result.groups and not result.excluded
    assert result.blocked == [f"{SOURCE}: source status {status}"]


@pytest.mark.parametrize("status", [
    "UNAVAILABLE", "PENDING", "ZONAL_RESOURCE_INACCESSIBLE", "LIMIT_EXCEEDED"])
def test_explicit_owner_side_resource_status_still_blocks(clients, status):
    cs, stubs = clients
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [live_share(SOURCE)]},
                             {"resourceOwner": "SELF"})
    stub_live_source(stubs, SOURCE, [live_resource(status=status)])
    result = inspect(cs)
    assert not result.groups
    assert result.blocked == [f"{SOURCE}: {RESOURCE}: resource status {status}"]


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
# Permission-change approvals (v0.2.0)
# ---------------------------------------------------------------------------
from ram_migration_discovery import (  # noqa: E402
    describe_difference, permission_change, policy_difference, policy_sha256, revalidate_change,
)
from ram_migration_record import approve_permission_change, permission_requests  # noqa: E402
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
    assert describe_difference(difference) == ["actions added: Allow ec2:CreateClientVpnEndpoint"]
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


def approval(migration=MIGRATION, changes=None):
    record = {"migration_id": migration, "revision": 0, "approvals": {"permission_changes": []}}
    request, = permission_requests(migration, changes or [expected_change()])
    return approve_permission_change(record, request)


def inspect_with(clients, approvals):
    return Discovery(OfflineRouter(clients), {CONSUMER}, MIGRATION, {}, {KIND.lower(): True},
                     approved_changes=approvals).inspect(OWNER, REGION)


def test_permission_change_blocks_with_comparison_until_approved(clients):
    cs, stubs = clients
    stub_changed_share(stubs)
    result = inspect_with(cs, [])
    assert not result.groups
    assert "requires approval" in result.blocked[0]
    assert "actions added: Allow route53resolver:AssociateResolverRule" in result.blocked[0]
    change, = result.permission_changes
    assert change["status"] == "APPROVAL_REQUIRED"
    assert (change["share"], change["from_version"], change["to_version"]) == (SOURCE, "1", "2")


def test_bound_approval_admits_the_change_onto_the_temporary_share_only(clients):
    cs, stubs = clients
    stub_changed_share(stubs)
    granted = approval()
    result = inspect_with(cs, [granted])
    assert not result.blocked
    g, = result.groups
    assert g.permission_snapshots[KIND]["Version"] == "2"      # temporary share gets the default
    evidence, = g.permission_changes
    assert evidence["approval_id"] == granted["approval_id"] and evidence["share"] == SOURCE
    assert result.permission_changes[0]["status"] == "APPROVED"


@pytest.mark.parametrize("mutation", [
    {"migration": "earlier-openfinance-migration"},
    {"field": ("to_version", "3")},
    {"field": ("from_policy_sha256", "0" * 64)},
    {"share": SOURCE + "-other"},
])
def test_approvals_for_other_scopes_never_authorize_this_change(clients, mutation):
    cs, stubs = clients
    stub_changed_share(stubs)
    change = expected_change()
    if "field" in mutation:
        change[mutation["field"][0]] = mutation["field"][1]
    if "share" in mutation:
        change["share"] = mutation["share"]
    granted = approval(mutation.get("migration", MIGRATION), [change])
    result = inspect_with(cs, [granted])
    assert not result.groups and "requires approval" in result.blocked[0]


def test_permission_type_mismatch_is_never_approvable(clients):
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
    result = inspect_with(cs, [approval()])
    assert not result.groups and "type differs" in result.blocked[0]


def compact(granted):
    change = expected_change()
    return {k: (granted["approval_id"] if k == "approval_id" else change[k]) for k in (
        "share", "permission_arn", "resource_type", "from_version", "to_version",
        "from_policy_sha256", "to_policy_sha256", "approval_id")}


def stub_revalidation(stubs, attached="1", default_version="2", default_policy=None):
    stubs["ram"].add_response("list_resource_share_permissions", {"permissions": [{
        "arn": PERMISSION, "version": attached, "resourceType": KIND,
        "defaultVersion": attached == default_version}]}, {"resourceShareArn": SOURCE})
    if attached != "1":
        return
    stubs["ram"].add_response("get_permission", {"permission": permission("1", NARROWER, default=False)},
                              {"permissionArn": PERMISSION, "permissionVersion": 1})
    stubs["ram"].add_response("get_permission", {"permission": permission(
        default_version, default_policy)}, {"permissionArn": PERMISSION})


def test_revalidation_accepts_unchanged_approved_change(clients):
    cs, stubs = clients
    stub_revalidation(stubs)
    revalidate_change(Api(cs["ram"]), compact(approval()))


@pytest.mark.parametrize("kwargs,message", [
    ({"attached": "2"}, "attached permission version changed"),
    ({"default_version": "3"}, "permission changed since approval"),
    ({"default_policy": TGW_V3}, "permission changed since approval"),
])
def test_revalidation_voids_approval_on_any_drift(clients, kwargs, message):
    cs, stubs = clients
    stub_revalidation(stubs, **kwargs)
    with pytest.raises(MigrationError, match=message):
        revalidate_change(Api(cs["ram"]), compact(approval()))


def approved_group(granted):
    g = group(approved=True)
    g.permission_changes = [compact(granted)]
    return g


def test_template_records_approved_change_and_rejects_tampered_evidence():
    granted = approval()
    g = approved_group(granted)
    template = template_for([g], MIGRATION)
    metadata = template["Resources"][g.logical_id]["Metadata"]
    row, = metadata["PermissionChanges"]
    assert (row["SourceShareArn"], row["FromVersion"], row["ToVersion"], row["ApprovalId"]) == \
        (SOURCE, "1", "2", granted["approval_id"])
    _validate_template(template, MIGRATION)
    for key, value in (("ToVersion", "3"), ("SourceShareArn", SOURCE + "-unlisted"),
                       ("PermissionArn", "arn:aws:ram::aws:permission/Other")):
        tampered = copy.deepcopy(template)
        tampered["Resources"][g.logical_id]["Metadata"]["PermissionChanges"][0][key] = value
        with pytest.raises(MigrationError, match="permission-change approval metadata"):
            _validate_template(tampered, MIGRATION)


def test_unapproved_change_cannot_enter_a_template():
    g = group(approved=True)
    g.permission_changes = [dict(compact(approval()), share=SOURCE + "-elsewhere")]
    with pytest.raises(MigrationError, match="does not belong"):
        template_for([g], MIGRATION)


def test_additive_template_merges_change_evidence_and_rejects_conflicts():
    granted = approval()
    plain = group(approved=True)
    old = template_for([plain], MIGRATION)
    new = template_for([approved_group(granted)], MIGRATION)
    merged = additive_template(old, new, MIGRATION)
    assert merged["Resources"][plain.logical_id]["Metadata"]["PermissionChanges"] == \
        new["Resources"][plain.logical_id]["Metadata"]["PermissionChanges"]
    conflicting = copy.deepcopy(new)
    conflicting["Resources"][plain.logical_id]["Metadata"]["PermissionChanges"][0]["ApprovalId"] = "pc-other"
    with pytest.raises(MigrationError, match="approval differs"):
        additive_template(merged, conflicting, MIGRATION)
