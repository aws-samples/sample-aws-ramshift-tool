"""large-estate production edge cases: discovery, stack readback and STS sessions.

case 022 fixed RAM per-share quotas, case 028 the owner's own FAILED principal association,
case 030 principals restored as external=true associations, case 032 shares RAM created
from a resource-based policy, case 071 Regional STS for opt-in Regions and case 114
per-share stack readback. Offline only: strict botocore Stubbers, no network, and no
credentials except the synthetic profile files the session tests write.
"""
from __future__ import annotations

import json
import urllib.request
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import boto3
import botocore.endpoint
import botocore.session
import pytest
from botocore.exceptions import ClientError
from botocore.stub import Stubber

import temporary_migration_ram_shares as cli
from ram_migration_common import MigrationError, Router
from ram_migration_stacks import (
    RAM_MAX_PRINCIPALS_PER_SHARE, RAM_MAX_RESOURCES_PER_SHARE, Stacks, quota_problems,
    stack_name, template_for,
)
from test_ram_migration_core import (  # noqa: F401 - clients is a fixture used by name
    CONSUMER, KIND, MIGRATION, OTHER, OWNER, PERMISSION, REGION, RESOURCE, SOURCE, STACK_ID,
    TEMP, OfflineRouter, clients, group, inspect, live_share, migration_share, no_stack,
    owning_stack, permission, resource, stack_info, stack_resource,
)

OWNER_FAILED = "The resource share owner cannot be associated with the resource share."
POLICY_NAME = "Resource Share From Policy Created by RAM"

# An offline stand-in for an SSO access value: never a real credential.
SSO_ACCESS_VALUE = "offline-sso-access-value"


@pytest.fixture(autouse=True)
def offline(request, monkeypatch):
    """No network, no ambient AWS configuration and, unless a test writes its own
    synthetic profile files (aws_files), no credentials at all."""
    for name in ("AWS_PROFILE", "AWS_DEFAULT_PROFILE", "AWS_ACCESS_KEY_ID",
                 "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_DEFAULT_REGION",
                 "AWS_REGION", "AWS_STS_REGIONAL_ENDPOINTS", "AWS_ROLE_ARN",
                 "AWS_WEB_IDENTITY_TOKEN_FILE", "AWS_CONTAINER_CREDENTIALS_RELATIVE_URI",
                 "AWS_CONTAINER_CREDENTIALS_FULL_URI", "AWS_ENDPOINT_URL",
                 "AWS_ENDPOINT_URL_STS", "AWS_USE_FIPS_ENDPOINT"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("AWS_CONFIG_FILE", "/dev/null")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Offline tests must not send requests or load ambient credentials")
    monkeypatch.setattr(botocore.endpoint.Endpoint, "_send", forbidden)
    monkeypatch.setattr(urllib.request, "urlopen", forbidden)
    if "aws_files" not in request.fixturenames:
        monkeypatch.setattr(botocore.session.Session, "get_credentials", forbidden)


def principal(entity, status="ASSOCIATED", share=SOURCE, external=None, message=None):
    """A GetResourceShareAssociations(associationType=PRINCIPAL) row in its live shape."""
    row = {"resourceShareArn": share, "resourceShareName": "ssm-resolver-rule-share",
           "associatedEntity": entity, "associationType": "PRINCIPAL", "status": status,
           "creationTime": "2026-05-12T10:00:00Z", "lastUpdatedTime": "2026-10-14T09:59:00Z"}
    if external is not None:
        row["external"] = external
    if message is not None:
        row["statusMessage"] = message
    return row


def listing(stubs, *shares):
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": list(shares)},
                              {"resourceOwner": "SELF"})


def stub_share(stubs, arn, rows, *, permissions=True, template=None):
    """Owner-side reads of one ACTIVE source share, in Discovery.inspect order."""
    ram = stubs["ram"]
    ram.add_response("list_resources", {"resources": [resource()]},
                     {"resourceOwner": "SELF", "resourceShareArns": [arn]})
    ram.add_response("get_resource_share_associations", {"resourceShareAssociations": rows},
                     {"associationType": "PRINCIPAL", "resourceShareArns": [arn]})
    if template is None:
        no_stack(stubs["cloudformation"], physical=True, arn=arn)
    else:
        owning_stack(stubs["cloudformation"], {"Resources": {"Original": {
            "Type": "AWS::RAM::ResourceShare", "Properties": {"Principals": template}}}},
            "Original", arn, {**stack_info(), "Tags": []})
    if permissions:
        ram.add_response("list_resource_share_permissions", {"permissions": [{
            "arn": PERMISSION, "version": "2", "resourceType": KIND, "defaultVersion": True}]},
            {"resourceShareArn": arn})
        ram.add_response("get_permission", {"permission": permission()},
                         {"permissionArn": PERMISSION})


# ---------------------------------------------------------------------------
# case 028: the owner's own principal association
# ---------------------------------------------------------------------------
def owner_exclusion(evidence):
    return (f"{SOURCE}: owner {OWNER} is listed as a principal of its own share ({evidence}); "
            "an owner is never a consumer of its own share, so it is excluded from the intended "
            "consumers and is never a temporary-share principal")


def test_owner_listed_as_its_own_failed_principal_is_an_explicit_exclusion(clients):
    """400000000005 lists itself on each of its shares; RAM fails that association."""
    cs, stubs = clients
    listing(stubs, live_share(SOURCE))
    stub_share(stubs, SOURCE, [principal(OWNER, "FAILED", external=False, message=OWNER_FAILED),
                               principal(CONSUMER, external=False)])
    result = inspect(cs)
    assert not result.blocked and not result.external_access
    g, = result.groups
    assert g.consumers == (CONSUMER,)
    assert result.excluded == [owner_exclusion(f"association FAILED: {OWNER_FAILED}")]
    share = template_for([g], MIGRATION)["Resources"][g.logical_id]["Properties"]
    assert share["Principals"] == [CONSUMER]  # never a temporary-share principal


def test_owner_named_by_its_owning_template_is_excluded_with_each_source(clients):
    cs, stubs = clients
    listing(stubs, live_share(SOURCE))
    stub_share(stubs, SOURCE, [principal(OWNER, "FAILED", message=OWNER_FAILED),
                               principal(CONSUMER)], template=[OWNER, CONSUMER])
    result = inspect(cs)
    assert not result.blocked and [g.consumers for g in result.groups] == [(CONSUMER,)]
    assert result.excluded == [owner_exclusion(
        f"association FAILED: {OWNER_FAILED}; owning template principal")]


def test_a_share_naming_only_its_owner_has_no_consumer_and_no_blocker(clients):
    cs, stubs = clients
    listing(stubs, live_share(SOURCE))
    # No permission reads: a share with no selected consumer is never grouped.
    stub_share(stubs, SOURCE, [principal(OWNER, "FAILED", message=OWNER_FAILED)],
               permissions=False, template=[OWNER])
    result = inspect(cs)
    assert not result.blocked and not result.groups
    assert result.excluded == [
        owner_exclusion(f"association FAILED: {OWNER_FAILED}; owning template principal"),
        f"{SOURCE}: no selected consumers"]


def test_the_owner_association_is_never_evidence_of_a_consumer(clients):
    """Without a template or a live consumer the intended consumers stay unresolved."""
    cs, stubs = clients
    listing(stubs, live_share(SOURCE))
    stub_share(stubs, SOURCE, [principal(OWNER, "FAILED", message=OWNER_FAILED)],
               permissions=False)
    result = inspect(cs)
    assert not result.groups
    assert result.excluded == [owner_exclusion(f"association FAILED: {OWNER_FAILED}")]
    assert result.blocked == [f"{SOURCE}: owner={OWNER} region={REGION} Original account-facing "
                              "consumers are unresolved; provide a principal-map override"]


# ---------------------------------------------------------------------------
# case 030: principals restored as external=true associations on the originals
# ---------------------------------------------------------------------------
def recovered_exclusion(accounts):
    return (f"{SOURCE}: recovered external access for {accounts}: each holds an ASSOCIATED "
            "principal association with external=true on this original share, so it is "
            "outside the owner's organization and keeps this access whatever organization it "
            "is in; that access is pre-existing, not created by this tool, so no temporary "
            "share duplicates it and the original share is never modified")


def evidence(consumer=CONSUMER):
    return {"owner": OWNER, "region": REGION, "share": SOURCE, "consumer": consumer,
            "status": "ASSOCIATED", "external": True}


def test_a_restored_external_association_is_recovered_access_and_is_not_duplicated(clients):
    """400000000014 was re-added to two us-east-1 originals after it left (external=true)."""
    cs, stubs = clients
    listing(stubs, live_share(SOURCE))
    stub_share(stubs, SOURCE, [principal(CONSUMER, external=True)], permissions=False)
    result = inspect(cs)
    assert not result.blocked and not result.groups and not result.permission_changes
    assert result.external_access == [evidence()]
    assert result.excluded == [recovered_exclusion([CONSUMER])]


def test_internal_consumers_of_the_same_original_are_still_bridged(clients):
    cs, stubs = clients
    listing(stubs, live_share(SOURCE))
    stub_share(stubs, SOURCE, [principal(CONSUMER, external=True),
                               principal(OTHER, external=False)])
    result = inspect(cs, consumers={CONSUMER, OTHER})
    assert not result.blocked
    g, = result.groups
    assert g.consumers == (OTHER,) and g.source_shares == [SOURCE]
    assert result.external_access == [evidence()]
    assert result.excluded == [recovered_exclusion([CONSUMER])]


@pytest.mark.parametrize("rows,states", [
    ([principal(CONSUMER, "ASSOCIATING", external=True)], "ASSOCIATING external=true"),
    ([principal(CONSUMER, external=False), principal(CONSUMER, external=True)],
     "ASSOCIATED external=false, ASSOCIATED external=true"),
])
def test_an_unsettled_external_association_blocks_with_its_states(clients, rows, states):
    cs, stubs = clients
    listing(stubs, live_share(SOURCE))
    stub_share(stubs, SOURCE, rows, permissions=False)
    result = inspect(cs)
    assert not result.groups and not result.external_access
    assert result.blocked == [
        f"{SOURCE}: owner={OWNER} region={REGION} external principal association of "
        f"{CONSUMER} on this original share is not settled ({states}): an external account "
        "holds no access until it accepts the share's invitation, and this tool never accepts "
        f"an original share's invitation; have {CONSUMER} accept or reject that invitation, "
        "then re-run plan"]


def test_only_a_live_association_can_be_recovered_external_access(clients):
    cs, stubs = clients
    listing(stubs, live_share(SOURCE))
    stub_share(stubs, SOURCE, [principal(CONSUMER, "DISASSOCIATED", external=True),
                               principal(CONSUMER, external=False)])
    result = inspect(cs)
    assert not result.blocked and not result.external_access and not result.excluded
    assert [g.consumers for g in result.groups] == [(CONSUMER,)]


def received(account, share=SOURCE):
    return {"account": account, "owner": OWNER, "region": REGION, "share": share,
            "share_status": "ACTIVE", "status": "OBSERVED",
            "resources": [{"arn": RESOURCE, "type": KIND, "status": "AVAILABLE"}],
            "context": f"account={account} owner={OWNER} region={REGION} share={share} "
                       "phase=received-audit"}


def test_the_received_audit_counts_recovered_external_access_for_that_consumer_only(clients):
    cs, stubs = clients
    listing(stubs, live_share(SOURCE))
    stub_share(stubs, SOURCE, [principal(CONSUMER, external=True),
                               principal(OTHER, external=False)])
    plan = inspect(cs, consumers={CONSUMER, OTHER})
    opts = SimpleNamespace(owners=[OWNER], principals={})
    audit = cli.ReceivedAudit(entries=[received(CONSUMER), received(OTHER)])
    cli.classify_received(audit, plan, {}, {OWNER: [REGION]}, opts)
    assert not audit.blocked
    restored, bridged = audit.entries
    assert restored["status"] == "RECOVERED_EXTERNAL"
    assert restored["association"] == {"status": "ASSOCIATED", "external": True}
    assert bridged["status"] == "OWNER_INCLUDED"   # covered by OTHER's temporary share
    assert audit.excluded == [
        f"{restored['context']} status=EXCLUDED recovered external access: the owner's "
        f"principal association for {CONSUMER} on this original share is ASSOCIATED with "
        "external=true, which does not depend on organization membership; it is pre-existing "
        "access, neither duplicated in a temporary share nor modified"]
    # Without owner-side evidence the same receipt would be lost when the account leaves.
    plan.external_access = []
    unproven = cli.ReceivedAudit(entries=[received(CONSUMER)])
    cli.classify_received(unproven, plan, {}, {OWNER: [REGION]}, opts)
    assert unproven.entries[0]["status"] == "NOT_COVERED"
    assert "not covered by any planned temporary share" in unproven.blocked[0]


# ---------------------------------------------------------------------------
# case 032: shares RAM created from a resource-based policy
# ---------------------------------------------------------------------------
def policy_share(arn, feature="CREATED_FROM_POLICY", status="ACTIVE"):
    return dict(live_share(arn, status), name=POLICY_NAME, featureSet=feature, tags=[])


def policy_principals(stubs, arn, rows):
    stubs["ram"].add_response("get_resource_share_associations", {"resourceShareAssociations": rows},
                              {"associationType": "PRINCIPAL", "resourceShareArns": [arn]})


def test_a_service_principal_only_policy_created_share_is_excluded_not_blocked(clients):
    """400000000015's pca-connector-ad shares: service-principal-only shares stay excluded."""
    cs, stubs = clients
    created = f"{SOURCE}-1f35643b"
    listing(stubs, policy_share(created), live_share(SOURCE))
    policy_principals(stubs, created, [principal("pca-connector-ad.amazonaws.com", share=created)])
    stub_share(stubs, SOURCE, [principal(CONSUMER)])
    result = inspect(cs)
    assert not result.blocked and [g.source_shares for g in result.groups] == [[SOURCE]]
    assert f"{created}: service-principal-only share (featureSet CREATED_FROM_POLICY); never " \
        "replicated account-wide" in result.excluded


def test_a_policy_created_share_blocks_alone_with_its_promotion_remediation(clients):
    """400000000015: four such shares in us-east-1 and two in eu-west-1 (pca-connector-ad)."""
    cs, stubs = clients
    created = f"{SOURCE}-1f35643b"
    listing(stubs, policy_share(created), live_share(SOURCE))
    # Strict stubs: the policy share is read only far enough to see it has account principals.
    policy_principals(stubs, created, [principal(CONSUMER, share=created)])
    stub_share(stubs, SOURCE, [principal(CONSUMER)])
    result = inspect(cs)
    assert [g.source_shares for g in result.groups] == [[SOURCE]]   # the sibling is planned
    reason, = result.blocked
    assert reason == (
        f"{created}: owner={OWNER} region={REGION} featureSet CREATED_FROM_POLICY: RAM created "
        "this share from a resource-based policy, so it is not a standard share and is never "
        "inspected as one: only its owner can see it, so the consumers' received-share audit "
        "cannot account for it, and the permission RAM derived from the policy cannot be "
        f"attached to a temporary share. In owner {OWNER} Region {REGION}, promote it to a "
        "standard share: aws ram promote-permission-created-from-policy for the permission it "
        "attaches, then aws ram promote-resource-share-created-from-policy "
        f"--resource-share-arn {created}; re-run plan once its featureSet is STANDARD")
    assert cli.blocker_category(reason) == "policy-created-share"
    assert "promote-resource-share-created-from-policy" in cli.blocker_action(
        "policy-created-share", "plan", True)


def test_a_share_being_promoted_blocks_until_it_is_standard(clients):
    cs, stubs = clients
    listing(stubs, policy_share(SOURCE, "PROMOTING_TO_STANDARD"))
    policy_principals(stubs, SOURCE, [principal(CONSUMER)])
    result = inspect(cs)
    assert not result.groups and not result.excluded
    reason, = result.blocked
    assert reason == (
        f"{SOURCE}: owner={OWNER} region={REGION} featureSet PROMOTING_TO_STANDARD: this share, "
        "which RAM created from a resource-based policy, is being promoted to a standard share "
        "and is not one yet; it is never inspected as one. Wait until aws ram "
        f"get-resource-shares --resource-owner SELF --resource-share-arns {SOURCE} --region "
        f"{REGION} in owner {OWNER} shows featureSet STANDARD, then re-run plan")
    assert cli.blocker_category(reason) == "policy-created-share"


def test_an_unknown_feature_set_is_never_treated_as_standard(clients):
    cs, stubs = clients
    listing(stubs, policy_share(SOURCE, "SOMETHING_NEW"))
    policy_principals(stubs, SOURCE, [principal(CONSUMER)])
    assert inspect(cs).blocked == [
        f"{SOURCE}: owner={OWNER} region={REGION} unsupported featureSet 'SOMETHING_NEW': only "
        "STANDARD shares are inspected; this tool version cannot classify this share, so it "
        "blocks"]


def test_policy_created_share_never_passes_as_a_migration_share(clients):
    """Migration tags on a policy-created share are not provenance: no stack is read."""
    cs, stubs = clients
    share = dict(migration_share(), featureSet="CREATED_FROM_POLICY")
    listing(stubs, share)
    policy_principals(stubs, share["resourceShareArn"],
                      [principal(CONSUMER, share=share["resourceShareArn"])])
    result = inspect(cs)
    assert not result.existing and not result.groups
    assert "featureSet CREATED_FROM_POLICY" in result.blocked[0]


def test_a_deleted_policy_created_share_is_still_a_deleted_exclusion(clients):
    cs, stubs = clients
    listing(stubs, policy_share(SOURCE, status="DELETED"))
    result = inspect(cs)
    assert not result.blocked and result.excluded == [f"{SOURCE}: deleted share (status DELETED)"]


# ---------------------------------------------------------------------------
# case 022: fixed RAM quotas per resource share
# ---------------------------------------------------------------------------
def rules(count, prefix="q"):
    return {f"arn:aws:route53resolver:{REGION}:{OWNER}:resolver-rule/rslvr-rr-{prefix}{i:05d}": KIND
            for i in range(count)}


def test_the_quotas_are_the_documented_fixed_ram_quotas():
    # "Number of resource/principal associations per resource share": 5,000, not adjustable.
    assert RAM_MAX_RESOURCES_PER_SHARE == RAM_MAX_PRINCIPALS_PER_SHARE == 5000


def test_a_share_at_the_resource_quota_passes_and_one_over_it_does_not():
    assert quota_problems(template_for([group(resources=rules(5000))], MIGRATION)) == []
    over = group(resources=rules(5001))
    assert quota_problems(template_for([over], MIGRATION)) == [
        f"{over.logical_id}: the temporary share would hold 5001 resource associations; AWS RAM "
        "allows at most 5000 resource associations per resource share and the quota is not "
        "adjustable"]


def test_a_share_over_the_principal_quota_is_named():
    consumers = tuple(f"{index:012d}" for index in range(10, 5011))   # 5,001 accounts
    over = group(consumers=consumers)
    assert quota_problems(template_for([over], MIGRATION)) == [
        f"{over.logical_id}: the temporary share would hold 5001 principal associations; AWS "
        "RAM allows at most 5000 principal associations per resource share and the quota is "
        "not adjustable"]


def test_plan_preflight_blocks_an_over_quota_group_before_any_permission_read(clients):
    cs, stubs = clients
    no_stack(stubs["cloudformation"])   # strict stubs: nothing after DescribeStacks
    over = group(resources=rules(5001), approved=True)
    with pytest.raises(MigrationError) as raised:
        Stacks(OfflineRouter(cs), MIGRATION).prepare(OWNER, REGION, [over])
    text = str(raised.value)
    assert text.startswith(f"{over.logical_id}: the temporary share would hold 5001 resource "
                           "associations; AWS RAM allows at most 5000")
    assert "Nothing was written" in text and "never splits a group across shares" in text
    reason = f"owner={OWNER} region={REGION} phase=stack-preflight {text}"
    assert cli.blocker_category(reason) == "ram-share-quota"


def test_apply_never_creates_a_change_set_for_an_over_quota_share(clients):
    cs, stubs = clients
    no_stack(stubs["cloudformation"])   # no CreateChangeSet is stubbed
    with pytest.raises(MigrationError, match="AWS RAM allows at most 5000 resource associations"):
        Stacks(OfflineRouter(cs), MIGRATION).apply(OWNER, REGION,
                                                    [group(resources=rules(5001), approved=True)])


def test_growing_a_deployed_share_past_the_quota_blocks_after_the_additive_merge(
        clients, monkeypatch):
    """The quota counts what the share would hold, its deployed resources included."""
    monkeypatch.setattr("ram_migration_stacks.RAM_MAX_RESOURCES_PER_SHARE", 3)
    cs, stubs = clients
    deployed = group(resources=rules(3), approved=True)
    grown = group(resources=rules(1, prefix="new"), approved=True)
    assert grown.logical_id == deployed.logical_id   # same owner, Region, consumers, permissions
    cfn = stubs["cloudformation"]
    cfn.add_response("describe_stacks", {"Stacks": [stack_info()]},
                     {"StackName": stack_name(MIGRATION, OWNER, REGION)})
    cfn.add_response("get_template", {"TemplateBody": json.dumps(template_for([deployed], MIGRATION))},
                     {"StackName": STACK_ID, "TemplateStage": "Processed"})
    stubs["ram"].add_response("get_permission", {"permission": permission()},
                              {"permissionArn": PERMISSION, "permissionVersion": 2})
    with pytest.raises(MigrationError, match=f"^{deployed.logical_id}: the temporary share would "
                                             "hold 4 resource associations; AWS RAM allows at most 3"):
        Stacks(OfflineRouter(cs), MIGRATION).prepare(OWNER, REGION, [grown])


# ---------------------------------------------------------------------------
# case 114: each logical share is read back on its own
# ---------------------------------------------------------------------------
FIRST = group(approved=True)
SECOND = group(resources={f"{RESOURCE}-2": KIND}, consumers=(OTHER,), approved=True)


def stub_stack(stubs, rows, groups=(FIRST, SECOND)):
    cfn = stubs["cloudformation"]
    cfn.add_response("describe_stacks", {"Stacks": [stack_info()]},
                     {"StackName": stack_name(MIGRATION, OWNER, REGION)})
    cfn.add_response("get_template", {"TemplateBody": json.dumps(template_for(list(groups), MIGRATION))},
                     {"StackName": STACK_ID, "TemplateStage": "Processed"})
    cfn.add_response("list_stack_resources", {"StackResourceSummaries": rows}, {"StackName": STACK_ID})


def stub_owned(stubs, g, arn, **changes):
    stubs["ram"].add_response("get_resource_shares", {"resourceShares": [
        {**migration_share(g), "resourceShareArn": arn, **changes}]},
        {"resourceOwner": "SELF", "resourceShareArns": [arn]})


def test_one_unproven_share_never_hides_its_proven_sibling(clients):
    cs, stubs = clients
    stub_stack(stubs, [stack_resource(FIRST.logical_id, TEMP),
                       stack_resource(SECOND.logical_id, f"{TEMP}-2")])
    stub_owned(stubs, FIRST, TEMP, tags=[])            # its ownership tags are gone
    stub_owned(stubs, SECOND, f"{TEMP}-2")
    readback = Stacks(OfflineRouter(cs), MIGRATION).readback(OWNER, REGION)
    assert list(readback.shares) == [SECOND.logical_id]
    assert readback.shares[SECOND.logical_id]["resourceShareArn"] == f"{TEMP}-2"
    assert list(readback.failures) == [FIRST.logical_id]
    assert readback.reason(FIRST.logical_id) == "Migration resource ownership verification failed"


def test_strict_readback_still_fails_closed_and_names_every_unproven_share(clients):
    """complete and the monitor need the whole stack."""
    cs, stubs = clients
    stub_stack(stubs, [stack_resource(FIRST.logical_id, TEMP)])     # SECOND never created
    stub_owned(stubs, FIRST, TEMP, name="renamed outside the tool")
    with pytest.raises(MigrationError) as raised:
        Stacks(OfflineRouter(cs), MIGRATION).shares(OWNER, REGION)
    reasons = {FIRST.logical_id: "Migration share provenance differs from owning template",
               SECOND.logical_id: f"Migration stack resource inventory is incomplete: "
                                  f"{SECOND.logical_id} is declared by the migration template "
                                  "but not in the stack"}
    assert str(raised.value) == "Migration stack shares could not all be proven: " + "; ".join(
        f"{logical}: {reasons[logical]}" for logical in sorted(reasons))


def test_a_throttled_share_read_keeps_its_error_so_verification_can_retry_it(clients):
    cs, stubs = clients
    stub_stack(stubs, [stack_resource(FIRST.logical_id, TEMP),
                       stack_resource(SECOND.logical_id, f"{TEMP}-2")])
    stubs["ram"].add_client_error("get_resource_shares", service_error_code="ThrottlingException",
                                  service_message="Rate exceeded", http_status_code=400,
                                  expected_params={"resourceOwner": "SELF",
                                                   "resourceShareArns": [TEMP]})
    stub_owned(stubs, SECOND, f"{TEMP}-2")
    readback = Stacks(OfflineRouter(cs), MIGRATION).readback(OWNER, REGION)
    assert list(readback.shares) == [SECOND.logical_id]
    error = readback.failures[FIRST.logical_id]
    assert isinstance(error, ClientError) and error.response["Error"]["Code"] == "ThrottlingException"
    assert cli.transient(error, verification=True)
    assert readback.reason(FIRST.logical_id).startswith(
        "operation=GetResourceShares ThrottlingException: Rate exceeded")


def test_undeclared_duplicate_and_uncreated_shares_fail_alone(clients):
    cs, stubs = clients
    third = group(resources={f"{RESOURCE}-3": KIND}, consumers=(CONSUMER, OTHER), approved=True)
    uncreated = {key: value for key, value in stack_resource(third.logical_id, "-").items()
                 if key != "PhysicalResourceId"}   # CloudFormation has not created it yet
    stub_stack(stubs, [stack_resource(FIRST.logical_id, TEMP),
                       stack_resource("ShareUndeclared", f"{TEMP}-9"),
                       stack_resource(SECOND.logical_id, f"{TEMP}-2"),
                       stack_resource(SECOND.logical_id, f"{TEMP}-2b"),
                       {**uncreated, "ResourceStatus": "CREATE_IN_PROGRESS"}],
               groups=(FIRST, SECOND, third))
    stub_owned(stubs, FIRST, TEMP)                     # the only share read
    readback = Stacks(OfflineRouter(cs), MIGRATION).readback(OWNER, REGION)
    assert list(readback.shares) == [FIRST.logical_id]
    assert {logical: readback.reason(logical) for logical in readback.failures} == {
        "ShareUndeclared": "Migration resource ownership verification failed: stack share "
                           "ShareUndeclared is not declared by the migration template",
        SECOND.logical_id: f"Duplicate migration stack resource: {SECOND.logical_id}",
        third.logical_id: f"Migration resource not created: {third.logical_id}"}


def test_a_non_ram_resource_still_fails_the_whole_stack(clients):
    cs, stubs = clients
    stub_stack(stubs, [stack_resource(FIRST.logical_id, TEMP),
                       {**stack_resource("Topic", "arn:aws:sns:us-east-1:000000000001:t"),
                        "ResourceType": "AWS::SNS::Topic"}])
    with pytest.raises(MigrationError, match="^Non-RAM resource in migration stack$"):
        Stacks(OfflineRouter(cs), MIGRATION).readback(OWNER, REGION)


# ---------------------------------------------------------------------------
# case 071: role and SSO sessions use Regional STS endpoints
# ---------------------------------------------------------------------------
TARGET = "000000000005"
BASE = "000000000006"


def identity(account, name="ram-migration"):
    return {"UserId": f"AROAEXAMPLE:{name}", "Account": account,
            "Arn": f"arn:aws:sts::{account}:assumed-role/Admin/{name}"}


class StubbedClients:
    """Every client a boto3 Session creates gets a strict Stubber with the responses
    planned for the next client of its service, and records each request's real URL."""

    def __init__(self, monkeypatch):
        self.plans: dict[str, list[list[tuple]]] = {}
        self.requests: list[tuple[str, str, str]] = []
        self.stubs: list[Stubber] = []
        self.created: list = []
        real, calls = boto3.Session.client, self

        def client(session, service, *args, **kwargs):
            created = real(session, service, *args, **kwargs)
            stub = Stubber(created)
            planned = calls.plans.get(service) or [[]]
            for operation, response, params in planned.pop(0):
                stub.add_response(operation, response, params)
            stub.activate()
            created.meta.events.register_first("before-call.*.*", calls.record)
            calls.stubs.append(stub)
            calls.created.append((service, created))
            return created
        monkeypatch.setattr(boto3.Session, "client", client)

    def plan(self, service, *responses):
        self.plans.setdefault(service, []).append(list(responses))

    def record(self, params, model, **_kwargs):
        self.requests.append((model.service_model.service_name, model.name, params["url"]))

    def done(self):
        for stub in self.stubs:
            stub.assert_no_pending_responses()


@pytest.fixture
def aws_files(tmp_path, monkeypatch):
    """Synthetic profile files; sts_regional_endpoints=legacy, which would send us-east-1
    to the global endpoint, and no Region on the base profile."""
    config, credentials = tmp_path / "config", tmp_path / "credentials"
    config.write_text("[profile base]\n"
                      "[profile sso-base]\nsso_session = corp\n"
                      "[sso-session corp]\nsso_start_url = https://example.awsapps.com/start\n"
                      "sso_region = eu-west-1\nsso_registration_scopes = sso:account:access\n")
    credentials.write_text("[base]\naws_access_key_id = AKIDBASEEXAMPLE0\n"
                           "aws_secret_access_key = synthetic-base-secret\n")
    monkeypatch.setenv("AWS_CONFIG_FILE", str(config))
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", str(credentials))
    monkeypatch.setenv("AWS_STS_REGIONAL_ENDPOINTS", "legacy")
    return config


ASSUMED = {"Credentials": {"AccessKeyId": "ASIAASSUMEDEXAMPLE", "SecretAccessKey": "synthetic",
                           "SessionToken": "synthetic-session-token",
                           "Expiration": datetime.now(timezone.utc) + timedelta(hours=1)},
           "AssumedRoleUser": {"AssumedRoleId": "AROAEXAMPLE:ram-migration",
                               "Arn": f"arn:aws:sts::{TARGET}:assumed-role/Admin/ram-migration"}}


@pytest.mark.parametrize("partition,endpoint", [
    ("aws", "https://sts.us-east-1.amazonaws.com/"),
    ("aws-us-gov", "https://sts.us-gov-west-1.amazonaws.com/"),
    ("aws-cn", "https://sts.cn-north-1.amazonaws.com.cn/"),
])
def test_role_sessions_assume_and_verify_on_a_regional_sts_endpoint(
        aws_files, monkeypatch, partition, endpoint):
    """af-south-1 rejected a token the global endpoint issued; Regional tokens are valid
    in every Region, so the session also works there."""
    clients = StubbedClients(monkeypatch)
    role = f"arn:{partition}:iam::{TARGET}:role/Admin"
    clients.plan("sts", ("get_caller_identity", identity(BASE, "base"), {}))
    clients.plan("sts", ("assume_role", ASSUMED, {
        "RoleArn": role, "RoleSessionName": "ram-migration", "DurationSeconds": 3600}))
    clients.plan("sts", ("get_caller_identity", identity(TARGET), {}))
    router = Router(["base"], {TARGET: role})
    session = router.session(TARGET)
    assert [request[1:] for request in clients.requests[1:]] == [
        ("AssumeRole", endpoint), ("GetCallerIdentity", endpoint)]
    assert all("sts.amazonaws.com" not in url for _, _, url in clients.requests[1:])
    assert session.get_credentials().get_frozen_credentials().access_key == "ASIAASSUMEDEXAMPLE"
    if partition == "aws":
        ram = router.client(TARGET, "ram", "af-south-1")   # the opt-in Region of the incident
        assert ram.meta.endpoint_url == "https://ram.af-south-1.amazonaws.com"
        assert ram.meta.region_name == "af-south-1"
    clients.done()


def test_sso_role_sessions_are_verified_on_a_regional_sts_endpoint(aws_files, monkeypatch):
    clients = StubbedClients(monkeypatch)

    class Tokens:
        def __init__(self, session, profile_name):
            assert profile_name == "sso-base"

        def load_token(self):
            return SimpleNamespace(get_frozen_token=lambda: SimpleNamespace(token=SSO_ACCESS_VALUE))
    monkeypatch.setattr("ram_migration_common.SSOTokenProvider", Tokens)
    expiry = int((datetime.now(timezone.utc) + timedelta(hours=1)).timestamp() * 1000)
    clients.plan("sts", ("get_caller_identity", identity(BASE, "sso"), {}))
    clients.plan("sso", ("get_role_credentials", {"roleCredentials": {
        "accessKeyId": "ASIASSOEXAMPLE000", "secretAccessKey": "synthetic",
        "sessionToken": "synthetic-sso-token", "expiration": expiry}},
        {"accountId": TARGET, "roleName": "AdministratorAccess",
         "accessToken": SSO_ACCESS_VALUE}))
    clients.plan("sts", ("get_caller_identity", identity(TARGET), {}))
    router = Router(["sso-base"], {}, sso_role="AdministratorAccess")
    session = router.session(TARGET)
    (_, portal, portal_url), (_, check, check_url) = clients.requests[1:]
    assert portal == "GetRoleCredentials" and ".eu-west-1." in portal_url
    assert (check, check_url) == ("GetCallerIdentity", "https://sts.us-east-1.amazonaws.com/")
    assert session.get_credentials().get_frozen_credentials().access_key == "ASIASSOEXAMPLE000"
    clients.done()


def test_a_region_specific_token_rejection_names_the_opt_in_cause():
    reason = (f"owner={OWNER} region=af-south-1 phase=discovery operation=GetResourceShares "
              "UnrecognizedClientException: The security token included in the request is "
              "invalid. (request r-1)")
    assert cli.blocker_category(reason) == "authentication"
    action = cli.blocker_action("authentication", "plan", True)
    assert "rejected only in an opt-in Region such as af-south-1" in action
    assert "Regional STS endpoints" in action and "not enabled in that account" in action
