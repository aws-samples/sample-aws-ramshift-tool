"""Offline fidelity tests for ram_migration_verification.py.

Unsigned real botocore clients behind strict Stubbers check every request's
parameters and every response's shape against the bundled service models. No
credentials are loaded and nothing is sent. These are not live evidence.
"""
from __future__ import annotations

import copy
import hashlib
import json
import threading
import time
from collections import defaultdict
from types import SimpleNamespace

import botocore.session
import pytest
from botocore import UNSIGNED
from botocore.config import Config
from botocore.exceptions import ClientError
from botocore.stub import Stubber

import ram_migration_verification as verification
import temporary_migration_ram_shares as cli
import test_ram_migration_cli as cli_tests
from ram_migration_common import PURPOSE, Group, MigrationError

OWNER, CONSUMER, SECOND, THIRD, OTHER_OWNER = (
    "111111111111", "222222222222", "333333333333", "444444444444", "555555555555")
REGION, MIGRATION = "us-west-2", "verification-offline"
RESOLVER, TGW_TYPE, IPAM, PCA, PREFIX = (
    "route53resolver:ResolverRule", "ec2:TransitGateway", "ec2:IpamPool",
    "acm-pca:CertificateAuthority", "ec2:PrefixList")
LEAK_MARKER = "do-not-copy: arn:aws:iam::999999999999:role/Secret token=AKIA0000"


def share_arn(name, owner=OWNER):
    return f"arn:aws:ram:{REGION}:{owner}:resource-share/{name}"


ORIGINAL = share_arn("0a8c3f1e-1111-4a6b-9d2e-000000000001")
TEMPORARY = share_arn("0a8c3f1e-2222-4a6b-9d2e-000000000002")
PERMANENT = share_arn("0a8c3f1e-3333-4a6b-9d2e-000000000003")
OTHER_MIGRATION = share_arn("0a8c3f1e-4444-4a6b-9d2e-000000000004")
FOREIGN = share_arn("0a8c3f1e-5555-4a6b-9d2e-000000000005", OTHER_OWNER)

RULE_ID, SECOND_RULE_ID, SYSTEM_RULE_ID = (
    "rslvr-rr-0a1b2c3d4e5f60718", "rslvr-rr-0b2c3d4e5f6071829", "rslvr-rr-0c3d4e5f607182930")
RULE = f"arn:aws:route53resolver:{REGION}:{OWNER}:resolver-rule/{RULE_ID}"
SECOND_RULE = f"arn:aws:route53resolver:{REGION}:{OWNER}:resolver-rule/{SECOND_RULE_ID}"
SYSTEM_RULE = f"arn:aws:route53resolver:{REGION}:{OWNER}:resolver-rule/{SYSTEM_RULE_ID}"
ENDPOINT_ID = "rslvr-out-0123456789abcdef0"
ASSOCIATION_ID, SECOND_ASSOCIATION_ID = "rslvr-rrassoc-0123456789abcdef0", "rslvr-rrassoc-0fedcba9876543210"
AUTODEFINED_ASSOCIATION = "rslvr-autodefined-assoc-vpc-0a1b2c3d4e5f60718-internet-resolver"
VPC, OTHER_VPC = "vpc-0a1b2c3d4e5f60718", "vpc-0f9e8d7c6b5a40312"
TGW_ID = "tgw-0123456789abcdef0"
TGW = f"arn:aws:ec2:{REGION}:{OWNER}:transit-gateway/{TGW_ID}"
ATTACHMENT_ID = "tgw-attach-0123456789abcdef0"
ROUTE_TABLE = "rtb-0123456789abcdef0"
POOL_ID = "ipam-pool-0123456789abcdef0"
POOL = f"arn:aws:ec2::{OWNER}:ipam-pool/{POOL_ID}"  # IPAM pool ARNs carry no Region
ALLOCATION_ID = "ipam-pool-alloc-0123456789abcdef0"
CA = f"arn:aws:acm-pca:{REGION}:{OWNER}:certificate-authority/0f1e2d3c-4b5a-4978-8796-a5b4c3d2e1f0"
PREFIX_LIST = f"arn:aws:ec2:{REGION}:{OWNER}:prefix-list/pl-0123456789abcdef0"
SECOND_PREFIX_LIST = f"arn:aws:ec2:{REGION}:{OWNER}:prefix-list/pl-0fedcba9876543210"
CERTIFICATE = "-----BEGIN CERTIFICATE-----\nMIIBszCCARmgAwIBAgIQ\n-----END CERTIFICATE-----\n"
CSR = b"-----BEGIN CERTIFICATE REQUEST-----\nMIIBszCCARwCAQAwczELMAkGA1UE\n-----END CERTIFICATE REQUEST-----\n"


@pytest.fixture(autouse=True)
def offline(monkeypatch):
    monkeypatch.setenv("AWS_CONFIG_FILE", "/dev/null")
    monkeypatch.setenv("AWS_SHARED_CREDENTIALS_FILE", "/dev/null")
    monkeypatch.setenv("AWS_EC2_METADATA_DISABLED", "true")
    monkeypatch.delenv("AWS_PROFILE", raising=False)

    def forbidden(*_args, **_kwargs):
        raise AssertionError("Offline verification tests must not load credentials or send requests")

    monkeypatch.setattr("botocore.session.Session.get_credentials", forbidden)
    monkeypatch.setattr("botocore.endpoint.Endpoint._send", forbidden)
    monkeypatch.setattr("urllib.request.urlopen", forbidden)


_SESSION: list = []


def unsigned(service, region=REGION):
    if not _SESSION:
        _SESSION.append(botocore.session.get_session())
    return _SESSION[0].create_client(service, region_name=region,
                                     config=Config(signature_version=UNSIGNED))


class World:
    """Strictly stubbed clients, one per (account, service), behind the router
    interface the module uses: ``client(account, service, region)``."""
    def __init__(self):
        self.clients, self.stubs = {}, {}
        self.requests, self.unexpected = [], []
        self.broken: dict[tuple[str, str], Exception] = {}
        self.wrap = None

    def stub(self, account, service):
        if (account, service) not in self.stubs:
            self.clients[account, service] = unsigned(service)
            self.stubs[account, service] = Stubber(self.clients[account, service])
            self.stubs[account, service].activate()
        return self.stubs[account, service]

    def reply(self, account, service, method, response, **params):
        self.stub(account, service).add_response(method, response, params)

    def fail(self, account, service, method, code="AccessDeniedException", request="req-0001", **params):
        self.stub(account, service).add_client_error(
            method, service_error_code=code, service_message=LEAK_MARKER, http_status_code=400,
            expected_params=params, response_meta={"RequestId": request})

    def client(self, account, service, region, *args, **kwargs):
        self.requests.append((account, service, region, args, kwargs))
        if (account, service) in self.broken:
            raise self.broken[account, service]
        if region != REGION or (account, service) not in self.clients:
            self.unexpected.append((account, service, region))
            raise AssertionError("client requested without a stub")
        client = self.clients[account, service]
        return self.wrap(client) if self.wrap else client

    def verify(self):
        assert not self.unexpected, f"unstubbed clients requested: {self.unexpected}"
        assert all(not args and not kwargs for *_, args, kwargs in self.requests), \
            "collect and replacement_access request clients only as client(account, service, region)"
        for stub in self.stubs.values():
            stub.assert_no_pending_responses()


@pytest.fixture
def world():
    value = World()
    yield value
    value.verify()


def collect(world, groups, temporary=frozenset(), workers=4):
    observation = verification.collect(world, groups, temporary_shares=temporary, workers=workers)
    assert not any(word in gap["reason"] for gap in observation.gaps
                   for word in ("Stub", "ParamValidation", "AssertionError")), observation.gaps
    return observation


def group(resources, consumers=(CONSUMER,), owner=OWNER, sources=(ORIGINAL,)):
    permissions = {kind: f"arn:aws:ram::aws:permission/AWSRAMDefaultPermission{kind.split(':')[-1]}"
                   for kind in resources.values()}
    return Group(owner, REGION, tuple(consumers), permissions, dict(resources), list(sources))


# AWS responses -----------------------------------------------------------------

def share(arn, status="ACTIVE", owner=OWNER, name="original-sharing", tags=None):
    row = {"resourceShareArn": arn, "name": name, "owningAccountId": owner, "status": status,
           "allowExternalPrincipals": True}
    if tags is not None:
        row["tags"] = [{"key": key, "value": value} for key, value in tags.items()]
    return row


def resource(arn, share_arn_, kind=PREFIX, status="AVAILABLE"):
    return {"arn": arn, "type": kind, "resourceShareArn": share_arn_, "status": status,
            "resourceRegionScope": "REGIONAL"}


def received(world, consumer, shares, listed):
    """The consumer's received shares, then list_resources for each share that must be listed."""
    world.reply(consumer, "ram", "get_resource_shares", {"resourceShares": shares},
                resourceOwner="OTHER-ACCOUNTS")
    for arn in sorted(listed):
        world.reply(consumer, "ram", "list_resources", {"resources": listed[arn]},
                    resourceOwner="OTHER-ACCOUNTS", resourceShareArns=[arn])


def visible(world, consumer, resources, via=ORIGINAL):
    received(world, consumer, [share(via)],
             {via: [resource(arn, via, kind) for arn, kind in sorted(resources.items())]})


def rule_row(arn, rule_id, rule_type="FORWARD", endpoint=ENDPOINT_ID):
    row = {"Id": rule_id, "Arn": arn, "DomainName": "corp.example.internal.", "Status": "COMPLETE",
           "RuleType": rule_type, "OwnerId": OWNER, "ShareStatus": "SHARED_BY_ME",
           "CreatorRequestId": "offline"}
    if endpoint:
        row["ResolverEndpointId"] = endpoint
    return row


AUTODEFINED_RULE = {"Id": "rslvr-autodefined-rr-internet-resolver", "Name": "Internet Resolver",
                    "Arn": f"arn:aws:route53resolver:{REGION}::autodefined-rule/"
                           "rslvr-autodefined-rr-internet-resolver",
                    "DomainName": ".", "Status": "COMPLETE", "RuleType": "RECURSIVE",
                    "OwnerId": "Route 53 Resolver", "ShareStatus": "NOT_SHARED"}


def association_row(association_id, rule_id=RULE_ID, vpc=VPC, status="COMPLETE"):
    return {"Id": association_id, "ResolverRuleId": rule_id, "VPCId": vpc, "Status": status,
            "Name": "offline", "StatusMessage": LEAK_MARKER}


def endpoint_reply(world, status="OPERATIONAL", endpoint_id=ENDPOINT_ID):
    world.reply(OWNER, "route53resolver", "get_resolver_endpoint", {"ResolverEndpoint": {
        "Id": endpoint_id, "Name": "outbound", "Direction": "OUTBOUND", "IpAddressCount": 2,
        "Arn": f"arn:aws:route53resolver:{REGION}:{OWNER}:resolver-endpoint/{endpoint_id}",
        "HostVPCId": VPC, "Status": status, "StatusMessage": LEAK_MARKER}}, ResolverEndpointId=endpoint_id)


def ip_row(ip, status="ATTACHED", family="Ip"):
    return {"IpId": "rni-0123456789abcdef0", "SubnetId": "subnet-0123456789abcdef0", family: ip,
            "Status": status, "StatusMessage": LEAK_MARKER}


def owner_attachment(attachment_id, association="associated", resource_owner=CONSUMER):
    row = {"TransitGatewayAttachmentId": attachment_id, "TransitGatewayId": TGW_ID,
           "TransitGatewayOwnerId": OWNER, "ResourceOwnerId": resource_owner, "ResourceType": "vpc",
           "ResourceId": VPC, "State": "available"}
    if association:
        row["Association"] = {"TransitGatewayRouteTableId": "tgw-rtb-0123456789abcdef0",
                              "State": association}
    return row


def vpc_attachment(attachment_id, vpc=VPC, state="available", vpc_owner=CONSUMER):
    return {"TransitGatewayAttachmentId": attachment_id, "TransitGatewayId": TGW_ID, "VpcId": vpc,
            "VpcOwnerId": vpc_owner, "State": state, "SubnetIds": ["subnet-0123456789abcdef0"]}


def tgw_route_row(destination, state="active", field="DestinationCidrBlock", target=TGW_ID):
    return {field: destination, "TransitGatewayId": target, "Origin": "CreateRoute", "State": state}


TGW_FILTER = [{"Name": "transit-gateway-id", "Values": [TGW_ID]}]
ROUTE_FILTER = [{"Name": "route.transit-gateway-id", "Values": [TGW_ID]}]


# Expected items (the section 2 fields) --------------------------------------------

def item(kind, parts, consumer, resource_arn, **fields):
    return {"kind": kind, "key": "|".join([kind, *parts]), "consumer": consumer, "owner": OWNER,
            "region": REGION, "resource_arn": resource_arn, **fields}


def entitlement(arn, kind=PREFIX, consumer=CONSUMER, via=(ORIGINAL,), temporary=()):
    shares = sorted(via)
    return item("entitlement", [consumer, REGION, arn], consumer, arn, type=kind, via_shares=shares,
                via_temporary=[s for s in shares if s in temporary],
                via_other=[s for s in shares if s not in temporary])


def association(association_id=ASSOCIATION_ID, rule_id=RULE_ID, arn=RULE, vpc=VPC,
                status="COMPLETE", consumer=CONSUMER):
    return item("resolver_association", [consumer, REGION, association_id], consumer, arn,
                rule_id=rule_id, vpc_id=vpc, association_id=association_id, status=status)


def endpoint(status="OPERATIONAL", ips=(("10.0.1.10", "ATTACHED"),), arn=RULE, rules=None):
    return item("resolver_endpoint", [OWNER, REGION, ENDPOINT_ID], None, arn,
                endpoint_id=ENDPOINT_ID, rule_arns=list(rules or [arn]), status=status,
                ip_addresses=None if ips is None else [{"ip": ip, "status": s} for ip, s in ips])


def attachment(attachment_id=ATTACHMENT_ID, vpc=VPC, state="available", owner_state="associated"):
    return item("tgw_attachment", [CONSUMER, REGION, attachment_id], CONSUMER, TGW, tgw_id=TGW_ID,
                attachment_id=attachment_id, vpc_id=vpc, state=state,
                owner_association_state=owner_state)


def route(destination="10.0.0.0/8", state="active", table=ROUTE_TABLE):
    return item("tgw_route", [CONSUMER, REGION, table, destination], CONSUMER, TGW, tgw_id=TGW_ID,
                route_table_id=table, destination=destination, state=state)


def allocation(allocation_id=ALLOCATION_ID, consumer=CONSUMER, cidr="10.1.0.0/16", resource_id=VPC,
               resource_type="vpc"):
    return item("ipam_allocation", [OWNER, REGION, POOL_ID, allocation_id], consumer, POOL,
                pool_id=POOL_ID, allocation_id=allocation_id, cidr=cidr, resource_id=resource_id,
                resource_type=resource_type, allocation_region=REGION)


def pca(consumer=CONSUMER, ca_status="ACTIVE", read="OK"):
    return item("pca_access", [consumer, REGION, CA], consumer, CA, ca_status=ca_status,
                consumer_read=read)


def gap(collector, resource_arn, reason, account=CONSUMER):
    return {"collector": collector, "account": account, "region": REGION,
            "resource_arn": resource_arn, "reason": reason}


def keyed(items):
    return {entry["key"]: entry for entry in items}


# ---------------------------------------------------------------------------
# Entitlements, scope inputs and gap hygiene
# ---------------------------------------------------------------------------

def test_entitlements_follow_active_received_shares_across_pages(world):
    g = group({PREFIX_LIST: PREFIX, SECOND_PREFIX_LIST: PREFIX})
    world.reply(CONSUMER, "ram", "get_resource_shares", {
        "resourceShares": [share(ORIGINAL), share(PERMANENT, status="PENDING")],
        "nextToken": "shares-2"}, resourceOwner="OTHER-ACCOUNTS")
    world.reply(CONSUMER, "ram", "get_resource_shares", {
        "resourceShares": [share(TEMPORARY, name=f"{PURPOSE}-x"), share(FOREIGN, owner=OTHER_OWNER)]},
        resourceOwner="OTHER-ACCOUNTS", nextToken="shares-2")
    # Neither the PENDING share nor another owner's share is listed.
    world.reply(CONSUMER, "ram", "list_resources", {
        "resources": [resource(PREFIX_LIST, ORIGINAL)], "nextToken": "resources-2"},
        resourceOwner="OTHER-ACCOUNTS", resourceShareArns=[ORIGINAL])
    world.reply(CONSUMER, "ram", "list_resources", {
        "resources": [resource(SECOND_PREFIX_LIST, ORIGINAL, status="UNAVAILABLE")]},
        resourceOwner="OTHER-ACCOUNTS", resourceShareArns=[ORIGINAL], nextToken="resources-2")
    world.reply(CONSUMER, "ram", "list_resources", {"resources": [
        resource(PREFIX_LIST, TEMPORARY), resource(SECOND_PREFIX_LIST, TEMPORARY, status="PENDING")]},
        resourceOwner="OTHER-ACCOUNTS", resourceShareArns=[TEMPORARY])
    observation = collect(world, [g], {TEMPORARY})
    assert observation.items == [
        entitlement(PREFIX_LIST, via=(ORIGINAL, TEMPORARY), temporary=(TEMPORARY,)),
        entitlement(SECOND_PREFIX_LIST, via=())]
    # Unsupported types still yield their entitlement, plus an exact-reason limit, never
    # a gap: their RAM access is observed, only resource-specific health is not.
    assert observation.gaps == []
    assert [(row["resource_arn"], row["type"], row["reason"]) for row in observation.limits] == [
        (PREFIX_LIST, PREFIX, "resource_checks_unavailable"),
        (SECOND_PREFIX_LIST, PREFIX, "resource_checks_unavailable")]
    assert {(account, service) for account, service, *_ in world.requests} == {(CONSUMER, "ram")}
    assert observation.observed_at and json.loads(json.dumps(observation.to_dict()))["items"]


def test_record_group_dicts_observe_exactly_like_group_objects():
    g = group({PREFIX_LIST: PREFIX})
    results = []
    for groups in ([g], [cli.group_record(g, MIGRATION)]):
        local = World()
        visible(local, CONSUMER, g.resources)
        results.append(collect(local, groups))
        local.verify()
    assert results[0].items == results[1].items == [entitlement(PREFIX_LIST)]
    assert results[0].gaps == results[1].gaps


def test_api_failures_are_gaps_with_code_operation_and_request_id_only(world):
    g = group({PREFIX_LIST: PREFIX}, consumers=(CONSUMER, SECOND, THIRD))
    world.fail(CONSUMER, "ram", "get_resource_shares", request="req-shares",
               resourceOwner="OTHER-ACCOUNTS")
    received(world, SECOND, [share(ORIGINAL), share(PERMANENT)],
             {ORIGINAL: [resource(PREFIX_LIST, ORIGINAL)]})
    # One share's listing fails; its sibling share still counts.
    world.fail(SECOND, "ram", "list_resources", code="ThrottlingException", request="req-throttled",
               resourceOwner="OTHER-ACCOUNTS", resourceShareArns=[PERMANENT])
    world.broken[THIRD, "ram"] = MigrationError(f"{THIRD}: supply a mapping; {LEAK_MARKER}")
    observation = collect(world, [g])
    assert observation.items == [entitlement(PREFIX_LIST, consumer=SECOND)]
    assert observation.gaps == [
        gap("entitlement", None, "AccessDeniedException operation=GetResourceShares request=req-shares"),
        gap("entitlement", None, "ThrottlingException operation=ListResources request=req-throttled",
            account=SECOND),
        gap("entitlement", None, "MigrationError operation=GetResourceShares request=none", account=THIRD)]
    assert [(row["account"], row["reason"]) for row in observation.limits] == [
        (consumer, "resource_checks_unavailable") for consumer in (CONSUMER, SECOND, THIRD)]
    assert "do-not-copy" not in json.dumps(observation.to_dict())


def test_reason_fields_cannot_be_forged_by_error_codes_or_request_ids(world):
    world.fail(CONSUMER, "ram", "get_resource_shares", code="Denied\nforged=1 operation=Spoofed",
               request="req 1\nrequest=forged", resourceOwner="OTHER-ACCOUNTS")
    observation = collect(world, [group({PREFIX_LIST: PREFIX})])
    assert observation.gaps[0]["reason"] == \
        "Deniedforged1operationSpoofed operation=GetResourceShares request=req1requestforged"


def test_malformed_response_is_a_gap_not_an_item(world):
    g = group({PREFIX_LIST: PREFIX})
    world.reply(CONSUMER, "ram", "get_resource_shares", {"resourceShares": [share(ORIGINAL)],
                                                         "nextToken": "again"},
                resourceOwner="OTHER-ACCOUNTS")
    world.reply(CONSUMER, "ram", "get_resource_shares", {"resourceShares": [share(ORIGINAL)]},
                resourceOwner="OTHER-ACCOUNTS", nextToken="again")
    observation = collect(world, [g])
    assert observation.items == []
    assert observation.gaps[0] == gap("entitlement", None,
                                      "UnexpectedResponse operation=GetResourceShares request=none")


@pytest.mark.parametrize("groups,message", [
    ("not-a-list", "groups must be a list"),
    ([], "No migration groups"),
    ([{"owner": OWNER, "region": REGION, "consumers": [CONSUMER]}], "lacks 'resources'"),
    ([group({PREFIX_LIST: PREFIX}, consumers=())], "nonempty consumer list"),
    ([group({PREFIX_LIST: PREFIX}, consumers=(OWNER,))], "never a consumer"),
    ([group({f"arn:aws:ec2:{REGION}:{OTHER_OWNER}:prefix-list/pl-1": PREFIX})], "invalid resource entry"),
    ([group({PREFIX_LIST: "not a type"})], "invalid resource entry"),
    ([group({PREFIX_LIST: PREFIX}), group({PREFIX_LIST: IPAM})], "conflicting RAM resource types"),
    ([Group(OWNER, "Oregon", (CONSUMER,), {}, {PREFIX_LIST: PREFIX})], "invalid group Region"),
])
def test_invalid_scope_is_refused_before_any_client(world, groups, message):
    with pytest.raises(MigrationError, match=message):
        verification.collect(world, groups)
    assert world.requests == []


@pytest.mark.parametrize("kwargs,message", [
    ({"workers": 0}, "workers"), ({"workers": 65}, "workers"), ({"workers": True}, "workers"),
    ({"temporary_shares": TEMPORARY}, "collection of RAM resource-share ARNs"),
    ({"temporary_shares": {"arn:aws:ram:us-west-2:1:resource-share/x"}}, "Invalid temporary share ARN"),
])
def test_invalid_options_are_refused_before_any_client(world, kwargs, message):
    with pytest.raises(MigrationError, match=message):
        verification.collect(world, [group({PREFIX_LIST: PREFIX})], **kwargs)
    assert world.requests == []


def test_reads_never_request_a_writable_client_and_refuse_mutations(world):
    # collect and replacement_access call client(account, service, region) with nothing
    # else (World.verify checks every request); the clients they build refuse writes.
    task = verification._Task(world, CONSUMER, REGION)
    world.stub(CONSUMER, "acm-pca")
    with pytest.raises(MigrationError, match="Read-only mode rejected API operation issue_certificate"):
        task.client("acm-pca").issue_certificate
    with pytest.raises(MigrationError, match="Read-only mode rejected"):
        task.client("acm-pca").delete_certificate_authority


def test_concurrency_never_exceeds_workers_and_one_slow_account_blocks_no_other(world):
    consumers = ("222222222201", "222222222202", "222222222203", "222222222204", "222222222205")
    g = group({PREFIX_LIST: PREFIX}, consumers=consumers)
    for consumer in consumers:
        visible(world, consumer, g.resources)
    lock, active, peak = threading.Lock(), [0], [0]

    class Slow:
        def __init__(self, client):
            self._client, self.meta = client, client.meta

        def __getattr__(self, name):
            method = getattr(self._client, name)

            def call(**kwargs):
                with lock:
                    active[0] += 1
                    peak[0] = max(peak[0], active[0])
                try:
                    time.sleep(0.03)
                    return method(**kwargs)
                finally:
                    with lock:
                        active[0] -= 1
            return call

    world.wrap = Slow
    observation = collect(world, [g], workers=2)
    assert peak[0] == 2
    assert [entry["consumer"] for entry in observation.items] == list(consumers)


# ---------------------------------------------------------------------------
# Route 53 Resolver rules: endpoints and associations
# ---------------------------------------------------------------------------

def test_resolver_forward_and_system_rules_endpoints_and_associations(world):
    resources = {RULE: RESOLVER, SECOND_RULE: RESOLVER, SYSTEM_RULE: RESOLVER}
    g = group(resources)
    world.reply(OWNER, "route53resolver", "list_resolver_rules", {
        "ResolverRules": [rule_row(RULE, RULE_ID), AUTODEFINED_RULE], "NextToken": "rules-2"})
    world.reply(OWNER, "route53resolver", "list_resolver_rules", {"ResolverRules": [
        rule_row(SECOND_RULE, SECOND_RULE_ID),  # the same endpoint: read once
        rule_row(SYSTEM_RULE, SYSTEM_RULE_ID, rule_type="SYSTEM", endpoint=None),
        rule_row(f"arn:aws:route53resolver:{REGION}:{OWNER}:resolver-rule/rslvr-rr-0d", "rslvr-rr-0d")]},
        NextToken="rules-2")
    endpoint_reply(world)
    world.reply(OWNER, "route53resolver", "list_resolver_endpoint_ip_addresses", {
        "IpAddresses": [ip_row("10.0.2.10", "UPDATING")], "NextToken": "ips-2"},
        ResolverEndpointId=ENDPOINT_ID)
    world.reply(OWNER, "route53resolver", "list_resolver_endpoint_ip_addresses", {
        "IpAddresses": [ip_row("10.0.1.10"), ip_row("fd00:ec2::10", family="Ipv6")]},
        ResolverEndpointId=ENDPOINT_ID, NextToken="ips-2")
    visible(world, CONSUMER, resources)
    world.reply(CONSUMER, "route53resolver", "list_resolver_rule_associations", {
        "ResolverRuleAssociations": [
            association_row(AUTODEFINED_ASSOCIATION, "rslvr-autodefined-rr-internet-resolver"),
            # Never in scope, even when a listing names an in-scope rule for it.
            association_row("rslvr-autodefined-assoc-vpc-0f9e8d7c6b5a40312-internet-resolver", RULE_ID),
            association_row(ASSOCIATION_ID)], "NextToken": "associations-2"})
    world.reply(CONSUMER, "route53resolver", "list_resolver_rule_associations", {
        "ResolverRuleAssociations": [
            association_row(SECOND_ASSOCIATION_ID, SYSTEM_RULE_ID, vpc=OTHER_VPC),
            association_row("rslvr-rrassoc-0aaaaaaaaaaaaaaaa", "rslvr-rr-0d")]},
        NextToken="associations-2")
    observation = collect(world, [g])
    assert observation.gaps == []
    assert keyed(observation.items) == keyed([
        entitlement(RULE, RESOLVER), entitlement(SECOND_RULE, RESOLVER),
        entitlement(SYSTEM_RULE, RESOLVER),
        # One item per endpoint, attributed to the first in-scope rule that uses it and
        # naming every in-scope rule that does.
        endpoint(ips=(("10.0.1.10", "ATTACHED"), ("10.0.2.10", "UPDATING"),
                      ("fd00:ec2::10", "ATTACHED")), rules=sorted([RULE, SECOND_RULE])),
        association(),
        association(SECOND_ASSOCIATION_ID, SYSTEM_RULE_ID, SYSTEM_RULE, vpc=OTHER_VPC)])
    assert "do-not-copy" not in json.dumps(observation.to_dict())
    # Every resolver item stays in the CLI's group scope, and SECOND_RULE is reported
    # by the CLI as never associated rather than lost.
    assert cli.scoped_items(observation.items, [g]) == observation.items
    assert cli.unassociated_rules([g], observation) == [(CONSUMER, REGION, SECOND_RULE)]
    assert cli.capture_problems(observation) == []


def test_resolver_rule_problems_are_gaps_and_spare_sibling_rules(world):
    resources = {RULE: RESOLVER, SECOND_RULE: RESOLVER}
    world.reply(OWNER, "route53resolver", "list_resolver_rules",
                {"ResolverRules": [rule_row(RULE, RULE_ID, endpoint=None)]})  # FORWARD, no endpoint
    visible(world, CONSUMER, resources)
    world.reply(CONSUMER, "route53resolver", "list_resolver_rule_associations",
                {"ResolverRuleAssociations": [association_row(ASSOCIATION_ID)]})
    observation = collect(world, [group(resources)])
    assert keyed(observation.items) == keyed([
        entitlement(RULE, RESOLVER), entitlement(SECOND_RULE, RESOLVER), association()])
    assert observation.gaps == [
        gap("resolver_endpoints", RULE, "UnexpectedResponse operation=ListResolverRules request=none",
            account=OWNER),
        gap("resolver_rules", SECOND_RULE, "NotListed operation=ListResolverRules request=none",
            account=OWNER)]


def test_resolver_endpoint_failures_keep_what_was_read(world):
    world.reply(OWNER, "route53resolver", "list_resolver_rules",
                {"ResolverRules": [rule_row(RULE, RULE_ID)]})
    endpoint_reply(world, status="ACTION_NEEDED")
    world.fail(OWNER, "route53resolver", "list_resolver_endpoint_ip_addresses",
               request="req-ips", ResolverEndpointId=ENDPOINT_ID)
    visible(world, CONSUMER, {RULE: RESOLVER})
    world.reply(CONSUMER, "route53resolver", "list_resolver_rule_associations",
                {"ResolverRuleAssociations": [association_row(ASSOCIATION_ID, status="FAILED")]})
    observation = collect(world, [group({RULE: RESOLVER})])
    assert keyed(observation.items) == keyed([
        entitlement(RULE, RESOLVER), endpoint(status="ACTION_NEEDED", ips=None),
        association(status="FAILED")])
    assert observation.gaps == [gap(
        "resolver_endpoints", RULE,
        "AccessDeniedException operation=ListResolverEndpointIpAddresses request=req-ips", account=OWNER)]
    assert len(cli.capture_problems(observation)) == 1  # only the read gap blocks capture
    # The unhealthy endpoint and association were so before the migration: recorded as found.
    assert len(cli.pre_existing(observation, "baseline")) == 2


def test_resolver_owner_listing_failure_hides_associations_rather_than_losing_them(world):
    world.fail(OWNER, "route53resolver", "list_resolver_rules", request="req-rules")
    visible(world, CONSUMER, {RULE: RESOLVER})
    observation = collect(world, [group({RULE: RESOLVER})])
    assert observation.items == [entitlement(RULE, RESOLVER)]
    assert observation.gaps == [gap("resolver_rules", None,
                                    "AccessDeniedException operation=ListResolverRules request=req-rules",
                                    account=OWNER)]
    comparison = verification.compare([entitlement(RULE, RESOLVER), association(), endpoint()],
                                      observation)
    assert comparison.status == "INCONCLUSIVE" and not comparison.missing
    assert {entry["key"] for entry in comparison.unobserved} == {association()["key"], endpoint()["key"]}


# ---------------------------------------------------------------------------
# Transit gateways, IPAM pools and private CAs
# ---------------------------------------------------------------------------

def test_transit_gateway_attachments_routes_and_owner_association_states(world):
    world.reply(OWNER, "ec2", "describe_transit_gateway_attachments", {
        "TransitGatewayAttachments": [owner_attachment(ATTACHMENT_ID),
                                      owner_attachment("tgw-attach-0b", association=None)],
        "NextToken": "owner-2"}, Filters=TGW_FILTER)
    world.reply(OWNER, "ec2", "describe_transit_gateway_attachments", {
        "TransitGatewayAttachments": [owner_attachment("tgw-attach-0f", resource_owner=THIRD)]},
        Filters=TGW_FILTER, NextToken="owner-2")
    visible(world, CONSUMER, {TGW: TGW_TYPE})
    world.reply(CONSUMER, "ec2", "describe_transit_gateway_vpc_attachments", {
        "TransitGatewayVpcAttachments": [
            vpc_attachment(ATTACHMENT_ID), vpc_attachment("tgw-attach-0b", OTHER_VPC, state="pending"),
            vpc_attachment("tgw-attach-0c", "vpc-0c"),  # the owner does not list it
            vpc_attachment("tgw-attach-0f", "vpc-0f", vpc_owner=THIRD)]}, Filters=TGW_FILTER)
    world.reply(CONSUMER, "ec2", "describe_route_tables", {"RouteTables": [{
        "RouteTableId": ROUTE_TABLE, "VpcId": VPC, "OwnerId": CONSUMER, "Routes": [
            {"DestinationCidrBlock": "10.10.0.0/16", "GatewayId": "local", "Origin": "CreateRouteTable",
             "State": "active"},
            tgw_route_row("10.0.0.0/8"),
            tgw_route_row("2001:db8::/32", field="DestinationIpv6CidrBlock"),
            tgw_route_row("pl-0123456789abcdef0", state="blackhole", field="DestinationPrefixListId"),
            tgw_route_row("172.16.0.0/12", target="tgw-0fedcba9876543210")]}],
        "NextToken": "tables-2"}, Filters=ROUTE_FILTER)
    world.reply(CONSUMER, "ec2", "describe_route_tables", {"RouteTables": [{
        "RouteTableId": "rtb-0f", "VpcId": "vpc-0f", "OwnerId": THIRD,
        "Routes": [tgw_route_row("10.0.0.0/8")]}]}, Filters=ROUTE_FILTER, NextToken="tables-2")
    observation = collect(world, [group({TGW: TGW_TYPE})])
    assert observation.gaps == []
    assert keyed(observation.items) == keyed([
        entitlement(TGW, TGW_TYPE),
        attachment(),
        attachment("tgw-attach-0b", OTHER_VPC, state="pending", owner_state="not_associated"),
        attachment("tgw-attach-0c", "vpc-0c", owner_state="not_listed"),
        route("10.0.0.0/8"), route("2001:db8::/32"),
        route("pl-0123456789abcdef0", state="blackhole")])  # observed, never absent


def test_transit_gateway_failures_on_either_side_are_independent(world):
    world.fail(OWNER, "ec2", "describe_transit_gateway_attachments", code="UnauthorizedOperation",
               request="req-owner", Filters=TGW_FILTER)
    visible(world, CONSUMER, {TGW: TGW_TYPE})
    world.reply(CONSUMER, "ec2", "describe_transit_gateway_vpc_attachments",
                {"TransitGatewayVpcAttachments": [vpc_attachment(ATTACHMENT_ID)]}, Filters=TGW_FILTER)
    world.fail(CONSUMER, "ec2", "describe_route_tables", code="RequestLimitExceeded",
               request="req-routes", Filters=ROUTE_FILTER)
    observation = collect(world, [group({TGW: TGW_TYPE})])
    assert keyed(observation.items) == keyed([entitlement(TGW, TGW_TYPE),
                                              attachment(owner_state=None)])
    assert observation.gaps == [
        gap("tgw_owner_attachments", TGW,
            "UnauthorizedOperation operation=DescribeTransitGatewayAttachments request=req-owner",
            account=OWNER),
        gap("tgw_routes", TGW, "RequestLimitExceeded operation=DescribeRouteTables request=req-routes")]



def pool_described(target):
    """DescribeIpamPools for POOL: the collector reads the pool's Locale first."""
    target.reply(OWNER, "ec2", "describe_ipam_pools", {"IpamPools": [
        {"IpamPoolId": POOL_ID, "IpamPoolArn": POOL, "OwnerId": OWNER, "Locale": REGION}]},
        IpamPoolIds=[POOL_ID])


def test_ipam_allocations_owned_by_consumers_are_read_from_the_pool_owner(world):
    g = group({POOL: IPAM}, consumers=(CONSUMER, SECOND))
    pool_described(world)
    world.reply(OWNER, "ec2", "get_ipam_pool_allocations", {"IpamPoolAllocations": [
        {"Cidr": "10.1.0.0/16", "IpamPoolAllocationId": ALLOCATION_ID, "ResourceId": VPC,
         "ResourceType": "vpc", "ResourceRegion": REGION, "ResourceOwner": CONSUMER},
        {"Cidr": "10.9.0.0/16", "IpamPoolAllocationId": "ipam-pool-alloc-0e", "ResourceId": "vpc-0e",
         "ResourceType": "vpc", "ResourceRegion": REGION, "ResourceOwner": THIRD}],
        "NextToken": "allocations-2"}, IpamPoolId=POOL_ID)
    world.reply(OWNER, "ec2", "get_ipam_pool_allocations", {"IpamPoolAllocations": [
        {"Cidr": "10.2.0.0/24", "IpamPoolAllocationId": "ipam-pool-alloc-0f", "ResourceType": "custom",
         "ResourceOwner": SECOND, "Description": LEAK_MARKER}]}, IpamPoolId=POOL_ID, NextToken="allocations-2")
    visible(world, CONSUMER, g.resources)
    visible(world, SECOND, g.resources)
    observation = collect(world, [g])
    assert observation.gaps == []
    assert keyed(observation.items) == keyed([
        entitlement(POOL, IPAM), entitlement(POOL, IPAM, consumer=SECOND), allocation(),
        allocation("ipam-pool-alloc-0f", SECOND, "10.2.0.0/24", None, "custom")])
    assert cli.scoped_items(observation.items, [g]) == observation.items


def test_private_ca_status_and_consumer_reads(world):
    g = group({CA: PCA}, consumers=(CONSUMER, SECOND, THIRD))
    world.reply(OWNER, "acm-pca", "describe_certificate_authority", {"CertificateAuthority": {
        "Arn": CA, "OwnerAccount": OWNER, "Status": "ACTIVE", "Type": "ROOT", "Serial": "01"}},
        CertificateAuthorityArn=CA)
    for consumer in g.consumers:
        visible(world, consumer, g.resources)
    world.reply(CONSUMER, "acm-pca", "get_certificate_authority_certificate",
                {"Certificate": CERTIFICATE}, CertificateAuthorityArn=CA)
    world.fail(SECOND, "acm-pca", "get_certificate_authority_certificate", request="req-denied",
               CertificateAuthorityArn=CA)
    world.fail(THIRD, "acm-pca", "get_certificate_authority_certificate", code="ThrottlingException",
               request="req-throttled", CertificateAuthorityArn=CA)
    observation = collect(world, [g])
    assert keyed(observation.items) == keyed([
        *[entitlement(CA, PCA, consumer=consumer) for consumer in g.consumers],
        pca(), pca(SECOND, read="DENIED"), pca(THIRD, read="ERROR")])
    # DENIED is an observed answer; ERROR is not, so only ERROR leaves a gap.
    assert observation.gaps == [gap(
        "pca_read", CA, "ThrottlingException operation=GetCertificateAuthorityCertificate "
        "request=req-throttled", account=THIRD)]


def test_private_ca_owner_failure_and_a_consumer_without_credentials_are_never_denials(world):
    g = group({CA: PCA}, consumers=(CONSUMER, SECOND))
    world.fail(OWNER, "acm-pca", "describe_certificate_authority", code="ResourceNotFoundException",
               request="req-describe", CertificateAuthorityArn=CA)
    visible(world, CONSUMER, g.resources)
    visible(world, SECOND, g.resources)
    world.reply(CONSUMER, "acm-pca", "get_certificate_authority_certificate",
                {"Certificate": CERTIFICATE}, CertificateAuthorityArn=CA)
    # An STS denial while building the consumer's client is not the CA denying access.
    world.broken[SECOND, "acm-pca"] = ClientError(
        {"Error": {"Code": "AccessDenied", "Message": LEAK_MARKER},
         "ResponseMetadata": {"RequestId": "req-sts"}}, "AssumeRole")
    observation = collect(world, [g])
    assert keyed(observation.items) == keyed([
        entitlement(CA, PCA), entitlement(CA, PCA, consumer=SECOND),
        pca(ca_status=None), pca(SECOND, ca_status=None, read="ERROR")])
    assert observation.gaps == [
        gap("pca_read", CA, "AccessDenied operation=AssumeRole request=req-sts", account=SECOND),
        gap("pca_status", CA,
            "ResourceNotFoundException operation=DescribeCertificateAuthority request=req-describe",
            account=OWNER)]
    assert "do-not-copy" not in json.dumps(observation.to_dict())


# ---------------------------------------------------------------------------
# compare: the Loss-when rules
# ---------------------------------------------------------------------------

def observed(items, gaps=()):
    return SimpleNamespace(observed_at="2026-10-14T06:00:00+00:00", items=list(items), gaps=list(gaps))


def partition(comparison):
    keys = [*comparison.present, *[e["key"] for e in comparison.missing],
            *[e["key"] for e in comparison.degraded], *[e["key"] for e in comparison.unobserved]]
    assert len(keys) == len(set(keys))
    return set(keys)


BASELINE = [entitlement(PREFIX_LIST), association(), endpoint(), attachment(), route(), allocation(), pca()]


def test_intact_when_every_item_holds_and_nothing_is_hidden():
    later = [*copy.deepcopy(BASELINE), association(SECOND_ASSOCIATION_ID)]
    comparison = verification.compare(BASELINE, observed(later))
    assert comparison.status == "INTACT"
    assert sorted(comparison.present) == sorted(entry["key"] for entry in BASELINE)
    assert comparison.added == [association(SECOND_ASSOCIATION_ID)["key"]]
    assert (comparison.missing, comparison.degraded, comparison.unobserved, comparison.gaps) == \
        ([], [], [], [])


@pytest.mark.parametrize("before", BASELINE, ids=lambda entry: entry["kind"])
def test_an_absent_baseline_item_is_missing(before):
    comparison = verification.compare(BASELINE, observed(e for e in BASELINE if e is not before))
    assert comparison.status == "LOSS"
    assert comparison.missing == [{"key": before["key"], "item": before}]
    assert cli.losses(comparison) == [{"key": before["key"], "item": before, "reason": "missing"}]


@pytest.mark.parametrize("before,after,reasons", [
    (entitlement(PREFIX_LIST), entitlement(PREFIX_LIST, via=()), ["not visible to the consumer"]),
    (association(), association(status="FAILED"), ["status FAILED"]),
    (association(), association(status="OVERRIDDEN"), ["status OVERRIDDEN"]),
    (association(), association(vpc=OTHER_VPC), ["vpc_id changed"]),
    (association(), association(rule_id=SECOND_RULE_ID), ["rule_id changed"]),
    (association(), association(status="DELETING", vpc=OTHER_VPC), ["status DELETING", "vpc_id changed"]),
    (endpoint(), endpoint(status="AUTO_RECOVERING"), ["status AUTO_RECOVERING"]),
    (endpoint(), endpoint(ips=(("10.0.1.10", "DETACHING"),)), ["ip 10.0.1.10 status DETACHING"]),
    (endpoint(), endpoint(ips=(("10.0.9.9", "ATTACHED"),)), ["ip 10.0.1.10 absent"]),
    (attachment(), attachment(state="deleting"), ["state deleting"]),
    (attachment(owner_state="not_associated"), attachment(state="rejected", owner_state="not_associated"),
     ["state rejected"]),
    (attachment(), attachment(owner_state="disassociated"), ["owner_association_state disassociated"]),
    (attachment(), attachment(owner_state="not_listed"), ["owner_association_state not_listed"]),
    (attachment(), attachment(vpc=OTHER_VPC), ["vpc_id changed"]),
    (route(), route(state="blackhole"), ["state blackhole"]),
    (allocation(), allocation(consumer=SECOND), ["consumer changed"]),
    (allocation(), allocation(cidr="10.1.0.0/24"), ["cidr changed"]),
    (pca(), pca(ca_status="DISABLED"), ["ca_status DISABLED"]),
    (pca(), pca(read="DENIED"), ["consumer_read DENIED"]),
    (pca(), pca(ca_status="DELETED", read="DENIED"), ["ca_status DELETED", "consumer_read DENIED"]),
], ids=lambda value: value["kind"] if isinstance(value, dict) else None)
def test_each_loss_rule_degrades_its_item(before, after, reasons):
    comparison = verification.compare([before], observed([after]))
    assert comparison.status == "LOSS"
    assert comparison.degraded == [{"key": before["key"], "before": before, "after": after,
                                    "reasons": reasons}]
    loss, = cli.losses(comparison)
    assert (loss["item"], loss["reason"]) == (before, "; ".join(reasons))


@pytest.mark.parametrize("before,after", [
    # "was OPERATIONAL", "was ATTACHED", "left associated", "left ACTIVE", "no longer OK":
    # a condition that did not hold at baseline is never a loss.
    (endpoint(status="UPDATING"), endpoint(status="UPDATING")),
    (endpoint(ips=(("10.0.1.10", "ATTACHING"),)), endpoint(ips=())),
    (attachment(owner_state="not_associated"), attachment(owner_state="not_listed")),
    (attachment(owner_state="associating"), attachment(owner_state="associated")),
    (pca(ca_status="DISABLED"), pca(ca_status="DISABLED")),
    (pca(read="DENIED"), pca(read="DENIED")),
    (entitlement(PREFIX_LIST, via=(ORIGINAL,)), entitlement(PREFIX_LIST, via=(TEMPORARY,),
                                                             temporary=(TEMPORARY,))),
], ids=lambda value: value["kind"])
def test_conditions_that_did_not_hold_at_baseline_are_not_judged(before, after):
    comparison = verification.compare([before], observed([after]))
    assert (comparison.status, comparison.present) == ("INTACT", [before["key"]])


OWNER_RULES_DENIED = gap("resolver_rules", None, "AccessDeniedException operation=ListResolverRules "
                         "request=r", account=OWNER)


@pytest.mark.parametrize("before,gaps", [
    (association(), [gap("resolver_associations", None, "ThrottlingException operation=X request=r")]),
    (association(), [gap("resolver_rules", RULE, "NotListed operation=ListResolverRules request=none",
                         account=OWNER)]),
    (association(), [OWNER_RULES_DENIED]),
    (endpoint(), [OWNER_RULES_DENIED]),
    # One endpoint serves several rules, so an endpoint read for another rule hides it too.
    (endpoint(), [gap("resolver_endpoints", SECOND_RULE, "ThrottlingException operation=X request=r",
                      account=OWNER)]),
    (entitlement(PREFIX_LIST), [gap("entitlement", None, "Throttling operation=X request=r")]),
    (attachment(), [gap("tgw_attachments", TGW, "UnauthorizedOperation operation=X request=r")]),
    (route(), [gap("tgw_routes", TGW, "UnauthorizedOperation operation=X request=r")]),
    (allocation(), [gap("ipam_allocations", POOL, "UnauthorizedOperation operation=X request=r",
                        account=OWNER)]),
    # A gap written elsewhere, naming the consumer and resource, is assumed to hide the item.
    (allocation(), [gap("tgw", POOL, "AccessDeniedException operation=X request=r")]),
], ids=lambda value: value["kind"] if isinstance(value, dict) else value[0]["collector"])
def test_an_absent_item_a_gap_could_hide_is_unobserved_not_missing(before, gaps):
    comparison = verification.compare([before], observed([], gaps))
    assert comparison.status == "INCONCLUSIVE"
    assert comparison.missing == [] and cli.losses(comparison) == []
    entry, = comparison.unobserved
    assert (entry["key"], entry["after"]) == (before["key"], None)
    assert entry["reasons"] == [f"not observed: {g['collector']} {g['reason']}" for g in gaps]


@pytest.mark.parametrize("before,gaps", [
    (association(), [gap("resolver_associations", None, "Throttling operation=X request=r", account=SECOND)]),
    (association(), [gap("resolver_rules", SECOND_RULE, "NotListed operation=X request=none", account=OWNER)]),
    (association(), [{**gap("resolver_associations", None, "Throttling operation=X request=r"),
                      "region": "eu-west-1"}]),
    (route(), [gap("tgw_attachments", TGW, "UnauthorizedOperation operation=X request=r")]),
    (attachment(), [gap("tgw_routes", TGW, "UnauthorizedOperation operation=X request=r")]),
    (pca(), [gap("resource_checks", CA, "resource_checks_unavailable")]),
], ids=lambda value: value["kind"] if isinstance(value, dict) else value[0]["collector"])
def test_a_gap_that_cannot_hide_the_item_leaves_it_missing(before, gaps):
    comparison = verification.compare([before], observed([], gaps))
    assert comparison.status == "LOSS"
    assert comparison.missing == [{"key": before["key"], "item": before}]


@pytest.mark.parametrize("before,after,gaps", [
    (entitlement(PREFIX_LIST), entitlement(PREFIX_LIST, via=()),
     [gap("entitlement", None, "ThrottlingException operation=ListResources request=r")]),
    (endpoint(), endpoint(ips=None), [gap("resolver_endpoints", RULE, "Throttling operation=X request=r",
                                          account=OWNER)]),
    (attachment(), attachment(owner_state=None),
     [gap("tgw_owner_attachments", TGW, "UnauthorizedOperation operation=X request=r", account=OWNER)]),
    (pca(), pca(read="ERROR"), [gap("pca_read", CA, "ThrottlingException operation=X request=r")]),
    (pca(), pca(ca_status=None), [gap("pca_status", CA, "Throttling operation=X request=r", account=OWNER)]),
], ids=lambda value: value["kind"] if isinstance(value, dict) else None)
def test_a_condition_left_unread_by_a_gap_is_unobserved(before, after, gaps):
    comparison = verification.compare([before], observed([after], gaps))
    assert comparison.status == "INCONCLUSIVE"
    entry, = comparison.unobserved
    assert (entry["key"], entry["before"], entry["after"]) == (before["key"], before, after)
    assert not comparison.degraded and not comparison.present


def test_any_gap_is_inconclusive_and_a_loss_always_wins():
    unavailable = gap("resource_checks", PREFIX_LIST, "resource_checks_unavailable")
    comparison = verification.compare(BASELINE, observed(copy.deepcopy(BASELINE), [unavailable]))
    assert comparison.status == "INCONCLUSIVE" and partition(comparison) == set(keyed(BASELINE))
    assert comparison.gaps == [unavailable] and len(comparison.present) == len(BASELINE)
    hidden = gap("resolver_associations", None, "ThrottlingException operation=X request=r")
    later = [e for e in BASELINE if e["kind"] not in ("resolver_association", "tgw_route")]
    comparison = verification.compare(BASELINE, observed(later, [hidden]))
    assert comparison.status == "LOSS"
    assert [e["key"] for e in comparison.missing] == [route()["key"]]
    assert [e["key"] for e in comparison.unobserved] == [association()["key"]]
    assert partition(comparison) == set(keyed(BASELINE))


def test_compare_accepts_a_baseline_read_back_from_the_record():
    record_baseline = json.loads(json.dumps(cli.new_baseline(observed(BASELINE), {CONSUMER: "o-a"}, 7)))
    comparison = verification.compare(record_baseline["items"], observed(BASELINE))
    assert comparison.status == "INTACT"
    assert verification.compare([], observed([])).status == "INTACT"  # as the reference fake


@pytest.mark.parametrize("baseline,observation,message", [
    ("items", observed([]), "baseline items must be a list"),
    ([{"kind": "vpc_lattice", "key": "vpc_lattice|x"}], observed([]), "unsupported or malformed"),
    ([{"kind": "entitlement", "key": "tgw_route|x"}], observed([]), "unsupported or malformed"),
    ([entitlement(PREFIX_LIST), entitlement(PREFIX_LIST)], observed([]), "duplicate item key"),
    ([], SimpleNamespace(items=[]), "lacks 'gaps'"),
    ([], observed([], ["gap"]), "gap objects"),
])
def test_compare_refuses_malformed_inputs(baseline, observation, message):
    with pytest.raises(MigrationError, match=message):
        verification.compare(baseline, observation)


def test_cli_baseline_flow_keeps_resolver_endpoint_losses_and_drop_kinds(world):
    """End to end with the CLI helpers: capture, record round trip, scoped compare, drops."""
    g = group({RULE: RESOLVER})

    def stub_resolver(target, ip_status, association_status):
        target.reply(OWNER, "route53resolver", "list_resolver_rules",
                     {"ResolverRules": [rule_row(RULE, RULE_ID)]})
        endpoint_reply(target)
        target.reply(OWNER, "route53resolver", "list_resolver_endpoint_ip_addresses",
                     {"IpAddresses": [ip_row("10.0.1.10", ip_status)]}, ResolverEndpointId=ENDPOINT_ID)
        visible(target, CONSUMER, g.resources)
        target.reply(CONSUMER, "route53resolver", "list_resolver_rule_associations", {
            "ResolverRuleAssociations": [association_row(ASSOCIATION_ID, status=association_status)]})

    stub_resolver(world, "ATTACHED", "COMPLETE")
    first = collect(world, [g])
    assert cli.capture_problems(first) == []
    baseline = json.loads(json.dumps(cli.new_baseline(first, {CONSUMER: "o-source0001"}, 4)))
    assert baseline["complete"] is True
    later_world = World()
    stub_resolver(later_world, "DETACHING", "FAILED")
    later = collect(later_world, [g])
    later_world.verify()
    comparison = verification.compare(cli.scoped_items(baseline["items"], [g]), later)
    drops = cli.drops_from(comparison, later, {CONSUMER: "o-target0001"}, "verify",
                           baseline["captured_at"], "record revision 5")
    assert sorted((d["kind"], d["consumer"], d["subject"], d["reason"]) for d in drops) == [
        ("association", CONSUMER, association()["key"], "status FAILED"),
        ("resolver_endpoint", None, endpoint()["key"], "ip 10.0.1.10 status DETACHING")]


# ---------------------------------------------------------------------------
# Replacement access
# ---------------------------------------------------------------------------

def migration_tags(migration="another-migration"):
    return {"Purpose": PURPOSE, "MigrationId": migration}


def test_replacement_access_needs_an_active_non_temporary_share(world):
    resources = {PREFIX_LIST: PREFIX, SECOND_PREFIX_LIST: PREFIX, CA: PCA}
    received(world, CONSUMER, [
        share(TEMPORARY, name=f"{PURPOSE}-{OWNER}-{REGION}-0a0b0c0d-1", tags=migration_tags(MIGRATION)),
        share(PERMANENT, name="permanent-sharing"),
        share(OTHER_MIGRATION, name="renamed", tags=migration_tags()),
        share(ORIGINAL, status="DELETING")], {
        TEMPORARY: [resource(arn, TEMPORARY, kind) for arn, kind in sorted(resources.items())],
        PERMANENT: [resource(PREFIX_LIST, PERMANENT), resource(CA, PERMANENT, PCA, status="PENDING")],
        OTHER_MIGRATION: [resource(SECOND_PREFIX_LIST, OTHER_MIGRATION)]})
    result = verification.replacement_access(world, [group(resources)], {TEMPORARY})
    base = {"consumer": CONSUMER, "owner": OWNER, "region": REGION}
    assert result == {
        "covered": [{**base, "resource_arn": PREFIX_LIST, "type": PREFIX, "via_shares": [PERMANENT]}],
        "uncovered": [
            # Only the temporary share remains.
            {**base, "resource_arn": CA, "type": PCA, "via_temporary": [TEMPORARY],
             "via_other_migrations": []},
            # Another migration's temporary share is no replacement either.
            {**base, "resource_arn": SECOND_PREFIX_LIST, "type": PREFIX, "via_temporary": [TEMPORARY],
             "via_other_migrations": [OTHER_MIGRATION]}],
        "gaps": []}
    assert {(account, service) for account, service, *_ in world.requests} == {(CONSUMER, "ram")}


def test_replacement_access_reports_gaps_instead_of_guessing(world):
    resources = {PREFIX_LIST: PREFIX, SECOND_PREFIX_LIST: PREFIX}
    world.reply(CONSUMER, "ram", "get_resource_shares", {"resourceShares": [
        share(PERMANENT), share(TEMPORARY), share(ORIGINAL)]}, resourceOwner="OTHER-ACCOUNTS")
    # Listed in share ARN order: the ORIGINAL listing fails; PERMANENT still covers one resource.
    world.fail(CONSUMER, "ram", "list_resources", code="ThrottlingException", request="req-original",
               resourceOwner="OTHER-ACCOUNTS", resourceShareArns=[ORIGINAL])
    world.reply(CONSUMER, "ram", "list_resources",
                {"resources": [resource(arn, TEMPORARY) for arn in sorted(resources)]},
                resourceOwner="OTHER-ACCOUNTS", resourceShareArns=[TEMPORARY])
    world.reply(CONSUMER, "ram", "list_resources", {"resources": [resource(PREFIX_LIST, PERMANENT)]},
                resourceOwner="OTHER-ACCOUNTS", resourceShareArns=[PERMANENT])
    world.fail(SECOND, "ram", "get_resource_shares", request="req-second", resourceOwner="OTHER-ACCOUNTS")
    result = verification.replacement_access(world, [group(resources, consumers=(CONSUMER, SECOND))],
                                             {TEMPORARY})
    assert [row["resource_arn"] for row in result["covered"]] == [PREFIX_LIST]
    assert result["uncovered"] == []
    assert [(row["consumer"], row["resource_arn"], row["account"], row["reason"]) for row in result["gaps"]] == [
        (CONSUMER, SECOND_PREFIX_LIST, CONSUMER,
         "ThrottlingException operation=ListResources request=req-original"),
        (SECOND, PREFIX_LIST, SECOND, "AccessDeniedException operation=GetResourceShares request=req-second"),
        (SECOND, SECOND_PREFIX_LIST, SECOND,
         "AccessDeniedException operation=GetResourceShares request=req-second")]
    assert "do-not-copy" not in json.dumps(result)


def test_replacement_access_requires_the_recorded_temporary_shares(world):
    with pytest.raises(MigrationError, match="temporary share ARNs"):
        verification.replacement_access(world, [group({PREFIX_LIST: PREFIX})], frozenset())
    assert world.requests == []


# ---------------------------------------------------------------------------
# Approved private CA issuance test: the only write path
# ---------------------------------------------------------------------------

def approval(**changes):
    value = {"kind": "pca_issuance_test", "migration_id": MIGRATION, "consumer": CONSUMER, "ca_arn": CA,
             "csr_sha256": hashlib.sha256(CSR).hexdigest(), "approval_id": "approval-0001",
             "approved_at": "2026-10-14T05:00:00Z"}
    value.update(changes)
    return {key: item_ for key, item_ in value.items() if item_ is not None}


@pytest.fixture
def issuer():
    client = unsigned("acm-pca")
    with Stubber(client) as stub:
        yield client, stub
        stub.assert_no_pending_responses()


def issue(client, **changes):
    arguments = {"migration": MIGRATION, "consumer": CONSUMER, "region": REGION, "ca_arn": CA,
                 "csr_pem": CSR, "signing_algorithm": "SHA256WITHRSA", "approval": approval()}
    arguments.update(changes)
    return verification.pca_issuance_test(client, **arguments)


def test_issuance_runs_only_with_the_exact_approval_and_polls_until_issued(issuer, monkeypatch):
    client, stub = issuer
    monkeypatch.setattr(verification, "ISSUANCE_POLL", 0)
    token = hashlib.sha256(json.dumps(approval(), sort_keys=True, separators=(",", ":"))
                           .encode()).hexdigest()[:32]
    certificate_arn = f"{CA}/certificate/0123456789abcdef0123456789abcdef"
    stub.add_response("issue_certificate", {"CertificateArn": certificate_arn}, {
        "CertificateAuthorityArn": CA, "Csr": CSR, "SigningAlgorithm": "SHA256WITHRSA",
        "Validity": {"Value": 1, "Type": "DAYS"}, "IdempotencyToken": token})
    stub.add_client_error("get_certificate", "RequestInProgressException", LEAK_MARKER,
                          expected_params={"CertificateAuthorityArn": CA, "CertificateArn": certificate_arn})
    stub.add_response("get_certificate", {"Certificate": CERTIFICATE, "CertificateChain": CERTIFICATE},
                      {"CertificateAuthorityArn": CA, "CertificateArn": certificate_arn})
    result = issue(client, csr_pem=CSR.decode())
    assert {key: result[key] for key in ("kind", "migration_id", "consumer", "ca_arn", "csr_sha256",
                                         "certificate_arn", "idempotency_token", "region")} == {
        "kind": "pca_issuance_test", "migration_id": MIGRATION, "consumer": CONSUMER, "ca_arn": CA,
        "csr_sha256": hashlib.sha256(CSR).hexdigest(), "certificate_arn": certificate_arn,
        "idempotency_token": token, "region": REGION}


@pytest.mark.parametrize("bound", [
    None, {}, approval(kind="permission_change"), approval(migration_id="another-migration"),
    approval(consumer=SECOND), approval(ca_arn=CA.replace("0f1e2d3c", "0f1e2d3d")),
    approval(csr_sha256=hashlib.sha256(CSR + b"\n").hexdigest()), approval(csr_sha256=None),
], ids=["none", "empty", "kind", "migration", "consumer", "ca", "csr", "unbound-csr"])
def test_issuance_refuses_any_approval_not_bound_to_this_exact_test(issuer, bound):
    client, _stub = issuer  # no response is queued: any request would fail the stubber
    with pytest.raises(MigrationError, match="PCA issuance test refused"):
        issue(client, approval=bound)


@pytest.mark.parametrize("changes,message", [
    ({"ca_arn": CA.replace(OWNER, CONSUMER)}, "owns"),
    ({"region": "eu-west-1"}, "not a private CA ARN in eu-west-1"),
    ({"csr_pem": b"not a request"}, "PEM-encoded certificate signing request"),
    ({"signing_algorithm": ""}, "signing_algorithm is required"),
    ({"migration": ""}, "migration ID"),
    ({"consumer": "2222"}, "Invalid account ID"),
])
def test_issuance_refuses_inconsistent_requests(issuer, changes, message):
    client, _stub = issuer
    bound = approval(**{name: changes[key] for key, name in (
        ("ca_arn", "ca_arn"), ("consumer", "consumer"), ("migration", "migration_id")) if key in changes})
    with pytest.raises(MigrationError, match=message):
        issue(client, **changes, approval=bound)


def test_issuance_needs_the_consumers_acm_pca_client_in_the_ca_region():
    for client in (unsigned("ram"), unsigned("acm-pca", "eu-west-1")):
        with pytest.raises(MigrationError, match="explicit acm-pca client"):
            issue(client)


def test_issuance_failures_report_code_operation_and_request_id(issuer, monkeypatch):
    client, stub = issuer
    stub.add_client_error("issue_certificate", "AccessDeniedException", LEAK_MARKER,
                          response_meta={"RequestId": "req-issue"})
    with pytest.raises(MigrationError) as raised:
        issue(client)
    assert "AccessDeniedException operation=IssueCertificate request=req-issue" in str(raised.value)
    assert "do-not-copy" not in str(raised.value)
    certificate_arn = f"{CA}/certificate/0123456789abcdef0123456789abcdef"
    monkeypatch.setattr(verification, "ISSUANCE_TIMEOUT", 0)
    stub.add_response("issue_certificate", {"CertificateArn": certificate_arn})
    stub.add_client_error("get_certificate", "RequestInProgressException", LEAK_MARKER)
    with pytest.raises(MigrationError, match="still in progress"):
        issue(client)


# ---------------------------------------------------------------------------
# Consistency with the CLI's reference fake (tests/test_ram_migration_cli.py)
# ---------------------------------------------------------------------------

FAKE_ORIGINAL, FAKE_PERMANENT = share_arn("original"), share_arn("permanent")
FAKE_GROUP = Group(OWNER, REGION, (CONSUMER,), {RESOLVER: "arn:aws:ram::aws:permission/R",
                                                IPAM: "arn:aws:ram::aws:permission/I"},
                   {SYSTEM_RULE: RESOLVER, POOL: IPAM}, [FAKE_ORIGINAL])
FAKE_TEMPORARY = cli_tests.Harness.share(FAKE_GROUP)["resourceShareArn"]


def fake_state(associations=None, lost=(), replaced=(), deleted=(), gaps=()):
    """Harness state for FakeVerification, which models the same world as fake_world."""
    samples = defaultdict(lambda: [[]])
    samples[CONSUMER, REGION] = [list(associations if associations is not None
                                      else [association_row(ASSOCIATION_ID, SYSTEM_RULE_ID)])]
    return SimpleNamespace(calls=[], resolver_samples=samples, original_lost=set(lost),
                           replacement=set(replaced), deleted_shares=list(deleted),
                           collect_gaps=list(gaps), replacement_gaps=[])


def fake_world(state, temporary, *, reads=True, pool_error=False):
    """Stubbed AWS reads equivalent to a FakeVerification harness state."""
    target = World()
    if reads:
        target.reply(OWNER, "route53resolver", "list_resolver_rules", {"ResolverRules": [
            rule_row(SYSTEM_RULE, SYSTEM_RULE_ID, rule_type="SYSTEM", endpoint=None)]})
        pool_described(target)
        if pool_error:
            target.fail(OWNER, "ec2", "get_ipam_pool_allocations", code="UnauthorizedOperation",
                        request="req-pool", IpamPoolId=POOL_ID)
        else:
            target.reply(OWNER, "ec2", "get_ipam_pool_allocations", {"IpamPoolAllocations": []},
                         IpamPoolId=POOL_ID)
    sites = [(arn, kind) for arn, kind in sorted(FAKE_GROUP.resources.items())]
    shares = {FAKE_ORIGINAL: [resource(arn, FAKE_ORIGINAL, kind) for arn, kind in sites
                              if (CONSUMER, REGION, arn) not in state.original_lost]}
    replaced = [resource(arn, FAKE_PERMANENT, kind) for arn, kind in sites
                if (CONSUMER, REGION, arn) in state.replacement]
    if replaced:
        shares[FAKE_PERMANENT] = replaced
    if FAKE_TEMPORARY in temporary and FAKE_TEMPORARY not in state.deleted_shares:
        shares[FAKE_TEMPORARY] = [resource(arn, FAKE_TEMPORARY, kind) for arn, kind in sites]
    received(target, CONSUMER, [share(arn) for arn in sorted(shares)], shares)
    if reads:
        target.reply(CONSUMER, "route53resolver", "list_resolver_rule_associations",
                     {"ResolverRuleAssociations": copy.deepcopy(state.resolver_samples[CONSUMER, REGION][0])})
    return target


def both_collect(state, temporary, **options):
    target = fake_world(state, temporary, **options)
    real = collect(target, [FAKE_GROUP], temporary)
    target.verify()
    fake = cli_tests.FakeVerification(state).collect(None, [FAKE_GROUP], temporary_shares=temporary)
    return real, fake


POOL_GAP = gap("ipam_allocations", POOL, "UnauthorizedOperation operation=GetIpamPoolAllocations "
               "request=req-pool", account=OWNER)
# name -> (harness changes after the baseline, expected status)
SCENARIOS = {
    "intact-after-apply": ({}, "INTACT"),
    "association-failed": ({"associations": [
        association_row(ASSOCIATION_ID, SYSTEM_RULE_ID, status="FAILED")]}, "LOSS"),
    "association-missing": ({"associations": []}, "LOSS"),
    "association-moved": ({"associations": [
        association_row(ASSOCIATION_ID, SYSTEM_RULE_ID, vpc=OTHER_VPC)]}, "LOSS"),
    "association-replaced": ({"associations": [
        association_row(SECOND_ASSOCIATION_ID, SYSTEM_RULE_ID)]}, "LOSS"),
    "association-added": ({"associations": [
        association_row(ASSOCIATION_ID, SYSTEM_RULE_ID),
        association_row(SECOND_ASSOCIATION_ID, SYSTEM_RULE_ID)]}, "INTACT"),
    "entitlements-invisible": ({"lost": [(CONSUMER, REGION, SYSTEM_RULE), (CONSUMER, REGION, POOL)],
                                "deleted": [FAKE_TEMPORARY]}, "LOSS"),
    "temporary-only": ({"lost": [(CONSUMER, REGION, POOL)]}, "INTACT"),
    # A gap that hides no baseline item: the harness reports the gap the real read produces.
    "unrelated-gap": ({"pool_error": True, "gaps": [POOL_GAP]}, "INCONCLUSIVE"),
}


@pytest.mark.parametrize("name", sorted(SCENARIOS))
def test_collect_and_compare_agree_with_the_reference_fake(name):
    changes, status = SCENARIOS[name]
    changes = dict(changes)
    pool_error = changes.pop("pool_error", False)
    real_before, fake_before = both_collect(fake_state(), frozenset())
    assert real_before.items == sorted(fake_before.items, key=lambda entry: entry["key"])
    assert real_before.gaps == fake_before.gaps == []
    baseline = real_before.items
    later = fake_state(**changes)
    real_after, fake_after = both_collect(later, frozenset({FAKE_TEMPORARY}), pool_error=pool_error)
    assert real_after.items == sorted(fake_after.items, key=lambda entry: entry["key"])
    assert real_after.gaps == fake_after.gaps
    # Both judge the very same observation.
    real = verification.compare(baseline, real_after)
    fake = cli_tests.FakeVerification(later).compare(baseline, real_after)
    assert real.status == fake.status == status
    assert sorted(real.present) == sorted(fake.present)
    assert real.missing == fake.missing
    assert real.degraded == fake.degraded
    assert sorted(real.added) == sorted(fake.added)
    assert real.gaps == fake.gaps
    assert cli.losses(real) == cli.losses(fake)


@pytest.mark.parametrize("changes", [
    {}, {"lost": [(CONSUMER, REGION, POOL)]},
    {"lost": [(CONSUMER, REGION, POOL), (CONSUMER, REGION, SYSTEM_RULE)],
     "replaced": [(CONSUMER, REGION, SYSTEM_RULE)]},
], ids=["original-path", "temporary-only", "permanent-replacement"])
def test_replacement_access_agrees_with_the_reference_fake(changes):
    state = fake_state(**changes)
    temporary = frozenset({FAKE_TEMPORARY})
    target = fake_world(state, temporary, reads=False)
    real = verification.replacement_access(target, [FAKE_GROUP], temporary)
    target.verify()
    fake = cli_tests.FakeVerification(state).replacement_access(None, [FAKE_GROUP], temporary)

    def rows(name, result):
        return sorted((row["consumer"], row["region"], row["resource_arn"]) for row in result[name])
    for name in ("covered", "uncovered", "gaps"):
        assert rows(name, real) == rows(name, fake)


@pytest.mark.parametrize("before", [
    association(status="CREATING"), association(status="FAILED"), route(state="blackhole"),
    attachment(state="pending"), endpoint(status="ACTION_NEEDED"), entitlement(PREFIX_LIST, via=()),
    pca(ca_status="DISABLED"),
], ids=lambda value: value["kind"])
def test_state_already_unhealthy_before_the_migration_is_no_loss(before):
    """The migration is judged only on what it can change."""
    comparison = verification.compare([before], observed([copy.deepcopy(before)]))
    assert comparison.status == "INTACT" and comparison.present == [before["key"]]


@pytest.mark.parametrize("before", [association(status="DELETING"), attachment(state="deleting"),
                                    route(state="blackhole")], ids=lambda v: v["kind"])
def test_a_pre_existing_unhealthy_item_that_disappears_ended_by_itself(before):
    """Review finding: an item that was already going away is no loss when it is gone."""
    comparison = verification.compare([before], observed([]))
    assert comparison.status == "INTACT" and comparison.missing == []
    assert comparison.ended == [{"key": before["key"], "item": before}]


def test_a_pre_existing_unhealthy_item_whose_binding_is_replaced_is_still_a_loss():
    before = association(status="FAILED")
    replaced = verification.compare([before], observed([association(status="FAILED", vpc=OTHER_VPC)]))
    assert replaced.status == "LOSS" and replaced.degraded[0]["reasons"] == ["vpc_id changed"]


def test_a_healthy_item_that_disappears_is_still_missing():
    assert verification.compare([association()], observed([])).status == "LOSS"


@pytest.mark.parametrize("locale", [None, "None"])
def test_an_ipam_pool_without_a_locale_is_read_where_its_share_is(world, locale):
    g = group({POOL: IPAM})
    world.reply(OWNER, "ec2", "describe_ipam_pools", {"IpamPools": [
        {"IpamPoolId": POOL_ID, "IpamPoolArn": POOL, "OwnerId": OWNER,
         **({} if locale is None else {"Locale": locale})}]}, IpamPoolIds=[POOL_ID])
    world.reply(OWNER, "ec2", "get_ipam_pool_allocations", {"IpamPoolAllocations": []},
                IpamPoolId=POOL_ID)
    visible(world, CONSUMER, g.resources)
    assert collect(world, [g]).gaps == []


def test_an_ipam_pool_locale_outside_the_regions_names_the_region_to_add(world):
    g = group({POOL: IPAM})
    world.reply(OWNER, "ec2", "describe_ipam_pools", {"IpamPools": [
        {"IpamPoolId": POOL_ID, "IpamPoolArn": POOL, "OwnerId": OWNER, "Locale": "eu-west-1"}]},
        IpamPoolIds=[POOL_ID])
    visible(world, CONSUMER, g.resources)
    gap_row, = collect(world, [g]).gaps
    assert gap_row["reason"].startswith("IpamPoolLocaleOutsideRegions:eu-west-1 ")
