"""Resource-specific migration evidence (RAM_MIGRATION_RECORD.md sections 2 and 6).

``collect`` observes, through read-only clients, every planned entitlement and
the resource bindings that break when sharing ends. ``compare`` judges an
observation against the recorded baseline by the loss rules of section 2, and
``replacement_access`` proves access that does not depend on a temporary share.
``pca_issuance_test`` is the only write path: it takes an explicit acm-pca
client and an approval bound to the migration, consumer, CA ARN and CSR SHA-256.

Every failed read is a gap ``{collector, account, region, resource_arn,
reason}``. Its reason is ``<error code> operation=<API> request=<request ID>``,
never exception or response text. A gap never counts as success, and one
failed read never stops the reads of other items.
"""
from __future__ import annotations

import hashlib
import json
import re
import time
from collections import defaultdict
from collections.abc import Iterable
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from typing import Any, Callable

from botocore.exceptions import ClientError

from ram_migration_common import PURPOSE, Api, MigrationError, account_id, managed, pages, timestamp
from ram_migration_discovery import evidence_pages

KINDS = ("entitlement", "resolver_association", "resolver_endpoint", "tgw_attachment",
         "tgw_route", "ipam_allocation", "pca_access")
INTACT, LOSS, INCONCLUSIVE = "INTACT", "LOSS", "INCONCLUSIVE"
UNAVAILABLE = "resource_checks_unavailable"
RESOLVER_RULE, TRANSIT_GATEWAY = "route53resolver:resolverrule", "ec2:transitgateway"
IPAM_POOL, PRIVATE_CA = "ec2:ipampool", "acm-pca:certificateauthority"
# Route 53 Resolver's own Internet Resolver rule and its per-VPC associations
# (rslvr-autodefined-rr-..., rslvr-autodefined-assoc-...) are never shared.
AUTODEFINED = "rslvr-autodefined-"
ISSUANCE_TIMEOUT, ISSUANCE_POLL = 300.0, 3.0

# Each collector: the item field naming the account it reads, and the item kinds
# its failure can hide. A gap hides only items of its own account and Region.
COLLECTORS: dict[str, tuple[str, tuple[str, ...]]] = {
    "entitlement": ("consumer", ("entitlement",)),
    "resolver_rules": ("owner", ("resolver_association", "resolver_endpoint")),
    "resolver_endpoints": ("owner", ("resolver_endpoint",)),
    "resolver_associations": ("consumer", ("resolver_association",)),
    "tgw_attachments": ("consumer", ("tgw_attachment",)),
    "tgw_owner_attachments": ("owner", ("tgw_attachment",)),
    "tgw_routes": ("consumer", ("tgw_route",)),
    "ipam_allocations": ("owner", ("ipam_allocation",)),
    "pca_status": ("owner", ("pca_access",)),
    "pca_read": ("consumer", ("pca_access",)),
    "resource_checks": ("consumer", ()),
}
# Loss rules ("Loss when", section 2). A REQUIRED or RETAINED state is a loss only
# when it held at baseline and no longer holds: a state already unhealthy before the
# migration is pre-existing, not something the migration changed. REQUIRED states are
# the ones a stable original state is expected to show. IDENTITY fields never change
# for one key; a change means the original binding was replaced.
REQUIRED = {"resolver_association": (("status", "COMPLETE"),),
            "tgw_attachment": (("state", "available"),),
            "tgw_route": (("state", "active"),)}
RETAINED = {"resolver_endpoint": (("status", "OPERATIONAL"),),
            "tgw_attachment": (("owner_association_state", "associated"),),
            "pca_access": (("ca_status", "ACTIVE"), ("consumer_read", "OK"))}
IDENTITY = {"resolver_association": ("vpc_id", "rule_id"),
            "tgw_attachment": ("tgw_id", "vpc_id"),
            "tgw_route": ("tgw_id",),
            "ipam_allocation": ("consumer", "cidr")}
# Observed values that mean "could not be read"; each comes with a gap.
UNREAD = {"consumer_read": ("ERROR",)}

_REGION = re.compile(r"[a-z]{2,4}(?:-[a-z0-9]+)+-\d+")
_TYPE = re.compile(r"[a-z0-9-]+:[A-Za-z0-9-]+")
_SHARE = re.compile(r"arn:[a-z0-9-]+:ram:[a-z0-9-]+:\d{12}:resource-share/[A-Za-z0-9-]+")
# Error codes, API names and request IDs need no other characters; dropping the rest
# keeps a reason's three fields unforgeable.
_UNSAFE = re.compile(r"[^A-Za-z0-9._:-]")
_FAILED = object()


@dataclass
class Observation:
    observed_at: str
    items: list[dict] = field(default_factory=list)
    gaps: list[dict] = field(default_factory=list)
    # Resources of a type with no resource-specific collector: their RAM access is
    # observed (entitlement items), their resource health is not. Never a gap: the
    # migration cannot be judged less complete for what no collector reads.
    limits: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class Comparison:
    """Each baseline key is in exactly one of present, missing, degraded and unobserved.

    ``present`` and ``added`` hold keys; ``missing`` holds ``{key, item}``;
    ``degraded`` and ``unobserved`` hold ``{key, before, after, reasons}``.
    """
    present: list[str] = field(default_factory=list)
    missing: list[dict] = field(default_factory=list)
    degraded: list[dict] = field(default_factory=list)
    added: list[str] = field(default_factory=list)
    gaps: list[dict] = field(default_factory=list)
    status: str = INCONCLUSIVE
    # Baseline items a gap hides, wholly or in part: neither present nor lost.
    unobserved: list[dict] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)


class _Unreadable(Exception):
    """A response this module cannot rely on; ``code`` is fixed text, never response data."""
    def __init__(self, code: str = "UnexpectedResponse"):
        super().__init__(code)
        self.code = code


# ---------------------------------------------------------------------------
# Inputs
# ---------------------------------------------------------------------------

@dataclass
class _Scope:
    owned: dict = field(default_factory=dict)     # (owner, region) -> {arn: type}
    received: dict = field(default_factory=dict)  # (consumer, region) -> {arn: (owner, type)}
    users: dict = field(default_factory=dict)     # (owner, region, arn) -> {consumer}


def _value(source: Any, name: str) -> Any:
    if isinstance(source, dict):
        if name in source:
            return source[name]
    elif hasattr(source, name):
        return getattr(source, name)
    raise MigrationError(f"Verification input lacks {name!r}; pass Group objects or record "
                         "group dicts, and a collect() observation")


def _sequence(value: Any) -> bool:
    return isinstance(value, Iterable) and not isinstance(value, (str, bytes, dict))


def _scope(groups: Any) -> _Scope:
    if not _sequence(groups):
        raise MigrationError("groups must be a list of Group objects or record group dicts")
    scope, types = _Scope(), {}
    for group in groups:
        owner = account_id(_value(group, "owner"))
        region, consumers = _value(group, "region"), _value(group, "consumers")
        resources = _value(group, "resources")
        if not isinstance(region, str) or not _REGION.fullmatch(region):
            raise MigrationError(f"{owner}: invalid group Region {region!r}")
        if not _sequence(consumers) or not consumers:
            raise MigrationError(f"{owner}/{region}: a group needs a nonempty consumer list")
        consumers = [account_id(consumer) for consumer in consumers]
        if owner in consumers:
            raise MigrationError(f"{owner}: an owner is never a consumer of its own resources")
        if not isinstance(resources, dict) or not resources:
            raise MigrationError(f"{owner}/{region}: a group needs a nonempty {{arn: type}} map")
        for arn, kind in resources.items():
            parts = arn.split(":", 5) if isinstance(arn, str) else []
            if len(parts) != 6 or parts[0] != "arn" or parts[4] != owner or \
                    not isinstance(kind, str) or not _TYPE.fullmatch(kind):
                raise MigrationError(f"{owner}/{region}: invalid resource entry {arn!r}: {kind!r}; "
                                     "groups map the owner's resource ARNs to RAM resource types")
            if types.setdefault(arn, kind) != kind:
                raise MigrationError(f"{arn}: conflicting RAM resource types across groups")
            scope.owned.setdefault((owner, region), {})[arn] = kind
            for consumer in consumers:
                scope.received.setdefault((consumer, region), {})[arn] = (owner, kind)
                scope.users.setdefault((owner, region, arn), set()).add(consumer)
    if not scope.owned:
        raise MigrationError("No migration groups to verify; take the scope from the migration record")
    return scope


def _share_arns(values: Any) -> frozenset[str]:
    if not _sequence(values):
        raise MigrationError("temporary_shares must be a collection of RAM resource-share ARNs")
    arns = frozenset(values)
    for arn in arns:
        if not isinstance(arn, str) or not _SHARE.fullmatch(arn):
            raise MigrationError(f"Invalid temporary share ARN: {arn!r}")
    return arns


def _workers(workers: Any) -> int:
    if isinstance(workers, bool) or not isinstance(workers, int) or not 1 <= workers <= 64:
        raise MigrationError("workers must be an integer from 1 through 64")
    return workers


# ---------------------------------------------------------------------------
# Reads
# ---------------------------------------------------------------------------

def _text(value: Any) -> bool:
    return isinstance(value, str) and bool(value)


def _clean(value: Any) -> str:
    return _UNSAFE.sub("", str(value))[:128] or "none"


def _api(operation: str) -> str:
    return "".join(part.capitalize() for part in operation.split("_"))


def _reason(code: Any, operation: str, request: Any = None) -> str:
    """An error code, the API operation and the request ID only: exception and
    response text can carry account data or credentials and is never copied."""
    return f"{_clean(code)} operation={_clean(operation)} request={_clean(request or 'none')}"


def _failure(operation: str, exc: BaseException) -> str:
    if isinstance(exc, ClientError):
        response = exc.response if isinstance(exc.response, dict) else {}
        return _reason((response.get("Error") or {}).get("Code") or "ClientError",
                       exc.operation_name or _api(operation),
                       (response.get("ResponseMetadata") or {}).get("RequestId"))
    return _reason(exc.code if isinstance(exc, _Unreadable) else type(exc).__name__, _api(operation))


def _item(kind: str, parts: list[str], consumer: str | None, owner: str, region: str,
          resource_arn: str, **fields: Any) -> dict:
    return {"kind": kind, "key": "|".join([kind, *parts]), "consumer": consumer, "owner": owner,
            "region": region, "resource_arn": resource_arn, **fields}


def _resource_id(arn: str, resource_type: str) -> str | None:
    """The last path segment of an ``arn:...:<resource_type>/<id>`` resource."""
    kind, _, path = arn.split(":", 5)[5].partition("/")
    identifier = path.rsplit("/", 1)[-1]
    return identifier if kind == resource_type and identifier else None


class _Task:
    """The reads of one account in one Region; one thread uses its clients."""
    def __init__(self, router: Any, account: str, region: str,
                 allowed_regions: set[str] | None = None):
        self.router, self.account, self.region = router, account, region
        self.allowed_regions = frozenset(allowed_regions if allowed_regions is not None else {region})
        self.items: list[dict] = []
        self.gaps: list[dict] = []
        self.limits: list[dict] = []
        self._clients: dict[tuple[str, str], Any] = {}

    def client(self, service: str, region: str | None = None) -> Any:
        region = self.region if region is None else region
        if region not in self.allowed_regions:
            raise _Unreadable("RegionOutsideVerificationScope")
        key = (service, region)
        if key not in self._clients:
            try:
                # Requested read-only; the Api boundary also refuses any mutation.
                self._clients[key] = Api(self.router.client(self.account, service, region))
            except Exception as exc:  # every read that needs this client becomes a gap
                self._clients[key] = exc
        value = self._clients[key]
        if isinstance(value, Exception):
            raise value
        return value

    def gap(self, collector: str, resource_arn: str | None, reason: str,
            account: str | None = None) -> None:
        self.gaps.append({"collector": collector, "account": account or self.account,
                          "region": self.region, "resource_arn": resource_arn, "reason": reason})

    def attempt(self, collector: str, resource_arn: str | None, operation: str,
                call: Callable[[], Any]) -> Any:
        try:
            return call()
        except Exception as exc:
            self.gap(collector, resource_arn, _failure(operation, exc))
            return _FAILED


# Owner side ----------------------------------------------------------------

def _owner(router: Any, owner: str, region: str, resources: dict[str, str],
           users: dict[str, set[str]], allowed_regions: set[str] | None = None) -> dict:
    task = _Task(router, owner, region, allowed_regions)
    found: dict[str, Any] = {"task": task, "rules": {}, "tgw": {}, "ca": {}}
    families: dict[str, list[str]] = defaultdict(list)
    for arn, kind in sorted(resources.items()):
        families[kind.lower()].append(arn)
    if families[RESOLVER_RULE]:
        _rules(task, families[RESOLVER_RULE], found["rules"])
    for arn in families[TRANSIT_GATEWAY]:
        found["tgw"][arn] = _owner_attachments(task, arn)
    for arn in families[IPAM_POOL]:
        _allocations(task, arn, users[arn])
    for arn in families[PRIVATE_CA]:
        found["ca"][arn] = _ca_status(task, arn)
    return found


def _rules(task: _Task, arns: list[str], rule_ids: dict[str, str]) -> None:
    """Rule IDs come from the owner's own inventory, never from parsing ARNs."""
    rows = task.attempt("resolver_rules", None, "list_resolver_rules", lambda: pages(
        task.client("route53resolver"), "list_resolver_rules", "ResolverRules"))
    if rows is _FAILED:
        return
    listed: dict[Any, list[dict]] = defaultdict(list)
    for row in rows:
        listed[row.get("Arn")].append(row)
    endpoints: dict[str, list[str]] = defaultdict(list)
    for arn in arns:
        matches = listed.get(arn, [])
        rule = matches[0] if len(matches) == 1 else {}
        rule_id, endpoint = rule.get("Id"), rule.get("ResolverEndpointId")
        if not matches:
            task.gap("resolver_rules", arn, _reason("NotListed", "ListResolverRules"))
            continue
        if not _text(rule_id) or (endpoint is not None and not _text(endpoint)):
            task.gap("resolver_rules", arn, _reason("UnexpectedResponse", "ListResolverRules"))
            continue
        # FORWARD and SYSTEM rules alike are bridged; only FORWARD rules need an endpoint.
        rule_ids[arn] = rule_id
        if endpoint:
            endpoints[endpoint].append(arn)
        elif rule.get("RuleType") == "FORWARD":
            task.gap("resolver_endpoints", arn, _reason("UnexpectedResponse", "ListResolverRules"))
    for endpoint, users in sorted(endpoints.items()):
        _endpoint(task, endpoint, sorted(users))


def _endpoint(task: _Task, endpoint_id: str, rule_arns: list[str]) -> None:
    """One item per endpoint. Its resource_arn is the first in-scope rule using it and
    rule_arns every one, so the item stays in the scope of any group relying on it."""
    rule_arn = rule_arns[0]
    def read():
        value = task.client("route53resolver").get_resolver_endpoint(
            ResolverEndpointId=endpoint_id).get("ResolverEndpoint") or {}
        if value.get("Id") != endpoint_id or not _text(value.get("Status")):
            raise _Unreadable()
        return value["Status"]

    def addresses():
        found: dict[str, str] = {}
        for row in pages(task.client("route53resolver"), "list_resolver_endpoint_ip_addresses",
                         "IpAddresses", ResolverEndpointId=endpoint_id):
            ip = row.get("Ip") or row.get("Ipv6")
            if not _text(ip) or not _text(row.get("Status")) or ip in found:
                raise _Unreadable()
            found[ip] = row["Status"]
        return [{"ip": ip, "status": found[ip]} for ip in sorted(found)]

    status = task.attempt("resolver_endpoints", rule_arn, "get_resolver_endpoint", read)
    if status is _FAILED:
        return
    ips = task.attempt("resolver_endpoints", rule_arn, "list_resolver_endpoint_ip_addresses", addresses)
    task.items.append(_item(
        "resolver_endpoint", [task.account, task.region, endpoint_id], None, task.account,
        task.region, rule_arn, endpoint_id=endpoint_id, rule_arns=rule_arns, status=status,
        ip_addresses=None if ips is _FAILED else ips))


def _owner_attachments(task: _Task, arn: str) -> dict | None:
    """The TGW owner's attachments by ID; None when they could not be read."""
    tgw = _resource_id(arn, "transit-gateway")
    if tgw is None:
        task.gap("tgw_owner_attachments", arn,
                 _reason("UnrecognizedArn", "DescribeTransitGatewayAttachments"))
        return None

    def read():
        view: dict[str, dict] = {}
        for row in pages(task.client("ec2"), "describe_transit_gateway_attachments",
                         "TransitGatewayAttachments",
                         Filters=[{"Name": "transit-gateway-id", "Values": [tgw]}]):
            attachment = row.get("TransitGatewayAttachmentId")
            if row.get("TransitGatewayId") != tgw or not _text(attachment) or attachment in view:
                raise _Unreadable()
            view[attachment] = row
        return view

    view = task.attempt("tgw_owner_attachments", arn, "describe_transit_gateway_attachments", read)
    return None if view is _FAILED else view


def _allocations(task: _Task, arn: str, consumers: set[str]) -> None:
    pool = _resource_id(arn, "ipam-pool")
    if pool is None:
        task.gap("ipam_allocations", arn, _reason("UnrecognizedArn", "GetIpamPoolAllocations"))
        return

    def describe():
        rows = evidence_pages(task.client("ec2"), "describe_ipam_pools", "IpamPools",
                              IpamPoolIds=[pool])
        if len(rows) != 1 or rows[0].get("IpamPoolId") != pool or \
                rows[0].get("IpamPoolArn") != arn or rows[0].get("OwnerId") != task.account:
            raise _Unreadable("IpamPoolIdentityMismatch")
        locale = rows[0].get("Locale")
        if not isinstance(locale, str) or not _REGION.fullmatch(locale):
            raise _Unreadable("IpamPoolLocaleUnknown")
        return locale

    locale = task.attempt("ipam_allocations", arn, "describe_ipam_pools", describe)
    if locale is _FAILED:
        return

    def read():
        found: dict[str, dict] = {}
        # The pool ARN is global and its RAM share can be in the IPAM home Region;
        # GetIpamPoolAllocations must be sent to the verified pool's Locale.
        for row in evidence_pages(task.client("ec2", locale), "get_ipam_pool_allocations",
                                  "IpamPoolAllocations", IpamPoolId=pool):
            allocation = row.get("IpamPoolAllocationId")
            if not _text(allocation) or allocation in found or \
                    (row.get("ResourceOwner") in consumers and not _text(row.get("Cidr"))):
                raise _Unreadable()
            found[allocation] = row
        return found

    rows = task.attempt("ipam_allocations", arn, "get_ipam_pool_allocations", read)
    if rows is _FAILED:
        return
    for allocation, row in sorted(rows.items()):
        if row.get("ResourceOwner") in consumers:
            task.items.append(_item(
                "ipam_allocation", [task.account, task.region, pool, allocation],
                row["ResourceOwner"], task.account, task.region, arn, pool_id=pool,
                allocation_id=allocation, cidr=row["Cidr"], resource_id=row.get("ResourceId"),
                resource_type=row.get("ResourceType"), allocation_region=locale))


def _ca_status(task: _Task, arn: str) -> str | None:
    def read():
        value = task.client("acm-pca").describe_certificate_authority(
            CertificateAuthorityArn=arn).get("CertificateAuthority") or {}
        if value.get("Arn") != arn or value.get("OwnerAccount") not in (None, task.account) or \
                not _text(value.get("Status")):
            raise _Unreadable()
        return value["Status"]

    status = task.attempt("pca_status", arn, "describe_certificate_authority", read)
    return None if status is _FAILED else status


# Consumer side ---------------------------------------------------------------

def _visible(task: _Task, received: dict[str, tuple[str, str]]) -> dict[str, dict[str, dict]] | None:
    """Resource ARN -> {ACTIVE received share ARN: share} listing it AVAILABLE.

    None when the received shares could not be listed. A share whose resources
    could not be listed leaves a gap, so the result is then a lower bound.
    """
    def listing():
        found: dict[str, dict] = {}
        for row in pages(task.client("ram"), "get_resource_shares", "resourceShares",
                         resourceOwner="OTHER-ACCOUNTS"):
            arn = row.get("resourceShareArn")
            if not _text(arn) or arn in found:
                raise _Unreadable()
            found[arn] = row
        return found

    shares = task.attempt("entitlement", None, "get_resource_shares", listing)
    if shares is _FAILED:
        return None
    owners = {owner for owner, _ in received.values()}
    visible: dict[str, dict[str, dict]] = {arn: {} for arn in received}
    for arn, share in sorted(shares.items()):
        # Only an owner can share its resources; other owners' shares cannot supply them.
        if share.get("status") != "ACTIVE" or share.get("owningAccountId") not in (None, *owners):
            continue
        rows = task.attempt("entitlement", None, "list_resources", lambda arn=arn: pages(
            task.client("ram"), "list_resources", "resources", resourceOwner="OTHER-ACCOUNTS",
            resourceShareArns=[arn]))
        if rows is _FAILED:
            continue
        for row in rows:
            if row.get("arn") in visible and row.get("status") == "AVAILABLE" and \
                    row.get("resourceShareArn") in (None, arn):
                visible[row["arn"]][arn] = share
    return visible


def _consumer(router: Any, consumer: str, region: str, received: dict[str, tuple[str, str]],
              owners: dict[tuple[str, str], dict], temporary: frozenset[str],
              include_tgw_routes: bool = True) -> _Task:
    task = _Task(router, consumer, region)
    visible = _visible(task, received)
    rules: dict[str, tuple[str, str]] = {}
    for arn, (owner, kind) in sorted(received.items()):
        if visible is not None:
            shares = sorted(visible[arn])
            task.items.append(_item(
                "entitlement", [consumer, region, arn], consumer, owner, region, arn, type=kind,
                via_shares=shares, via_temporary=[s for s in shares if s in temporary],
                via_other=[s for s in shares if s not in temporary]))
        family, inventory = kind.lower(), owners[(owner, region)]
        if family == RESOLVER_RULE:
            if arn in inventory["rules"]:  # otherwise the owner's gap covers this rule
                rules[inventory["rules"][arn]] = (arn, owner)
        elif family == TRANSIT_GATEWAY:
            _consumer_tgw(task, arn, owner, inventory["tgw"].get(arn), include_tgw_routes)
        elif family == PRIVATE_CA:
            _ca_read(task, arn, owner, inventory["ca"].get(arn))
        elif family != IPAM_POOL:  # IPAM allocations are read from the owner
            task.limits.append({"collector": "resource_checks", "account": consumer,
                                "region": region, "resource_arn": arn, "type": kind,
                                "reason": UNAVAILABLE})
    if rules:
        _associations(task, rules)
    return task


def _associations(task: _Task, rules: dict[str, tuple[str, str]]) -> None:
    def read():
        found: dict[str, dict] = {}
        seen: set[str] = set()
        for row in pages(task.client("route53resolver"), "list_resolver_rule_associations",
                         "ResolverRuleAssociations"):
            association, rule = row.get("Id"), row.get("ResolverRuleId")
            if not _text(association) or association in seen:
                raise _Unreadable()
            seen.add(association)
            if association.startswith(AUTODEFINED) or rule not in rules:
                continue
            if not _text(row.get("VPCId")) or not _text(row.get("Status")):
                raise _Unreadable()
            found[association] = row
        return found

    rows = task.attempt("resolver_associations", None, "list_resolver_rule_associations", read)
    if rows is _FAILED:
        return
    for association, row in sorted(rows.items()):
        arn, owner = rules[row["ResolverRuleId"]]
        task.items.append(_item(
            "resolver_association", [task.account, task.region, association], task.account, owner,
            task.region, arn, rule_id=row["ResolverRuleId"], vpc_id=row["VPCId"],
            association_id=association, status=row["Status"]))


def _owner_state(task: _Task, view: dict | None, attachment: str, owner: str, arn: str) -> str | None:
    """The TGW owner's route-table association state; None only when unobserved."""
    if view is None:
        return None
    row = view.get(attachment)
    if row is None:
        return "not_listed"
    association = row.get("Association")
    state = association.get("State") if isinstance(association, dict) else None
    if row.get("ResourceOwnerId") not in (None, task.account) or \
            (association is not None and not _text(state)):
        task.gap("tgw_owner_attachments", arn,
                 _reason("UnexpectedResponse", "DescribeTransitGatewayAttachments"), account=owner)
        return None
    return "not_associated" if association is None else state


def _consumer_tgw(task: _Task, arn: str, owner: str, view: dict | None,
                  include_tgw_routes: bool = True) -> None:
    tgw, consumer, region = _resource_id(arn, "transit-gateway"), task.account, task.region
    if tgw is None:
        collectors = [("tgw_attachments", "DescribeTransitGatewayVpcAttachments")]
        if include_tgw_routes:
            collectors.append(("tgw_routes", "DescribeRouteTables"))
        for collector, operation in collectors:
            task.gap(collector, arn, _reason("UnrecognizedArn", operation))
        return

    def attachments():
        found: dict[str, tuple[str, str]] = {}
        for row in pages(task.client("ec2"), "describe_transit_gateway_vpc_attachments",
                         "TransitGatewayVpcAttachments",
                         Filters=[{"Name": "transit-gateway-id", "Values": [tgw]}]):
            attachment = row.get("TransitGatewayAttachmentId")
            if row.get("TransitGatewayId") != tgw or not _text(attachment) or \
                    not _text(row.get("VpcOwnerId")) or attachment in found:
                raise _Unreadable()
            if row["VpcOwnerId"] != consumer:
                continue
            if not _text(row.get("VpcId")) or not _text(row.get("State")):
                raise _Unreadable()
            found[attachment] = (row["VpcId"], row["State"])
        return found

    def routes():
        """Every route to the TGW in the consumer's own route tables, in any state:
        a blackhole route is observed state, never an absent one."""
        found: dict[tuple[str, str], str] = {}
        for table in pages(task.client("ec2"), "describe_route_tables", "RouteTables",
                           Filters=[{"Name": "route.transit-gateway-id", "Values": [tgw]}]):
            table_id = table.get("RouteTableId")
            if not _text(table_id) or not _text(table.get("OwnerId")):
                raise _Unreadable()
            if table["OwnerId"] != consumer:
                continue
            for route in table.get("Routes") or []:
                if route.get("TransitGatewayId") != tgw:
                    continue
                destination = route.get("DestinationCidrBlock") or \
                    route.get("DestinationIpv6CidrBlock") or route.get("DestinationPrefixListId")
                if not _text(destination) or not _text(route.get("State")) or \
                        (table_id, destination) in found:
                    raise _Unreadable()
                found[(table_id, destination)] = route["State"]
        return found

    rows = task.attempt("tgw_attachments", arn, "describe_transit_gateway_vpc_attachments", attachments)
    if rows is not _FAILED:
        for attachment, (vpc, state) in sorted(rows.items()):
            task.items.append(_item(
                "tgw_attachment", [consumer, region, attachment], consumer, owner, region, arn,
                tgw_id=tgw, attachment_id=attachment, vpc_id=vpc, state=state,
                owner_association_state=_owner_state(task, view, attachment, owner, arn)))
    if not include_tgw_routes:
        return
    rows = task.attempt("tgw_routes", arn, "describe_route_tables", routes)
    if rows is not _FAILED:
        for (table_id, destination), state in sorted(rows.items()):
            task.items.append(_item(
                "tgw_route", [consumer, region, table_id, destination], consumer, owner, region, arn,
                tgw_id=tgw, route_table_id=table_id, destination=destination, state=state))


def _ca_read(task: _Task, arn: str, owner: str, status: str | None) -> None:
    """OK, DENIED (an AccessDenied* answer to the read itself) or ERROR with a gap."""
    operation, read = "get_certificate_authority_certificate", "ERROR"
    try:
        client = task.client("acm-pca")
    except Exception as exc:  # no client is no answer from ACM PCA, never a denial
        task.gap("pca_read", arn, _failure(operation, exc))
    else:
        try:
            body = client.get_certificate_authority_certificate(CertificateAuthorityArn=arn)
            if not _text(body.get("Certificate")) or not body["Certificate"].strip():
                raise _Unreadable()
            read = "OK"
        except ClientError as exc:
            if str((exc.response.get("Error") or {}).get("Code") or "").startswith("AccessDenied"):
                read = "DENIED"
            else:
                task.gap("pca_read", arn, _failure(operation, exc))
        except Exception as exc:
            task.gap("pca_read", arn, _failure(operation, exc))
    task.items.append(_item("pca_access", [task.account, task.region, arn], task.account, owner,
                            task.region, arn, ca_status=status, consumer_read=read))


def _sorted_gaps(gaps: list[dict]) -> list[dict]:
    unique = {json.dumps(gap, sort_keys=True): gap for gap in gaps}
    return sorted(unique.values(), key=lambda gap: tuple(
        str(gap.get(name) or "") for name in ("collector", "account", "region", "resource_arn", "reason")))


def collect(router: Any, groups: Any, *, temporary_shares: Any = frozenset(),
            workers: int = 4, allowed_regions: Iterable[str] | None = None,
            include_tgw_routes: bool = True) -> Observation:
    """Observe the groups: owner inventories first, then every consumer.

    At most ``workers`` account/Region reads run at once. Only read-only clients
    are requested. IPAM allocation reads use the verified pool Locale, only within
    ``allowed_regions`` (by default the Regions of the supplied groups).
    ``include_tgw_routes=False`` excludes route collection only; entitlement and
    existing attachment reads still run. The CLI binds this choice to the record.
    """
    if type(include_tgw_routes) is not bool:
        raise MigrationError("include_tgw_routes must be a boolean")
    scope = _scope(groups)
    temporary = _share_arns(temporary_shares)
    count = _workers(workers)
    owned, received = sorted(scope.owned), sorted(scope.received)
    scoped_regions = {region for _, region in owned + received}
    if allowed_regions is not None and not _sequence(allowed_regions):
        raise MigrationError("allowed_regions must be a collection of Region names")
    allowed = set(allowed_regions) if allowed_regions is not None else scoped_regions
    if any(not isinstance(region, str) or not _REGION.fullmatch(region) for region in allowed) or \
            not scoped_regions <= allowed:
        raise MigrationError("allowed_regions must include every group Region and be valid Regions")
    with ThreadPoolExecutor(max_workers=count) as pool:
        owners = dict(zip(owned, pool.map(lambda key: _owner(
            router, *key, scope.owned[key],
            {arn: scope.users[(*key, arn)] for arn in scope.owned[key]}, allowed), owned)))
        consumers = list(pool.map(lambda key: _consumer(
            router, *key, scope.received[key], owners, temporary, include_tgw_routes), received))
    items: dict[str, dict] = {}
    gaps: list[dict] = []
    limits: list[dict] = []
    for task in [owners[key]["task"] for key in owned] + consumers:
        for item in task.items:
            if item["key"] in items:
                raise MigrationError(f"Duplicate verification item {item['key']}")
            items[item["key"]] = item
        gaps.extend(task.gaps)
        limits.extend(task.limits)
    return Observation(timestamp(), [items[key] for key in sorted(items)], _sorted_gaps(gaps),
                       _sorted_gaps(limits))


# ---------------------------------------------------------------------------
# Comparison
# ---------------------------------------------------------------------------

def _touches(gap: dict, item: dict) -> bool:
    """Whether a gap can hide this item, or part of it."""
    collector, arn = gap.get("collector"), gap.get("resource_arn")
    if collector not in COLLECTORS:
        # Not written by this module: assume it hides whatever it names.
        return gap.get("region") in (None, item.get("region")) and \
            gap.get("account") in (None, item.get("consumer"), item.get("owner")) and \
            arn in (None, item.get("resource_arn"))
    side, kinds = COLLECTORS[collector]
    # One endpoint serves several rules, so endpoint reads are owner-and-Region wide.
    return item.get("kind") in kinds and gap.get("region") == item.get("region") and \
        gap.get("account") == item.get(side) and \
        (arn is None or arn == item.get("resource_arn") or item.get("kind") == "resolver_endpoint")


def _index(items: Any, label: str) -> dict[str, dict]:
    if not _sequence(items):
        raise MigrationError(f"{label} items must be a list of verification items")
    index: dict[str, dict] = {}
    for item in items:
        if not isinstance(item, dict) or item.get("kind") not in KINDS or \
                not isinstance(item.get("key"), str) or not item["key"].startswith(item["kind"] + "|"):
            raise MigrationError(f"{label} contains an unsupported or malformed verification item; "
                                 "compare only items written by this tool (baseline schema 1)")
        if item["key"] in index:
            raise MigrationError(f"{label} contains duplicate item key {item['key']}")
        index[item["key"]] = item
    return index


def _gap_list(gaps: Any) -> list[dict]:
    gaps = list(gaps) if _sequence(gaps) else None
    if gaps is None or any(not isinstance(gap, dict) for gap in gaps):
        raise MigrationError("observation gaps must be a list of gap objects")
    return [dict(gap) for gap in gaps]


def _state(name: str, now: Any, healthy: str, lost: list[str], unread: list[str]) -> None:
    if now == healthy:
        return
    if now is None or now in UNREAD.get(name, ()):
        unread.append(f"{name} not observed")
    else:
        lost.append(f"{name} {now}")


def _judge(before: dict, after: dict, hidden: bool) -> tuple[list[str], list[str]]:
    """(losses, conditions that could not be judged) for one present baseline item."""
    kind, lost, unread = before["kind"], [], []
    # The migration is judged only on what it can change: an entitlement the consumer
    # could not see, or a state that was already unhealthy, before the migration is
    # recorded as found and is no loss while it stays so (it may still be lost
    # entirely, or have its identity replaced).
    if kind == "entitlement" and not after.get("via_shares") and before.get("via_shares"):
        if hidden:  # a share that could not be listed may still supply it
            unread.append("visible through no listed share; not every received share was listed")
        else:
            lost.append("not visible to the consumer")
    for name, healthy in (*REQUIRED.get(kind, ()), *RETAINED.get(kind, ())):
        if before.get(name) == healthy:
            _state(name, after.get(name), healthy, lost, unread)
    if kind == "resolver_endpoint":
        attached = [row.get("ip") for row in before.get("ip_addresses") or []
                    if isinstance(row, dict) and row.get("status") == "ATTACHED"]
        now = after.get("ip_addresses")
        if attached and now is None:
            unread.append("ip_addresses not observed")
        elif attached:
            states = {row.get("ip"): row.get("status") for row in now if isinstance(row, dict)}
            for ip in attached:
                if ip not in states:
                    lost.append(f"ip {ip} absent")
                elif states[ip] != "ATTACHED":
                    lost.append(f"ip {ip} status {states[ip]}")
    lost += [f"{name} changed" for name in IDENTITY.get(kind, ()) if after.get(name) != before.get(name)]
    return lost, unread


def compare(baseline_items: Any, observation: Any) -> Comparison:
    """Judge every baseline item by the Loss-when rules of section 2.

    An absent item is missing unless a gap could hide it; then it, like any
    condition a gap leaves unread, is unobserved. LOSS when anything is missing
    or degraded; otherwise INCONCLUSIVE while the observation has any gap or an
    unobserved item; otherwise INTACT. Items the baseline lacks are only
    reported as ``added``: coverage of new consumers is the caller's check.
    """
    baseline = _index(baseline_items, "baseline")
    current = _index(_value(observation, "items"), "observation")
    result = Comparison(gaps=_gap_list(_value(observation, "gaps")))
    for key in sorted(baseline):
        before, after = baseline[key], current.get(key)
        hiding = [gap for gap in result.gaps if _touches(gap, before)]
        if after is None:
            if hiding:
                result.unobserved.append({"key": key, "before": before, "after": None, "reasons": [
                    f"not observed: {gap.get('collector')} {gap.get('reason')}" for gap in hiding]})
            else:
                result.missing.append({"key": key, "item": before})
            continue
        lost, unread = _judge(before, after, bool(hiding))
        if lost:
            result.degraded.append({"key": key, "before": before, "after": after, "reasons": lost})
        elif unread:
            result.unobserved.append({"key": key, "before": before, "after": after, "reasons": unread})
        else:
            result.present.append(key)
    result.added = sorted(set(current) - set(baseline))
    result.status = LOSS if result.missing or result.degraded else \
        INCONCLUSIVE if result.gaps or result.unobserved else INTACT
    return result


# ---------------------------------------------------------------------------
# Replacement access
# ---------------------------------------------------------------------------

def _migration_share(share: dict) -> bool:
    """A share named or tagged by this tool is temporary in some migration, never permanent."""
    if str(share.get("name") or "").startswith(PURPOSE + "-"):
        return True
    try:
        return managed(share.get("tags") or [])
    except MigrationError:  # ambiguous or malformed tags: never trusted as permanent
        return True


def replacement_access(router: Any, groups: Any, temporary_shares: Any, *,
                       workers: int = 4) -> dict:
    """One row per temporary entitlement (consumer, region, resource_arn):
    ``covered`` when an ACTIVE share that is neither a recorded temporary share
    nor any migration's share lists it AVAILABLE, ``uncovered`` when the
    received shares were all read and none does, else ``gaps``."""
    scope = _scope(groups)
    temporary = _share_arns(temporary_shares)
    count = _workers(workers)
    if not temporary:
        raise MigrationError("replacement_access needs the recorded temporary share ARNs; without "
                             "them a temporary share would count as its own replacement")

    def check(key: tuple[str, str]) -> dict[str, list[dict]]:
        consumer, region = key
        task = _Task(router, consumer, region)
        visible = _visible(task, scope.received[key])
        rows: dict[str, list[dict]] = {"covered": [], "uncovered": [], "gaps": []}
        for arn, (owner, kind) in sorted(scope.received[key].items()):
            entry = {"consumer": consumer, "owner": owner, "region": region,
                     "resource_arn": arn, "type": kind}
            shares = visible[arn] if visible is not None else {}
            replacements = sorted(share for share, row in shares.items()
                                  if share not in temporary and not _migration_share(row))
            if replacements:
                rows["covered"].append({**entry, "via_shares": replacements})
            elif task.gaps:
                rows["gaps"].append({**entry, "collector": "entitlement", "account": consumer,
                                     "reason": "; ".join(sorted({gap["reason"] for gap in task.gaps}))})
            else:
                rows["uncovered"].append({
                    **entry, "via_temporary": sorted(share for share in shares if share in temporary),
                    "via_other_migrations": sorted(share for share in shares if share not in temporary)})
        return rows

    with ThreadPoolExecutor(max_workers=count) as pool:
        results = list(pool.map(check, sorted(scope.received)))
    return {name: [row for result in results for row in result[name]]
            for name in ("covered", "uncovered", "gaps")}


# ---------------------------------------------------------------------------
# Approved private CA issuance test (the only write path)
# ---------------------------------------------------------------------------

def pca_issuance_test(write_client: Any, *, migration: str, consumer: str, region: str,
                      ca_arn: str, csr_pem: str | bytes, signing_algorithm: str,
                      approval: dict) -> dict:
    """Issue one 1-day certificate as the consumer from a shared private CA.

    Refuses, before any request, unless ``approval`` binds exactly this test:
    ``kind`` ``pca_issuance_test``, ``migration_id``, ``consumer``, ``ca_arn`` and
    the ``csr_sha256`` of the CSR bytes. ``write_client`` must be the consumer's
    acm-pca client in ``region``. The idempotency token derives from the
    approval, so retrying the same approved test within ACM PCA's token window
    issues no second certificate.
    """
    account_id(consumer)
    if not _text(migration):
        raise MigrationError("pca_issuance_test needs the migration ID its approval is bound to")
    csr = csr_pem.encode() if isinstance(csr_pem, str) else csr_pem
    if not isinstance(csr, bytes) or not re.search(rb"-----BEGIN (NEW )?CERTIFICATE REQUEST-----", csr):
        raise MigrationError("csr_pem must be a PEM-encoded certificate signing request")
    binding = {"kind": "pca_issuance_test", "migration_id": migration, "consumer": consumer,
               "ca_arn": ca_arn, "csr_sha256": hashlib.sha256(csr).hexdigest()}
    if not isinstance(approval, dict) or any(approval.get(k) != v for k, v in binding.items()):
        raise MigrationError("PCA issuance test refused: approve this exact test first; the approval "
                             "must bind kind=pca_issuance_test, this migration, consumer, CA ARN and "
                             "CSR SHA-256")
    parts = ca_arn.split(":", 5) if isinstance(ca_arn, str) else []
    if len(parts) != 6 or parts[0] != "arn" or parts[2] != "acm-pca" or parts[3] != region or \
            not parts[5].startswith("certificate-authority/"):
        raise MigrationError(f"{ca_arn!r} is not a private CA ARN in {region}")
    if parts[4] == consumer:
        raise MigrationError(f"{consumer} owns {ca_arn}; the issuance test must run as a consumer "
                             "of the shared CA")
    meta = getattr(write_client, "meta", None)
    if getattr(meta, "region_name", None) != region or \
            getattr(getattr(meta, "service_model", None), "service_name", None) != "acm-pca":
        raise MigrationError(f"pca_issuance_test needs an explicit acm-pca client for {consumer} "
                             f"in {region}")
    if not _text(signing_algorithm):
        raise MigrationError("signing_algorithm is required, for example SHA256WITHRSA")
    token = hashlib.sha256(json.dumps(approval, sort_keys=True, separators=(",", ":"),
                                      default=str).encode()).hexdigest()[:32]
    requested_at = timestamp()
    try:
        certificate = write_client.issue_certificate(
            CertificateAuthorityArn=ca_arn, Csr=csr, SigningAlgorithm=signing_algorithm,
            Validity={"Value": 1, "Type": "DAYS"}, IdempotencyToken=token).get("CertificateArn")
    except ClientError as exc:
        raise MigrationError(f"{consumer} could not issue from {ca_arn}: "
                             f"{_failure('issue_certificate', exc)}") from None
    if not _text(certificate) or not certificate.startswith(ca_arn + "/certificate/"):
        raise MigrationError(f"issue_certificate returned no certificate ARN under {ca_arn}")
    deadline = time.monotonic() + ISSUANCE_TIMEOUT
    while True:
        try:
            body = write_client.get_certificate(CertificateAuthorityArn=ca_arn, CertificateArn=certificate)
            break
        except ClientError as exc:
            if (exc.response.get("Error") or {}).get("Code") != "RequestInProgressException":
                raise MigrationError(f"{certificate}: {_failure('get_certificate', exc)}") from None
        if time.monotonic() >= deadline:
            raise MigrationError(f"{certificate}: issuance still in progress after "
                                 f"{ISSUANCE_TIMEOUT:.0f}s; re-run the same approved test, whose "
                                 "idempotency token is stable")
        time.sleep(ISSUANCE_POLL)
    if not _text(body.get("Certificate")):
        raise MigrationError(f"{certificate}: get_certificate returned no certificate")
    return {**binding, "region": region, "signing_algorithm": signing_algorithm,
            "idempotency_token": token, "certificate_arn": certificate,
            "requested_at": requested_at, "issued_at": timestamp()}
