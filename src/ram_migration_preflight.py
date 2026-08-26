"""Read-only organization-policy preflight for temporary migration shares.

large-estate cases case 051, case 053 and case 054. ``plan`` runs it before recording a
reviewed plan, and ``apply`` runs it again before its confirmation and after it,
immediately before the write gate. Through each organization's management
account it reads the service control policies (SCPs) and resource control
policies (RCPs) attached to every target on each account's path (account, its
OUs, the root) and evaluates every statement, conservatively, for the requests
this tool makes:

* every owner that writes temporary shares, in every Region it writes them:
  ``ram:CreateResourceShare`` with ``allowExternalPrincipals=true``,
  ``ram:TagResource`` and ``ram:AssociateResourceShare`` (CloudFormation calls
  RAM with the caller's credentials), the CloudFormation change-set and stack
  calls, and the RAM reads;
* every consumer: ``ram:AcceptResourceShareInvitation`` for each owner's share,
  evaluated against the consumer's policies and the RCPs of the owner, whose
  account holds the invitation, and the invitation read;
* with ``--destination-ou``, every migrating account in the plan on the
  destination path (the OU, its parents, the root): the reads verify and the
  monitor need after the move.

A Deny statement that applies is a blocker naming the policy, its target, the
statement and the actions. A target where no attached statement allows an
action denies it as well (an allow-list that omits a namespace). Whatever the
evaluator cannot decide - a condition key or operator it does not evaluate, a
policy variable, a resource pattern, a principal element or a malformed
statement - is a gap: it blocks too and is listed for review. A read that fails
is a named blocker; nothing unread is assumed allowed. Where original shares use
OU or organization principals, the RAM organization prerequisites (ALL features
and ram.amazonaws.com trusted access, which RAM's sharing with AWS Organizations
enables) are checked in their organization and in the destination organization.
The module never enables, attaches or edits anything, and it requests read-only
clients only.
"""
from __future__ import annotations

import hashlib
import json
import re
from collections import defaultdict
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Any, Callable, Iterable

from botocore.exceptions import ClientError

from ram_migration_common import MigrationError, account_id, pages, timestamp
from ram_migration_discovery import failure_text

SCHEMA = "ram-migration-org-policy-preflight/1"
ORGANIZATIONS_REGION = "us-east-1"
SCP, RCP = "SERVICE_CONTROL_POLICY", "RESOURCE_CONTROL_POLICY"
KINDS = (SCP, RCP)
SHORT = {SCP: "SCP", RCP: "RCP"}
RAM_SERVICE = "ram.amazonaws.com"
# Hash of this evaluator as it was loaded, recorded with every result.
EVALUATOR_SHA256 = hashlib.sha256(Path(__file__).read_bytes()).hexdigest()

# Account and path statuses.
EVALUATED, STANDALONE, MANAGEMENT_ACCOUNT, UNREADABLE = (
    "EVALUATED", "STANDALONE", "MANAGEMENT_ACCOUNT", "UNREADABLE")
# Whether a policy type governs a path: every target has attachments, none has
# (the type is not enabled), or only some have (contradicts AWS Organizations).
ENABLED, NOT_ENABLED, INCOMPLETE = "ENABLED", "NOT_ENABLED", "INCOMPLETE"
# Finding decisions.
EXPLICIT_DENY, NO_ALLOW, UNDECIDED, NOT_MET = "EXPLICIT_DENY", "NO_ALLOW", "UNDECIDED", "NOT_MET"

_ORG = r"o-[a-z0-9]{10,32}"
_ROOT = r"r-[0-9a-z]{4,32}"
_OU = r"ou-[0-9a-z]{4,32}-[a-z0-9]{8,32}"
ORG_ID, ROOT_ID, OU_ID = re.compile(_ORG), re.compile(_ROOT), re.compile(_OU)
POLICY_ID = re.compile(r"p-[0-9a-zA-Z_]{8,128}")
DESTINATION = re.compile(
    rf"arn:(?:aws|aws-us-gov|aws-cn):organizations::(\d{{12}}):"
    rf"(?:ou/({_ORG})/({_OU})|root/({_ORG})/({_ROOT}))")
# The shapes discovery accepts for OU and organization principals.
ORGANIZATION_PRINCIPAL = re.compile(
    r"arn:[a-z0-9-]+:organizations::(\d{12}):"
    r"(?:organization/(o-[a-z0-9]+)|ou/(o-[a-z0-9]+)/ou-[a-z0-9]+-[a-z0-9]+)")
# Root plus at most five nested OUs; anything longer is not an Organizations path.
MAX_DEPTH = 8
# The partitions a request's resource ARN can be in.
PARTITIONS = ("aws", "aws-cn", "aws-us-gov", "aws-iso", "aws-iso-b", "aws-iso-e", "aws-iso-f",
              "aws-eusc")


@dataclass(frozen=True)
class Action:
    """One API action and what its request context is known to hold.

    ``resource`` names the account that owns the resource the request acts on:
    ``self`` the caller's account, ``owner`` the share owner's, None unknown (a
    list or read whose resource account is not modeled). ``external`` marks a
    request with ``ram:RequestedAllowsExternalPrincipals=true``; every other
    request lacks that key. ``region`` fixes the Region of a global API."""
    name: str
    resource: str | None = None
    external: bool = False
    region: str | None = None


# What apply does in each owner account and Region: the migration stack creates or
# extends the shares (CloudFormation calls RAM with the caller's credentials), and
# the tool reads them back.
OWNER_ACTIONS = (
    Action("ram:CreateResourceShare", external=True),
    Action("ram:TagResource"),
    Action("ram:AssociateResourceShare", resource="self"),
    Action("cloudformation:CreateChangeSet", resource="self"),
    Action("cloudformation:DescribeChangeSet", resource="self"),
    Action("cloudformation:ExecuteChangeSet", resource="self"),
    Action("cloudformation:DescribeStacks", resource="self"),
    Action("cloudformation:GetTemplate", resource="self"),
    Action("cloudformation:ListStackResources", resource="self"),
    Action("ram:GetResourceShares"),
    Action("ram:ListResources"),
    Action("ram:GetResourceShareAssociations"),
    Action("ram:ListResourceSharePermissions"),
    Action("ram:GetPermission"),
)
# What apply does in each consumer account, per owner and Region. The invitation
# belongs to the owner's account.
CONSUMER_ACTIONS = (
    Action("ram:AcceptResourceShareInvitation", resource="owner"),
    Action("ram:GetResourceShareInvitations"),
)
# What verify and the monitor read in a migrated account after the move.
DESTINATION_ACTIONS = (
    Action("ram:GetResourceShares"),
    Action("ram:ListResources"),
    Action("ram:GetResourceShareAssociations"),
    Action("ram:GetResourceShareInvitations"),
    Action("ram:ListResourceSharePermissions"),
    Action("ram:GetPermission"),
    Action("route53resolver:ListResolverRules"),
    Action("route53resolver:ListResolverRuleAssociations"),
    Action("route53resolver:GetResolverRule"),
    Action("route53resolver:GetResolverEndpoint"),
    Action("route53resolver:ListResolverEndpointIpAddresses"),
    Action("ec2:DescribeTransitGatewayAttachments"),
    Action("ec2:DescribeTransitGatewayVpcAttachments"),
    Action("ec2:DescribeTransitGatewayRouteTables"),
    Action("ec2:DescribeRouteTables"),
    Action("ec2:DescribeInstances"),
    Action("ec2:SearchTransitGatewayRoutes"),
    Action("ec2:GetIpamPoolAllocations"),
    Action("ec2:DescribeRegions", region=ORGANIZATIONS_REGION),
    Action("acm-pca:DescribeCertificateAuthority"),
    Action("acm-pca:GetCertificateAuthorityCertificate"),
    Action("organizations:DescribeOrganization", region=ORGANIZATIONS_REGION),
)

# Condition keys this evaluator decides, with their type. Every other key is a gap.
STRING_KEYS = frozenset({"aws:requestedregion", "aws:principalorgid", "aws:resourceorgid",
                         "aws:principalaccount", "aws:resourceaccount"})
BOOL_KEYS = frozenset({"ram:requestedallowsexternalprincipals"})
# Positive string operators: (case-folded, wildcards). Negated ones invert them.
_STRING_OPERATORS = {"StringEquals": (False, False), "StringEqualsIgnoreCase": (True, False),
                     "StringLike": (False, True)}
_NEGATED = {"StringNotEquals": "StringEquals", "StringNotEqualsIgnoreCase": "StringEqualsIgnoreCase",
            "StringNotLike": "StringLike"}
OPERATORS = tuple(sorted({*_STRING_OPERATORS, *_NEGATED, "Bool", "Null"}))
_ELEMENTS = frozenset({"Sid", "Effect", "Action", "NotAction", "Resource", "NotResource",
                       "Condition", "Principal", "NotPrincipal"})
# Request-context value of a key the request is known not to carry.
ABSENT = object()


# ---------------------------------------------------------------------------
# Statement evaluation: True applies, False does not, None cannot be decided
# ---------------------------------------------------------------------------

def _all(values: Iterable[bool | None]) -> bool | None:
    """Three-valued AND: any False decides, otherwise any None leaves it open."""
    values = list(values)
    if any(value is False for value in values):
        return False
    return None if any(value is None for value in values) else True


@lru_cache(maxsize=4096)
def _glob(pattern: str, fold: bool) -> re.Pattern:
    body = "".join(".*" if char == "*" else "." if char == "?" else re.escape(char)
                   for char in pattern)
    return re.compile(body, re.DOTALL | (re.IGNORECASE if fold else 0))


def _matches(pattern: str, value: str, fold: bool = False) -> bool:
    return _glob(pattern, fold).fullmatch(value) is not None


@lru_cache(maxsize=4096)
def _intersects(first: str, second: str) -> bool:
    """Some string matches both globs; case-folded, and '*' spans any characters."""
    first, second = first.lower(), second.lower()
    seen: set[tuple[int, int]] = set()
    pending = [(0, 0)]
    while pending:
        state = pending.pop()
        if state in seen:
            continue
        seen.add(state)
        i, j = state
        if i == len(first) and j == len(second):
            return True
        a = first[i] if i < len(first) else None
        b = second[j] if j < len(second) else None
        if a == "*":
            pending.append((i + 1, j))
        if b == "*":
            pending.append((i, j + 1))
        if a is not None and b is not None and (a in "*?" or b in "*?" or a == b):
            pending.append((i if a == "*" else i + 1, j if b == "*" else j + 1))
    return False


def _strings(value: Any) -> list[str] | None:
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and value and all(isinstance(item, str) for item in value):
        return value
    return None


def _actions(statement: dict, action: str) -> tuple[bool | None, list[str]]:
    """IAM action names match case-insensitively, with * and ? wildcards."""
    if ("Action" in statement) == ("NotAction" in statement):
        return None, ["the statement needs exactly one of Action and NotAction"]
    element = "Action" if "Action" in statement else "NotAction"
    patterns = _strings(statement[element])
    if patterns is None:
        return None, [f"{element} is not a string or a list of strings"]
    hit = any(_matches(pattern, action, fold=True) for pattern in patterns)
    return (hit if element == "Action" else not hit), []


def _may_name(pattern: str, service: str) -> bool:
    """Whether a Resource pattern can match a resource of ``service`` in any partition,
    or the "*" of an action without resource-level permissions. The partition is
    literal, so a wildcard in the pattern cannot stand in for the service segment."""
    return _matches(pattern, "*") or any(_intersects(pattern, f"arn:{partition}:{service}:*")
                                         for partition in PARTITIONS)


def _resources(statement: dict, action: str) -> tuple[bool | None, list[str]]:
    """Only '*' is known to cover every request; a pattern of another service never
    matches; any other pattern is not resolved."""
    if "Resource" in statement and "NotResource" in statement:
        return None, ["the statement has both Resource and NotResource"]
    element = "Resource" if "Resource" in statement else "NotResource" \
        if "NotResource" in statement else None
    if element is None:
        return None, ["the statement has no Resource element"]
    patterns = _strings(statement[element])
    if patterns is None:
        return None, [f"{element} is not a string or a list of strings"]
    service = action.split(":", 1)[0]
    everything = any(pattern and not pattern.strip("*") for pattern in patterns)
    possible = sorted(pattern for pattern in patterns if _may_name(pattern, service))
    if element == "Resource":
        if everything:
            return True, []
        if not possible:
            return False, []
        return None, [f"Resource {', '.join(possible)} is not resolved for {action}"]
    if everything:
        return False, []
    if not possible:
        return True, []
    return None, [f"NotResource {', '.join(possible)} is not resolved for {action}"]


def _principals(statement: dict) -> tuple[bool | None, list[str]]:
    """SCPs have no principal element; RCPs name every principal with '*'."""
    if "NotPrincipal" in statement:
        return None, ["NotPrincipal is not evaluated"]
    if "Principal" not in statement:
        return True, []
    value = statement["Principal"]
    if value == "*" or value == {"AWS": "*"} or value == {"AWS": ["*"]}:
        return True, []
    return None, [f"Principal {json.dumps(value, sort_keys=True)} is not evaluated"]


def _clause(operator: str, key: Any, values: Any, context: dict) -> tuple[bool | None, str | None]:
    """One operator/key pair. An absent key fails a positive operator, satisfies a
    negated one, an ...IfExists one and ForAllValues, and fails ForAnyValue."""
    qualifier, base = None, operator
    for prefix in ("ForAnyValue:", "ForAllValues:"):
        if base.startswith(prefix):
            qualifier, base = prefix[:-1], base[len(prefix):]
    if_exists = base.endswith("IfExists")
    if if_exists:
        base = base[:-len("IfExists")]
    name = key.lower() if isinstance(key, str) else None
    if name not in STRING_KEYS and name not in BOOL_KEYS:
        return None, f"condition key {key} is not evaluated"
    if base not in _STRING_OPERATORS and base not in _NEGATED and base not in ("Bool", "Null") \
            or (base == "Null" and (qualifier or if_exists)):
        return None, f"condition operator {operator} is not evaluated"
    if base != "Null" and (base == "Bool") != (name in BOOL_KEYS):
        return None, f"condition operator {operator} is not evaluated for {key}"
    items = values if isinstance(values, list) else [values]
    if not items or any(not isinstance(item, (str, bool)) for item in items):
        return None, f"condition values of {key} are not strings"
    texts = [str(item).lower() if isinstance(item, bool) else item for item in items]
    if any("${" in text for text in texts):
        return None, f"condition values of {key} use a policy variable"
    if name not in context:
        return None, f"condition key {key} has no known value for this request"
    actual = context[name]
    if base == "Null":
        wanted = {text.lower() for text in texts}
        if not wanted <= {"true", "false"}:
            return None, f"Null condition values of {key} are not true or false"
        return ("true" if actual is ABSENT else "false") in wanted, None
    if actual is ABSENT:
        if if_exists or qualifier == "ForAllValues":
            return True, None
        if qualifier == "ForAnyValue":
            return False, None
        return base in _NEGATED, None
    if base == "Bool":
        return ("true" if actual is True else "false") in {text.lower() for text in texts}, None
    fold, wildcards = _STRING_OPERATORS[_NEGATED.get(base, base)]
    hit = any(_matches(text, actual, fold) if wildcards else
              (text.lower() == actual.lower() if fold else text == actual) for text in texts)
    return (not hit) if base in _NEGATED else hit, None


def _conditions(condition: Any, context: dict) -> tuple[bool | None, list[str]]:
    if condition is None:
        return True, []
    if not isinstance(condition, dict):
        return None, ["Condition is not a JSON object"]
    results: list[bool | None] = []
    reasons: list[str] = []
    for operator, block in condition.items():
        if not isinstance(operator, str) or not isinstance(block, dict) or not block:
            results.append(None)
            reasons.append(f"condition block {operator} is malformed")
            continue
        for key, values in block.items():
            value, reason = _clause(operator, key, values, context)
            results.append(value)
            if reason:
                reasons.append(reason)
    value = _all(results)
    return value, reasons if value is None else []


def statement_applies(statement: Any, action: str, context: dict) -> tuple[bool | None, list[str]]:
    """Whether one statement applies to one request: True, False, or None with the
    reasons it cannot be decided. ``context`` maps lower-case condition keys to the
    request's value, or ABSENT; a key it does not name has no known value."""
    if not isinstance(statement, dict):
        return None, ["the statement is not a JSON object"]
    matched, reasons = _actions(statement, action)
    if matched is False:
        return False, []
    parts = [(matched, reasons), _resources(statement, action), _principals(statement),
             _conditions(statement.get("Condition"), context)]
    unsupported = sorted(set(statement) - _ELEMENTS)
    if unsupported:
        parts.append((None, [f"element {', '.join(unsupported)} is not evaluated"]))
    value = _all(part for part, _ in parts)
    return value, [] if value is not None else [r for part, why in parts if part is None for r in why]


def _statements(content: Any) -> tuple[list | None, str | None]:
    try:
        document = json.loads(content) if isinstance(content, str) else content
    except ValueError:
        return None, "the policy document is not valid JSON"
    if not isinstance(document, dict):
        return None, "the policy document is not a JSON object"
    statements = document.get("Statement")
    if isinstance(statements, dict):
        statements = [statements]
    if not isinstance(statements, list) or not statements:
        return None, "the policy document has no Statement"
    return statements, None


# ---------------------------------------------------------------------------
# Organization reads, through each organization's management account
# ---------------------------------------------------------------------------

@dataclass
class Policy:
    id: str
    name: str
    kind: str
    aws_managed: bool
    sha256: str
    statements: list | None
    problem: str | None = None

    def summary(self) -> dict:
        return {"name": self.name, "type": self.kind, "aws_managed": self.aws_managed,
                "sha256": self.sha256, "problem": self.problem}


@dataclass
class Governance:
    """The organization policies on one account's path, or on the destination path."""
    account: str | None
    status: str
    organization: str | None = None
    manager: str | None = None
    feature_set: str | None = None
    path: list[str] = field(default_factory=list)            # root first
    attached: dict[str, list[tuple[str, list[Policy]]]] = field(default_factory=dict)
    enabled: dict[str, str] = field(default_factory=dict)
    problem: str | None = None

    def to_dict(self) -> dict:
        return {
            "status": self.status, "organization": self.organization,
            "management_account": self.manager, "feature_set": self.feature_set,
            "path": list(self.path),
            "service_control_policies": self.enabled.get(SCP),
            "resource_control_policies": self.enabled.get(RCP),
            "attachments": {target: {kind: [p.id for p in dict(self.attached.get(kind, [])).get(target, [])]
                                     for kind in KINDS if kind in self.attached}
                            for target in self.path},
            "problem": self.problem}


def _not_enabled(exc: Exception) -> bool:
    """An explicit answer that a policy type is not enabled or available."""
    return isinstance(exc, ClientError) and exc.response.get("Error", {}).get("Code") in (
        "PolicyTypeNotEnabledException", "PolicyTypeNotAvailableForOrganizationException")


def _organization(raw: Any) -> dict:
    organization = raw.get("Organization") if isinstance(raw, dict) else None
    if not isinstance(organization, dict):
        raise MigrationError("Organization identity was not returned")
    identifier = organization.get("Id")
    manager = organization.get("ManagementAccountId", organization.get("MasterAccountId"))
    if not isinstance(identifier, str) or not ORG_ID.fullmatch(identifier):
        raise MigrationError("Organization identity was not returned")
    if not isinstance(manager, str):
        raise MigrationError("Organization management account was not returned")
    return {"id": identifier, "manager": account_id(manager),
            "feature_set": organization.get("FeatureSet")}


class _Reader:
    """Memoized read-only Organizations reads for one preflight run; a failure is
    remembered too, so one unreadable item is read once and reported everywhere."""
    def __init__(self, router: Any):
        self.router = router
        self.memo: dict[tuple, tuple[bool, Any]] = {}

    def _once(self, key: tuple, load: Callable[[], Any]) -> Any:
        if key not in self.memo:
            try:
                self.memo[key] = (True, load())
            except Exception as exc:
                self.memo[key] = (False, exc)
        ok, value = self.memo[key]
        if not ok:
            raise value
        return value

    def client(self, account: str) -> Any:
        return self._once(("client", account), lambda: self.router.client(
            account, "organizations", ORGANIZATIONS_REGION))

    def member(self, account: str) -> dict | None:
        """The organization an account belongs to, as the account sees it; None
        when it is in no organization."""
        def load():
            try:
                return _organization(self.client(account).describe_organization())
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") == "AWSOrganizationsNotInUseException":
                    return None
                raise
        return self._once(("member", account), load)

    def organization(self, manager: str) -> dict:
        """The organization as its management account describes it."""
        def load():
            organization = _organization(self.client(manager).describe_organization())
            if organization["manager"] != manager:
                raise MigrationError(f"account {manager} is not the management account of "
                                     f"organization {organization['id']}")
            return organization
        return self._once(("organization", manager), load)

    def parent(self, manager: str, child: str) -> tuple[str, str]:
        def load():
            rows = pages(self.client(manager), "list_parents", "Parents", ChildId=child)
            if len(rows) != 1 or not isinstance(rows[0], dict):
                raise MigrationError(f"{child}: Organizations did not return exactly one parent")
            identifier, kind = rows[0].get("Id"), rows[0].get("Type")
            if not (kind == "ROOT" and isinstance(identifier, str) and ROOT_ID.fullmatch(identifier)
                    or kind == "ORGANIZATIONAL_UNIT" and isinstance(identifier, str)
                    and OU_ID.fullmatch(identifier)):
                raise MigrationError(f"{child}: Organizations returned an unrecognized parent")
            return identifier, kind
        return self._once(("parent", manager, child), load)

    def path(self, manager: str, start: str) -> list[str]:
        """``start`` and its parents up to the root, root first."""
        chain, child = [start], start
        for _ in range(MAX_DEPTH):
            parent, kind = self.parent(manager, child)
            if parent in chain:
                raise MigrationError(f"{start}: the organization path repeats {parent}")
            chain.append(parent)
            if kind == "ROOT":
                return chain[::-1]
            child = parent
        raise MigrationError(f"{start}: the organization path is deeper than AWS Organizations allows")

    def attached(self, manager: str, target: str, kind: str) -> list[dict]:
        def load():
            rows = pages(self.client(manager), "list_policies_for_target", "Policies",
                         TargetId=target, Filter=kind)
            for row in rows:
                if not isinstance(row, dict) or not isinstance(row.get("Id"), str) or \
                        not POLICY_ID.fullmatch(row["Id"]) or row.get("Type", kind) != kind:
                    raise MigrationError(f"{target}: Organizations returned an unrecognized "
                                         f"{kind} attachment")
            return rows
        return self._once(("attached", manager, target, kind), load)

    def document(self, manager: str, summary: dict, kind: str) -> Policy:
        identifier = summary["Id"]

        def load():
            policy = self.client(manager).describe_policy(PolicyId=identifier).get("Policy") or {}
            described = policy.get("PolicySummary") or {}
            content = policy.get("Content")
            if described.get("Id", identifier) != identifier or not isinstance(content, str):
                raise MigrationError(f"{identifier}: Organizations returned no policy content")
            statements, problem = _statements(content)
            return Policy(identifier, str(described.get("Name") or summary.get("Name") or ""),
                          kind, bool(described.get("AwsManaged", summary.get("AwsManaged"))),
                          hashlib.sha256(content.encode()).hexdigest(), statements, problem)
        return self._once(("document", manager, identifier), load)

    def services(self, manager: str) -> set[str]:
        def load():
            rows = pages(self.client(manager), "list_aws_service_access_for_organization",
                         "EnabledServicePrincipals")
            return {row.get("ServicePrincipal") for row in rows if isinstance(row, dict)}
        return self._once(("services", manager), load)


def _load_policies(reader: _Reader, governance: Governance) -> None:
    """Every SCP, then every RCP, attached to each target, root first."""
    if governance.feature_set != "ALL":
        # Consolidated billing only: no organization policy type can be enabled.
        governance.enabled = {kind: NOT_ENABLED for kind in KINDS}
        return
    for kind in KINDS:
        rows: list[tuple[str, list[Policy]]] = []
        try:
            for target in governance.path:
                rows.append((target, [reader.document(governance.manager, summary, kind)
                                      for summary in reader.attached(governance.manager, target, kind)]))
        except Exception as exc:
            if not _not_enabled(exc):
                raise
            rows = [(target, []) for target in governance.path]
        counts = [len(policies) for _, policies in rows]
        governance.attached[kind] = rows
        governance.enabled[kind] = NOT_ENABLED if not any(counts) else \
            ENABLED if all(counts) else INCOMPLETE


def _govern(reader: _Reader, account: str) -> Governance:
    governance = Governance(account, EVALUATED)
    try:
        member = reader.member(account)
        if member is None:
            governance.status = STANDALONE
            return governance
        governance.organization, governance.manager = member["id"], member["manager"]
        governance.feature_set = member["feature_set"]
        if account == member["manager"]:
            governance.status = MANAGEMENT_ACCOUNT
            return governance
        organization = reader.organization(member["manager"])
        if organization["id"] != member["id"]:
            raise MigrationError(f"management account {member['manager']} describes organization "
                                 f"{organization['id']}, not {member['id']}")
        governance.feature_set = organization["feature_set"]
        governance.path = reader.path(member["manager"], account)
        _load_policies(reader, governance)
    except Exception as exc:
        governance.status, governance.problem = UNREADABLE, failure_text(exc)
    return governance


def destination_target(arn: str) -> dict:
    """The management account, organization and OU (or root) a destination ARN names."""
    match = DESTINATION.fullmatch(arn) if isinstance(arn, str) else None
    if match is None:
        raise MigrationError(
            "--destination-ou must be an OU or root ARN, "
            "arn:aws:organizations::<management-account>:ou/<o-id>/<ou-id>; its management "
            "account must be reachable through the account map or a base profile")
    manager, ou_org, ou, root_org, root = match.groups()
    return {"arn": arn, "manager": manager, "organization": ou_org or root_org,
            "target": ou or root}


def _destination(reader: _Reader, arn: str) -> Governance:
    target = destination_target(arn)
    governance = Governance(None, EVALUATED, organization=target["organization"],
                            manager=target["manager"])
    try:
        organization = reader.organization(target["manager"])
        if organization["id"] != target["organization"]:
            raise MigrationError(f"management account {target['manager']} manages organization "
                                 f"{organization['id']}, not {target['organization']}")
        governance.feature_set = organization["feature_set"]
        governance.path = [target["target"]] if ROOT_ID.fullmatch(target["target"]) else \
            reader.path(target["manager"], target["target"])
        _load_policies(reader, governance)
    except Exception as exc:
        governance.status, governance.problem = UNREADABLE, failure_text(exc)
    return governance


# ---------------------------------------------------------------------------
# Evaluation of requests against a path
# ---------------------------------------------------------------------------

def _context(action: Action, region: str, principal: Governance, organization: str | None,
             resource: Governance | None) -> dict:
    """What the request context of ``action`` is known to hold."""
    context: dict[str, Any] = {
        "aws:requestedregion": action.region or region,
        "aws:principalaccount": principal.account,
        "aws:principalorgid": organization or ABSENT,
        "ram:requestedallowsexternalprincipals": True if action.external else ABSENT,
    }
    if resource is not None and resource.account and resource.status != UNREADABLE:
        context["aws:resourceaccount"] = resource.account
        context["aws:resourceorgid"] = resource.organization or ABSENT
    return context


def _sid(statement: Any) -> str:
    sid = statement.get("Sid") if isinstance(statement, dict) else None
    return sid if isinstance(sid, str) and sid else "none"


def _text(statement: Any) -> str:
    return json.dumps(statement, sort_keys=True, separators=(",", ":"))


class _Findings:
    """Findings aggregated over the actions and Regions they share."""
    def __init__(self) -> None:
        self.rows: dict[tuple, dict] = {}

    def add(self, key: tuple, base: dict, action: str | None = None, region: str | None = None,
            reasons: Iterable[str] = ()) -> None:
        row = self.rows.setdefault(key, {**base, "actions": set(), "regions": set(), "reasons": set()})
        if action:
            row["actions"].add(action)
        if region:
            row["regions"].add(region)
        row["reasons"].update(reasons)

    def to_list(self) -> list[dict]:
        return [{**row, "actions": sorted(row["actions"]), "regions": sorted(row["regions"]),
                 "reasons": sorted(row["reasons"])} for _, row in sorted(self.rows.items())]


def _evaluate(found: _Findings, governance: Governance, kind: str, account: str, role: str,
              action: str, region: str, context: dict, share_owner: str | None = None) -> None:
    """One request against the policies of one type on one path: each Deny that
    applies, each one that cannot be decided, and each target without an Allow."""
    if governance.enabled.get(kind) != ENABLED:
        return  # NOT_ENABLED governs nothing; INCOMPLETE is one gap per path
    common = {"account": account, "role": role, "organization": governance.organization,
              "policy_type": kind, "share_owner": share_owner}
    for target, policies in governance.attached[kind]:
        allowed, undecided = False, []
        for policy in policies:
            located = {**common, "target": target, "policy": policy.id, "policy_name": policy.name}
            if policy.statements is None:
                found.add((UNDECIDED, account, role, kind, target, policy.id, 0, share_owner or ""),
                          {**located, "decision": UNDECIDED, "statement": None, "sid": "none",
                           "statement_text": None}, action, region, [policy.problem or ""])
                undecided.append(f"{policy.id} document ({policy.problem})")
                continue
            for index, statement in enumerate(policy.statements, 1):
                effect = statement.get("Effect") if isinstance(statement, dict) else None
                applies, reasons = statement_applies(statement, action, context)
                if applies is False:
                    continue
                if effect == "Allow":
                    if applies:
                        allowed = True
                    else:
                        undecided.append(f"{policy.id} statement {index} sid={_sid(statement)} "
                                         f"({'; '.join(reasons)})")
                    continue
                if effect != "Deny":
                    applies, reasons = None, reasons + ["Effect is neither Allow nor Deny"]
                decision = EXPLICIT_DENY if applies else UNDECIDED
                found.add((decision, account, role, kind, target, policy.id, index, share_owner or ""),
                          {**located, "decision": decision, "statement": index,
                           "sid": _sid(statement), "statement_text": _text(statement)},
                          action, region, reasons)
        if allowed:
            continue
        names = [(policy.id, policy.name) for policy in policies]
        if undecided:
            found.add((UNDECIDED, account, role, kind, target, "allow", 0, share_owner or ""),
                      {**common, "decision": UNDECIDED, "target": target, "policies": names,
                       "undecided_allows": []}, action, region)
            row = found.rows[(UNDECIDED, account, role, kind, target, "allow", 0, share_owner or "")]
            row["undecided_allows"] = sorted(set(row["undecided_allows"]) | set(undecided))
        else:
            found.add((NO_ALLOW, account, role, kind, target, "", 0, share_owner or ""),
                      {**common, "decision": NO_ALLOW, "target": target, "policies": names},
                      action, region)


def _incomplete(found: _Findings, governance: Governance, account: str, role: str) -> None:
    for kind in KINDS:
        if governance.enabled.get(kind) == INCOMPLETE:
            empty = [target for target, policies in governance.attached[kind] if not policies]
            found.add((UNDECIDED, account, role, kind, "path", "", 0, ""),
                      {"decision": UNDECIDED, "account": account, "role": role,
                       "organization": governance.organization, "policy_type": kind,
                       "target": ",".join(empty), "share_owner": None, "incomplete": True})


# ---------------------------------------------------------------------------
# Blocker text
# ---------------------------------------------------------------------------

def _named(policies: list) -> str:
    return ",".join(f"{identifier}({json.dumps(name)})" for identifier, name in policies) or "none"


def _blocker(row: dict) -> str:
    decision = row["decision"]
    status = "GAP" if decision == UNDECIDED else "BLOCKED"
    who = f"account={row['account']} role={row['role']}" if row.get("account") else \
        f"role={row['role']}"
    text = f"phase=org-policy status={status} decision={decision} {who}"
    if row.get("organization"):
        text += f" organization={row['organization']}"
    if row.get("share_owner"):
        text += f" share_owner={row['share_owner']}"
    if row.get("regions"):
        text += f" regions={','.join(row['regions'])}"
    if row.get("actions"):
        text += f" actions={','.join(row['actions'])}"
    kind = SHORT[row["policy_type"]]
    text += f" policy_type={kind}"
    if row.get("incomplete"):
        return (text + f" targets_without_policies={row['target']}: some targets on this path "
                f"have {kind}s attached and these have none, which AWS Organizations does not "
                "allow, so whether this policy type is enforced cannot be decided; listed for "
                "human review, and the run stays blocked while it is undecided")
    text += f" target={row['target']}"
    if decision == NO_ALLOW:
        return (text + f" policies={_named(row['policies'])}: no statement in the {kind}s "
                "attached at this target allows these actions, so they are denied (an "
                "allow-list without them); the tool never edits organization policies")
    if "undecided_allows" in row:
        return (text + f" policies={_named(row['policies'])}: no statement at this target "
                "definitely allows these actions, and these Allow statements cannot be "
                f"decided: {'; '.join(row['undecided_allows'])}; listed for human review, and "
                "the run stays blocked while it is undecided")
    text += (f" policy={row['policy']} policy_name={json.dumps(row['policy_name'])} "
             f"sid={row['sid']} statement={row['statement'] or 'document'}")
    if decision == EXPLICIT_DENY:
        return (text + ": this Deny statement applies to these requests; the tool never edits "
                "organization policies and an administrator role does not override them")
    return (text + f": whether this statement denies these requests cannot be decided "
            f"({'; '.join(row['reasons'])}); listed for human review, and the run stays blocked "
            "while it is undecided")


def _unreadable(governance: Governance, roles: list[str], destination: str | None = None) -> str:
    who = f"destination={destination}" if destination else \
        f"account={governance.account} roles={','.join(roles)}"
    text = f"phase=org-policy status=BLOCKED decision=UNREADABLE {who}"
    if governance.organization:
        text += f" organization={governance.organization}"
    if governance.manager:
        text += f" management_account={governance.manager}"
    return (text + f": {governance.problem}; the organization policies that govern "
            + ("this path" if destination else "this account")
            + " could not be read, and unread policies never pass")


# ---------------------------------------------------------------------------
# RAM organization prerequisites (case 054)
# ---------------------------------------------------------------------------

def _organization_principal(principal: str) -> tuple[str, str] | None:
    match = ORGANIZATION_PRINCIPAL.fullmatch(principal) if isinstance(principal, str) else None
    if match is None:
        return None
    return match.group(1), match.group(2) or match.group(3)


def _prerequisites(reader: _Reader, needed: dict[str, dict]) -> tuple[list[dict], list[str]]:
    """ALL features and ram.amazonaws.com trusted access, read-only, never enabled."""
    records, blockers = [], []
    for organization, need in sorted(needed.items()):
        manager = need["manager"]
        entry = {"organization": organization, "management_account": manager,
                 "scope": sorted(need["scope"]), "required_by": sorted(need["shares"]),
                 "all_features": None, "ram_trusted_access": None, "status": NOT_MET, "problem": None}
        head = (f"phase=ram-org-prerequisites status=BLOCKED organization={organization} "
                f"management_account={manager}")
        try:
            described = reader.organization(manager)
            if described["id"] != organization:
                raise MigrationError(f"management account {manager} manages organization "
                                     f"{described['id']}, not {organization}")
            entry["all_features"] = described["feature_set"] == "ALL"
            entry["ram_trusted_access"] = RAM_SERVICE in reader.services(manager)
        except Exception as exc:
            entry["status"], entry["problem"] = UNREADABLE, failure_text(exc)
            blockers.append(f"{head.replace('status=BLOCKED', 'status=BLOCKED decision=UNREADABLE')}: "
                            f"{entry['problem']}; the RAM organization prerequisites could not be "
                            "read, and unread prerequisites never pass")
            records.append(entry)
            continue
        shares = len(need["shares"])
        if not entry["all_features"]:
            blockers.append(f"{head} decision={NOT_MET} prerequisite=all-features "
                            f"feature_set={described['feature_set']} shares={shares}: sharing with "
                            "OU or organization principals needs ALL features; this tool never "
                            "enables them")
        if not entry["ram_trusted_access"]:
            blockers.append(f"{head} decision={NOT_MET} prerequisite=ram-trusted-access "
                            f"shares={shares}: {RAM_SERVICE} trusted access, which RAM's sharing "
                            "with AWS Organizations enables, is not enabled; this tool never "
                            "enables it")
        if entry["all_features"] and entry["ram_trusted_access"]:
            entry["status"] = "MET"
        records.append(entry)
    return records, blockers


# ---------------------------------------------------------------------------
# The preflight
# ---------------------------------------------------------------------------

def organization_preflight(router: Any, groups: Iterable[Any], migrating: Iterable[str], *,
                           destination: str | None = None,
                           organization_shares: dict[str, list[str]] | None = None,
                           emit: Callable[[str], None] | None = None) -> dict:
    """Evaluate the organization policies for ``groups`` (Group objects or record
    group dicts). ``migrating`` lists the accounts that move; with ``destination``
    (an OU or root ARN) those in the groups are evaluated on the destination path.
    ``organization_shares`` maps original share ARNs to their OU and organization
    principals. Returns the JSON-serializable result; its ``blockers`` join the plan's."""
    emit = emit or (lambda _line: None)
    reader = _Reader(router)
    moving = set(migrating)
    owners: dict[str, set[str]] = defaultdict(set)
    consumers: dict[str, set[tuple[str, str]]] = defaultdict(set)
    regions: dict[str, set[str]] = defaultdict(set)
    for group in groups:
        owner = group["owner"] if isinstance(group, dict) else group.owner
        region = group["region"] if isinstance(group, dict) else group.region
        members = group["consumers"] if isinstance(group, dict) else group.consumers
        owners[owner].add(region)
        regions[owner].add(region)
        for consumer in members:
            consumers[consumer].add((owner, region))
            regions[consumer].add(region)
    accounts = sorted(set(owners) | set(consumers))
    roles = {account: [role for role, scope in (("owner", owners), ("consumer", consumers))
                       if account in scope] for account in accounts}
    governance = {account: _govern(reader, account) for account in accounts}
    found = _Findings()
    blockers: list[str] = []
    notes: list[str] = []

    for account in accounts:
        state = governance[account]
        if state.status == UNREADABLE:
            blockers.append(_unreadable(state, roles[account]))
            continue
        if state.status == MANAGEMENT_ACCOUNT:
            notes.append(f"account={account} is the management account of {state.organization}: "
                         "SCPs and RCPs do not apply to it")
            continue
        if state.status == STANDALONE:
            notes.append(f"account={account} is in no organization: no SCPs or RCPs apply")
            continue
        for role in roles[account]:
            _incomplete(found, state, account, role)
        for region in sorted(owners.get(account, ())):
            for action in OWNER_ACTIONS:
                context = _context(action, region, state, state.organization,
                                   state if action.resource == "self" else None)
                for kind in KINDS:
                    _evaluate(found, state, kind, account, "owner", action.name, region, context)
        for owner, region in sorted(consumers.get(account, ())):
            resource = governance.get(owner)
            for action in CONSUMER_ACTIONS:
                held = resource if action.resource == "owner" else None
                # An acceptance depends on whose share it is (its resource organization).
                via = owner if held is not None else None
                context = _context(action, region, state, state.organization, held)
                for kind in KINDS:
                    _evaluate(found, state, kind, account, "consumer", action.name, region, context,
                              share_owner=via)
                if held is not None and held.status == EVALUATED and owner != account:
                    # The invitation is the owner's resource: the owner's RCPs govern it.
                    _evaluate(found, held, RCP, account, "consumer", action.name, region, context,
                              share_owner=owner)

    target = None
    if destination:
        target = _destination(reader, destination)
        if target.status == UNREADABLE:
            blockers.append(_unreadable(target, [], destination))
        else:
            for account in [a for a in accounts if a in moving]:
                principal = Governance(account, EVALUATED, organization=target.organization)
                for action in DESTINATION_ACTIONS:
                    for region in ([action.region] if action.region else sorted(regions[account])):
                        context = _context(action, region, principal, target.organization, None)
                        for kind in KINDS:
                            _evaluate(found, target, kind, account, "destination", action.name,
                                      region, context)
            for kind in KINDS:
                if target.enabled.get(kind) == INCOMPLETE:
                    empty = [t for t, policies in target.attached[kind] if not policies]
                    found.add((UNDECIDED, "", "destination", kind, "path", "", 0, ""),
                              {"decision": UNDECIDED, "account": None, "role": "destination",
                               "organization": target.organization, "policy_type": kind,
                               "target": ",".join(empty), "share_owner": None, "incomplete": True})
            notes.append("policies attached directly to each account after it joins the "
                         "destination organization are not known before the move and are not "
                         "evaluated")

    needed: dict[str, dict] = {}
    for share, principals in sorted((organization_shares or {}).items()):
        for principal in principals:
            parsed = _organization_principal(principal)
            if parsed is None:
                continue
            manager, organization = parsed
            entry = needed.setdefault(organization, {"manager": manager, "shares": set(),
                                                     "scope": set()})
            entry["shares"].add(share)
            entry["scope"].add("source")
        if destination and principals:
            parsed_destination = destination_target(destination)
            entry = needed.setdefault(parsed_destination["organization"], {
                "manager": parsed_destination["manager"], "shares": set(), "scope": set()})
            entry["shares"].add(share)
            entry["scope"].add("destination")
    prerequisites, unmet = _prerequisites(reader, needed)
    if needed:
        notes.append("the RAM service-linked role is not read: IAM is outside this preflight")

    findings = found.to_list()
    blockers += [_blocker(row) for row in findings]
    organizations: dict[str, dict] = {}
    for state in [*governance.values(), *([target] if target is not None else [])]:
        if not state.organization:
            continue
        entry = organizations.setdefault(state.organization, {
            "management_account": state.manager, "feature_set": state.feature_set, "policies": {}})
        for kind in KINDS:
            for _target, policies in state.attached.get(kind, []):
                for policy in policies:
                    entry["policies"][policy.id] = policy.summary()
    blockers += unmet
    result = {
        "schema": SCHEMA,
        "status": "BLOCKED" if blockers else "ALLOWED",
        "checked_at": timestamp(),
        "destination_ou": destination,
        "evaluator": {"sha256": EVALUATOR_SHA256,
                      "condition_keys": sorted(STRING_KEYS | BOOL_KEYS), "operators": list(OPERATORS),
                      "owner_actions": [a.name for a in OWNER_ACTIONS],
                      "consumer_actions": [a.name for a in CONSUMER_ACTIONS],
                      "destination_actions": [a.name for a in DESTINATION_ACTIONS]},
        "accounts": [{"account": account, "roles": roles[account],
                      "regions": sorted(regions[account]), **governance[account].to_dict()}
                     for account in accounts],
        "destination": None if target is None else {
            "arn": destination, **target.to_dict(),
            "accounts": [a for a in accounts if a in moving]},
        "organizations": organizations,
        "ram_organization_prerequisites": prerequisites,
        "findings": findings,
        "blockers": blockers,
        "notes": notes,
    }
    _report(result, emit)
    return result


def _report(result: dict, emit: Callable[[str], None]) -> None:
    for entry in result["accounts"]:
        line = (f"phase=org-policy account={entry['account']} roles={','.join(entry['roles'])} "
                f"status={entry['status']}")
        if entry["organization"]:
            line += f" organization={entry['organization']}"
        if entry["path"]:
            line += (f" path={'/'.join(entry['path'])} "
                     f"scp={entry['service_control_policies']} rcp={entry['resource_control_policies']}")
        emit(line)
    if result["destination"] is not None:
        entry = result["destination"]
        line = f"phase=org-policy destination={entry['arn']} status={entry['status']}"
        if entry["path"]:
            line += (f" path={'/'.join(entry['path'])} scp={entry['service_control_policies']} "
                     f"rcp={entry['resource_control_policies']} accounts={len(entry['accounts'])}")
        emit(line)
    for entry in result["ram_organization_prerequisites"]:
        emit(f"phase=ram-org-prerequisites organization={entry['organization']} "
             f"status={entry['status']} all_features={json.dumps(entry['all_features'])} "
             f"ram_trusted_access={json.dumps(entry['ram_trusted_access'])} "
             f"shares={len(entry['required_by'])}")
    reviewed = set()
    for row in result["findings"]:
        key = (row.get("organization"), row.get("policy"), row.get("statement"))
        if row.get("statement_text") and key not in reviewed:
            reviewed.add(key)
            emit(f"phase=org-policy status=REVIEW policy={row['policy']} statement={row['statement']} "
                 f"text={row['statement_text']}")
    for note in result["notes"]:
        emit(f"phase=org-policy status=NOTE {note}")
    decisions = [row["decision"] for row in result["findings"]]
    emit(f"phase=org-policy status={result['status']} accounts={len(result['accounts'])} "
         f"denies={sum(d in (EXPLICIT_DENY, NO_ALLOW) for d in decisions)} "
         f"gaps={decisions.count(UNDECIDED)} "
         f"unreadable={sum('decision=UNREADABLE' in b for b in result['blockers'])} "
         f"prerequisites_not_met={sum(f'decision={NOT_MET}' in b for b in result['blockers'])}")


def recorded_destination(result: dict | None) -> str | None:
    """The destination OU a recorded preflight result evaluated."""
    return (result or {}).get("destination_ou")


def policy_changes(before: dict | None, after: dict, since: str = "the reviewed plan") -> list[str]:
    """Informational drift since ``before`` (by default the reviewed plan's result):
    policies whose content changed, or that were or are no longer attached on an
    evaluated path. The current result alone decides; this is evidence only."""
    if not before:
        return []

    def index(result: dict) -> dict[tuple[str, str], str | None]:
        return {(organization, identifier): policy.get("sha256")
                for organization, entry in (result.get("organizations") or {}).items()
                for identifier, policy in (entry.get("policies") or {}).items()}
    old, new = index(before), index(after)
    lines = []
    for organization, identifier in sorted(set(old) | set(new)):
        key = (organization, identifier)
        change = "content" if key in old and key in new and old[key] != new[key] else \
            "attached" if key not in old else "detached" if key not in new else None
        if change:
            lines.append(f"phase=org-policy status=POLICY_CHANGED organization={organization} "
                         f"policy={identifier} change={change} since {since}; this run "
                         "evaluated the current policies")
    return lines
