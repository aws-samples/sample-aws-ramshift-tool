"""Read-only inventory and conservative entitlement planning."""
from __future__ import annotations

import copy
import hashlib
import json
import re
import threading
import urllib.request
from collections import defaultdict
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, Callable, NamedTuple

import yaml
from botocore.exceptions import ClientError

from ram_migration_common import (
    ACCOUNT, Group, MigrationError, Plan, Router, account_id, error_text,
    managed, pages, tags,
)

CATALOG = "https://docs.aws.amazon.com/ram/latest/userguide/shareable.md"
ACCOUNT_ROOT = re.compile(r"^arn:([a-z0-9-]+):iam::([0-9]{12}):root$")
SERVICE_PRINCIPAL = re.compile(r"^[a-z0-9][a-z0-9.-]*\.amazonaws\.com(?:\.cn)?$")
# The catalogue restates each icon with a standard scope sentence, e.g.
# "Yes <br />Can share with **any** AWS account." Only the sentence matching the
# icon's own answer is unconditional; any other qualifier stays ambiguous.
STANDARD_SCOPE = {True: r"can share with any (?:aws )?accounts?",
                  False: r"can share with only (?:aws )?accounts in its (?:own )?organization"}


def direct_account_principal(principal: str, partition: str | None = None) -> str | None:
    """Only account IDs and an exact, same-partition IAM account root are accounts."""
    if ACCOUNT.fullmatch(principal):
        return principal
    root = ACCOUNT_ROOT.fullmatch(principal)
    if root is None:
        return None
    if partition is None or root.group(1) != partition:
        raise MigrationError("Account-root principal partition does not match the owning RAM client")
    return account_id(root.group(2))


def validate_principal_scopes(principals: list[str], partition: str) -> None:
    """An inventory override cannot widen a role/user/service restriction."""
    for principal in principals:
        if direct_account_principal(principal, partition) is not None or \
                SERVICE_PRINCIPAL.fullmatch(principal):
            continue
        parts = principal.split(":", 5)
        if len(parts) == 6 and parts[:4] == ["arn", partition, "organizations", ""] and \
                ACCOUNT.fullmatch(parts[4]) and re.fullmatch(
                    r"(?:organization/o-[a-z0-9]+|ou/o-[a-z0-9]+/ou-[a-z0-9]+-[a-z0-9]+)",
                    parts[5]):
            continue
        raise MigrationError(f"Unsupported account-level principal conversion: {principal}; "
                             "principal-map overrides cannot broaden restricted access")


def external_catalog(text: str | None = None) -> dict[str, bool]:
    """AWS's table supplies a capability absent from ListResourceTypes."""
    if text is None:
        with urllib.request.urlopen(CATALOG, timeout=20) as response:
            text = response.read().decode()
    values: dict[str, bool] = {}
    ambiguous: set[str] = set()
    for line in text.splitlines():
        cells = re.split(r"(?<!\\)\|", line.strip().strip("|"))
        if len(cells) < 6:
            continue
        codes = re.findall(r"`([a-zA-Z0-9_-]+:[a-zA-Z0-9_-]+)`", cells[0])
        cell = cells[3]
        yes, no = "icon-yes.png" in cell, "icon-no.png" in cell
        # A row can describe several types. Qualified/mixed support needs a
        # resource-specific decision; never turn it into unconditional support.
        remainder = re.sub(r"!\[[^\n]*?\]\([^)]*\)", "", cell)
        remainder = " ".join(re.sub(r"<[^>]*>|[*_]", " ", remainder).split()).lower()
        unconditional = rf"(?:{'yes' if yes else 'no'})?(?: ?{STANDARD_SCOPE[yes]}\.?)?"
        if codes and (yes == no or not re.fullmatch(unconditional, remainder)):
            ambiguous.update(code.lower() for code in codes)
        elif codes:
            for code in codes:
                key = code.lower()
                if key in values and values[key] != yes:
                    raise MigrationError(f"Conflicting external-sharing catalogue rows: {key}")
                values[key] = yes
    for key in ambiguous:
        values.pop(key, None)
    if not values:
        raise MigrationError("Unable to parse AWS external-sharing capability table")
    return values


class CfnLoader(yaml.SafeLoader):
    pass


def _intrinsic(loader, tag, node):
    if isinstance(node, yaml.ScalarNode):
        value = loader.construct_scalar(node)
    elif isinstance(node, yaml.SequenceNode):
        value = loader.construct_sequence(node)
    else:
        value = loader.construct_mapping(node)
    return {tag if tag == "Ref" else "Fn::" + tag: value}


CfnLoader.add_multi_constructor("!", _intrinsic)


class LookupCache:
    """Explicit per-run memo of read-only lookups that repeat across shares.

    Keys name the account and Region of the read. Concurrent callers of one key
    share a single read, failures are never kept, and every caller receives its
    own copy. Planning reads through it; the post-confirmation recheck and every
    write path read fresh by not passing it.
    """
    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entries: dict[tuple, Future] = {}

    def get(self, key: tuple, load: Callable[[], Any]) -> Any:
        with self._lock:
            entry = self._entries.get(key)
            loading = entry is None
            if loading:
                entry = self._entries[key] = Future()
        if loading:
            try:
                entry.set_result(load())
            except BaseException as exc:
                with self._lock:
                    if self._entries.get(key) is entry:
                        del self._entries[key]
                entry.set_exception(exc)
        return copy.deepcopy(entry.result())

    def discard(self, key: tuple) -> None:
        with self._lock:
            self._entries.pop(key, None)


def lookup(cache: LookupCache | None, key: tuple, load: Callable[[], Any]) -> Any:
    return load() if cache is None else cache.get(key, load)


def evidence_pages(client: Any, operation: str, key: str, **kwargs: Any) -> list[dict]:
    """Complete read with a checked response shape; missing data never proves absence."""
    rows: list[dict] = []
    seen: set[str] = set()
    while True:
        response = getattr(client, operation)(**kwargs)
        values = response.get(key) if isinstance(response, dict) else None
        if not isinstance(values, list) or any(not isinstance(row, dict) for row in values):
            raise MigrationError(f"{operation}: {key} inventory was not returned correctly")
        rows.extend(values)
        if any(response.get(name) is not None and not isinstance(response[name], str)
               for name in ("nextToken", "NextToken")):
            raise MigrationError(f"{operation}: pagination token was not returned correctly")
        token = response.get("nextToken") or response.get("NextToken")
        if not token:
            return rows
        if not isinstance(token, str) or token in seen:
            raise MigrationError(f"{operation}: invalid or repeated pagination token")
        seen.add(token)
        kwargs["nextToken" if response.get("nextToken") else "NextToken"] = token


def template_key(account: str, region: str, stack: dict) -> tuple | None:
    """One template version. A StackId survives updates, so the key also carries when
    the stack last changed and its status, from the same DescribeStacks as the caller's
    parameters and resources; None when the description cannot identify the version."""
    version = stack.get("LastUpdatedTime") or stack.get("CreationTime")
    if version is None:
        return None
    return ("template", account, region, stack["StackId"], version, stack.get("StackStatus"))


def read_template(cache: LookupCache | None, account: str, region: str, cfn: Any,
                  stack: dict) -> dict:
    """GetTemplate (processed) by StackId, parsed; through the run cache if given and
    the stack's version is known, otherwise read fresh."""
    def load():
        body = cfn.get_template(StackName=stack["StackId"],
                                TemplateStage="Processed")["TemplateBody"]
        return yaml.load(body, Loader=CfnLoader) if isinstance(body, str) else body
    key = template_key(account, region, stack)
    return lookup(cache if key is not None else None, key, load)


def failure_text(exc: Exception) -> str:
    """error_text plus the API operation, which every runtime denial must name (FR-09)."""
    operation = f"operation={exc.operation_name} " if isinstance(exc, ClientError) else ""
    return operation + error_text(exc)


def share_blocker(owner: str, region: str, arn: str, exc: Exception) -> str:
    """A source share's blocker names its owner and Region, and the operation of an API error."""
    return f"{arn}: owner={owner} region={region} {failure_text(exc)}"


LIVE = ("ASSOCIATED", "ASSOCIATING")


def feature_set_problem(owner: str, region: str, arn: str, feature: Any) -> str:
    """Why a share that is not a STANDARD share blocks, and what makes it one.

    RAM creates a CREATED_FROM_POLICY share from a resource-based policy. Only its owner
    can see it, so no consumer's received-share audit can account for it, and the
    permission RAM derived from the policy cannot be attached to a standard share."""
    if feature == "CREATED_FROM_POLICY":
        return ("featureSet CREATED_FROM_POLICY: RAM created this share from a resource-based "
                "policy, so it is not a standard share and is never inspected as one: only its "
                "owner can see it, so the consumers' received-share audit cannot account for it, "
                "and the permission RAM derived from the policy cannot be attached to a "
                f"temporary share. In owner {owner} Region {region}, promote it to a standard "
                "share: aws ram promote-permission-created-from-policy for the permission it "
                "attaches, then aws ram promote-resource-share-created-from-policy "
                f"--resource-share-arn {arn}; re-run plan once its featureSet is STANDARD")
    if feature == "PROMOTING_TO_STANDARD":
        return ("featureSet PROMOTING_TO_STANDARD: this share, which RAM created from a "
                "resource-based policy, is being promoted to a standard share and is not one "
                "yet; it is never inspected as one. Wait until aws ram get-resource-shares "
                f"--resource-owner SELF --resource-share-arns {arn} --region {region} in owner "
                f"{owner} shows featureSet STANDARD, then re-run plan")
    return (f"unsupported featureSet {feature!r}: only STANDARD shares are inspected; this "
            "tool version cannot classify this share, so it blocks")


@dataclass
class ApprovedGroup(Group):
    """Compatible Group carrying the reviewed permission policies and source stacks."""
    permission_snapshots: dict[str, dict] = field(default_factory=dict)
    source_stacks: list[str] = field(default_factory=list)
    stationary_consumers: tuple[str, ...] = ()


def policy_semantics(policy: str | dict) -> Any:
    """Canonicalize IAM set-valued fields without relaxing policy constraints."""
    document = json.loads(policy) if isinstance(policy, str) else policy
    # GetPermission returns AWS managed permissions as one bare statement,
    # {"Effect": ..., "Action": [...]}; a list of statements is accepted too.
    def statement(value):
        return isinstance(value, dict) and "Effect" in value and \
            ("Action" in value or "NotAction" in value)
    if isinstance(document, dict) and "Statement" not in document and statement(document):
        document = {"Statement": [document]}
    elif isinstance(document, list) and document and all(statement(v) for v in document):
        document = {"Statement": document}
    if not isinstance(document, dict) or "Statement" not in document:
        raise MigrationError("Managed permission policy has no Statement")

    def normalize(value, key="", context="", in_list=False):
        if key in ("Statement", "Action", "NotAction", "Resource", "NotResource") \
                and not isinstance(value, list):
            value = [value]
        if context in ("Principal", "NotPrincipal", "ConditionValues") \
                and not isinstance(value, (list, dict)) and not in_list:
            value = [value]
        if isinstance(value, list):
            items = [normalize(v, context=context, in_list=True) for v in value]
            unique = {json.dumps(v, sort_keys=True): v for v in items}
            return [unique[k] for k in sorted(unique)]
        if isinstance(value, dict):
            output = {}
            for k, v in value.items():
                if (context == "Statement" and k == "Sid") or (not context and k == "Id"):
                    continue
                child_context = k
                if context in ("Principal", "NotPrincipal"):
                    child_context = context
                elif context == "Condition":
                    child_context = "ConditionValues"
                elif context == "ConditionValues":
                    child_context = "ConditionValues"
                output[k] = normalize(v, k, child_context)
            return output
        return value

    return normalize(document)


def policy_sha256(policy: Any) -> str:
    """Hash of the canonical policy semantics, stable across key order/scalars."""
    return hashlib.sha256(json.dumps(policy_semantics(policy), sort_keys=True,
                                     separators=(",", ":")).encode()).hexdigest()


def _facets(policy: dict) -> dict[str, set[str]]:
    """Literal values per effect, pooled across statements (no binding)."""
    facets: dict[str, set[str]] = {
        "actions": set(), "not_actions": set(), "resources": set(),
        "not_resources": set(), "conditions": set(), "principals": set()}
    for statement in policy.get("Statement", []):
        if not isinstance(statement, dict):
            continue  # reported by the statement-level analysis as unanalyzed
        effect = statement.get("Effect", "?")
        for key, facet in (("Action", "actions"), ("NotAction", "not_actions"),
                           ("Resource", "resources"), ("NotResource", "not_resources")):
            for value in statement.get(key, []):
                facets[facet].add(f"{effect} {value}")
        if "Condition" in statement:
            facets["conditions"].add(f"{effect} " + json.dumps(statement["Condition"], sort_keys=True))
        for key in ("Principal", "NotPrincipal"):
            if key in statement:
                facets["principals"].add(
                    f"{effect} {key} " + json.dumps(statement[key], sort_keys=True))
    return facets


# Statement-level comparison. Facets pool values per effect, so they cannot say
# which resources or conditions an action carried. Here each statement is split
# into single-action atoms that keep the statement's resource scope, condition
# and principal, and every (effect, action) is compared by the bindings that
# apply to it before and after. Coverage is only ever proven, never assumed: a
# wildcard, NotAction or NotResource the other version does not provably cover
# is a difference. The analysis can report a change that is not one; it never
# reports a broadening as unchanged.
class _Binding(NamedTuple):
    """What one atom applies to, apart from its action."""
    resource: tuple    # ("Resource", glob) | ("NotResource", globs) | ("Unspecified", None)
    condition: tuple   # ((operator, lower-case key, frozenset of values), ...); () = none
    principal: tuple   # ("Principal"|"NotPrincipal", ((type, value), ...)) | ("Unspecified", None)
    condition_text: str
    principal_text: str


_STATEMENT_KEYS = frozenset({"Effect", "Action", "NotAction", "Resource", "NotResource",
                             "Condition", "Principal", "NotPrincipal"})
# Operators whose values are alternatives (fewer values is stricter) and negated
# operators whose values are exclusions (more values is stricter). Any other
# operator is implied only by itself with identical values.
_ANY_OF_OPERATORS = frozenset({
    "StringEquals", "StringEqualsIgnoreCase", "StringLike", "NumericEquals",
    "NumericLessThan", "NumericLessThanEquals", "NumericGreaterThan",
    "NumericGreaterThanEquals", "DateEquals", "DateLessThan", "DateLessThanEquals",
    "DateGreaterThan", "DateGreaterThanEquals", "Bool", "BinaryEquals", "IpAddress",
    "ArnEquals", "ArnLike", "Null"})
_NONE_OF_OPERATORS = frozenset({
    "StringNotEquals", "StringNotEqualsIgnoreCase", "StringNotLike", "NumericNotEquals",
    "DateNotEquals", "NotIpAddress", "ArnNotEquals", "ArnNotLike"})
_UNANALYZED = "(unanalyzed statements)"


def _compact(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@lru_cache(maxsize=8192)
def _glob_contains(outer: str, inner: str) -> bool:
    """Every string glob ``inner`` matches is matched by glob ``outer`` (sound)."""
    size = len(inner)
    below = [j == size for j in range(size + 1)]
    for symbol in reversed(outer):
        row = [False] * (size + 1)
        for j in range(size, -1, -1):
            if symbol == "*":
                row[j] = below[j] or (j < size and row[j + 1])
            elif j < size and inner[j] != "*" and (symbol == "?" or inner[j] == symbol):
                row[j] = below[j + 1]
        below = row
    return below[0]


@lru_cache(maxsize=8192)
def _glob_intersects(first: str, second: str) -> bool:
    """Some string matches both globs; case-folded, '*' spans any character."""
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


def _all_stars(pattern: str) -> bool:
    return bool(pattern) and not pattern.strip("*")


@lru_cache(maxsize=8192)
def _pattern_contains(outer: str, inner: str, fold: bool) -> bool:
    """Containment checked per ':' segment, which holds whether or not a
    wildcard may span segments; IAM action names are case-insensitive."""
    if fold:
        outer, inner = outer.lower(), inner.lower()
    if _all_stars(outer):
        return True
    outer_parts, inner_parts = outer.split(":"), inner.split(":")
    return len(outer_parts) == len(inner_parts) and all(
        _glob_contains(o, i) for o, i in zip(outer_parts, inner_parts))


def _disjoint(pattern: str, excluded: tuple[str, ...]) -> bool:
    return not any(_glob_intersects(pattern, other) for other in excluded)


@lru_cache(maxsize=8192)
def _action_covers(outer: tuple, inner: tuple) -> bool:
    """Every action ``inner`` selects is selected by ``outer``."""
    (outer_kind, outer_value), (inner_kind, inner_value) = outer, inner
    if outer_kind == "Action":
        return _pattern_contains(outer_value, inner_value, True) if inner_kind == "Action" \
            else _all_stars(outer_value)
    if inner_kind == "Action":
        return _disjoint(inner_value, outer_value)
    # NotAction covers NotAction when it excludes no more than the other one.
    return all(any(_pattern_contains(i, o, True) for i in inner_value) for o in outer_value)


def _resource_covers(outer: tuple, inner: tuple) -> bool:
    """Every resource ``inner`` applies to is one ``outer`` applies to. A missing
    Resource element means the share's own resources: only '*' covers them."""
    (outer_kind, outer_value), (inner_kind, inner_value) = outer, inner
    if outer_kind == "Unspecified":
        return inner_kind == "Unspecified"
    if outer_kind == "Resource":
        return _pattern_contains(outer_value, inner_value, False) if inner_kind == "Resource" \
            else _all_stars(outer_value)
    if inner_kind == "Resource":
        return _disjoint(inner_value, outer_value)
    if inner_kind == "NotResource":
        return all(any(_pattern_contains(i, o, False) for i in inner_value) for o in outer_value)
    return False


def _base_operator(operator: str) -> str:
    for prefix in ("ForAllValues:", "ForAnyValue:"):
        if operator.startswith(prefix):
            operator = operator[len(prefix):]
    return operator[:-len("IfExists")] if operator.endswith("IfExists") else operator


def _condition_implies(strong: tuple, weak: tuple) -> bool:
    """Every request that meets ``strong`` also meets ``weak`` (sound, not complete)."""
    for operator, key, values in weak:
        base = _base_operator(operator)
        if not any(other_operator == operator and other_key == key and (
                other_values == values
                or (base in _ANY_OF_OPERATORS and other_values <= values)
                or (base in _NONE_OF_OPERATORS and other_values >= values))
                for other_operator, other_key, other_values in strong):
            return False
    return True


def _principal_covers(outer: tuple, inner: tuple) -> bool:
    (outer_kind, outer_value), (inner_kind, inner_value) = outer, inner
    if outer_kind == "Principal" and ("*", "*") in outer_value:
        return True
    if outer_kind != inner_kind:
        return False
    if outer_kind == "Unspecified":
        return True
    if outer_kind == "Principal":
        return all(p in outer_value or (p[0], "*") in outer_value for p in inner_value)
    return set(outer_value) <= set(inner_value)    # NotPrincipal: excluding more is narrower


def _binding_covers(outer: _Binding, inner: _Binding) -> bool:
    return _resource_covers(outer.resource, inner.resource) and \
        _condition_implies(inner.condition, outer.condition) and \
        _principal_covers(outer.principal, inner.principal)


def _strings(value: Any) -> tuple[str, ...] | None:
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        return tuple(sorted(set(value)))
    return None


def _principal_pairs(value: Any) -> tuple | None:
    listed = _strings(value)
    if listed is not None:                                   # "Principal": "*"
        return tuple(("*", v) for v in listed)
    if isinstance(value, dict) and value and all(_strings(v) is not None for v in value.values()):
        return tuple(sorted((kind, v) for kind, values in value.items() for v in set(values)))
    return None


def _statement_parts(statement: Any) -> tuple[str, list[tuple], list[_Binding]] | None:
    """(effect, action specs, bindings) of one normalized statement; None when
    its shape is outside what this analysis evaluates."""
    if not isinstance(statement, dict) or statement.get("Effect") not in ("Allow", "Deny") or \
            set(statement) - _STATEMENT_KEYS or \
            ("Action" in statement) == ("NotAction" in statement) or \
            {"Resource", "NotResource"} <= set(statement) or \
            {"Principal", "NotPrincipal"} <= set(statement):
        return None
    action_key = "Action" if "Action" in statement else "NotAction"
    actions = _strings(statement[action_key])
    if actions is None:
        return None
    specs = [(action_key, a) for a in actions] if action_key == "Action" \
        else [(action_key, actions)]
    scopes: list[tuple] = [("Unspecified", None)]
    for resource_key in ("Resource", "NotResource"):
        if resource_key in statement:
            values = _strings(statement[resource_key])
            if values is None:
                return None
            scopes = [(resource_key, v) for v in values] if resource_key == "Resource" \
                else [(resource_key, values)]
    condition = statement.get("Condition", {})
    if not isinstance(condition, dict) or not all(
            isinstance(operator, str) and isinstance(block, dict) and all(
                isinstance(key, str) and isinstance(values, list) for key, values in block.items())
            for operator, block in condition.items()):
        return None
    clauses = tuple(sorted(
        ((operator, key.lower(), frozenset(_compact(v) for v in values))
         for operator, block in condition.items() for key, values in block.items()),
        key=lambda clause: (clause[0], clause[1], sorted(clause[2]))))
    principal: tuple = ("Unspecified", None)
    principal_text = ""
    for principal_key in ("Principal", "NotPrincipal"):
        if principal_key in statement:
            pairs = _principal_pairs(statement[principal_key])
            if pairs is None:
                return None
            principal = (principal_key, pairs)
            principal_text = _compact(statement[principal_key])
    condition_text = _compact(condition) if condition else ""
    return statement["Effect"], specs, [
        _Binding(scope, clauses, principal, condition_text, principal_text) for scope in scopes]


def _access_model(policy: dict) -> tuple[dict, dict]:
    """Per effect, action spec -> bindings; plus the statements left unanalyzed."""
    grants: dict[str, dict[tuple, set[_Binding]]] = defaultdict(lambda: defaultdict(set))
    unanalyzed: dict[str, set[str]] = defaultdict(set)
    for statement in policy.get("Statement", []):
        parts = _statement_parts(statement)
        if parts is None:
            effect = statement.get("Effect") if isinstance(statement, dict) else None
            unanalyzed[effect if isinstance(effect, str) else "?"].add(
                "statement " + _compact(statement))
            continue
        effect, specs, bindings = parts
        for spec in specs:
            grants[effect][spec].update(bindings)
    return grants, unanalyzed


def _action_label(spec: tuple) -> str:
    kind, value = spec
    return value if kind == "Action" else f"NotAction [{', '.join(value)}]"


def _binding_texts(applicable: list[tuple[_Binding, str]]) -> list[str]:
    """'on <resources> unconditionally|when <condition>[ for <principal>][ via <action>]'."""
    scopes: dict[tuple, set[str]] = defaultdict(set)
    for binding, via in applicable:
        kind, value = binding.resource
        if kind == "Unspecified":
            scope = "the shared resources"
        elif kind == "Resource":
            scope = value
        else:
            scope = f"NotResource [{', '.join(value)}]"
        key = (binding.condition_text, binding.principal[0], binding.principal_text, via)
        scopes[key].add(scope)
    texts = []
    for (condition, principal_kind, principal, via), names in scopes.items():
        text = f"on {' or '.join(sorted(names))} " + (
            f"when {condition}" if condition else "unconditionally")
        if principal:
            text += f" for {principal_kind} {principal}"
        texts.append(text + (f" via {via}" if via else ""))
    return sorted(texts)


def _access_status(more: bool, less: bool) -> str:
    return "CHANGED" if more and less else "BROADENED" if more else \
        "NARROWED" if less else "UNCHANGED"


def _access_changes(old: dict, new: dict) -> list[dict]:
    """One entry per (effect, action): the bindings that apply to it before and
    after, and whether access is BROADENED, NARROWED, CHANGED or UNCHANGED."""
    (old_grants, old_other), (new_grants, new_other) = _access_model(old), _access_model(new)

    def applicable(grants: dict, spec: tuple) -> list[tuple[_Binding, str]]:
        # Bindings of every statement action that includes all of ``spec``.
        return [(binding, "" if other == spec else _action_label(other))
                for other, bindings in grants.items() if _action_covers(other, spec)
                for binding in bindings]
    entries = []
    for effect in sorted(set(old_grants) | set(new_grants)):
        prior, current = old_grants.get(effect, {}), new_grants.get(effect, {})
        for spec in sorted(set(prior) | set(current), key=lambda s: (_action_label(s), s[0])):
            before, after = applicable(prior, spec), applicable(current, spec)
            gained = any(not any(_binding_covers(o, n) for o, _ in before) for n, _ in after)
            lost = any(not any(_binding_covers(n, o) for n, _ in after) for o, _ in before)
            # A Deny that applies to less grants more, and one that applies to more grants less.
            more, less = (lost, gained) if effect == "Deny" else (gained, lost)
            entries.append({"effect": effect, "action": _action_label(spec),
                            "status": _access_status(more, less),
                            "before": _binding_texts(before), "after": _binding_texts(after)})
    for effect in sorted(set(old_other) | set(new_other)):
        before, after = sorted(old_other.get(effect, ())), sorted(new_other.get(effect, ()))
        # Compared verbatim: a statement outside the analysis may grant anything.
        entries.append({"effect": effect, "action": _UNANALYZED,
                        "status": "UNCHANGED" if before == after else "CHANGED",
                        "before": before, "after": after})
    return entries


def _access_label(entry: dict) -> str:
    label = f"{entry.get('effect')} {entry.get('action')}"
    status = entry.get("status")
    if entry.get("effect") != "Deny" or status == "UNCHANGED":
        return label
    note = {"BROADENED": "deny weakened" if entry.get("after") else "deny removed",
            "NARROWED": "deny strengthened" if entry.get("before") else "deny added"}.get(
                status, "deny changed")
    return f"{label} ({note})"


def _access_summary(access: list[dict]) -> str:
    """'grants more: ...' and/or 'grants less: ...', or 'no semantic change'.
    CHANGED counts both ways; an unknown status counts as granting more."""
    more = [_access_label(e) for e in access if e.get("status") not in ("UNCHANGED", "NARROWED")]
    less = [_access_label(e) for e in access if e.get("status") in ("NARROWED", "CHANGED")]
    return "; ".join(f"grants {direction}: {', '.join(labels)}"
                     for direction, labels in (("more", more), ("less", less)) if labels) \
        or "no semantic change"


def _access_line(entry: dict) -> str:
    action = str(entry.get("action"))
    absent = "not denied" if entry.get("effect") == "Deny" else "not granted"
    if action == _UNANALYZED:
        absent = "none"
    elif "*" in action or "?" in action or action.startswith("NotAction "):
        absent += " as a whole"

    def side(texts: Any) -> str:
        return " or ".join(map(str, texts)) if texts else absent
    return (f"{entry.get('status')} {entry.get('effect')} {action}: "
            f"before {side(entry.get('before'))}; after {side(entry.get('after'))}")


def policy_difference(before: Any, after: Any) -> dict:
    """What a managed-permission version change grants or withdraws.

    ``access`` keeps statement binding: per (effect, action), the resources and
    conditions it applies to before and after and whether access is BROADENED,
    NARROWED, CHANGED or UNCHANGED; ``summary`` states the overall direction.
    Facets are per effect so an added Deny is never shown as an added grant;
    the exact added/removed statements are kept for statement-level review.
    """
    old, new = policy_semantics(before), policy_semantics(after)
    old_facets, new_facets = _facets(old), _facets(new)
    result: dict[str, Any] = {}
    for facet in old_facets:
        result[f"{facet}_added"] = sorted(new_facets[facet] - old_facets[facet])
        result[f"{facet}_removed"] = sorted(old_facets[facet] - new_facets[facet])

    def statements(policy: dict) -> dict[str, dict]:
        return {json.dumps(s, sort_keys=True): s for s in policy.get("Statement", [])}
    old_s, new_s = statements(old), statements(new)
    result["statements_added"] = [new_s[k] for k in sorted(set(new_s) - set(old_s))]
    result["statements_removed"] = [old_s[k] for k in sorted(set(old_s) - set(new_s))]
    result["access"] = _access_changes(old, new)
    result["summary"] = _access_summary(result["access"])
    return result


def permission_change(owner: str, region: str, share: str, prior: dict, target: dict) -> dict:
    """One original share's attached version -> the version its temporary share attaches:
    the current default, or the version an existing temporary share keeps."""
    return {
        "owner": owner, "region": region, "share": share,
        "permission_arn": target["Arn"], "resource_type": target["ResourceType"],
        "from_version": prior["Version"], "to_version": target["Version"],
        "from_policy_sha256": policy_sha256(prior["Policy"]),
        "to_policy_sha256": policy_sha256(target["Policy"]),
        "from_policy": prior["Policy"], "to_policy": target["Policy"],
        "difference": policy_difference(prior["Policy"], target["Policy"]),
    }


def describe_difference(difference: dict) -> list[str]:
    """Operator-facing lines for a permission comparison.

    The first line states the direction: ``grants more: ...`` and/or ``grants
    less: ...``, or ``no semantic change``. Then one line per (effect, action)
    whose access changed, with what it applies to before and after, the
    unchanged ones, and the per-effect facets (empty facets omitted).
    """
    facets = [f"{facet.replace('_', '-')} {verb}: {value}"
              for facet in ("actions", "not_actions", "resources", "not_resources",
                            "conditions", "principals")
              for verb in ("added", "removed")
              for value in difference.get(f"{facet}_{verb}", [])]
    access = difference.get("access")
    if not isinstance(access, list) or not all(isinstance(e, dict) for e in access):
        # Made without the statement-level analysis: bindings are unknown.
        return ["grants more: not ruled out; this comparison has no statement-level "
                "analysis, re-run plan --record", *facets]
    lines = [_access_summary(access)]
    lines += [_access_line(e) for e in access if e.get("status") != "UNCHANGED"]
    unchanged = [_access_label(e) for e in access if e.get("status") == "UNCHANGED"]
    if unchanged:
        lines.append("unchanged access: " + ", ".join(unchanged))
    lines += facets
    if lines[0] == "no semantic change" and not facets and (
            difference.get("statements_added") or difference.get("statements_removed")):
        lines.append("statements differ only in structure; every action keeps the same "
                     "resources and conditions")
    return lines


def grants_less(difference: dict) -> list[str]:
    """What the later policy of a comparison grants less than the earlier one: the labels
    of describe_difference's 'grants less:' (NARROWED entries, and CHANGED ones, which also
    grant more). A comparison without the statement-level analysis cannot rule it out."""
    access = difference.get("access")
    if not isinstance(access, list) or not all(isinstance(e, dict) for e in access):
        return ["not ruled out without the statement-level analysis"]
    return [_access_label(e) for e in access if e.get("status") in ("NARROWED", "CHANGED")]


def permission_snapshot(ram: Any, arn: str, version: str | None = None) -> dict:
    kwargs = {"permissionArn": arn}
    if version is not None:
        if not isinstance(version, str) or not re.fullmatch(r"[1-9][0-9]*", version):
            raise MigrationError(f"{arn}: invalid managed permission version")
        # RAM returns string versions but GetPermission's input is an integer.
        kwargs["permissionVersion"] = int(version)
    permission = ram.get_permission(**kwargs)["permission"]
    if permission.get("arn") != arn or not isinstance(permission.get("version"), str) or \
            not re.fullmatch(r"[1-9][0-9]*", permission["version"]) or \
            (version is not None and permission["version"] != version):
        raise MigrationError(f"{arn}: permission identity/version was not returned correctly")
    allowed_status = {"ATTACHABLE", "UNATTACHABLE"} if version is not None else {"ATTACHABLE"}
    if permission.get("status") not in allowed_status or \
            permission.get("featureSet") != "STANDARD":
        raise MigrationError(f"{arn}: permission is not an attachable standard managed permission")
    kind = permission.get("resourceType")
    if not isinstance(kind, str) or not kind:
        raise MigrationError(f"{arn}: permission resource type missing")
    return {"Arn": arn, "Version": permission["version"], "ResourceType": kind,
            "Policy": policy_semantics(permission["permission"]),
            "DefaultVersion": permission.get("defaultVersion") is True}


def cached_permission(cache: LookupCache | None, account: str, region: str, ram: Any,
                      arn: str, version: str | None = None) -> dict:
    return lookup(cache, ("permission", account, region, arn, version),
                  lambda: permission_snapshot(ram, arn, version))


def resolve(value: Any, parameters: dict, template: dict, pseudo: dict) -> Any:
    """Resolve principal expressions; unknown expressions fail closed."""
    if isinstance(value, list):
        return [resolve(v, parameters, template, pseudo) for v in value]
    if not isinstance(value, dict):
        return value
    if len(value) != 1:
        raise MigrationError("Ambiguous principal expression")
    if "Ref" in value:
        key = value["Ref"]
        if key in pseudo:
            return pseudo[key]
        if key not in parameters:
            raise MigrationError(f"Unresolved principal Ref: {key}")
        result = parameters[key]
        definition = template.get("Parameters", {}).get(key, {})
        if definition.get("Type", "").startswith(("List<", "CommaDelimitedList")) \
                and isinstance(result, str):
            return result.split(",")
        return result
    if "Fn::Split" in value:
        delimiter, item = value["Fn::Split"]
        item = resolve(item, parameters, template, pseudo)
        if not isinstance(item, str):
            raise MigrationError("Principal Fn::Split input must be a string")
        return item.split(delimiter)
    if "Fn::Join" in value:
        delimiter, items = value["Fn::Join"]
        items = resolve(items, parameters, template, pseudo)
        if not isinstance(items, list) or any(not isinstance(v, str) for v in items):
            raise MigrationError("Principal Fn::Join inputs must be strings")
        return delimiter.join(items)
    if "Fn::Equals" in value:
        a, b = resolve(value["Fn::Equals"], parameters, template, pseudo)
        return a == b
    if "Fn::Not" in value:
        return not resolve(value["Fn::Not"][0], parameters, template, pseudo)
    if "Fn::And" in value:
        return all(resolve(value["Fn::And"], parameters, template, pseudo))
    if "Fn::Or" in value:
        return any(resolve(value["Fn::Or"], parameters, template, pseudo))
    if "Condition" in value:
        return resolve(template["Conditions"][value["Condition"]], parameters, template, pseudo)
    if "Fn::If" in value:
        name, yes, no = value["Fn::If"]
        condition = resolve(template["Conditions"][name], parameters, template, pseudo)
        return resolve(yes if condition else no, parameters, template, pseudo)
    if "Fn::Sub" in value:
        raw = value["Fn::Sub"]
        expression, variables = (raw, {}) if isinstance(raw, str) else raw
        variables = {k: resolve(v, parameters, template, pseudo) for k, v in variables.items()}
        def replace(match):
            key = match.group(1)
            if key in variables:
                result = variables[key]
            else:
                result = resolve({"Ref": key}, parameters, template, pseudo)
            if not isinstance(result, str):
                raise MigrationError(f"Principal Fn::Sub variable must be a string: {key}")
            return result
        return re.sub(r"\$\{([^}]+)\}", replace, expression)
    raise MigrationError(f"Unresolved principal intrinsic: {list(value)}")


def flatten(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, list):
        return [x for item in value for x in flatten(item)]
    if not isinstance(value, str):
        raise MigrationError("Principal must resolve to strings, not numeric IDs")
    return [x.strip() for x in value.split(",") if x.strip()]


class Discovery:
    def __init__(self, router: Router, consumers: set[str], migration: str,
                 overrides: dict, capabilities: dict[str, bool],
                 migrating_owners: set[str] | None = None,
                 share_workers: int = 1, cache: LookupCache | None = None,
                 deployed: dict[str, dict[str, dict]] | None = None,
                 excluded_consumers: set[str] | None = None,
                 consumer_exclusion_reason: str | None = None):
        for consumer in consumers:
            account_id(consumer)
        if type(share_workers) is not int or not 1 <= share_workers <= 16:
            raise MigrationError("share_workers must be an integer between 1 and 16")
        self.router, self.consumers, self.migration = router, consumers, migration
        self.overrides, self.capabilities = overrides, capabilities
        self.migrating_owners = set(migrating_owners or ())
        self.excluded_consumers = set(excluded_consumers or ())
        for consumer in self.excluded_consumers:
            account_id(consumer)
        if self.excluded_consumers & (self.consumers | self.migrating_owners):
            raise MigrationError("Excluded recipients overlap the migrating account scope")
        if self.excluded_consumers and (
                not isinstance(consumer_exclusion_reason, str) or
                not consumer_exclusion_reason.strip()):
            raise MigrationError("Excluded recipients require an explicit recorded reason")
        self.consumer_exclusion_reason = consumer_exclusion_reason
        self.share_workers, self.cache = share_workers, cache
        # Entitlement key -> {resource type: permission snapshot} of each temporary share
        # already in a migration stack, as recorded in its template. Such a share keeps
        # the version it was created with, so a source share joining it is compared
        # with that version, not with the current default.
        self.deployed = copy.deepcopy(deployed or {})
        # Original share ARN -> its OU and organization principals, configured or
        # associated: where these shares rely on RAM sharing with AWS Organizations,
        # whose prerequisites ram_migration_preflight checks.
        self.organization_principals: dict[str, list[str]] = {}
        self._principals_lock = threading.Lock()

    def _org(self, owner: str):
        member = self.router.client(owner, "organizations", "us-east-1")
        organization = member.describe_organization()["Organization"]
        manager = organization.get("ManagementAccountId", organization.get("MasterAccountId"))
        if not manager:
            raise MigrationError("Organization management account was not returned")
        return self.router.client(manager, "organizations", "us-east-1"), organization

    def _stack_source(self, owner: str, region: str, share: str):
        cfn = self.router.client(owner, "cloudformation", region)
        try:
            rows = cfn.describe_stack_resources(PhysicalResourceId=share)["StackResources"]
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            if code == "ValidationError" and \
                    any(x in exc.response["Error"]["Message"].lower()
                        for x in ("does not exist", "not found", "not associated")):
                return None
            raise
        matches = [r for r in rows if r.get("PhysicalResourceId") == share]
        if len(matches) != 1:
            raise MigrationError(f"{share}: owning stack lookup was inconclusive")
        match = matches[0]
        if match.get("ResourceType") != "AWS::RAM::ResourceShare":
            raise MigrationError(f"{share}: owning resource is not a native RAM share")
        stack = cfn.describe_stacks(StackName=match["StackId"])["Stacks"][0]
        template = read_template(self.cache, owner, region, cfn, stack)
        parameters = {k: v.get("Default") for k, v in template.get("Parameters", {}).items()
                      if "Default" in v}
        parameters.update({p["ParameterKey"]: p.get("ResolvedValue", p.get("ParameterValue"))
                           for p in stack.get("Parameters", [])})
        pseudo = {"AWS::AccountId": owner, "AWS::Region": region,
                  "AWS::Partition": share.split(":")[1], "AWS::NoValue": None}
        resource = template["Resources"][match["LogicalResourceId"]]
        if resource.get("Type") != "AWS::RAM::ResourceShare":
            raise MigrationError(f"{share}: owning template resource type is inconclusive")
        return stack, match, resource, template, parameters, pseudo

    def _stack_principals(self, owner: str, region: str, share: str) -> list[str] | None:
        source = self._stack_source(owner, region, share)
        if source is None:
            return None
        _, _, resource, template, parameters, pseudo = source
        if "Principals" not in resource.get("Properties", {}):
            raise MigrationError(f"{share}: owning template has no intended principals")
        return flatten(resolve(resource["Properties"]["Principals"], parameters, template, pseudo))

    def _migration_owned(self, owner: str, region: str, share: dict) -> bool:
        if not managed(share.get("tags", [])):
            return False
        values = tags(share["tags"])
        source = self._stack_source(owner, region, share["resourceShareArn"])
        if source is None:
            raise MigrationError("Migration-tagged share has no proven owning migration stack")
        stack, match, resource, *_ = source
        properties = resource.get("Properties", {})
        recorded = tags(properties.get("Tags", []))
        migration = values.get("migrationid")
        if not migration or not managed(stack.get("Tags", []), migration) or \
                not managed(properties.get("Tags", []), migration) or \
                values.get("owneraccount") != owner or \
                recorded.get("owneraccount") != owner or \
                not values.get("entitlementhash") or \
                recorded.get("entitlementhash") != values["entitlementhash"] or \
                match["LogicalResourceId"] != "Share" + values["entitlementhash"] or \
                properties.get("Name") != share.get("name") or \
                not resource.get("Metadata", {}).get("SourceShareArns"):
            raise MigrationError("Migration share provenance does not match its owning template")
        return True

    def _expand(self, owner: str, principal: str, *, partition: str | None = None) -> set[str]:
        direct = direct_account_principal(principal, partition)
        if direct is not None:
            return {direct}
        if SERVICE_PRINCIPAL.fullmatch(principal):
            return set()
        if ":organization/" not in principal and ":ou/" not in principal:
            raise MigrationError(f"Unsupported account-level principal conversion: {principal}")
        org, organization = self._org(owner)
        if ":organization/" in principal:
            if principal.rsplit("/", 1)[-1] != organization["Id"]:
                raise MigrationError("Organization principal does not match owner's organization")
            return {a["Id"] for a in pages(org, "list_accounts", "Accounts")
                    if a.get("State", a.get("Status")) == "ACTIVE"}
        if ":ou/" in principal:
            components = principal.split("/")
            if components[-2] != organization["Id"]:
                raise MigrationError("OU principal does not match owner's organization")
            def descend(parent: str) -> set[str]:
                found = {a["Id"] for a in pages(org, "list_accounts_for_parent", "Accounts",
                                                ParentId=parent)
                         if a.get("State", a.get("Status")) == "ACTIVE"}
                for child in pages(org, "list_organizational_units_for_parent",
                                   "OrganizationalUnits", ParentId=parent):
                    found.update(descend(child["Id"]))
                return found
            return descend(components[-1])
        raise MigrationError(f"Unsupported account-level principal conversion: {principal}")

    def _members(self, owner: str) -> set[str]:
        org, _ = self._org(owner)
        return {a["Id"] for a in pages(org, "list_accounts", "Accounts")
                if a.get("State", a.get("Status")) == "ACTIVE"}

    @staticmethod
    def _owner_listed(owner: str, partition: str, associations: list[dict],
                      configured: list[str], overridden: list[str]) -> list[str]:
        """Where a share names its own owner as a principal. RAM fails that association
        ('The resource share owner cannot be associated with the resource share.'); it is
        neither a consumer, nor a blocker, nor a missing entitlement."""
        evidence = []
        for row in associations:
            if direct_account_principal(row["associatedEntity"], partition) == owner:
                message = row.get("statusMessage")
                evidence.append(f"association {row.get('status')}"
                                + (f": {message}" if message else ""))
        if any(direct_account_principal(p, partition) == owner for p in configured):
            evidence.append("owning template principal")
        if owner in overridden:
            evidence.append("principal-map entry")
        return list(dict.fromkeys(evidence))

    @staticmethod
    def _external_access(associations: list[dict], selected: set[str],
                         partition: str) -> set[str]:
        """Selected consumers whose live association on this original share is external:
        the account is outside the owner's organization and holds the share directly, for
        example a principal restored after it left. That access does not depend on
        organization membership. An external association that is not ASSOCIATED holds no
        access yet, and an invitation is never accepted on an original share's behalf."""
        rows: dict[str, list[dict]] = defaultdict(list)
        for row in associations:
            account = direct_account_principal(row["associatedEntity"], partition)
            if account in selected and row.get("status") in LIVE:
                rows[account].append(row)
        recovered = set()
        for account, live in sorted(rows.items()):
            if not any(row.get("external") is True for row in live):
                continue
            if all(row.get("external") is True and row["status"] == "ASSOCIATED" for row in live):
                recovered.add(account)
                continue
            states = ", ".join(sorted(
                f"{row['status']} external={'true' if row.get('external') is True else 'false'}"
                for row in live))
            raise MigrationError(
                f"external principal association of {account} on this original share is not "
                f"settled ({states}): an external account holds no access until it accepts the "
                "share's invitation, and this tool never accepts an original share's invitation; "
                f"have {account} accept or reject that invitation, then re-run plan")
        return recovered

    def inspect(self, owner: str, region: str) -> Plan:
        """Shares are inspected concurrently (share_workers) and merged in share-ARN
        order, so the plan never depends on completion order."""
        account_id(owner)
        plan = Plan(self.migration)
        ram = self.router.client(owner, "ram", region)
        try:
            shares = pages(ram, "get_resource_shares", "resourceShares", resourceOwner="SELF")
        except Exception as exc:
            plan.blocked.append(f"owner={owner} region={region} phase=discovery {failure_text(exc)}")
            return plan
        arns = [share["resourceShareArn"] for share in shares]
        members = LookupCache()  # one active-membership read per inspection

        def one(share: dict) -> tuple[Plan, ApprovedGroup | None]:
            return self._inspect_share(owner, region, ram, share, members)
        if self.share_workers > 1 and len(shares) > 1:
            with ThreadPoolExecutor(max_workers=min(self.share_workers, len(shares))) as executor:
                results = list(executor.map(one, shares))
        else:
            results = [one(share) for share in shares]
        for arn, (part, group) in sorted(zip(arns, results), key=lambda pair: pair[0]):
            self._merge(plan, owner, region, arn, part, group)
        return plan

    def _merge(self, plan: Plan, owner: str, region: str, arn: str, part: Plan,
               group: ApprovedGroup | None) -> None:
        plan.excluded.extend(part.excluded)
        plan.existing.extend(part.existing)
        plan.blocked.extend(part.blocked)
        plan.notes.extend(part.notes)
        plan.external_access.extend(part.external_access)
        if group is None:
            return
        try:
            prior_group = next((g for g in plan.groups if g.key == group.key), None)
            if prior_group is not None:
                if prior_group.permission_snapshots != group.permission_snapshots:
                    raise MigrationError("Permission snapshot changed during discovery")
                prior_group.source_stacks = sorted(set(prior_group.source_stacks
                                                       + group.source_stacks))
                if any(a in prior_group.resources and prior_group.resources[a] != k
                       for a, k in group.resources.items()):
                    raise MigrationError("Conflicting RAM types for the same source resource")
            plan.merge(Plan(self.migration, groups=[group]))
            plan.permission_changes.extend(part.permission_changes)
            plan.owner_continuity.extend(part.owner_continuity)
        except Exception as exc:
            plan.blocked.append(share_blocker(owner, region, arn, exc))

    def _orphan_policy_ca(self, owner: str, region: str, ram: Any, share: dict,
                          associations: list[dict]) -> str | None:
        """Exclude only a policy-created CA share with independently proven missing CAs.

        Any principal association, an existing/restorable CA, a mixed resource type,
        or an unsuccessful read leaves the share blocked. Nothing is promoted or deleted.
        """
        if share.get("featureSet") != "CREATED_FROM_POLICY" or \
                share.get("status") != "ACTIVE" or associations:
            return None
        partition = ram.meta.partition
        arn = share["resourceShareArn"]
        prefix = f"arn:{partition}:ram:{region}:{owner}:resource-share/"
        if not arn.startswith(prefix) or not re.fullmatch(
                r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", arn[len(prefix):]):
            raise MigrationError("Policy-created share ARN does not match its owner/Region")
        resources = evidence_pages(ram, "list_resources", "resources", resourceOwner="SELF",
                                    resourceShareArns=[arn])
        if not resources or any(row.get("type") != "acm-pca:CertificateAuthority"
                                for row in resources):
            return None
        ca_prefix = f"arn:{partition}:acm-pca:{region}:{owner}:certificate-authority/"

        def checked_arn(value: Any) -> str:
            if not isinstance(value, str) or not value.startswith(ca_prefix) or \
                    not re.fullmatch(r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}",
                                     value[len(ca_prefix):]):
                raise MigrationError("Private CA evidence does not match its owner/Region")
            return value

        missing = sorted({checked_arn(row.get("arn")) for row in resources})
        pca = self.router.client(owner, "acm-pca", region)
        if pca.meta.partition != partition or pca.meta.region_name != region:
            raise MigrationError("Private CA client does not match the RAM partition/Region")
        for ca in missing:
            try:
                pca.describe_certificate_authority(CertificateAuthorityArn=ca)
            except ClientError as exc:
                if exc.response.get("Error", {}).get("Code") != "ResourceNotFoundException":
                    raise
            else:
                return None  # Including DELETED CAs still within their restoration period.

        def inventory():
            rows = evidence_pages(pca, "list_certificate_authorities", "CertificateAuthorities",
                                   MaxResults=100, ResourceOwner="SELF")
            for row in rows:
                checked_arn(row.get("Arn"))
                if row.get("OwnerAccount", owner) != owner:
                    raise MigrationError("Private CA inventory contains an unexpected owner")
            return sorted({row["Arn"] for row in rows})

        owned = lookup(self.cache, ("owned-private-cas", owner, region), inventory)
        if set(missing) & set(owned):
            return None
        return (f"{arn}: orphan CREATED_FROM_POLICY private CA share; owner={owner} "
                f"region={region}; no principal associations; CAs {missing} each returned "
                "DescribeCertificateAuthority ResourceNotFoundException and were absent from "
                "complete ListCertificateAuthorities(ResourceOwner=SELF); read-only exclusion")

    def _inspect_share(self, owner: str, region: str, ram: Any, share: dict,
                       members: LookupCache) -> tuple[Plan, ApprovedGroup | None]:
        """One source share's exclusions, evidence and group, merged later by ARN."""
        part = Plan(self.migration)
        arn = share["resourceShareArn"]
        try:
            if share.get("owningAccountId") != owner:
                raise MigrationError("Source share owner does not match the inspected account")
            # RAM keeps listing deleted shares for a while; DELETED is terminal and
            # grants nothing to replicate. DELETING and FAILED shares grant nothing now
            # either (below); a PENDING share is being set up and still blocks.
            if share.get("status") == "DELETED":
                part.excluded.append(f"{arn}: deleted share (status DELETED)")
                return part, None
            # A row without featureSet predates the field and describes a standard share.
            feature = share.get("featureSet", "STANDARD")
            if feature != "STANDARD":
                # A service-principal-only share is never replicated account-wide, whatever
                # its featureSet (for example pca-connector-ad shares created from policy).
                associations = evidence_pages(
                    ram, "get_resource_share_associations", "resourceShareAssociations",
                    associationType="PRINCIPAL", resourceShareArns=[arn])
                principals = [r["associatedEntity"] for r in associations if r.get("status") in LIVE]
                if principals and all(SERVICE_PRINCIPAL.fullmatch(p) for p in principals):
                    part.excluded.append(f"{arn}: service-principal-only share (featureSet "
                                         f"{feature}); never replicated account-wide")
                    return part, None
                orphan = self._orphan_policy_ca(owner, region, ram, share, associations)
                if orphan is not None:
                    part.excluded.append(orphan)
                    return part, None
                raise MigrationError(feature_set_problem(owner, region, arn, feature))
            if self._migration_owned(owner, region, share):
                part.existing.append(share)
                return part, None
            if share["status"] in ("DELETING", "FAILED"):
                part.excluded.append(f"{arn}: source status {share['status']}; it grants no access "
                                     "now, so the migration does not change it")
                return part, None
            if share["status"] != "ACTIVE":
                raise MigrationError(f"source status {share['status']}")
            resources = pages(ram, "list_resources", "resources", resourceOwner="SELF",
                              resourceShareArns=[arn])
            if not resources:
                part.excluded.append(f"{arn}: empty share")
                return part, None
            associations = pages(ram, "get_resource_share_associations",
                                 "resourceShareAssociations", associationType="PRINCIPAL",
                                 resourceShareArns=[arn])
            observed = flatten([r["associatedEntity"] for r in associations])
            live = [r["associatedEntity"] for r in associations if r["status"] in LIVE]
            explicit = self.overrides.get(arn)
            source_stacks = []
            source = self._stack_source(owner, region, arn)
            configured = []
            if source is not None:
                source_stacks = [source[0]["StackId"]]
                _, _, resource, template, parameters, pseudo = source
                if "Principals" not in resource.get("Properties", {}):
                    raise MigrationError("Owning template has no intended principals")
                configured = flatten(resolve(resource["Properties"]["Principals"],
                                             parameters, template, pseudo))
            original = sorted(set(configured + live))
            validate_principal_scopes(sorted(set(configured + observed)), ram.meta.partition)
            organizational = sorted({p for p in configured + observed
                                     if ":ou/" in p or ":organization/" in p})
            if organizational:
                with self._principals_lock:
                    self.organization_principals[arn] = organizational
            scope_evidence = configured or observed
            service_only = bool(scope_evidence) and all(
                SERVICE_PRINCIPAL.fullmatch(p) for p in scope_evidence)
            if configured and all(SERVICE_PRINCIPAL.fullmatch(p) for p in configured) and \
                    any(not SERVICE_PRINCIPAL.fullmatch(p) for p in live):
                raise MigrationError("Service-only template conflicts with live account principals")
            if explicit is not None:
                principals = flatten(explicit)
                for principal in principals:
                    account_id(principal)
                if service_only and principals:
                    raise MigrationError("Principal-map override cannot broaden a "
                                         "service-principal-only share to account-wide access")
            else:
                principals = original
            listed = self._owner_listed(owner, ram.meta.partition, associations, configured,
                                        principals if explicit is not None else [])
            if listed:
                part.excluded.append(
                    f"{arn}: owner {owner} is listed as a principal of its own share "
                    f"({'; '.join(listed)}); an owner is never a consumer of its own share, so it "
                    "is excluded from the intended consumers and is never a temporary-share "
                    "principal")
            # Live evidence, whatever the configured or overridden principals say.
            recovered = self._external_access(associations, self.consumers - {owner},
                                              ram.meta.partition)
            if recovered:
                part.external_access.extend(
                    {"owner": owner, "region": region, "share": arn, "consumer": consumer,
                     "status": "ASSOCIATED", "external": True} for consumer in sorted(recovered))
                part.excluded.append(
                    f"{arn}: recovered external access for {sorted(recovered)}: each holds an "
                    "ASSOCIATED principal association with external=true on this original share, "
                    "so it is outside the owner's organization and keeps this access whatever "
                    "organization it is in; that access is pre-existing, not created by this tool, "
                    "so no temporary share duplicates it and the original share is never modified")
            if not principals and not (owner in self.migrating_owners and original):
                if explicit is not None:
                    part.excluded.append(f"{arn}: explicitly approved empty consumer inventory")
                    return part, None
                raise MigrationError("Original account-facing consumers are unresolved; "
                                     "provide a principal-map override")
            if principals and all(SERVICE_PRINCIPAL.fullmatch(p) for p in principals):
                part.excluded.append(f"{arn}: service-principal-only share")
                return part, None
            consumers: set[str] = set()
            for principal in principals:
                consumers.update(self._expand(owner, principal, partition=ram.meta.partition))
            # Historical OU membership cannot be guessed after account departure.
            if explicit is None and any(":ou/" in p or ":organization/" in p for p in principals):
                active_members = members.get(("active", owner), lambda: self._members(owner))
                direct = {
                    account for p in principals
                    if (account := direct_account_principal(p, ram.meta.partition)) is not None}
                unresolved = self.consumers - active_members - direct - {owner}
                if unresolved:
                    raise MigrationError("Provide principal-map override to resolve historical "
                                         f"organization/OU membership for {sorted(unresolved)}")
                outside_scope = (self.consumers & active_members) - consumers - {owner}
                if outside_scope:
                    part.excluded.append(
                        f"{arn}: selected active source-organization consumers outside "
                        f"this principal scope: {sorted(outside_scope)}")
            unrelated = consumers - self.consumers - {owner}
            stationary: set[str] = set()
            if owner in self.migrating_owners:
                # Preserve the original share's stationary recipients as account IDs.
                # An override can resolve historical moving recipients, but cannot remove
                # a live/configured stationary recipient or invent another one.
                stationary = set(unrelated)
                if explicit is not None:
                    proven: set[str] = set()
                    for principal in sorted(set(configured) | set(live)):
                        proven.update(self._expand(owner, principal, partition=ram.meta.partition))
                    unproven = unrelated - proven - self.excluded_consumers
                    if unproven:
                        raise MigrationError(
                            f"principal-map stationary consumers {sorted(unproven)} have no "
                            "live or owning-template principal evidence on the original share")
                    stationary = proven - self.consumers - {owner}
                omitted = (consumers | stationary) & self.excluded_consumers
                if omitted:
                    part.excluded.append(
                        f"{arn}: recipient accounts {sorted(omitted)} explicitly excluded "
                        f"by operator: {self.consumer_exclusion_reason}")
                consumers -= self.excluded_consumers
                stationary -= self.excluded_consumers
                external_stationary = self._external_access(
                    associations, stationary, ram.meta.partition)
                # Continuity keeps access a stationary recipient has now; it never grants
                # access the original share no longer gives. Only an ASSOCIATED principal
                # association (an account, or an OU or organization expanded to its active
                # members) proves current access; a recipient only the owning template names
                # would receive new access, so it blocks unless explicitly excluded.
                associated: set[str] = set()
                for row in associations:
                    if row.get("status") == "ASSOCIATED":
                        associated.update(self._expand(owner, row["associatedEntity"],
                                                       partition=ram.meta.partition))
                unassociated = stationary - associated
                if unassociated:
                    raise MigrationError(
                        f"stationary recipients {sorted(unassociated)} hold no ASSOCIATED "
                        "principal association on this original share now (the owning template "
                        "or a pending association names them), so a temporary share would grant "
                        "them new access: reconcile the original share, or leave them out with "
                        "--exclude-consumers and --exclude-consumers-reason")
                if external_stationary:
                    part.external_access.extend(
                        {"owner": owner, "region": region, "share": arn, "consumer": consumer,
                         "status": "ASSOCIATED", "external": True}
                        for consumer in sorted(external_stationary))
                    part.excluded.append(
                        f"{arn}: stationary consumers {sorted(external_stationary)} already "
                        "hold ASSOCIATED external account-level access on the original share; "
                        "no temporary share duplicates that access")
                recovered |= external_stationary
                consumers = (consumers & self.consumers) | stationary
            elif unrelated:
                part.excluded.append(
                    f"{arn}: unrelated consumers outside migration population: {sorted(unrelated)}")
                consumers &= self.consumers
            consumers.discard(owner)
            consumers -= recovered
            stationary &= consumers
            if not consumers:
                if not recovered:
                    part.excluded.append(f"{arn}: no selected consumers")
                return part, None
            permission_map: dict[str, str] = {}
            attached: dict[str, tuple[dict, dict]] = {}
            for permission in pages(ram, "list_resource_share_permissions", "permissions",
                                    resourceShareArn=arn):
                default = cached_permission(self.cache, owner, region, ram, permission["arn"])
                if not default["DefaultVersion"]:
                    raise MigrationError("GetPermission did not return the current default version")
                kind = permission["resourceType"]
                if kind in permission_map or default["ResourceType"] != kind:
                    raise MigrationError(f"{kind}: ambiguous managed permission mapping")
                if not permission.get("version"):
                    raise MigrationError(f"{kind}: attached managed permission version missing")
                permission_map[kind] = permission["arn"]
                attached[kind] = permission, default
            # A new temporary share receives the current default version: AWS attaches
            # nothing else, so an older version is never pinned. A temporary share already
            # in the migration stack keeps the version it was created with, so a source
            # share that joins it is compared with that version.
            candidate = Group(owner, region, tuple(sorted(consumers)), permission_map)
            existing, logical = self.deployed.get(candidate.key), candidate.logical_id
            snapshots: dict[str, dict] = {}
            changes: list[dict] = []
            for kind, (permission, default) in attached.items():
                target = default
                if existing is not None:
                    kept = existing.get(kind)
                    if not isinstance(kept, dict) or kept.get("Arn") != permission["arn"] or \
                            not kept.get("Version") or "Policy" not in kept:
                        raise MigrationError(f"{kind}: permission evidence of existing temporary "
                                             f"share {logical} is incomplete")
                    target = copy.deepcopy(kept)
                    if default["Version"] != target["Version"]:
                        part.notes.append(
                            f"{arn}: owner={owner} region={region} permission={permission['arn']} "
                            f"status=DEFAULT_CHANGED existing temporary share {logical} keeps "
                            f"version {target['Version']}; the current default is version "
                            f"{default['Version']} and the original share attaches version "
                            f"{permission['version']}. Nothing this tool writes attaches the new "
                            "default to that share, so the default change does not affect it")
                if target["Version"] != permission["version"]:
                    prior = cached_permission(self.cache, owner, region, ram, permission["arn"],
                                              permission["version"])
                    if prior["ResourceType"] != kind:
                        raise MigrationError(f"Non-default permission type differs: {permission['arn']}")
                    if prior["Policy"] != policy_semantics(target["Policy"]):
                        # The temporary share grants what its own version grants, which can be
                        # more or less than the original's. The difference is reported for the
                        # reviewer and never blocks or needs approval: the share is temporary.
                        change = permission_change(owner, region, arn, prior, target)
                        change["applies_to"] = (
                            f"existing temporary share {logical} (keeps version {target['Version']})"
                            if existing is not None else
                            "new temporary share (receives the current default)")
                        changes.append(change)
                snapshots[kind] = target
            available: dict[str, str] = {}
            for resource in resources:
                resource_arn, kind = resource["arn"], resource["type"]
                # Owner-side (SELF) listings omit status. A resource being added (PENDING)
                # blocks; one this share cannot provide now (for example
                # ZONAL_RESOURCE_INACCESSIBLE or LIMIT_EXCEEDED) is not changed by the
                # migration and is left out.
                status = resource.get("status", "AVAILABLE")
                if status == "PENDING":
                    raise MigrationError(f"{resource_arn}: resource status PENDING")
                if status != "AVAILABLE":
                    part.excluded.append(f"{arn}: resource {resource_arn} status {status}; it is "
                                         "not available through this share now, so the migration "
                                         "does not change it")
                    continue
                if resource_arn.split(":")[4] != owner:
                    raise MigrationError(f"Cannot re-share resource owned by another account: {resource_arn}")
                if self.capabilities.get(kind.lower()) is not True:
                    raise MigrationError(f"{kind}: unsupported or unverified external-sharing capability")
                if kind not in permission_map:
                    raise MigrationError(f"{kind}: source managed permission missing")
                available[resource_arn] = kind
            if not available:
                part.excluded.append(f"{arn}: no resource is available through this share now; "
                                     "the migration does not change it")
                return part, None
            kinds = set(available.values())
            if set(permission_map) != {resource["type"] for resource in resources}:
                raise MigrationError("Source permissions do not exactly match its resource types")
            # A resource type left out entirely needs no permission on the temporary share.
            permission_map = {k: v for k, v in permission_map.items() if k in kinds}
            snapshots = {k: v for k, v in snapshots.items() if k in kinds}
            group = ApprovedGroup(owner, region, tuple(sorted(consumers)),
                                  permission_map, available, [arn], snapshots, source_stacks,
                                  tuple(sorted(stationary)))
            if stationary:
                part.owner_continuity.append({
                    "owner": owner, "region": region, "share": arn,
                    "stationary_consumers": sorted(stationary),
                    "resources": sorted(available),
                    "original_principals": sorted(set(configured) | set(live)),
                })
                part.notes.append(
                    f"phase=owner-continuity owner={owner} region={region} share={arn} "
                    f"stationary_consumers={','.join(sorted(stationary))} "
                    "status=PLANNED account-level external shares retain these recipients; "
                    "baseline capture and invitation acceptance are required before the owner moves")
            # Only a share that is planned reports its difference, for the types it holds.
            part.permission_changes.extend(c for c in changes if c["resource_type"] in kinds)
            return part, group
        except Exception as exc:
            part.blocked.append(share_blocker(owner, region, arn, exc))
            return part, None
