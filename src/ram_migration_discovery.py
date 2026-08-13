"""Read-only inventory and conservative entitlement planning."""
from __future__ import annotations

import hashlib
import json
import re
import urllib.request
from collections import defaultdict
from dataclasses import dataclass, field
from functools import lru_cache
from typing import Any, NamedTuple

import yaml
from botocore.exceptions import ClientError

from ram_migration_common import (
    ACCOUNT, Group, MigrationError, Plan, Router, account_id, error_text,
    managed, pages, tags,
)
from ram_migration_record import approval_for

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


@dataclass
class ApprovedGroup(Group):
    """Compatible Group carrying the policy and source-stack approval evidence."""
    permission_snapshots: dict[str, dict] = field(default_factory=dict)
    source_stacks: list[str] = field(default_factory=list)
    # Approved original-version -> current-default changes, one per source share.
    permission_changes: list[dict] = field(default_factory=list)


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


def permission_change(owner: str, region: str, share: str, prior: dict, default: dict) -> dict:
    """One original share's attached version -> the current default AWS attaches."""
    return {
        "owner": owner, "region": region, "share": share,
        "permission_arn": default["Arn"], "resource_type": default["ResourceType"],
        "from_version": prior["Version"], "to_version": default["Version"],
        "from_policy_sha256": policy_sha256(prior["Policy"]),
        "to_policy_sha256": policy_sha256(default["Policy"]),
        "from_policy": prior["Policy"], "to_policy": default["Policy"],
        "difference": policy_difference(prior["Policy"], default["Policy"]),
    }


APPROVED_CHANGE_FIELDS = ("share", "permission_arn", "resource_type", "from_version",
                          "to_version", "from_policy_sha256", "to_policy_sha256", "approval_id")


def approved_change(change: dict) -> dict:
    """Compact, template-safe evidence of an approved change."""
    if change.get("status") != "APPROVED" or not change.get("approval_id"):
        raise MigrationError("Only approved permission changes can join an entitlement group")
    return {key: change[key] for key in APPROVED_CHANGE_FIELDS}


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
        # Recorded without the statement-level analysis: bindings are unknown.
        return ["grants more: not ruled out; this comparison has no statement-level "
                "analysis, re-run plan --record before approving", *facets]
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


def revalidate_change(ram: Any, change: dict) -> None:
    """Re-read both sides of an approved change just before any write.

    The original share must still attach the approved version, and the current
    default must still be the approved version with the approved policy. Any
    drift voids the approval; a renewed approval is required.
    """
    attached = [p for p in pages(ram, "list_resource_share_permissions", "permissions",
                                 resourceShareArn=change["share"])
                if p.get("arn") == change["permission_arn"]]
    if len(attached) != 1 or attached[0].get("version") != change["from_version"]:
        raise MigrationError(f"{change['share']}: attached permission version changed since "
                             f"approval {change['approval_id']}; re-run plan and approve again")
    prior = permission_snapshot(ram, change["permission_arn"], change["from_version"])
    default = permission_snapshot(ram, change["permission_arn"])
    if not default["DefaultVersion"] or default["Version"] != change["to_version"] or \
            policy_sha256(prior["Policy"]) != change["from_policy_sha256"] or \
            policy_sha256(default["Policy"]) != change["to_policy_sha256"]:
        raise MigrationError(f"{change['permission_arn']}: permission changed since approval "
                             f"{change['approval_id']}; re-run plan and approve again")


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
                 approved_changes: list[dict] | None = None,
                 migrating_owners: set[str] | None = None):
        for consumer in consumers:
            account_id(consumer)
        self.router, self.consumers, self.migration = router, consumers, migration
        self.overrides, self.capabilities = overrides, capabilities
        # Approvals come only from this migration's record; see ram_migration_record.
        self.approved_changes = list(approved_changes or [])
        self.migrating_owners = set(migrating_owners or ())

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
        body = cfn.get_template(StackName=stack["StackId"], TemplateStage="Processed")["TemplateBody"]
        template = yaml.load(body, Loader=CfnLoader) if isinstance(body, str) else body
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

    def inspect(self, owner: str, region: str) -> Plan:
        account_id(owner)
        plan = Plan(self.migration)
        ram = self.router.client(owner, "ram", region)
        try:
            shares = pages(ram, "get_resource_shares", "resourceShares", resourceOwner="SELF")
        except Exception as exc:
            plan.blocked.append(f"{owner}/{region}: {error_text(exc)}")
            return plan
        active_members: set[str] | None = None
        for share in shares:
            arn = share["resourceShareArn"]
            try:
                if share.get("owningAccountId") != owner:
                    raise MigrationError("Source share owner does not match the inspected account")
                # RAM keeps listing deleted shares for a while; DELETED is terminal and
                # grants nothing to replicate. DELETING/PENDING/FAILED still block below.
                if share.get("status") == "DELETED":
                    plan.excluded.append(f"{arn}: deleted share (status DELETED)")
                    continue
                if self._migration_owned(owner, region, share):
                    plan.existing.append(share)
                    continue
                if share["status"] != "ACTIVE":
                    raise MigrationError(f"source status {share['status']}")
                resources = pages(ram, "list_resources", "resources", resourceOwner="SELF",
                                  resourceShareArns=[arn])
                if not resources:
                    plan.excluded.append(f"{arn}: empty share")
                    continue
                associations = pages(ram, "get_resource_share_associations",
                                     "resourceShareAssociations", associationType="PRINCIPAL",
                                     resourceShareArns=[arn])
                observed = flatten([r["associatedEntity"] for r in associations])
                live = [r["associatedEntity"] for r in associations
                        if r["status"] in ("ASSOCIATED", "ASSOCIATING")]
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
                if not principals:
                    if explicit is not None:
                        plan.excluded.append(f"{arn}: explicitly approved empty consumer inventory")
                        continue
                    raise MigrationError("Original account-facing consumers are unresolved; "
                                         "provide a principal-map override")
                if all(SERVICE_PRINCIPAL.fullmatch(p) for p in principals):
                    plan.excluded.append(f"{arn}: service-principal-only share")
                    continue
                consumers: set[str] = set()
                for principal in principals:
                    consumers.update(self._expand(owner, principal, partition=ram.meta.partition))
                # Historical OU membership cannot be guessed after account departure.
                if explicit is None and any(":ou/" in p or ":organization/" in p for p in principals):
                    if active_members is None:
                        org, _ = self._org(owner)
                        active_members = {
                            a["Id"] for a in pages(org, "list_accounts", "Accounts")
                            if a.get("State", a.get("Status")) == "ACTIVE"}
                    direct = {
                        account for p in principals
                        if (account := direct_account_principal(p, ram.meta.partition)) is not None}
                    unresolved = self.consumers - active_members - direct - {owner}
                    if unresolved:
                        raise MigrationError("Provide principal-map override to resolve historical "
                                             f"organization/OU membership for {sorted(unresolved)}")
                    outside_scope = (self.consumers & active_members) - consumers - {owner}
                    if outside_scope:
                        plan.excluded.append(
                            f"{arn}: selected active source-organization consumers outside "
                            f"this principal scope: {sorted(outside_scope)}")
                unrelated = consumers - self.consumers - {owner}
                if unrelated and owner in self.migrating_owners:
                    # A stationary consumer of a migrating owner loses access when the owner
                    # leaves; bridging that direction is not supported (requirements §10).
                    raise MigrationError(
                        f"migrating owner {owner} shares with stationary consumers "
                        f"{sorted(unrelated)}; their access ends when the owner leaves its "
                        "organization and owner-migration continuity is not supported by this "
                        "tool version")
                if unrelated:
                    plan.excluded.append(
                        f"{arn}: unrelated consumers outside migration population: {sorted(unrelated)}")
                consumers &= self.consumers
                consumers.discard(owner)
                if not consumers:
                    plan.excluded.append(f"{arn}: no selected consumers")
                    continue
                permission_map: dict[str, str] = {}
                snapshots: dict[str, dict] = {}
                changes: list[dict] = []
                for permission in pages(ram, "list_resource_share_permissions", "permissions",
                                        resourceShareArn=arn):
                    default = permission_snapshot(ram, permission["arn"])
                    if not default["DefaultVersion"]:
                        raise MigrationError("GetPermission did not return the current default version")
                    kind = permission["resourceType"]
                    if kind in permission_map or default["ResourceType"] != kind:
                        raise MigrationError(f"{kind}: ambiguous managed permission mapping")
                    if not permission.get("version"):
                        raise MigrationError(f"{kind}: attached managed permission version missing")
                    if default["Version"] != permission["version"]:
                        prior = permission_snapshot(ram, permission["arn"], permission["version"])
                        if prior["ResourceType"] != kind:
                            raise MigrationError(f"Non-default permission type differs: {permission['arn']}")
                        if prior["Policy"] != default["Policy"]:
                            # AWS attaches only the current default version, so the temporary
                            # share cannot reproduce the original grant. Never pin or bypass:
                            # the difference needs an approval bound to this exact change.
                            change = permission_change(owner, region, arn, prior, default)
                            approval = approval_for(self.approved_changes, self.migration, change)
                            change["status"] = "APPROVED" if approval else "APPROVAL_REQUIRED"
                            if approval:
                                change["approval_id"] = approval["approval_id"]
                            changes.append(change)
                    permission_map[kind] = permission["arn"]
                    snapshots[kind] = default
                plan.permission_changes.extend(changes)
                pending = [c for c in changes if c["status"] == "APPROVAL_REQUIRED"]
                if pending:
                    raise MigrationError(
                        "Non-default permission differs from the current default and requires "
                        "approval: " + "; ".join(
                            f"{c['permission_arn']} v{c['from_version']}->v{c['to_version']} "
                            f"({', '.join(describe_difference(c['difference']))})" for c in pending)
                        + ". Record this plan with --record, review it, then run approve")
                available: dict[str, str] = {}
                for resource in resources:
                    resource_arn, kind = resource["arn"], resource["type"]
                    # Owner-side (SELF) listings omit status; an explicit non-AVAILABLE
                    # status still blocks.
                    if resource.get("status", "AVAILABLE") != "AVAILABLE":
                        raise MigrationError(f"{resource_arn}: resource status {resource.get('status')}")
                    if resource_arn.split(":")[4] != owner:
                        raise MigrationError(f"Cannot re-share resource owned by another account: {resource_arn}")
                    if self.capabilities.get(kind.lower()) is not True:
                        raise MigrationError(f"{kind}: unsupported or unverified external-sharing capability")
                    if kind not in permission_map:
                        raise MigrationError(f"{kind}: source managed permission missing")
                    available[resource_arn] = kind
                kinds = set(available.values())
                if set(permission_map) != kinds:
                    raise MigrationError("Source permissions do not exactly match its resource types")
                group = ApprovedGroup(owner, region, tuple(sorted(consumers)),
                                      permission_map, available, [arn], snapshots, source_stacks,
                                      permission_changes=[approved_change(c) for c in changes])
                prior_group = next((g for g in plan.groups if g.key == group.key), None)
                if prior_group is not None:
                    if prior_group.permission_snapshots != snapshots:
                        raise MigrationError("Permission approval changed during discovery")
                    prior_group.source_stacks = sorted(set(prior_group.source_stacks + source_stacks))
                    if any(a in prior_group.resources and prior_group.resources[a] != k
                           for a, k in available.items()):
                        raise MigrationError("Conflicting RAM types for the same source resource")
                plan.merge(Plan(self.migration, groups=[group]))
            except Exception as exc:
                plan.blocked.append(f"{arn}: {error_text(exc)}")
        return plan
