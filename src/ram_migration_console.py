"""Readable console view of a RAMShift run.

Every mode reports through a reporter that receives the technical event stream: one
key=value line per event. ``--raw-output`` prints exactly that stream, which scripts and
log parsers rely on. :class:`ReadableReporter` receives the same events and renders them
for people: a short header, concise progress lines while the run works, then sections
with aligned plain-text tables and a result block with the status in words, the key
counts, the record, the exit code and the next step.

Nothing that matters is hidden: every blocked, failed, incomplete, cancelled, lost,
inconclusive, overridden, not acceptable or warning event, every gap, loss and blocker,
every error text and the context of every confirmation is shown. Routine detail is
summarized (per-item observations, progress ticks, stack templates, per-resource
listings, verified sign-ins), and an event this module does not recognize is printed as
it is. The module uses the standard library only; a malformed line never raises, and the
reporter never changes what the run does or its exit code.
"""
from __future__ import annotations

import json
import re
import sys
import textwrap
import threading
from collections import Counter, OrderedDict, defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable

WIDTH = 100
RAW_HINT = "Run with --raw-output for the full technical event stream."
WRITING_MODES = ("approve", "apply", "verify", "complete")

# ---------------------------------------------------------------------------
# Event lines
# ---------------------------------------------------------------------------

_KEY = re.compile(r"([a-z][a-z0-9_-]*)=")
_JSON = json.JSONDecoder()
_BLOCKER_ID = re.compile(r"\s+blocker=(b-[0-9a-f]{12})$")
_ACCOUNT = re.compile(r"\b\d{12}\b")
_SUBJECT_KEYS = {"phase", "status", "account", "owner", "region", "share", "consumer",
                 "consumers", "logical_id", "resource", "migration"}


class Event:
    """One event line: the first value of each key=value field, the position after each
    field, and the words that are not fields. Values that start with a quote, bracket
    or brace are decoded as JSON when they are valid JSON; parsing never raises."""

    __slots__ = ("raw", "fields", "tokens", "_ends", "words")

    def __init__(self, raw: str):
        self.raw = raw
        self.fields: dict[str, Any] = {}
        self.tokens: list[tuple[str | None, int, int]] = []
        self._ends: dict[str, int] = {}
        self.words: list[str] = []
        position, size = 0, len(raw)
        while position < size:
            if raw[position] == " ":
                position += 1
                continue
            end = raw.find(" ", position)
            end = size if end < 0 else end
            match = _KEY.match(raw, position)
            if match is None or match.end() > end:
                self.words.append(raw[position:end])
                self.tokens.append((None, position, end))
                position = end
                continue
            start, value = match.end(), raw[match.end():end]
            if start < size and raw[start] in "\"[{":
                try:
                    decoded, stop = _JSON.raw_decode(raw, start)
                except (ValueError, RecursionError):
                    pass
                else:
                    if stop == size or raw[stop] == " ":
                        value, end = decoded, stop
            key = match.group(1)
            self.tokens.append((key, position, end))
            if key not in self.fields:
                self.fields[key] = value
                self._ends[key] = end
            position = end

    def get(self, key: str, default: Any = None) -> Any:
        return self.fields.get(key, default)

    def text(self, key: str, default: str = "") -> str:
        value = self.fields.get(key)
        if value is None:
            return default
        if isinstance(value, str):
            return value
        if isinstance(value, list):
            return ", ".join(str(item) for item in value)
        return json.dumps(value, sort_keys=True)

    @property
    def phase(self) -> str | None:
        value = self.fields.get("phase")
        return value if isinstance(value, str) else None

    @property
    def status(self) -> str | None:
        value = self.fields.get("status")
        return value if isinstance(value, str) else None

    def after(self, key: str) -> str:
        """The rest of the line after the first ``key=value`` field."""
        end = self._ends.get(key)
        return "" if end is None else self.raw[end:].strip()

    def message(self) -> str:
        """The text after the leading subject fields (phase, status, account, ...)."""
        end = 0
        for key, _start, stop in self.tokens:
            if key is None or key not in _SUBJECT_KEYS:
                break
            end = stop
        return self.raw[end:].strip()


def _int(value: Any) -> int | None:
    if isinstance(value, str) and re.fullmatch(r"[0-9]+", value):
        return int(value)
    return None


# ---------------------------------------------------------------------------
# Words
# ---------------------------------------------------------------------------

def plural(count: int, singular: str, many: str | None = None) -> str:
    return f"{count} {singular if count == 1 else (many or singular + 's')}"


TYPE_NAMES = {
    "route53resolver:resolverrule": ("Resolver rule", "Resolver rules"),
    "ec2:transitgateway": ("Transit Gateway", "Transit Gateways"),
    "ec2:ipampool": ("IPAM pool", "IPAM pools"),
    "acm-pca:certificateauthority": ("Private CA", "Private CAs"),
    "ec2:subnet": ("subnet", "subnets"),
    "ec2:prefixlist": ("prefix list", "prefix lists"),
    "route53resolver:firewallrulegroup": ("DNS Firewall rule group", "DNS Firewall rule groups"),
    "route53resolver:resolverqueryloggingconfig": ("Resolver query logging configuration",
                                                   "Resolver query logging configurations"),
    "ec2:transitgatewaymulticastdomain": ("TGW multicast domain", "TGW multicast domains"),
    "network-firewall:firewallpolicy": ("Network Firewall policy", "Network Firewall policies"),
}
KIND_NAMES = {
    "entitlement": ("access grant", "access grants"),
    "resolver_association": ("Resolver rule association", "Resolver rule associations"),
    "resolver_endpoint": ("Resolver endpoint", "Resolver endpoints"),
    "tgw_attachment": ("TGW attachment", "TGW attachments"),
    "tgw_route": ("TGW route", "TGW routes"),
    "ipam_allocation": ("IPAM allocation", "IPAM allocations"),
    "pca_access": ("Private CA access check", "Private CA access checks"),
    "pca_issuance_test": ("Private CA issuance test", "Private CA issuance tests"),
}


def type_label(kind: str, count: int) -> str:
    names = TYPE_NAMES.get(str(kind).lower())
    if names is None:
        return f"{count} {kind}"
    return f"{count} {names[0] if count == 1 else names[1]}"


def kind_label(kind: str, count: int) -> str:
    names = KIND_NAMES.get(str(kind))
    if names is None:
        return f"{count} {kind}"
    return f"{count} {names[0] if count == 1 else names[1]}"


def counted(counter: Counter, label=type_label) -> str:
    return ", ".join(label(kind, count) for kind, count in sorted(counter.items()))


def share_id(arn: Any) -> str:
    text = str(arn)
    return text.split("resource-share/", 1)[1] if "resource-share/" in text else text


def accounts_text(accounts: Iterable[str], limit: int = 3) -> str:
    accounts = [a for a in accounts if a]
    if len(accounts) > limit:
        return plural(len(accounts), "account")
    return ", ".join(accounts) or "none"


def _capital(text: str) -> str:
    return text[:1].upper() + text[1:] if text[:1].islower() else text


def _short(text: str, limit: int = 110) -> str:
    """One line for a heading, cut at a clause or word; the full text is shown as well."""
    text = " ".join(str(text).split())
    if len(text) <= limit:
        return text
    clause = text.rfind("; ", 0, limit - 3)
    cut = clause if clause > limit // 2 else text.rfind(" ", 0, limit - 3)
    return text[:cut if cut > limit // 3 else limit - 3].rstrip(" ,;:") + "..."


def wrap(text: str, indent: str = "  ", hang: str | None = None) -> list[str]:
    """Wrap at about WIDTH characters with a hanging indent; words, ARNs and error
    details are never broken or cut."""
    hang = indent + "  " if hang is None else hang
    lines = textwrap.wrap(str(text), width=WIDTH, initial_indent=indent, subsequent_indent=hang,
                          break_long_words=False, break_on_hyphens=False)
    return lines or [indent.rstrip()]


def table(headers: list[str], rows: list[list[Any]], indent: str = "  ") -> list[str]:
    cells = [[str(cell) for cell in row] for row in rows]
    widths = [max([len(header)] + [len(row[index]) for row in cells])
              for index, header in enumerate(headers)]
    lines = [indent + "  ".join(h.ljust(w) for h, w in zip(headers, widths)).rstrip(),
             indent + "  ".join("-" * w for w in widths)]
    lines += [indent + "  ".join(c.ljust(w) for c, w in zip(row, widths)).rstrip() for row in cells]
    return lines


# ---------------------------------------------------------------------------
# Blockers: categories, the same patterns as the run's blocker summary
# ---------------------------------------------------------------------------

# The run's own blocker categories (temporary_migration_ram_shares.BLOCKER_PATTERNS),
# repeated so this module needs nothing but the standard library; a test keeps the two
# identical. First match wins.
RECORDED_LOSS = ("the recorded baseline is never replaced - restore it or start a new "
                 "migration record")
BLOCKER_PATTERNS = (
    ("authentication", re.compile(
        r"phase=authentication|ExpiredToken|InvalidClientTokenId|UnrecognizedClientException"
        r"|security token included in the request is (?:expired|invalid)"
        r"|SSO (?:session|token|login)|token has expired|unable to locate credentials",
        re.IGNORECASE)),
    ("organization-policy-unreadable", re.compile(
        r"phase=(?:org-policy|ram-org-prerequisites) status=BLOCKED decision=UNREADABLE ")),
    ("organization-policy-gap", re.compile(r"phase=org-policy status=GAP ")),
    ("organization-policy-deny", re.compile(
        r"phase=org-policy status=BLOCKED decision=(?:EXPLICIT_DENY|NO_ALLOW) ")),
    ("ram-organization-prerequisites", re.compile(r"phase=ram-org-prerequisites ")),
    ("region-scope", re.compile(
        r"phase=(?:regions|received-regions) |Region is outside the selected discovery scope"
        r"|outside the explicit owner/Region scope")),
    ("baseline-loss", re.compile(r"phase=baseline status=BLOCKED original .*"
                                 + re.escape(RECORDED_LOSS))),
    ("baseline-scope", re.compile(r"phase=baseline-scope ")),
    ("baseline-capture", re.compile(r"phase=baseline ")),
    ("owner-outside-approved-scope", re.compile(r"phase=owner-scope ")),
    ("reviewed-record-mismatch", re.compile(
        r"phase=reviewed-record |plan changed; run plan/apply")),
    ("policy-created-share", re.compile(r"featureSet (?:CREATED_FROM_POLICY|PROMOTING_TO_STANDARD):")),
    ("ram-share-quota", re.compile(r"AWS RAM allows at most \d+ \w+ associations per resource share")),
    ("region-denied-by-policy", re.compile(
        r"phase=(?:received-audit|discovery|owned-audit)\b.*with an explicit deny in a "
        r"(?:service|resource) control policy")),
    ("discovery-api-error", re.compile(r"operation=\w+|\(request [^)]*\)")),
    ("received-dependency-not-covered", re.compile(r"not covered by any planned temporary share")),
    ("configuration", re.compile(
        r"external-sharing capability|provide (?:a )?principal-map override", re.IGNORECASE)),
)
CATEGORY_TITLES = {
    "owner-outside-approved-scope": "Owner outside the approved owner scope",
    "received-dependency-not-covered": "Received access not covered by the plan",
    "configuration": "Configuration needed",
    "organization-policy-deny": "Denied by an organization policy",
    "organization-policy-gap": "Organization policy cannot be decided",
    "organization-policy-unreadable": "Organization policies could not be read",
    "ram-organization-prerequisites": "RAM organization prerequisites",
    "authentication": "Account access",
    "region-scope": "Region scope",
    "region-denied-by-policy": "Reads denied by an organization policy",
    "discovery-api-error": "AWS API errors",
    "baseline-loss": "Loss against the recorded baseline",
    "baseline-capture": "Baseline cannot be captured",
    "baseline-scope": "Outside the recorded baseline",
    "reviewed-record-mismatch": "Run does not match the reviewed record",
    "policy-created-share": "Shares created from a resource policy",
    "ram-share-quota": "AWS RAM share quota",
    "other": "Other",
}
COUNT_NAMES = {"owners": "owner", "shares": "share", "resources": "resource",
               "observations": "observation", "accounts": "account", "consumers": "consumer",
               "policies": ("policy", "policies"), "organizations": "organization"}


def blocker_category(text: str) -> str:
    return next((name for name, pattern in BLOCKER_PATTERNS if pattern.search(text)), "other")


# ---------------------------------------------------------------------------
# One plain line for a technical text
# ---------------------------------------------------------------------------

_SHARE_SUBJECT = re.compile(r"^(arn:[\w-]+:ram:[\w-]*:\d{12}:resource-share/[\w.-]+): (.*)$")
_STACK_SUBJECT = re.compile(r"^(\d{12})/([a-z0-9-]+)(?:/(\S+))?: (.*)$")
_OWNER_SCOPE = re.compile(
    r"owner (\d{12}) is outside the approved owner scope but provides (\d+) unique received "
    r"resources \(([^)]*)\) through (\d+) shares in (\S+) to migrating accounts (\S+)")
PHASE_SUBJECTS = {
    "discovery": "Inspecting owner {owner} in {region} failed",
    "stack-preflight": "Checking the migration stack of owner {owner} in {region} failed",
    "stored-plan": "Reading the migration stack of owner {owner} in {region} failed",
    "received-provenance": "Proving the temporary shares of owner {owner} in {region} failed",
    "regions": "Reading the enabled Regions of owner {owner} failed",
    "received-regions": "Reading the enabled Regions of account {account} failed",
    "owned-audit": "Reading the shares that account {account} owns in {region} failed",
    "organization": "Reading the organization of account {account} failed",
    "creation": "Creating the migration stack of owner {owner} in {region} failed",
    "share-readback": "Reading back the temporary shares of owner {owner} in {region} failed",
    "acceptance": "Accepting the invitations of account {consumer} in {region} failed",
    "verification": "Verifying temporary share {share_id} of owner {owner} in {region} failed",
    "authentication": "Account {account} could not be authenticated",
    "invitation-accounting": "Counting the accepted invitations of {consumer} in {region} failed",
    "interrupted-readback": "Reading back the shares of owner {owner} in {region} failed",
}
SUBJECT_WORDS = (("account", "account"), ("consumer", "account"), ("owner", "owner"),
                 ("region", "Region"), ("share", "share"), ("resource", "resource"),
                 ("logical_id", "logical ID"))


def _subject(event: Event) -> str:
    """The subject fields of a line in words, for a line no template describes."""
    parts = []
    for key, word in SUBJECT_WORDS:
        if event.get(key):
            value = event.text(key).rstrip(":")
            parts.append(f"{word} {share_id(value) if key == 'share' else value}")
    return ", ".join(parts)


def _org_policy_text(event: Event) -> str:
    decision = event.get("decision")
    account, role = event.get("account"), event.text("role") or event.text("roles")
    if account:
        who = f"account {account}" + (f" ({role})" if role else "")
    elif event.get("destination"):
        who = f"the destination {event.text('destination')}"
    else:
        who = f"the {role or 'evaluated'} path"
    kind = event.text("policy_type", "policy")
    actions = event.text("actions").replace(",", ", ") or "the migration's requests"
    policy = event.text("policy")
    name = event.text("policy_name")
    named = f"{kind} {policy}" + (f" ({name})" if name else "") if policy else kind
    detail = event.raw.split(": ", 1)[1] if ": " in event.raw else ""
    if decision == "EXPLICIT_DENY":
        return f"{named} denies {actions} for {who}"
    if decision == "NO_ALLOW":
        return f"No {kind} attached at {event.text('target')} allows {actions} for {who}"
    if decision == "UNREADABLE":
        return f"The organization policies of {who} could not be read: {detail}"
    if event.get("targets_without_policies"):
        return (f"Whether {kind}s are enforced on the path of {who} cannot be decided: "
                f"targets {event.text('targets_without_policies')} have none attached")
    return f"Whether {named} denies {actions} for {who} cannot be decided: {detail}"


def describe(text: str) -> str:
    """A plain sentence for a blocker, warning, problem or reason. The error details it
    carries are kept whole."""
    text = str(text).strip()
    prefix = ""
    if text.startswith("post-confirmation "):
        prefix, text = "After the confirmation: ", text[len("post-confirmation "):]
    event = Event(text)
    phase = event.phase
    if phase == "org-policy" and event.get("decision"):
        return prefix + _org_policy_text(event)
    if phase == "ram-org-prerequisites":
        organization, manager = event.text("organization"), event.text("management_account")
        detail = text.split(": ", 1)[1] if ": " in text else event.message()
        who = f"Organization {organization}" + (f" (management account {manager})" if manager else "")
        return prefix + f"{who}: {detail}"
    if phase == "owner-scope":
        match = _OWNER_SCOPE.search(text)
        if match:
            owner, count, types, shares, regions, consumers = match.groups()
            return prefix + (f"Owner {owner} is outside the approved owner scope; it provides "
                             f"{plural(int(count), 'received resource')} ({types}) through "
                             f"{plural(int(shares), 'share')} in {regions.replace(',', ', ')} to "
                             f"{consumers.replace(',', ', ')}")
    match = _SHARE_SUBJECT.match(text)
    if match:
        arn, rest = match.groups()
        inner = Event(rest)
        owner, region = inner.text("owner"), inner.text("region")
        where = f" of owner {owner}" if owner else ""
        where += f" in {region}" if region else ""
        detail = inner.message() if (owner or region) else rest
        return prefix + f"Share {share_id(arn)}{where}: {detail}"
    if phase == "received-audit":
        subject = f"Share {share_id(event.text('share'))} that account {event.text('account')} receives"
        if event.get("owner"):
            subject += f" from {event.text('owner')}"
        if event.get("region"):
            subject += f" in {event.text('region')}"
        if event.get("resource"):
            subject += f" (resource {event.text('resource')})"
        return prefix + f"{subject}: {event.message()}"
    message = event.message()
    if phase == "record":
        if event.status == "NOT_RECORDED":
            return prefix + f"The migration record could not be updated: {message}"
        if event.get("owner"):
            return prefix + f"Owner {event.text('owner')} in {event.text('region')}: {message}"
        return prefix + _capital(message)
    if phase == "complete" and (event.get("share") or event.get("owner")):
        if event.get("share"):
            return prefix + f"Temporary share {share_id(event.text('share'))}: {message}"
        return prefix + (f"Deleting the migration stack of owner {event.text('owner')} in "
                         f"{event.text('region')} failed: {message}")
    template = PHASE_SUBJECTS.get(phase or "")
    if template is not None and not (phase == "verification" and not event.get("share")):
        values = defaultdict(lambda: "?", {key: event.text(key) for key in event.fields})
        values["share_id"] = share_id(event.text("share", "?"))
        return prefix + template.format_map(values) + (f": {message}" if message else "")
    match = _STACK_SUBJECT.match(text)
    if match:
        owner, region, _key, rest = match.groups()
        return prefix + f"Owner {owner} in {region}: {rest}"
    subject = _subject(event)
    if subject and message != text:
        return prefix + f"{_capital(subject)}: {message}"
    return prefix + _capital(message or text)


def _reason(text: str) -> str:
    """A status reason: a plain sentence stays as the run wrote it."""
    return describe(text) if _KEY.search(text) else text


# Exclusions: one short line per reason, counted.
_EXCLUSIONS = (
    (re.compile(r"^deleted share"), "deleted shares (status DELETED)"),
    (re.compile(r"^service-principal-only share"), "shared only with AWS service principals"),
    (re.compile(r"^orphan CREATED_FROM_POLICY private CA share"),
     "Private CA shares created from a policy whose CAs no longer exist"),
    (re.compile(r"^source status (\w+)"),
     lambda m: f"source share is {m[1]} and grants no access now"),
    (re.compile(r"^empty share"), "empty shares"),
    (re.compile(r"^owner \d{12} is listed as a principal of its own share"),
     "the owner is listed as a principal of its own share and is never its own consumer"),
    (re.compile(r"^recovered external access"),
     "the account already has this access outside its organization (no temporary share needed)"),
    (re.compile(r"^explicitly approved empty consumer inventory"),
     "explicitly approved empty consumer list (--principal-map)"),
    (re.compile(r"^selected active source-organization consumers outside this principal scope"),
     lambda m: "selected accounts are outside this share's principals: " + _ids(m.string)),
    (re.compile(r"^recipient accounts .* explicitly excluded by operator"),
     lambda m: "recipients excluded by the operator: " + _ids(m.string)),
    (re.compile(r"^stationary consumers .* already hold ASSOCIATED external"),
     lambda m: "stationary consumers already have external access: " + _ids(m.string)),
    (re.compile(r"^unrelated consumers outside migration population"),
     lambda m: "recipients outside this migration are left out: " + _ids(m.string)),
    (re.compile(r"^no selected consumers"), "no migrating account receives it"),
    (re.compile(r"^resource \S+ status (\w+)"),
     lambda m: f"a resource is {m[1]} and not available through the share now"),
    (re.compile(r"^no resource is available through this share now"),
     "no resource is available through the share now"),
    (re.compile(r"^nonactive received share status (\w+)"),
     lambda m: f"received share is {m[1]} and grants no access now"),
    (re.compile(r"^empty active received share"), "received shares without resources"),
    (re.compile(r"^current migration share proven"), "this migration's own temporary shares"),
    (re.compile(r"^received resource status (\w+)"),
     lambda m: f"received resource is {m[1]}; the account has no access to it now"),
)


def _ids(text: str) -> str:
    return ", ".join(dict.fromkeys(_ACCOUNT.findall(text))) or "none named"


def exclusion_reason(text: str) -> str:
    event = Event(text)
    body = text
    if event.status == "EXCLUDED" and event.phase:
        body = event.after("status")
    else:
        match = re.match(r"^(arn:\S+?): (.*)$", text)
        if match:
            body = match.group(2)
    for pattern, short in _EXCLUSIONS:
        match = pattern.search(body)
        if match:
            return short(match) if callable(short) else short
    return _short(body.split("; ", 1)[0], 100)


# ---------------------------------------------------------------------------
# Status words and next steps
# ---------------------------------------------------------------------------

STATUS_WORDS = {
    "plan": {
        "PLANNED": "the plan is ready for review; nothing was written to AWS",
        "BLOCKED": "the plan cannot be applied until each blocker above is resolved or accepted",
    },
    "apply": {
        "SHARING_READY": "the temporary shares are in place, accepted and verified",
        "INCOMPLETE": "some steps failed; the temporary shares that succeeded are kept",
        "BLOCKED": "nothing was written to AWS; the blockers above stop apply",
        "CANCELLED": "the confirmation did not match; nothing was written to AWS",
    },
    "verify": {
        "MIGRATION_VALIDATED": "every migrating account has left its baseline organization and "
                               "nothing in the baseline was lost",
        "PENDING_MIGRATION": "the temporary shares work; at least one account is still in its "
                             "baseline organization",
        "INCONCLUSIVE": "some checks could not be completed, so nothing is assumed",
        "FAILED": "access recorded in the baseline was lost, or a failure was recorded earlier",
        "SHARING_INCOMPLETE": "at least one temporary share failed verification",
        "BLOCKED": "verification could not run; the blockers above must be resolved",
        "INCOMPLETE": "no temporary shares were found to verify in the recorded scope",
        "ALREADY_COMPLETE": "the migration is complete; no temporary shares remain to verify",
    },
    "complete": {
        "COMPLETED": "the temporary access of every tracked account is retired; the migration "
                     "is complete",
        "PARTIALLY_COMPLETED": "the chosen accounts' temporary access is retired; other accounts "
                               "still use theirs",
        "NOTHING_TO_RETIRE": "the chosen accounts have no temporary access left to retire",
        "ALREADY_COMPLETE": "the migration was already completed",
        "BLOCKED": "nothing was retired; the checks above failed",
        "FAILED": "completion stopped after a failure; the remaining temporary access is kept",
        "INTERRUPTED": "completion was interrupted; the remaining temporary access is kept",
        "CANCELLED": "the confirmation did not match; nothing was changed",
    },
    "monitor": {
        "UNCHANGED": "No changes detected in the monitored baseline.",
        "CHANGED": "Changes detected; the monitored baseline remains intact.",
        "LOSS": "Baseline items were lost or degraded.",
        "INCONCLUSIVE": "Some checks could not be completed.",
    },
    "approve": {
        "NOTHING_PENDING": "nothing in this record is waiting for approval",
        "APPROVED": "the proposed owners are approved for this migration's owner scope",
        "NOT_APPROVED": "the confirmation did not match; nothing was approved",
        "ACCEPTED": "the blockers above are accepted and recorded with their consequences",
        "NOT_ACCEPTED": "the confirmation did not match; nothing was accepted",
        "NOTHING_ACCEPTED": "no acceptable blocker was chosen; nothing was accepted",
    },
}
SHARING_WORDS = {"SHARING_READY": "every temporary share is in place and verified",
                 "SHARING_INCOMPLETE": "at least one temporary share failed verification"}
NEXT_STEPS = {
    ("plan", "PLANNED"): "Review this plan. Before any account moves, run apply with the same "
                         "--record and options to create the temporary shares.",
    ("plan", "BLOCKED"): "Resolve or accept each blocker (the next step is under each "
                         "category), then re-run plan with --record.",
    ("apply", "SHARING_READY"): "Run verify with the same --record (expect sharing ready and "
                                "migration pending), then move the accounts and run monitor "
                                "after each step.",
    ("apply", "INCOMPLETE"): "Resolve the failures listed above, then re-run apply with the same "
                             "--record; it resumes from the shares already recorded.",
    ("apply", "BLOCKED"): "Resolve or accept each blocker (the next step is under each "
                          "category), then re-run apply with the same --record.",
    ("apply", "CANCELLED"): "Re-run apply and type the confirmation exactly as shown to create "
                            "the temporary shares.",
    ("verify", "PENDING_MIGRATION"): "Move the accounts (outside RAMShift) and run monitor after "
                                     "each step; run verify again after the move.",
    ("verify", "MIGRATION_VALIDATED"): "Set up permanent sharing in the destination "
                                       "organization, then run complete to retire the "
                                       "temporary access.",
    ("verify", "INCONCLUSIVE"): "Resolve the read gaps and unknown items listed above, then "
                                "re-run verify with the same --record.",
    ("verify", "FAILED"): "Restore the lost access listed above. A recorded loss stays in this "
                          "record, so complete refuses it and a new migration record is needed.",
    ("verify", "SHARING_INCOMPLETE"): "Resolve the share failures listed above (apply with the "
                                      "same --record resumes an interrupted apply), then re-run "
                                      "verify.",
    ("verify", "BLOCKED"): "Resolve each blocker listed above, then re-run verify with the same "
                           "--record.",
    ("verify", "INCOMPLETE"): "No temporary shares remain in the recorded scope; if every "
                              "account is retired, run monitor to compare with the baseline.",
    ("verify", "ALREADY_COMPLETE"): "Run monitor to compare current access with the "
                                    "pre-migration baseline.",
    ("complete", "COMPLETED"): "Nothing temporary remains. Run monitor to compare current "
                               "access with the pre-migration baseline.",
    ("complete", "ALREADY_COMPLETE"): "Nothing to do. Run monitor to compare current access "
                                      "with the pre-migration baseline.",
    ("complete", "BLOCKED"): "Resolve the failed checks listed above, then re-run complete with "
                             "the same --record.",
    ("complete", "FAILED"): "Resolve the failure listed above, then re-run complete with the "
                            "same --record; it continues with the remaining temporary access.",
    ("complete", "INTERRUPTED"): "Re-run complete with the same --record; it continues with the "
                                 "remaining temporary access.",
    ("complete", "CANCELLED"): "Re-run complete and type the confirmation exactly as shown to "
                               "retire the temporary access.",
    ("monitor", None): "One snapshot completed. Run the command again for another snapshot.",
    ("approve", "NOTHING_PENDING"): "Nothing to approve; continue with apply once the recorded "
                                    "plan is PLANNED.",
    ("approve", "NOT_APPROVED"): "Re-run approve and type the confirmation exactly as shown.",
    ("approve", "NOT_ACCEPTED"): "Re-run approve and type the confirmation exactly as shown.",
    ("approve", "NOTHING_ACCEPTED"): "Resolve the blockers that cannot be accepted (each says "
                                     "why), then re-run plan with --record.",
}
EXIT_CODES = {
    "plan": {"PLANNED": 0},
    "apply": {"SHARING_READY": 0, "CANCELLED": 2},
    "verify": {"MIGRATION_VALIDATED": 0, "PENDING_MIGRATION": 0, "ALREADY_COMPLETE": 0,
               "INCONCLUSIVE": 3},
    "complete": {"COMPLETED": 0, "PARTIALLY_COMPLETED": 0, "NOTHING_TO_RETIRE": 0,
                 "ALREADY_COMPLETE": 0, "CANCELLED": 2, "INTERRUPTED": 130},
    "approve": {"NOTHING_PENDING": 0, "APPROVED": 0, "ACCEPTED": 0, "NOT_APPROVED": 2,
                "NOT_ACCEPTED": 2},
}
RECEIVED_WORDS = {
    "OWNER_INCLUDED": "from owners in scope",
    "CURRENT_MIGRATION": "this migration's temporary shares",
    "RECOVERED_EXTERNAL": "already shared outside the organization",
    "EXCLUDED": "excluded",
    "OUTSIDE_OWNER_SCOPE": "from owners outside the approved scope",
    "NOT_COVERED": "not covered by the plan",
    "BLOCKED": "blocked",
}
ATTENTION = ("OUTSIDE_OWNER_SCOPE", "NOT_COVERED", "BLOCKED")
ORG_STATUS = {"EVALUATED": "evaluated", "STANDALONE": "no organization",
              "MANAGEMENT_ACCOUNT": "management account", "UNREADABLE": "UNREADABLE"}
OBSERVATIONS = {
    "baseline-preflight": ("Recording the current state of {n} before any change...",
                           "Current state before any change"),
    "baseline": ("Checking the current state right before the first write ({n})...",
                 "Current state right before the first write"),
    "post-apply": ("Checking access after apply ({n})...", "Access after apply"),
    "verification": ("Comparing current access with the baseline ({n})...", "Current access"),
    "monitor": ("Checking baseline access and existing resource bindings...", "Current access"),
    "complete-preflight": ("Checking current access before retiring ({n})...",
                           "Current access before retiring"),
    "complete-final": ("Final check of the retired access ({n})...", "Final check"),
}
STAGES = {
    "prepare": "Preparing {tasks} migration stack template{s}...",
    "prepare-recheck": "Re-checking {tasks} migration stack template{s} after the confirmation...",
}
MONITOR_COUNTS = ("original_share_drops", "shares_added", "lost", "degraded", "added", "unobserved")
CHANGE_LABELS = {"ORIGINAL_SHARE_DROPPED": "Original share access removed",
                 "SHARE_ADDED": "Shared access added", "LOST": "Lost", "DEGRADED": "Degraded",
                 "ADDED": "Added", "UNOBSERVED": "Could not observe"}
DETAIL_LIMIT = 10  # access-change groups shown one per line before they are counted
PLAIN = {
    "TGW route health and network reachability are outside this verification scope.": "route-note",
    "Sharing status is not live migration acceptance evidence. Resource totals cover planned "
    "entitlements; excluded inventory is reported separately.": "disclaimer",
    "Resolver rules without an association had none before migration; no association repair "
    "was performed.": "resolver-note",
    "Successful temporary shares are retained. Resume this migration ID after resolving "
    "failures.": "retained",
    "For unmapped accounts, supply explicit --sso-role or an "
    "--account-map/--profile-map/--role-map.": "hint",
    "Re-run plan with --record to produce a PLANNED revision for review before apply.": "next",
}


def _is_observation(phase: str | None) -> bool:
    return bool(phase) and (phase in OBSERVATIONS or phase.startswith("complete-settle-"))


def _observation_label(phase: str) -> str:
    if phase.startswith("complete-settle-"):
        return f"Re-verification after action {phase.rsplit('-', 1)[-1]}"
    return OBSERVATIONS.get(phase, (None, phase))[1]


# ---------------------------------------------------------------------------
# The reporter
# ---------------------------------------------------------------------------

_APPROVE_OWN = re.compile(r"^blocker=(b-[0-9a-f]{12}|\S+) phase=approve(?: status=(\w+))?(?= |$)")
_CHECK_REPLACEMENT = re.compile(r"^phase=replacement consumer=(\S+) region=(\S+) resource=(\S+): "
                                r"only the temporary share provides access")


class ReadableReporter:
    """Reporter for people. emit() may be called from worker threads, flush() right before
    a confirmation prompt and close() once when the run ends. Progress lines print as the
    run works; sections print at flush() and close()."""

    lock = threading.Lock()  # one console for every reporter and worker thread

    def __init__(self, mode: str, args: Any = None, stream: Any = None):
        self.mode = mode or "plan"
        self.args = args
        self.context: Any = None
        self.exit_code: int | None = None  # the run's exit code, when the run sets it
        self._stream = stream
        self._closed = False
        self._header_done = False
        self._loose = False
        self._prompted = False
        self._absorbed = 0
        self._summarized = 0
        self._retained: list[str] = []
        self._parent: tuple[str, Any] | None = None
        # header
        self._migration: str | None = None
        self._route_reason: str | None = None
        self._recipients: tuple[str, str] | None = None
        self._excluded_regions: tuple[str, str] | None = None
        # progress
        self._auth = 0
        self._stage: dict | None = None
        self._stages_seen: set[str] = set()
        self._scope: dict[str, list[str]] = {}
        self._announced: set[str] = set()
        self._read_gaps: dict[str, dict[str, int]] = defaultdict(dict)
        # plan and apply
        self._accounts_done = False
        self._groups: list[dict] = []
        self._stack_actions: dict[tuple[str, str], str] = {}
        self._existing: list[str] = []
        self._exclusions: list[str] = []
        self._notes: list[str] = []
        self._warnings: list[str] = []
        self._permissions: list[dict] = []
        self._accepted: list[dict] = []
        self._blockers: list[dict] = []
        self._hints: dict[str, dict] = {}
        self._categories: "OrderedDict[str, Event]" = OrderedDict()
        self._received: dict[str, Any] = {"totals": None, "status": Counter(), "attention": [],
                                          "types": Counter(), "owned": Counter(),
                                          "not_enabled": defaultdict(list)}
        self._received_done = False
        self._detected: dict[str, Event] = {}
        self._stationary: list[str] = []
        self._approved_owners: list[str] = []
        self._org: dict = self._new_org()
        self._org_evaluations: list[dict] = []
        self._observations: "OrderedDict[str, dict]" = OrderedDict()
        # apply and verify
        self._captured = False
        self._shares: "OrderedDict[str, dict]" = OrderedDict()
        self._drops: list[Event] = []
        self._unassociated: list[Event] = []
        self._losses: list[tuple[str, str, str]] = []
        self._reasons: list[tuple[str, str]] = []
        self._problems: list[tuple[str, str]] = []
        self._retired: list[tuple[str, str]] = []
        self._retired_done = False
        self._caveats: list[str] = []
        self._result_notes: list[str] = []
        self._hint: str | None = None
        self._summary: Event | None = None
        self._result: tuple[str, Event] | None = None
        self._revision: str | None = None
        self._exported: str | None = None
        self._next_sentence: str | None = None
        # complete
        self._checks: list[str] = []
        self._not_overridden: str | None = None
        self._overridden: list[str] = []
        self._actions: list[Event] = []
        self._covered: Counter = Counter()
        # monitor
        self._monitor_start: Event | None = None
        self._monitor_orgs: dict[str, Event] = {}
        self._monitor_changes: list[Event] = []
        self._monitor_counts: dict[str, dict[str, int]] = {}
        self._monitor_reasons: list[str] = []
        self._monitor_final: Event | None = None
        # approve
        self._proposal: dict | None = None
        self._to_accept: list[Event] = []
        self._refused: list[Event] = []
        self._refused_count = 0
        self._already_accepted: list[str] = []
        self._accepted_now: list[str] = []
        self._approve_status: str | None = None

    # -- public interface -------------------------------------------------------

    def emit(self, message: str) -> None:
        with self.lock:
            text = str(message)
            try:
                if self._closed or not self._absorb(Event(text)):
                    self._say(text, header=False)  # exactly as received
                    return
                self._absorbed += 1
                self._retained.append(text)
            except Exception:  # presentation never changes the run: show the line as it is
                self._say(text, header=False)

    def flush(self) -> None:
        """Everything a confirmation covers is on screen before its prompt."""
        with self.lock:
            if not self._closed:
                self._safely(final=False)
            self._prompted = self._prompted or bool(self._absorbed)  # a confirmation, not an input

    def close(self) -> None:
        with self.lock:
            if self._closed:
                return
            self._closed = True
            self._safely(final=True)

    def _safely(self, final: bool) -> None:
        try:
            self._render(final)
        except Exception:  # presentation never changes the run: show the events as received
            retained, self._retained = self._retained, []
            self._write(retained)

    # -- output -----------------------------------------------------------------

    def _write(self, lines: Iterable[str]) -> None:
        stream = self._stream if self._stream is not None else sys.stdout
        try:
            for line in lines:
                print(line, file=stream)
            stream.flush()
        except (OSError, ValueError):  # a closed or broken console never stops the run
            pass

    def _say(self, line: str, header: bool = True) -> None:
        if header:
            self._header()
        self._write([line])
        self._loose = True  # a section that follows starts after a blank line

    def _progress(self, line: str) -> None:
        self._end_auth()
        self._say(line)

    def _header(self) -> None:
        if not self._header_done:
            self._header_done = True
            self._write(self._header_lines())

    def _header_lines(self) -> list[str]:
        context, args = self.context, self.args
        record = getattr(args, "record", None)
        migration = self._migration or getattr(args, "migration_id", None) or \
            self._recorded("migration_id")
        title = f"RAMShift {self.mode}"
        if migration:
            title += f" - migration {migration}"
        elif record:
            title += f" - record {record}"
        lines = [title]
        start = self._monitor_start
        if self.mode == "monitor" and start is not None:
            lines.append(f"Accounts: {len([a for a in start.text('consumers').split(',') if a])}")
        regions = list(getattr(context, "regions", None) or [])
        if regions and self.mode != "approve":
            line = "Regions: " + ", ".join(regions)
            if self.mode in ("plan", "apply") and getattr(args, "scan_enabled_regions", False):
                line += ", plus every Region enabled in each owner account"
            lines += wrap(line, "", "  ")
        if self.mode == "monitor" and start is not None:
            baseline = start.text("baseline_captured_at", "None")
            try:
                baseline = datetime.fromisoformat(baseline).isoformat(
                    sep=" ", timespec="seconds").replace("+00:00", " UTC")
            except ValueError:
                pass
            lines.append("Baseline: " + ("not recorded" if baseline == "None" else baseline))
        excluded = self._excluded_regions
        if excluded is None and getattr(context, "excluded_regions", None):
            excluded = (", ".join(context.excluded_regions),
                        str(getattr(context, "exclusion_reason", "")))
        if excluded:
            lines += wrap(f"Excluded Regions: {excluded[0]} (reason: {excluded[1]})", "", "  ")
        recipients = self._recipients
        if recipients is None and getattr(context, "excluded_consumers", None):
            recipients = (", ".join(context.excluded_consumers),
                          str(getattr(context, "consumer_exclusion_reason", "")))
        if recipients:
            lines += wrap(f"Excluded recipients: {recipients[0]} (reason: {recipients[1]})", "", "  ")
        route = self._route_reason or getattr(context, "tgw_route_exclusion_reason", None)
        if route:
            lines += wrap(f"TGW route checks excluded: {route}", "", "  ")
            lines.append("  Route health and network reachability are outside this check.")
        lines.append("")
        return lines

    # -- events -----------------------------------------------------------------

    def _absorb(self, event: Event) -> bool:
        raw = event.raw
        if raw.startswith("  "):
            return self._indented(event)
        self._parent = None
        if raw in PLAIN:
            return self._plain(PLAIN[raw])
        if raw.startswith("Regions ") and "were excluded by the operator" in raw:
            self._caveats.append(raw)
            return True
        if raw.startswith("Re-run plan with --record: accepted blockers"):
            self._next_sentence = raw
            return True
        if raw.startswith("Completion stopped; "):
            self._result_notes.append(raw)
            return True
        phase, status = event.phase, event.status
        if phase == "authentication" and status == "VERIFIED" and not raw.startswith("status="):
            self._auth += 1
            self._summarized += 1
            return True
        if phase != "progress":
            self._end_auth()
        if raw.startswith("status="):
            if "resources_in_plan" in event.fields:
                self._summary = event
                self._result = ("summary", event)
                self._absorb_exclusions(event)
                return True
            if phase == "monitor":
                return self._monitor_event(event)
            if phase == "verification" and status == "ALREADY_COMPLETE":
                self._migration = self._migration or event.text("migration") or None
                self._result = ("verify-complete", event)
                return True
            return self._status_event(event)
        if phase == "baseline" and status == "CAPTURED":
            return self._baseline_event(event)
        if phase == "verification" and self._verification_event(event):
            return True
        handler = {
            "progress": self._progress_event, "recipient-scope": self._header_event,
            "verification-scope": self._header_event, "scope": self._scope_event,
            "discovery": self._discovery_event, "received-regions": self._received_regions,
            "owned-audit": self._owned_event, "received-audit": self._received_event,
            "received-inventory": self._inventory_event,
            "owner-continuity": self._continuity_event, "owner-scope": self._owner_scope_event,
            "plan": self._plan_event, "preflight": self._preflight_event,
            "permission-change": self._permission_event, "org-policy": self._org_event,
            "ram-org-prerequisites": self._prerequisite_event,
            "accept-hint": self._hint_event, "blocker-summary": self._category_event,
            "write-gate": self._gate_event, "record": self._record_event,
            "creation": self._creation_event, "acceptance": self._acceptance_event,
            "invitation-accounting": self._problem_event,
            "interrupted-readback": self._problem_event,
            "monitor": self._monitor_event, "complete": self._complete_event,
            "replacement": self._replacement_event, "approve": self._approve_event,
        }.get(phase or "")
        if handler is not None and handler(event):
            return True
        if _is_observation(phase) and self._observation_event(event):
            return True
        if event.get("group") and event.get("stack") and "external_principals" in event.fields:
            return self._group_event(event)
        return False

    def _plain(self, kind: str) -> bool:
        if kind == "disclaimer":
            self._summarized += 1
        elif kind == "retained":
            self._result_notes.append("Successful temporary shares are retained; resume this "
                                      "migration ID after resolving the failures.")
        elif kind == "hint":
            self._hint = ("For unmapped accounts, supply an explicit --sso-role or an "
                          "--account-map, --profile-map or --role-map entry.")
        elif kind == "next":
            self._next_sentence = ("Re-run plan with --record to produce a PLANNED revision for "
                                   "review before apply.")
        return True  # route-note and resolver-note are part of their sections

    def _indented(self, event: Event) -> bool:
        if self._parent is None:
            return False
        kind, target = self._parent
        text = event.raw.strip()
        if kind == "group":
            if event.get("resource") and event.get("type"):
                target["types"][event.text("type")] += 1
                self._summarized += 1
                return True
            if event.get("source_shares") is not None:
                target["sources"] = len([s for s in event.text("source_shares").split(",") if s])
                self._summarized += 1
                return True
            return False
        if kind == "received":
            if event.get("resource") and event.get("type"):
                self._received["types"][event.text("type")] += 1
                self._summarized += 1
                return True
            return False
        if kind == "permission":
            if text.startswith("share="):
                target["shares"].append(event.text("share"))
                if "applies_to=" in text:
                    target["applies"].add(text.split("applies_to=", 1)[1])
            else:
                target["lines"].append(text)
            return True
        if kind == "proposal":
            (target["owners"] if text.startswith("owner=") else target["notes"]).append(
                event if text.startswith("owner=") else text)
            return True
        return False

    def _end_auth(self) -> None:
        if self._auth:
            count, self._auth = self._auth, 0
            more = " more" if "auth" in self._announced else ""
            self._announced.add("auth")
            self._say(f"Checking account access... {count}{more} "
                      f"account{'' if count == 1 else 's'} verified")

    def _header_event(self, event: Event) -> bool:
        if event.status != "EXCLUDED":
            return False
        if event.phase == "verification-scope":
            self._route_reason = event.text("reason")
        else:
            self._recipients = (event.text("accounts").replace(",", ", "), event.text("reason"))
        return True

    def _absorb_exclusions(self, event: Event) -> None:
        if event.get("excluded_regions") and self._excluded_regions is None:
            self._excluded_regions = (event.text("excluded_regions").replace(",", ", "),
                                      event.text("exclusion_reason"))
        if event.get("verification_exclusion_reason") and not self._route_reason:
            self._route_reason = event.text("verification_exclusion_reason")

    # progress
    def _progress_event(self, event: Event) -> bool:
        stage = event.text("stage")
        if not stage:
            return False
        if event.status == "STARTED":
            self._end_auth()
            tasks, accounts = _int(event.get("tasks")) or 0, _int(event.get("accounts")) or 0
            self._stage = {"name": stage, "bucket": 0}
            if stage in self._stages_seen:  # the same check again, as in a settle window
                self._summarized += 1
                return True
            self._stages_seen.add(stage)
            self._summarized += 1
            self._progress(self._stage_line(stage, accounts, tasks))
            return True
        overall = re.fullmatch(r"(\d+)/(\d+)", event.text("overall"))
        if overall is None:
            return False
        self._summarized += 1
        if stage.startswith("observation:") and event.get("account"):
            gaps = _int(event.get("gaps"))
            if gaps is not None:
                self._read_gaps[stage.split(":", 1)[1]][event.text("account")] = gaps
        try:
            seconds = float(event.text("elapsed_seconds"))
        except ValueError:
            seconds = 0.0
        if self._stage is not None and self._stage["name"] == stage:
            bucket, done, total = int(seconds // 30), int(overall[1]), int(overall[2])
            if bucket > self._stage["bucket"] and done < total:
                self._stage["bucket"] = bucket
                self._say(f"  {done} of {total} done after {int(seconds)} s")
        return True

    def _stage_line(self, stage: str, accounts: int, tasks: int) -> str:
        if stage == "received-inventory":
            if accounts == 1:
                return f"Checking what 1 migrating account receives in {plural(tasks, 'Region')}..."
            return (f"Checking what {accounts} migrating accounts receive "
                    f"({tasks} account-Region checks)...")
        if stage == "discovery":
            regions = {region for owner_regions in self._scope.values() for region in owner_regions}
            where = plural(len(regions), "Region") if regions else plural(tasks, "owner-Region check")
            return f"Inspecting {plural(accounts, 'owner')} in {where}..."
        if stage in STAGES:
            return STAGES[stage].format(tasks=tasks, s="" if tasks == 1 else "s")
        if stage.startswith("observation:"):
            phase, who = stage.split(":", 1)[1], plural(accounts, "account")
            if phase.startswith("complete-settle-"):
                return f"Re-verifying after action {phase.rsplit('-', 1)[-1]} ({who})..."
            return OBSERVATIONS.get(phase, (f"Observing {phase} ({{n}})...",))[0].format(n=who)
        return f"Working: {stage} ({plural(tasks, 'task')})..."

    def _scope_event(self, event: Event) -> bool:
        if not event.get("owner") or event.get("regions") is None:
            return False
        self._scope[event.text("owner")] = [r for r in event.text("regions").split(",") if r]
        self._summarized += 1
        return True

    def _discovery_event(self, event: Event) -> bool:
        if event.status != "STARTED":
            return False
        self._summarized += 1
        return True

    # received access
    def _received_regions(self, event: Event) -> bool:
        if event.status == "EXCLUDED":
            self._received["not_enabled"][event.text("account")].append(event.text("region"))
            self._summarized += 1
            return True
        if event.status == "EXCLUDED_BY_OPERATOR":  # the header names the excluded Regions
            self._summarized += 1
            return True
        return False

    def _owned_event(self, event: Event) -> bool:
        if event.status == "MIGRATING_OWNER":
            account = event.text("account")
            self._detected[account] = event
            self._add(self._notes, f"Account {account} owns "
                                   f"{plural(_int(event.get('owned_shares')) or 0, 'RAM share')} in "
                                   f"{event.text('regions').replace(',', ', ')}, so it is inspected "
                                   "as a migrating owner in every audited Region; a share with any "
                                   "stationary consumer blocks.")
            return True
        if event.status == "OWNED":
            self._received["owned"][event.text("account")] += 1
            self._summarized += 1
            return True
        return False

    def _received_event(self, event: Event) -> bool:
        status = event.status
        if status is None or not event.get("share"):
            return False
        self._received["status"][status] += 1
        if status in ATTENTION or status not in RECEIVED_WORDS:
            self._received["attention"].append(event)
        else:
            self._summarized += 1
        self._parent = ("received", None)
        return True

    def _inventory_event(self, event: Event) -> bool:
        if event.get("received_accounts") is not None:
            self._received["totals"] = event
            return True
        if event.get("owner") and event.get("shares") is not None:
            self._summarized += 1
            return True
        return False

    def _continuity_event(self, event: Event) -> bool:
        if event.status != "SCOPED":
            return False
        self._stationary = [a for a in event.text("stationary_consumers").split(",") if a]
        return True

    def _owner_scope_event(self, event: Event) -> bool:
        if event.status != "APPROVED":
            return False
        self._approved_owners = [a for a in event.text("owners").split(",") if a]
        self._add(self._notes, "Owners approved in the record joined the owner scope: "
                               f"{', '.join(self._approved_owners)}; each needs a profile or role "
                               "mapping.")
        return True

    # plan
    def _plan_event(self, event: Event) -> bool:
        status = event.status
        if event.get("capability_provenance") is not None or event.get("writes") == "DISABLED":
            if event.get("migration"):
                self._migration = event.text("migration")
            self._summarized += 1
            return True
        if event.get("action") and event.get("template") is not None:
            self._stack_actions[(event.text("owner"), event.text("region"))] = event.text("action")
            self._summarized += 1
            return True
        if status == "EXCLUDED":
            self._exclusions.append(event.after("status"))
            return True
        if status == "EXISTING":
            self._existing.append(event.text("share"))
            return True
        if status == "NOTE":
            self._add(self._notes, self._plan_note(event.after("status")))
            return True
        if event.get("record") is not None and event.get("revision") is not None:
            self._revision = event.text("revision")
            return True
        if event.get("exported") is not None:
            self._exported = event.text("exported")
            return True
        return False

    @staticmethod
    def _plan_note(text: str) -> str:
        event = Event(text)
        if event.phase == "owner-continuity" and event.status == "PLANNED":
            return (f"Migrating owner {event.text('owner')} in {event.text('region')}: stationary "
                    f"recipients {event.text('stationary_consumers').replace(',', ', ')} of share "
                    f"{share_id(event.text('share'))} keep access through account-level temporary "
                    "shares; capture the baseline and accept the invitations before the owner "
                    "moves.")
        match = _SHARE_SUBJECT.match(text)
        if match and "status=DEFAULT_CHANGED" in text:
            inner = Event(match.group(2))
            return (f"Share {share_id(match.group(1))} of owner {inner.text('owner')} in "
                    f"{inner.text('region')}: {_capital(inner.after('status'))}")
        return describe(text)

    def _group_event(self, event: Event) -> bool:
        group = {"owner": event.text("owner"), "region": event.text("region"),
                 "consumers": [c for c in event.text("consumers").split(",") if c],
                 "stack": event.text("stack"), "types": Counter(), "sources": 0}
        self._groups.append(group)
        self._parent = ("group", group)
        return True

    def _preflight_event(self, event: Event) -> bool:
        if event.status == "ACCEPTED" and event.get("blocker"):
            self._accepted.append({"id": event.text("blocker"), "category": event.text("category"),
                                   "at": event.text("accepted_at"),
                                   "reason": event.text("accepted_reason"),
                                   "consequence": event.text("consequence"),
                                   "text": event.after("consequence")})
            return True
        if event.status == "BLOCKED":
            text, identity = event.after("status"), None
            match = _BLOCKER_ID.search(text)
            if match:
                identity, text = match.group(1), text[:match.start()]
            self._blockers.append({"id": identity, "text": text})
            return True
        return False

    def _permission_event(self, event: Event) -> bool:
        if event.status not in ("INFO", "WARNING"):
            return False
        entry = {"level": event.status, "event": event, "lines": [], "shares": [],
                 "applies": set()}
        self._permissions.append(entry)
        if event.status == "INFO":
            self._parent = ("permission", entry)
        return True

    # organization policies
    @staticmethod
    def _new_org() -> dict:
        return {"accounts": [], "destination": None, "prerequisites": [], "reviews": [],
                "notes": [], "result": None}

    def _org_event(self, event: Event) -> bool:
        status = event.status
        if event.get("decision"):
            return False
        if event.get("account") and event.get("roles") is not None:
            self._org["accounts"].append(event)
            return True
        if event.get("destination") and status:
            self._org["destination"] = event
            return True
        if status == "REVIEW":
            self._org["reviews"].append(event)
            return True
        if status == "NOTE":
            self._add(self._org["notes"], _capital(event.after("status")))
            return True
        if status == "POLICY_CHANGED":
            self._add(self._notes, f"Organization policy {event.text('policy')} in "
                                   f"{event.text('organization')} changed "
                                   f"({event.text('change')}) {event.after('change')}.")
            return True
        if status in ("ALLOWED", "BLOCKED") and event.get("accounts") is not None:
            self._org["result"] = event
            evaluation, self._org = self._org, self._new_org()
            evaluation["after_prompt"] = self._prompted
            if self._prompted:
                self._progress(f"Organization policies re-checked: {status} "
                               f"({self._org_counts(event)})")
            self._org_evaluations.append(evaluation)
            return True
        return False

    def _prerequisite_event(self, event: Event) -> bool:
        if event.status == "WARNING":
            self._add(self._warnings, event.raw)
            return True
        if event.get("organization") and event.get("all_features") is not None:
            self._org["prerequisites"].append(event)
            return True
        return False

    @staticmethod
    def _org_counts(event: Event) -> str:
        found = []
        for key, one, many in (("denies", "deny", "denies"),
                               ("gaps", "undecided statement", "undecided statements"),
                               ("unreadable", "unreadable", "unreadable"),
                               ("prerequisites_not_met", "unmet RAM prerequisite",
                                "unmet RAM prerequisites")):
            count = _int(event.get(key))
            if count:
                found.append(f"{count} {one if count == 1 else many}")
        checked = plural(_int(event.get("accounts")) or 0, "account") + " checked"
        return f"{checked}; " + (", ".join(found) if found else
                                 "no denies, undecided statements or unreadable policies")

    def _hint_event(self, event: Event) -> bool:
        if not event.get("of"):
            return False
        self._hints[event.text("of")] = {"count": event.text("blockers"),
                                         "command": event.text("command")}
        return True

    def _category_event(self, event: Event) -> bool:
        if event.get("category"):
            self._categories[event.text("category")] = event
            return True
        if event.status == "BLOCKED":
            self._summarized += 1
            return True
        return False

    # apply
    def _baseline_event(self, event: Event) -> bool:
        self._revision = event.text("revision") or self._revision
        self._captured = True
        complete = "complete" if event.get("complete") == "true" else "INCOMPLETE"
        self._progress(f"Baseline captured: {plural(_int(event.get('items')) or 0, 'item')}, "
                       f"{complete} (record revision {event.text('revision')})")
        return True

    def _gate_event(self, event: Event) -> bool:
        if event.status != "OPEN":
            return False
        self._revision = event.text("revision") or self._revision
        self._progress("Creating the temporary shares of reviewed plan revision "
                       f"{event.text('plan_revision')}...")
        return True

    def _record_event(self, event: Event) -> bool:
        status = event.status
        if status == "STACK_COMPLETE":
            self._revision = event.text("revision") or self._revision
            self._summarized += 1
            return True
        if status in ("INTERRUPTING", "FAILING"):
            self._progress(_capital(event.after("status")) + "...")
            return True
        if event.get("record") is not None and status in ("INTERRUPTED", "INCOMPLETE"):
            self._revision = event.text("revision") or self._revision
            next_action = event.raw.split("next_action=", 1)[1] if "next_action=" in event.raw else ""
            self._result_notes.append(
                f"The record holds {plural(_int(event.get('recorded_shares')) or 0, 'temporary share')}"
                f" of this run" + (f"; {next_action}." if next_action else "."))
            return True
        if status == "PLAN_SUPERSEDED":
            self._add(self._warnings, event.raw)
            return True
        if status in ("INCOMPLETE", "NOT_RECORDED", "CONFLICT", "UNKNOWN"):
            self._problems.append((status, event.raw))
            return True
        return False

    def _creation_event(self, event: Event) -> bool:
        if event.status != "COMPLETE":
            return False
        self._progress(f"Migration stack ready: {event.text('stack')} "
                       f"(owner {event.text('owner')}, {event.text('region')})")
        return True

    def _share(self, event: Event) -> dict:
        return self._shares.setdefault(event.text("share"), {
            "owner": event.text("owner"), "region": event.text("region"), "consumers": set(),
            "resources": None, "acceptance": {}, "verified": set()})

    def _acceptance_event(self, event: Event) -> bool:
        if not event.get("share") or not event.status:
            return False
        if "accepting" not in self._announced:
            self._announced.add("accepting")
            self._progress("Accepting the share invitations in the receiving accounts...")
        share = self._share(event)
        share["consumers"].add(event.text("consumer"))
        share["acceptance"][event.text("consumer")] = event.status
        if event.status in ("ASSOCIATED", "ASSOCIATING", "MISSING"):  # settles while polling
            self._summarized += 1
        else:
            self._problems.append((event.status, f"Share {share_id(event.text('share'))} (owner "
                                                 f"{event.text('owner')}, {event.text('region')}): "
                                                 f"the association of account "
                                                 f"{event.text('consumer')} is {event.status}"))
        return True

    def _problem_event(self, event: Event) -> bool:
        self._problems.append((event.status or "INCOMPLETE", event.raw))
        return True

    def _verification_event(self, event: Event) -> bool:
        status = event.status
        if status == "VERIFIED" and event.get("share"):
            if "verifying" not in self._announced:
                self._announced.add("verifying")
                self._progress("Verifying the temporary shares...")
            share = self._share(event)
            share["consumers"].add(event.text("consumer"))
            share["verified"].add(event.text("consumer"))
            share["resources"] = event.text("resources")
            self._summarized += 1
            return True
        if status == "RETIRED":
            self._retired.append((event.text("consumer"), event.text("at")))
            return True
        if status == "BLOCKED" and not event.get("kind"):
            self._blockers.append({"id": None, "text": event.after("status")})
            return True
        return False

    def _observation_event(self, event: Event) -> bool:
        phase, status = event.phase or "", event.status
        if event.get("change") == "ORIGINAL_SHARE_DROPPED" and phase != "monitor":
            self._drops.append(event)
            return True
        if event.get("migration_status") is not None and status is None:
            self._reasons.append((event.text("migration_status"), event.after("migration_status")))
            return True
        if status == "NOT_ASSOCIATED":
            self._unassociated.append(event)
            return True
        if status and status.startswith("BASELINE_"):
            self._losses.append((status, event.text("key"), event.after("key")))
            return True
        item = len(event.tokens) > 1 and event.tokens[0][0] == "phase" and \
            event.tokens[1][0] == "kind"  # phase=<phase> kind=...: one observed item
        if not item and status not in ("GAP", "LIMITED", "PRE_EXISTING"):
            return False
        observation = self._observations.setdefault(phase, {
            "items": Counter(), "gaps": [], "limited": Counter(), "pre_existing": []})
        if item:
            observation["items"][event.text("kind")] += 1
            self._summarized += 1
            return True
        if status == "GAP":
            observation["gaps"].append(event)
            return True
        if status == "LIMITED":
            observation["limited"][event.text("type")] += 1
            self._summarized += 1
            return True
        observation["pre_existing"].append(event)
        return True

    # monitor
    def _monitor_event(self, event: Event) -> bool:
        status = event.status
        if event.get("change"):
            self._monitor_changes.append(event)
            return True
        if status == "STARTED" and event.get("consumers") is not None:
            self._monitor_start = event
            self._migration = event.text("migration") or self._migration
            self._absorb_exclusions(event)
            self._header()
            return True
        if event.get("consumer") and "organization_now" in event.fields:
            self._monitor_orgs[event.text("consumer")] = event
            return True
        if event.get("consumer") and "original_share_drops" in event.fields and status is None:
            counts = self._monitor_numbers(event)
            if counts is None:
                return False
            self._monitor_counts[event.text("consumer")] = counts
            return True
        if status in STATUS_WORDS["monitor"]:
            if event.get("exit_code") is not None:
                if self._monitor_numbers(event) is None or _int(event.get("gaps")) is None or \
                        _int(event.get("exit_code")) is None:
                    return False
                self._monitor_final = event
                self._result = ("monitor", event)
                self._revision = event.text("revision") or self._revision
                self._absorb_exclusions(event)
                return True
            if event.raw.startswith("phase=monitor status="):
                self._monitor_reasons.append(event.after("status"))
                return True
            return False
        return self._observation_event(event)

    @staticmethod
    def _monitor_numbers(event: Event) -> dict[str, int] | None:
        values = {key: _int(event.get(key)) for key in MONITOR_COUNTS}
        if any(value is None for value in values.values()):
            return None
        return values  # type: ignore[return-value]

    # complete
    def _complete_event(self, event: Event) -> bool:
        status, raw = event.status, event.raw
        if event.get("action") in ("DELETE_SHARE", "REMOVE_PRINCIPALS", "DELETE_STACK"):
            self._actions.append(event)
            return True
        if raw.startswith("phase=complete status=BLOCKED "):
            self._checks.append(event.after("status"))
            return True
        if raw.startswith("phase=complete status=OVERRIDDEN "):
            self._overridden.append(event.after("status"))
            return True
        if raw.startswith("phase=complete status=NOT_OVERRIDDEN "):
            self._not_overridden = event.after("status")
            return True
        if status in ("SHARE_DELETED", "PRINCIPALS_REMOVED") and event.get("share"):
            consumers = event.text("consumers").replace(",", ", ")
            where = f"owner {event.text('owner')}, {event.text('region')}"
            if status == "SHARE_DELETED":
                self._progress(f"Deleted temporary share {share_id(event.text('share'))} ({where}) "
                               f"for {consumers}")
            else:
                self._progress(f"Removed {consumers} from temporary share "
                               f"{share_id(event.text('share'))} ({where})")
            return True
        if status == "STACK_DELETED":
            self._progress(f"Deleted migration stack (owner {event.text('owner')}, "
                           f"{event.text('region')})")
            return True
        if status == "ALREADY_RETIRED" and event.get("consumer"):
            self._add(self._notes, f"Account {event.text('consumer')}: its temporary access was "
                                   f"already retired at {event.text('at')}.")
            return True
        if status == "NO_TEMPORARY_SHARES" and event.get("consumer"):
            self._add(self._notes, f"Account {event.text('consumer')}: no recorded temporary share "
                                   "serves this account.")
            return True
        if status == "ALREADY_COMPLETE":
            self._migration = self._migration or event.text("migration") or None
            self._result = ("complete", event)
            return True
        return False

    def _replacement_event(self, event: Event) -> bool:
        if event.status != "COVERED":
            return False
        self._covered[event.text("consumer")] += 1
        self._summarized += 1
        return True

    # approve
    def _approve_event(self, event: Event) -> bool:
        raw = event.raw
        if event.get("migration"):
            self._migration = event.text("migration")
        own = _APPROVE_OWN.match(raw)
        if own is not None:
            identity, status = own.groups()
            if status is None and event.get("consequence") is not None:
                self._to_accept.append(event)
            elif status == "NOT_ACCEPTABLE":
                self._refused.append(event)
                self._refused_count += 1
            elif status == "ALREADY_ACCEPTED":
                self._already_accepted.append(identity)
            elif status == "ACCEPTED":
                self._accepted_now.append(identity)
                self._approve_status = "ACCEPTED"
                self._result = ("approve", event)
            else:
                return False
            return True
        status = event.status
        if event.get("scope") == "REGIONS_EXCLUDED":
            self._absorb_exclusions(event)
            return True
        if event.get("owner-scope") and event.get("proposed_owners") is not None:
            self._proposal = {"event": event, "owners": [], "notes": []}
            self._parent = ("proposal", self._proposal)
            return True
        if status == "CONFIRMED":
            self._summarized += 1
            return True
        if status in STATUS_WORDS["approve"]:
            self._approve_status = status
            self._result = ("approve", event)
            return True
        return False

    # outcome lines that start with status=
    def _status_event(self, event: Event) -> bool:
        status, raw = event.status or "", event.raw
        if event.get("migration"):
            self._migration = self._migration or event.text("migration")
        if status == "CANCELLED":
            self._result = ("cancelled", event)
            return True
        if status == "INCOMPLETE":
            if raw == "status=INCOMPLETE Interrupted; existing temporary shares are retained":
                self._result = ("interrupted", event)
            elif raw.endswith("; successful temporary shares are retained"):
                self._result = ("failed", event)
            else:
                self._problems.append(("INCOMPLETE", event.after("status")))
            return True
        if event.phase == "complete" and event.get("migration") and status in (
                "COMPLETED", "PARTIALLY_COMPLETED", "NOTHING_TO_RETIRE", "BLOCKED"):
            self._absorb_exclusions(event)
            self._result = ("complete", event)
            return True
        if status in ("NOTHING_TO_RETIRE", "COMPLETED", "PARTIALLY_COMPLETED") and \
                event.get("migration"):
            self._absorb_exclusions(event)
            self._result = ("complete", event)
            return True
        if status in ("FAILED", "INTERRUPTED"):
            self._problems.append((status, event.after("status")))
            if self.mode == "complete":
                self._result = ("complete-stopped", event)
            return True
        if status == "BLOCKED":
            self._result = ("error", event)
            return True
        return False

    @staticmethod
    def _add(items: list, value: str) -> None:
        if value not in items:
            items.append(value)

    # -- rendering ----------------------------------------------------------------

    def _render(self, final: bool) -> None:
        self._end_auth()
        if not self._absorbed:
            return
        try:
            lines = self._sections(final)
        except Exception as exc:  # show what was received rather than lose it
            lines = [f"(The readable summary could not be shown: {type(exc).__name__}: {exc}. "
                     "The events follow as received.)", *self._retained]
        if lines:
            self._header()
            self._write(([""] if self._loose else []) + lines)
            self._loose = False
        self._retained = []  # shown; until here a failure shows them as received

    def _sections(self, final: bool) -> list[str]:
        lines: list[str] = []

        def section(body: list[str]) -> None:
            if body:
                if lines and lines[-1] != "":
                    lines.append("")
                lines.extend(body)

        if self.mode == "monitor":
            if final:
                for body in self._monitor_sections():
                    section(body)
        else:
            bodies = self._approve_sections() if self.mode == "approve" else [
                self._accounts_section(), self._retired_section(), self._received_section(),
                self._plan_section(), self._permission_section(), self._exclusion_section(),
                self._org_section(), *self._observation_sections(), self._replacement_section(),
                self._overridden_section(), self._actions_section(), self._share_section(),
                self._baseline_section(), self._drops_section(), self._unassociated_section(),
                self._loss_section(), self._problem_section(), self._warning_section(),
                self._note_section(), self._accepted_section(), self._blocker_section(),
                self._checks_section()]
            for body in bodies:
                section(body)
            if final:
                section(self._result_section())
        if final and self._summarized:
            section([RAW_HINT])
        if lines and not final:
            lines.append("")  # a blank line before the prompt that follows
        return lines

    # sections ---------------------------------------------------------------------

    def _roles(self) -> list[list[str]]:
        context = self.context
        owners = set(getattr(context, "owners", None) or self._scope)
        consumers = set(getattr(context, "consumers", None) or
                        {c for g in self._groups for c in g["consumers"]} - set(self._stationary))
        stationary = set(getattr(context, "stationary_consumers", None) or self._stationary)
        retired = dict(self._retired)
        rows = []
        for account in sorted(owners | consumers | stationary):
            if account in owners and account in consumers:
                role = "Migrating owner"
            elif account in consumers:
                role = "Migrating"
            elif account in owners:
                role = "Stationary owner"
                if account in self._approved_owners:
                    role += " (approved in the record)"
            else:
                role = "Stationary consumer (receives from a migrating owner)"
            if account in retired:
                role += f"; temporary access retired {retired[account]}"
            rows.append([account, role])
        return rows

    def _accounts_section(self) -> list[str]:
        if self._accounts_done or self.mode not in ("plan", "apply", "verify"):
            return []
        rows = self._roles()
        if not rows:
            return []
        self._accounts_done = True
        return [f"Accounts ({len(rows)})", *table(["Account", "Role"], rows)]

    def _retired_section(self) -> list[str]:
        if not self._retired or self._retired_done:
            return []
        self._retired_done = True
        body = [f"Retired accounts ({len(self._retired)}): complete retired their temporary "
                "access, so it is no longer verified"]
        return body + [f"  {account}  retired {at}" for account, at in self._retired]

    def _received_section(self) -> list[str]:
        received = self._received
        totals = received["totals"]
        if totals is None or self._received_done:
            return []
        self._received_done = True
        number = lambda key: _int(totals.get(key)) or 0  # noqa: E731
        accounts, shares = number("received_accounts"), number("received_shares")
        who = ("1 migrating account receives" if accounts == 1 else
               f"{accounts} migrating accounts receive")
        regions = plural(number("received_regions"), "Region")
        if shares:
            first = (f"{who} {plural(shares, 'share')} ({plural(number('received_resources'), 'resource')})"
                     f" from {plural(number('received_owners'), 'owner')}; {regions} checked.")
        else:
            first = f"{who} no shares from other accounts; {regions} checked."
        body = ["Received access", *wrap(first)]
        if received["types"]:
            body += wrap("Resource types: " + counted(received["types"]))
        if received["status"]:
            body += wrap("By result: " + ", ".join(
                f"{count} {RECEIVED_WORDS.get(status, status)}"
                for status, count in sorted(received["status"].items(), key=lambda i: (-i[1], i[0]))))
        if received["owned"]:
            body += wrap("Shares the migrating accounts own: " + ", ".join(
                f"{account} owns {count}" for account, count in sorted(received["owned"].items())))
        for account, missing in sorted(received["not_enabled"].items()):
            body += wrap(f"Not enabled in {account}, so not inspected: {', '.join(missing)}")
        if received["attention"]:
            body.append("  Needing attention (see Blockers):")
            body += table(["Account", "Owner", "Region", "Share", "Result"], [
                [e.text("account"), e.text("owner", "?"), e.text("region"),
                 share_id(e.text("share")), RECEIVED_WORDS.get(e.status or "", e.status)]
                for e in received["attention"]], indent="    ")
        return body

    def _plan_section(self) -> list[str]:
        if self.mode not in ("plan", "apply"):
            return []
        groups, self._groups = self._groups, []
        actions, self._stack_actions = self._stack_actions, {}
        existing, self._existing = self._existing, []
        if not groups and not actions and not existing:
            return []
        stacks = Counter(actions.values())
        detail = []
        if stacks.get("CREATE"):
            detail.append(f"{plural(stacks['CREATE'], 'migration stack')} to create")
        if stacks.get("UPDATE_OR_REUSE"):
            detail.append(f"{plural(stacks['UPDATE_OR_REUSE'], 'migration stack')} to update or "
                          "reuse")
        body = [f"Planned temporary shares ({len(groups)}" +
                (f"; {', '.join(detail)})" if detail else ")")]
        if groups:
            body += table(["Owner", "Region", "Accounts", "Resources"], [
                [g["owner"], g["region"], accounts_text(g["consumers"]), counted(g["types"]) or "?"]
                for g in sorted(groups, key=lambda g: (g["owner"], g["region"]))])
        else:
            body.append("  No temporary shares are needed.")
        if existing:
            body += wrap(f"{plural(len(existing), 'temporary share')} of this migration already "
                         "exist and are reused.")
        if self.mode == "apply" and groups and not self._prompted:
            body += wrap("Apply creates or updates these migration stacks, accepts the share "
                         "invitations in the receiving accounts and captures the pre-migration "
                         "baseline before its first write.")
        return body

    def _permission_section(self) -> list[str]:
        entries, self._permissions = self._permissions, []
        if not entries:
            return []
        body = ["Permission versions (information; nothing to approve)"]
        for entry in entries:
            event = entry["event"]
            kind = event.text("resource_type")
            subject = (f"{TYPE_NAMES.get(kind.lower(), (kind, kind))[1]}: permission "
                       f"{event.text('permission').rsplit('/', 1)[-1]} version "
                       f"{event.text('version').replace('->', ' -> ')}")
            if entry["level"] == "INFO":
                shares = _int(event.get("shares")) or 0
                body += wrap(f"INFO     {subject} ({plural(shares, 'original share')})", "  ",
                             " " * 11)
                for line in entry["lines"]:
                    body += wrap(line, " " * 11, " " * 13)
                for applies in sorted(entry["applies"]):
                    body += wrap(f"Applies to: {applies}", " " * 11, " " * 13)
            else:
                body += wrap(f"WARNING  {subject}: {event.after('shares')}", "  ", " " * 11)
        return body

    def _exclusion_section(self) -> list[str]:
        exclusions, self._exclusions = self._exclusions, []
        if not exclusions:
            return []
        grouped = Counter(exclusion_reason(text) for text in exclusions)
        width = len(str(max(grouped.values())))
        body = [f"Exclusions ({len(exclusions)})"]
        for reason, count in sorted(grouped.items(), key=lambda item: (-item[1], item[0])):
            body += wrap(f"{str(count).rjust(width)}  {reason}", "  ", " " * (width + 4))
        return body

    def _org_section(self) -> list[str]:
        evaluations, self._org_evaluations = self._org_evaluations, []
        body: list[str] = []
        for evaluation in evaluations:
            result = evaluation["result"]
            if evaluation.get("after_prompt"):  # its progress line reported the result
                for event in evaluation["reviews"]:
                    body += wrap(f"For review (re-check): policy {event.text('policy')} statement "
                                 f"{event.text('statement')}: {self._statement(event)}", "", "  ")
                continue
            body.append(f"Organization policies: {result.status} - {self._org_counts(result)}")
            rows = [[event.text("account"), event.text("roles").replace(",", ", "),
                     event.text("organization", "-"),
                     ORG_STATUS.get(event.status or "", event.status or "?"),
                     event.text("scp", "-").lower().replace("_", " "),
                     event.text("rcp", "-").lower().replace("_", " "), event.text("path", "-")]
                    for event in evaluation["accounts"]]
            if rows:
                body += table(["Account", "Roles", "Organization", "Policies", "SCPs", "RCPs",
                               "Path"], rows)
            destination = evaluation["destination"]
            if destination is not None:
                text = (f"Destination {destination.text('destination')}: "
                        f"{ORG_STATUS.get(destination.status or '', destination.status)}")
                if destination.get("path"):
                    text += (f"; path {destination.text('path')}, SCPs "
                             f"{destination.text('scp').lower().replace('_', ' ')}, RCPs "
                             f"{destination.text('rcp').lower().replace('_', ' ')}")
                body += wrap(text)
            for event in evaluation["prerequisites"]:
                body += wrap(f"RAM sharing with AWS Organizations in {event.text('organization')}: "
                             f"{event.status} (ALL features: {event.text('all_features')}, RAM "
                             f"trusted access: {event.text('ram_trusted_access')}; "
                             f"{plural(_int(event.get('shares')) or 0, 'share')} rely on it)")
            for event in evaluation["reviews"]:
                body += wrap(f"For review: policy {event.text('policy')} statement "
                             f"{event.text('statement')}: {self._statement(event)}")
            for event in evaluation["accounts"]:
                if event.get("principal_arn") == "UNKNOWN":
                    problem = event.raw.split("principal_arn_problem=", 1)[-1]
                    body += wrap(f"Account {event.text('account')}: the signed-in role ARN could "
                                 f"not be read ({problem}), so conditions on aws:PrincipalArn "
                                 "cannot be decided for it.")
            for note in evaluation["notes"]:
                body += wrap(f"Note: {note}")
            for blocker in self._blockers:
                if re.match(r"(?:post-confirmation )?phase=org-policy ", blocker["text"]):
                    body += wrap(f"- {describe(blocker['text'])}; blocker "
                                 f"{blocker['id'] or 'without ID'}, see Blockers", "  ", "    ")
            for row in self._accepted:
                if re.match(r"(?:post-confirmation )?phase=org-policy ", row["text"]):
                    body += wrap(f"- ACCEPTED: {describe(row['text'])}; blocker {row['id']}",
                                 "  ", "    ")
        return body

    @staticmethod
    def _statement(event: Event) -> str:
        return event.raw.split(" text=", 1)[1] if " text=" in event.raw else event.after("statement")

    def _observation_sections(self) -> list[list[str]]:
        if self.mode == "monitor":
            return []
        observations, self._observations = self._observations, OrderedDict()
        sections = []
        rechecks = [phase for phase in observations
                    if phase.startswith("complete-settle-") or phase == "complete-final"]
        for phase, observation in observations.items():
            if phase in rechecks:
                continue
            items, gaps, pre = observation["items"], observation["gaps"], observation["pre_existing"]
            limited = observation["limited"]
            if phase == "baseline" and self._captured and not (gaps or pre or limited):
                continue  # the "Baseline captured" line reported it
            line = f"{_observation_label(phase)}: {plural(sum(items.values()), 'item')} observed"
            if items:
                line += f" ({counted(items, kind_label)})"
            line += f"; {plural(len(gaps), 'read gap')}" if gaps else "; no read gaps"
            body = wrap(line, "", "  ")
            for gap in gaps:
                body += self._gap_lines(gap)
            if pre:
                body += wrap(f"Recorded as found ({len(pre)}): already not healthy or not visible "
                             "before the migration; recorded in the baseline, never a blocker, "
                             "and judged only on what changes.")
                body += table(["Kind", "Account", "Region", "Resource", "Found"],
                              [self._pre_existing_row(event) for event in pre], indent="    ")
            if limited:
                body += wrap("No resource-specific health check for these types (their RAM access "
                             "is verified): " + counted(limited))
            sections.append(body)
        if rechecks:
            settles = [phase for phase in rechecks if phase.startswith("complete-settle-")]
            gaps = [gap for phase in rechecks for gap in observations[phase]["gaps"]]
            line = "Re-verified"
            if settles:
                line += f" after each of {plural(len(settles), 'action')}"
            if "complete-final" in rechecks:
                line += " and once more at the end" if settles else " once more at the end"
            line += f": {plural(len(gaps), 'read gap')}" if gaps else ": no read gaps"
            body = wrap(line, "", "  ")
            for gap in gaps:
                body += self._gap_lines(gap)
            sections.append(body)
        return sections

    @staticmethod
    def _gap_lines(gap: Event) -> list[str]:
        where = ", ".join(f"{word} {gap.text(key)}" for key, word in (
            ("account", "account"), ("region", "Region"), ("resource", "resource"))
            if gap.get(key) not in (None, "None", ""))
        reason = gap.raw.split(" reason=", 1)[1] if " reason=" in gap.raw else gap.message()
        return wrap(f"- Read gap ({gap.text('collector', 'unknown collector')})"
                    + (f", {where}" if where else "") + f": {reason}", "  ", "    ")

    @staticmethod
    def _pre_existing_row(event: Event) -> list[str]:
        body, found = event.after("status"), ""
        if ": not " in body:
            body, expected = body.rsplit(": not ", 1)
            found = "not " + expected.split(" before the migration", 1)[0]
        item = Event(body)
        state = next((item.text(key) for key in ("status", "state", "consumer_read", "ca_status")
                      if item.get(key)), "")
        if state:
            found = f"{state} ({found})" if found else state
        return [KIND_NAMES.get(item.text("kind"), (item.text("kind"),))[0],
                item.text("consumer") or item.text("owner") or "-", item.text("region", "-"),
                item.text("resource_arn", "-"), found or "-"]

    def _replacement_section(self) -> list[str]:
        covered, self._covered = self._covered, Counter()
        if not covered:
            return []
        return wrap("Permanent replacement access found: " + ", ".join(
            f"{plural(count, 'resource')} for {account}" for account, count in sorted(covered.items())),
            "", "  ")

    def _overridden_section(self) -> list[str]:
        problems, self._overridden = self._overridden, []
        if not problems:
            return []
        if self._prompted:  # found by the re-verification after a write
            title = (f"OVERRIDDEN AFTER THE WRITES ({len(problems)}): losses or gaps found while "
                     "re-verifying; --force continued and recorded each")
        else:
            title = (f"OVERRIDDEN SAFETY CHECKS ({len(problems)}): --force proceeds despite these "
                     "failed checks, and each override is recorded")
        return [*wrap(title, "", "  "), *self._check_lines(problems, "OVERRIDDEN")]

    @staticmethod
    def _check_lines(problems: list[str], label: str) -> list[str]:
        """Failed checks, numbered; missing replacement access is one table."""
        body: list[str] = []
        replacement = [m.groups() for m in map(_CHECK_REPLACEMENT.match, problems) if m]
        others = [p for p in problems if not _CHECK_REPLACEMENT.match(p)]
        for number, problem in enumerate(others, 1):
            body += wrap(f"{number}. {label}: {describe(problem)}", "  ", "     ")
        if replacement:
            body += wrap(f"{len(others) + 1}. {label}: only the temporary share provides access to "
                         f"{plural(len(replacement), 'resource')}; set up permanent replacement "
                         "sharing first:", "  ", "     ")
            body += table(["Account", "Region", "Resource"], [list(row) for row in replacement],
                          indent="     ")
        return body

    def _actions_section(self) -> list[str]:
        actions, self._actions = self._actions, []
        if not actions:
            return []
        rows = []
        for event in actions:
            action = event.text("action")
            if action == "DELETE_STACK":
                rows.append([action, event.text("owner"), event.text("region"), "-", "-", "-",
                             event.text("stack")])
            else:
                kept = event.text("retained_consumers").replace(",", ", ")
                rows.append([action, event.text("owner"), event.text("region"),
                             share_id(event.text("share")),
                             event.text("consumers").replace(",", ", "), event.text("resources"),
                             f"keeps serving {kept}" if kept else ""])
        return [f"Planned actions ({len(actions)}; smallest share first, re-verifying after each)",
                *table(["Action", "Owner", "Region", "Share", "Accounts", "Resources", "Note"], rows)]

    def _share_section(self) -> list[str]:
        shares, self._shares = self._shares, OrderedDict()
        if not shares:
            return []
        rows = []
        for arn, share in sorted(shares.items(), key=lambda i: (i[1]["owner"], i[1]["region"], i[0])):
            consumers = sorted(share["consumers"])
            if share["verified"] and share["verified"] >= set(consumers):
                state = "verified"
            elif share["verified"]:
                state = f"verified for {len(share['verified'])} of {len(consumers)} accounts"
            else:
                states = sorted(set(share["acceptance"].values()))
                state = "accepted, not verified" if states == ["ASSOCIATED"] else \
                    (", ".join(states).lower() or "-")
            rows.append([share["owner"], share["region"], share_id(arn),
                         accounts_text(consumers), share["resources"] or "-", state])
        return [f"Temporary shares ({len(rows)})",
                *table(["Owner", "Region", "Share", "Accounts", "Resources", "Status"], rows)]

    def _moving(self) -> list[str]:
        accounts = list(getattr(self.context, "consumers", None) or [])
        if not accounts:
            accounts = sorted({c for share in self._shares.values() for c in share["consumers"]})
        retired = {account for account, _at in self._retired}
        return [account for account in accounts if account not in retired]

    def _baseline_section(self) -> list[str]:
        summary = self._summary
        if summary is None or self.mode not in ("apply", "verify") or \
                summary.get("baseline_status") is None:
            return []
        body = [f"Baseline comparison: {summary.text('baseline_status')} - "
                f"{summary.text('baseline_missing', '?')} missing, "
                f"{summary.text('baseline_degraded', '?')} degraded, "
                f"{plural(_int(summary.get('observation_gaps')) or 0, 'read gap')}"]
        migration = summary.text("migration_status")
        if migration:
            body += wrap(f"Migration status: {migration} - "
                         f"{STATUS_WORDS['verify'].get(migration, migration)}", "", "  ")
        reasons = [reason for _status, reason in self._reasons]
        rows, shown = [], set()
        for account in self._moving():
            state = None
            for reason in reasons:
                if re.match(rf"{account} is still in its baseline organization \S+$", reason):
                    state = ("still in its baseline organization "
                             f"{reason.rsplit(' ', 1)[-1]} (not moved yet)")
                    shown.add(reason)
                elif reason == f"current organization of {account} is unknown":
                    state = "unknown: it could not be read"
                    shown.add(reason)
            if state is None:
                state = ("left its baseline organization"
                         if migration in ("MIGRATION_VALIDATED", "PENDING_MIGRATION")
                         else "not judged (see the migration status)")
            rows.append([account, state])
        if rows:
            body += table(["Account", "Organization"], rows)
        lost = {key for _status, key, _reason in self._losses}
        for reason in reasons:
            if reason not in shown and not any(key in reason for key in lost if key):
                body += wrap(f"- {_reason(reason)}", "  ", "    ")
        self._reasons = []
        return body

    def _drops_section(self) -> list[str]:
        drops, self._drops = self._drops, []
        if not drops:
            return []
        return ["Access changes (expected while accounts move; not losses)",
                *self._change_lines(drops)]

    @staticmethod
    def _change_lines(events: list[Event]) -> list[str]:
        groups: "OrderedDict[tuple, list[Event]]" = OrderedDict()
        for event in events:
            key = (event.text("change"), event.text("consumer"), event.text("region"),
                   event.text("share"), event.text("access"))
            groups.setdefault(key, []).append(event)
        lines: list[str] = []
        if len(groups) > DETAIL_LIMIT:
            totals: Counter = Counter()
            shares: dict[tuple, set] = defaultdict(set)
            for (change, consumer, _region, share, access), rows in groups.items():
                totals[(change, consumer, access)] += len(rows)
                shares[(change, consumer, access)].add(share)
            for (change, consumer, access), count in sorted(totals.items()):
                lines += wrap(f"- {CHANGE_LABELS.get(change, change)}: {consumer} | "
                              f"{plural(count, 'resource')} through "
                              f"{plural(len(shares[(change, consumer, access)]), 'share')} | "
                              f"current access={access}", "  ", "    ")
            return lines
        for (change, consumer, region, share, access), rows in groups.items():
            what = rows[0].text("resource") if len(rows) == 1 else plural(len(rows), "resource")
            lines += wrap(f"- {CHANGE_LABELS.get(change, change)}: {consumer} | {region} | {what} | "
                          f"current access={access} | share={share}", "  ", "    ")
        return lines

    def _unassociated_section(self) -> list[str]:
        rules, self._unassociated = self._unassociated, []
        if not rules:
            return []
        accounts = sorted({event.text("consumer") for event in rules})
        return wrap(f"Not associated: {plural(len(rules), 'shared Resolver rule')} had no VPC "
                    f"association in {', '.join(accounts)} before the migration; sharing does not "
                    "create one, and none was repaired.", "", "  ")

    def _loss_section(self) -> list[str]:
        losses, self._losses = self._losses, []
        if not losses:
            return []
        body = [f"LOSSES AGAINST THE BASELINE ({len(losses)})"]
        for status, key, reason in losses:
            kind = "missing" if status == "BASELINE_MISSING" else "degraded"
            body += wrap(f"- {kind}: {key}: {reason}", "  ", "    ")
        return body

    def _problem_section(self) -> list[str]:
        problems, self._problems = self._problems, []
        if not problems:
            return []
        body = [f"PROBLEMS ({len(problems)})"]
        for label, text in problems:
            body += wrap(f"- {label.replace('_', ' ')}: {describe(text)}", "  ", "    ")
        return body

    def _warning_section(self) -> list[str]:
        warnings, self._warnings = self._warnings, []
        if not warnings:
            return []
        body = [f"Warnings ({len(warnings)})"]
        for warning in warnings:
            event = Event(warning)
            text = _capital(event.after("status")) if event.phase == "record" else describe(warning)
            body += wrap(f"- WARNING: {text}", "  ", "    ")
        return body

    def _note_section(self) -> list[str]:
        notes, self._notes = self._notes, []
        if not notes:
            return []
        body = ["Notes"]
        for note in notes:
            body += wrap(f"- {note}", "  ", "    ")
        return body

    def _accepted_section(self) -> list[str]:
        accepted, self._accepted = self._accepted, []
        if not accepted:
            return []
        body = [f"ACCEPTED BLOCKERS ({len(accepted)}): the run proceeds without what they concern"]
        for row in accepted:
            title = CATEGORY_TITLES.get(row["category"], row["category"])
            body += wrap(f"ACCEPTED {row['id']}  {title} [{row['category']}]: "
                         f"{_short(describe(row['text']), 70)}", "  ", "    ")
            body += wrap(f"Accepted {row['at']}: {row['reason']}", "    ", "      ")
            body += wrap(f"Consequence: {row['consequence']}", "    ", "      ")
            body += wrap(f"Full text: {row['text']}", "    ", "      ")
        return body

    def _blocker_section(self) -> list[str]:
        blockers, self._blockers = self._blockers, []
        if not blockers:
            return []
        grouped: "OrderedDict[str, list[dict]]" = OrderedDict()
        for blocker in blockers:
            grouped.setdefault(blocker_category(blocker["text"]), []).append(blocker)
        order = list(self._categories) + [c for c in CATEGORY_TITLES if c not in self._categories]
        record = getattr(self.args, "record", None)
        body = [f"BLOCKERS ({len(blockers)})"]
        if self._hint:
            body += wrap(self._hint)
        number = 0
        for category in sorted(grouped, key=lambda c: order.index(c) if c in order else len(order)):
            rows, summary = grouped[category], self._categories.get(category)
            counts = []
            for key, value in (summary.fields.items() if summary is not None else ()):
                count = _int(value)
                if key in COUNT_NAMES and count:
                    names = COUNT_NAMES[key]
                    counts.append(plural(count, *(names if isinstance(names, tuple) else (names,))))
            title = (f"{CATEGORY_TITLES.get(category, category)} [{category}]: "
                     f"{plural(len(rows), 'blocker')}" + (f" ({', '.join(counts)})" if counts else ""))
            body.append("")
            body += wrap(title, "  ", "    ")
            for blocker in rows:
                number += 1
                lead = f"{number}. {blocker['id'] or '(no ID)'}  "
                body += wrap(lead + _short(describe(blocker["text"]), WIDTH - 6 - len(lead)),
                             "    ", "       ")
                body += wrap(f"Full text: {blocker['text']}", "       ", "         ")
            if summary is not None and "next_action=" in summary.raw:
                body += wrap(f"Next step: {summary.raw.split('next_action=', 1)[1]}", "    ",
                             "      ")
            hint = self._hints.get(category)
            if hint:
                command = hint["command"].replace("<path>", str(record) if record else "<path>")
                command = command.replace("--accept-reason <reason>", '--accept-reason "<reason>"')
                body.append(f"    To accept instead ({hint['count']} of {len(rows)} can be "
                            "accepted):")
                body.append(f"      ramshift {command}")  # one line, to copy as it is
                body += wrap("You can also name blocker IDs. Each consequence is shown and "
                             "recorded before you confirm, and the run then proceeds without what "
                             "the accepted blockers concern.", "      ", "      ")
        return body

    def _checks_section(self) -> list[str]:
        checks, self._checks = self._checks, []
        if not checks:
            return []
        body = [f"FAILED CHECKS ({len(checks)}): nothing was retired",
                *self._check_lines(checks, "BLOCKED")]
        if self._not_overridden:
            body += wrap(f"Not overridden: {self._not_overridden}")
        return body

    # result -------------------------------------------------------------------------

    def _status(self) -> tuple[str | None, str]:
        """(status, words) of the run's outcome."""
        kind, event = self._result if self._result else (None, None)
        if event is None:
            return None, ""
        status = event.status or ""
        if kind == "error":
            if self._summary is not None:  # the run reported its outcome, then failed
                return "BLOCKED", f"{self.mode.capitalize()} stopped with an error"
            return "BLOCKED", f"{self.mode.capitalize()} could not run"
        if kind == "interrupted":
            return "INCOMPLETE", "the run was interrupted; existing temporary shares are kept"
        if kind == "failed":
            return "INCOMPLETE", ("the run failed after it started writing; the temporary shares "
                                  "that succeeded are kept")
        if kind == "verify-complete":
            return "ALREADY_COMPLETE", STATUS_WORDS["verify"]["ALREADY_COMPLETE"]
        if kind == "approve":
            status = self._approve_status or status
            return status, STATUS_WORDS["approve"].get(status, "")
        if kind == "cancelled":
            return "CANCELLED", STATUS_WORDS.get(self.mode, {}).get(
                "CANCELLED", "the confirmation did not match; nothing was written to AWS")
        return status, STATUS_WORDS.get(self.mode, {}).get(status, "")

    def _exit(self, status: str | None) -> int | None:
        if self.exit_code is not None:
            return self.exit_code
        kind = self._result[0] if self._result else None
        if kind == "monitor":
            return _int(self._result[1].get("exit_code"))
        if kind == "interrupted":
            return 130
        if status is None:
            return None
        if self.mode == "approve" and status == "NOTHING_ACCEPTED":
            return 1 if self._refused_count else 0
        return EXIT_CODES.get(self.mode, {}).get(status, 1)

    def _record_line(self) -> str | None:
        record = getattr(self.args, "record", None)
        if record is None:
            if self.mode == "plan":
                return "Record: none (re-run plan with --record <path> to record this plan)"
            return None
        if self._result and self._result[0] == "monitor" and \
                self._result[1].get("recorded") == "false":
            return "Record: result could not be saved."
        revision = self._revision if self.mode in ("plan", "monitor") else None
        if revision is None and self.mode in (*WRITING_MODES, "plan"):
            # The revision this run left: apply and verify write theirs after the summary.
            recorded = self._recorded("revision")
            revision = self._revision if recorded is None else str(recorded)
        return f"Record: {record}" + (f" (revision {revision})" if revision else "")

    def _recorded(self, field: str) -> Any:
        """One top-level field of the migration record file, read only for display; None
        when there is no record or it cannot be read."""
        record = getattr(self.args, "record", None)
        if record is None:
            return None
        try:
            return json.loads(Path(record).read_text(encoding="utf-8")).get(field)
        except Exception:
            return None

    def _result_section(self) -> list[str]:
        status, words = self._status()
        kind, event = self._result if self._result else (None, None)
        body: list[str] = []
        if status is None:
            body.append("Result: UNKNOWN - the run ended before it reported a result.")
        else:
            body += wrap(f"Result: {status}" + (f" - {words}" if words else ""), "", "  ")
        if kind in ("error", "failed") and event is not None:
            body += wrap(f"Reason: {describe(event.after('status'))}")
        if kind == "summary" and self._summary is not None:
            body += self._counts(self._summary)
        if kind == "complete" and event is not None:
            body += self._complete_counts(event)
        if kind == "cancelled" and event is not None:
            body += wrap(event.after("status"))
        for caveat in self._caveats:
            body += wrap(caveat)
        if self._exported:
            body += wrap(f"Plan exported to {self._exported}")
        record = self._record_line()
        if record:
            body.append(f"  {record}")  # one line: the path stays whole
        code = self._exit(status)
        if code is not None:
            body.append(f"  Exit code: {code}")
        for note in self._result_notes:
            body += wrap(note)
        body += wrap(f"Next step: {self._next_step(status)}", "", "  ")
        return body

    def _counts(self, summary: Event) -> list[str]:
        value = summary.text
        if self.mode == "plan":
            line = (f"Resources: {value('resources_in_plan')}   Access grants: "
                    f"{value('expected_entitlements')}   Temporary shares: {value('planned_shares')}"
                    f"   Exclusions: {value('exclusions')}   Blockers: {value('blockers')}")
            if summary.get("accepted_blockers"):
                line += f"   Accepted blockers: {value('accepted_blockers')}"
            return wrap(line)
        lines: list[str] = []
        if summary.get("sharing_status"):
            sharing = value("sharing_status")
            lines += wrap(f"Sharing: {sharing} - {SHARING_WORDS.get(sharing, sharing)}")
        if summary.get("migration_status") and self.mode == "apply":
            lines += wrap(f"Migration: {value('migration_status')}")
        line = f"Temporary shares: {value('planned_shares')}"
        if self.mode == "apply":
            line += (f" ({value('created_shares')} created, {value('reused_shares')} reused)   "
                     f"Invitations accepted: {value('accepted_invitations')} (already accepted: "
                     f"{value('reused_invitations')})")
        line += (f"   Access grants: {value('expected_entitlements')}   Verification failures: "
                 f"{value('verification_failures')}   Blockers: {value('blockers')}")
        if summary.get("accepted_blockers"):
            line += f"   Accepted blockers: {value('accepted_blockers')}"
        lines += wrap(line)
        if summary.get("baseline_status"):
            gaps = plural(_int(summary.get("observation_gaps")) or 0, "read gap")
            lines += wrap(f"Baseline: {value('baseline_status')} ({value('baseline_missing')} "
                          f"missing, {value('baseline_degraded')} degraded, {gaps})")
        return lines

    @staticmethod
    def _complete_counts(event: Event) -> list[str]:
        value = event.text
        lines: list[str] = []
        if event.get("deleted_shares") is not None:
            lines += wrap(f"Deleted temporary shares: {value('deleted_shares')}   Removed "
                          f"principals: {value('removed_principals')}   Deleted stacks: "
                          f"{value('deleted_stacks')}")
        if event.get("retired_accounts") is not None:
            lines += wrap(f"Retired accounts: {value('retired_accounts').replace(',', ', ')}   "
                          f"Remaining accounts: {value('remaining_accounts').replace(',', ', ')}")
        if event.get("forced") == "true":
            lines += wrap(f"FORCED: {value('overridden')} failed safety checks were overridden "
                          "and recorded.")
        elif "original baseline intact" in event.raw:
            lines += wrap("The original baseline is intact for the retired accounts.")
        if event.status == "BLOCKED" and event.get("blockers") is not None:
            lines += wrap(f"Failed checks: {value('blockers')}; the temporary shares are retained.")
        return lines

    def _next_step(self, status: str | None) -> str:
        kind = self._result[0] if self._result else None
        recorded = getattr(self.args, "record", None) is not None
        if kind == "error":
            return "Resolve the problem above, then run the command again."
        if kind in ("interrupted", "failed"):
            if self.mode == "apply":
                return ("Re-run apply with the same --record to resume; the existing temporary "
                        "shares are retained.")
            if self.mode == "complete":
                return NEXT_STEPS[("complete", "INTERRUPTED")]
            return "Run the command again with the same --record."
        if self.mode == "plan" and not recorded and status == "PLANNED":
            return ("To apply this plan, re-run plan with --record <path>: apply needs the "
                    "recorded plan.")
        if self.mode == "plan" and not recorded and status == "BLOCKED":
            return ("Resolve or accept each blocker (the next step is under each category), then "
                    "re-run plan; add --record <path> to record the plan.")
        if self.mode == "approve" and status in ("APPROVED", "ACCEPTED") and self._next_sentence:
            return self._next_sentence
        if self.mode == "complete" and status in ("PARTIALLY_COMPLETED", "NOTHING_TO_RETIRE") \
                and self._result:
            remaining = self._result[1].text("remaining_accounts").replace(",", ", ")
            if status == "NOTHING_TO_RETIRE":
                return f"Nothing to do for these accounts. Accounts with temporary access: {remaining}."
            return (f"Run complete for the remaining accounts ({remaining}) once their permanent "
                    "sharing is in place.")
        return NEXT_STEPS.get((self.mode, status),
                              "Check the messages above, then run the command again.")

    # monitor --------------------------------------------------------------------------

    def _monitor_sections(self) -> list[list[str]]:
        sections: list[list[str]] = []
        final = self._monitor_final
        kind, event = self._result if self._result else (None, None)
        observation = self._observations.get("monitor", {"gaps": [], "limited": Counter()})
        if final is not None:
            rows = []
            for account in [a for a in final.text("consumers").split(",") if a]:
                org, counts = self._monitor_orgs.get(account), self._monitor_counts.get(account)
                numbers = ["?", "?", "?", "?"] if counts is None else [
                    str(counts["original_share_drops"] + counts["shares_added"] + counts["added"]),
                    str(counts["lost"]), str(counts["degraded"]), str(counts["unobserved"])]
                change = org.text("organization_change", "UNKNOWN") if org else "UNKNOWN"
                if org is not None and org.get("temporary_access") == "RETIRED":
                    change += " (temporary access retired)"
                rows.append([account, org.text("organization_now", "UNKNOWN") if org else "UNKNOWN",
                             change, *numbers])
            sections.append(["Accounts", *table(["Account", "Current org", "Org change", "Changes",
                                                 "Lost", "Degraded", "Unobserved"], rows)])
        access = [e for e in self._monitor_changes
                  if e.text("change") in ("ORIGINAL_SHARE_DROPPED", "SHARE_ADDED")]
        others = [e for e in self._monitor_changes if e not in access]
        if access:
            sections.append(["Access changes (expected while accounts move; not losses)",
                             *self._change_lines(access)])
        if others:
            body = ["Changes and incomplete checks"]
            added = [e for e in others if e.text("change") == "ADDED"]
            for item in others:
                change = item.text("change")
                if change == "ADDED" and len(added) > DETAIL_LIMIT:
                    continue
                detail = item.raw.replace("phase=monitor ", "", 1).replace(f"change={change} ", "", 1)
                body += wrap(f"- {CHANGE_LABELS.get(change, change)}: {detail}", "  ", "    ")
            if len(added) > DETAIL_LIMIT:
                body += wrap(f"- Added: {counted(Counter(i.text('kind') for i in added), kind_label)}"
                             " that the baseline did not hold", "  ", "    ")
            sections.append(body)
        attention: list[str] = []
        for account, count in sorted(self._read_gaps.get("monitor", {}).items()):
            if count:
                attention += wrap(f"- {account}: {count} read gap(s)", "  ", "    ")
        for gap in observation["gaps"]:
            attention += self._gap_lines(gap)
        for reason in self._monitor_reasons:
            attention += wrap("- " + _reason(reason), "  ", "    ")
        for label, text in self._problems:
            attention += wrap(f"- {label.replace('_', ' ')}: {describe(text)}", "  ", "    ")
        self._problems = []
        if attention:
            sections.append(["Checks needing attention", *attention])
        if observation["limited"]:
            sections.append(wrap("No resource-specific health check for these types (their RAM "
                                 "access is verified): " + counted(observation["limited"]), "", "  "))
        result: list[str] = []
        if kind == "error" and event is not None:
            result.append("Result: BLOCKED - Monitor could not run.")
            result += wrap(f"Reason: {describe(event.after('status'))}")
        elif kind == "interrupted":
            result.append("Result: INCOMPLETE - the run was interrupted.")
        elif final is not None:
            status = final.status or ""
            totals = self._monitor_numbers(final) or {}
            result.append(f"Result: {status} - {STATUS_WORDS['monitor'].get(status, '')}")
            result.append(f"  Lost: {totals.get('lost')}   Degraded: {totals.get('degraded')}   "
                          f"Unobserved: {totals.get('unobserved')}   Read gaps: {final.text('gaps')}")
            if any(totals.get(key) for key in ("original_share_drops", "shares_added", "added")):
                result.append(f"  Access changes: original grants removed="
                              f"{totals['original_share_drops']}, shares added="
                              f"{totals['shares_added']}, items added={totals['added']}")
        else:
            result.append("Result: UNKNOWN - the run ended before it reported a result.")
        if final is not None:
            record = self._record_line()
            if record:
                result.append(f"  {record}")
        code = self._exit(final.status if final is not None else None)
        if code is None and kind == "error":
            code = 1
        if code is not None:
            result.append(f"  Exit code: {code}")
        if kind == "error":
            result += wrap("Next step: Resolve the problem above, then run monitor again.", "", "  ")
        elif final is not None:
            result.append(f"Next step: {NEXT_STEPS[('monitor', None)]}")
        else:
            result.append("Next step: Check the messages above, then run monitor again.")
        sections.append(result)
        return sections

    # approve ----------------------------------------------------------------------------

    def _approve_sections(self) -> list[list[str]]:
        sections: list[list[str]] = []
        proposal, self._proposal = self._proposal, None
        if proposal is not None:
            event = proposal["event"]
            body = [f"Owner scope to approve ({event.text('owner-scope')}): "
                    f"{event.text('proposed_owners').replace(',', ', ')}"]
            rows = []
            for owner in proposal["owners"]:
                types = re.search(r"types=\[(.*)\]$", owner.raw)
                rows.append([owner.text("owner"), owner.text("unique_resources"),
                             owner.text("shares"), owner.text("pending_shares"),
                             owner.text("regions").replace(",", ", "),
                             accounts_text(owner.text("consumers").split(",")),
                             types.group(1) if types else ""])
            if rows:
                body += table(["Owner", "Resources", "Shares", "Pending", "Regions",
                               "Migrating accounts", "Types"], rows)
            for note in proposal["notes"]:
                body += wrap(note)
            sections.append(body)
        to_accept, self._to_accept = self._to_accept, []
        if to_accept:
            body = [f"Blockers to accept ({len(to_accept)})"]
            for number, event in enumerate(to_accept, 1):
                text, category = event.after("consequence"), event.text("category")
                lead = f"{number}. {event.text('blocker')}  "
                body += wrap(lead + f"{CATEGORY_TITLES.get(category, category)} [{category}]: "
                             f"{_short(describe(text), 60)}", "  ", "     ")
                body += wrap(f"Consequence if accepted: {event.text('consequence')}", "     ",
                             "       ")
                body += wrap(f"Full text: {text}", "     ", "       ")
            reason = getattr(self.args, "accept_reason", None)
            if reason:
                body += wrap(f"Reason recorded with each acceptance: {reason}")
            sections.append(body)
        refused, self._refused = self._refused, []
        if refused:
            body = [f"NOT ACCEPTABLE ({len(refused)}): resolve these blockers instead"]
            for event in refused:
                text, category = event.after("why"), event.text("category")
                body += wrap(f"- {event.text('blocker')}  {CATEGORY_TITLES.get(category, category)} "
                             f"[{category}]: {_short(describe(text), 60)}", "  ", "    ")
                body += wrap(f"Why: {event.text('why')}", "    ", "      ")
                body += wrap(f"Full text: {text}", "    ", "      ")
            sections.append(body)
        already, self._already_accepted = self._already_accepted, []
        if already:
            sections.append(wrap(f"Already accepted: {', '.join(already)}", "", "  "))
        accepted, self._accepted_now = self._accepted_now, []
        if accepted:
            sections.append(wrap(f"Accepted and recorded: {', '.join(accepted)}", "", "  "))
        return sections


__all__ = ["ReadableReporter", "Event", "BLOCKER_PATTERNS", "blocker_category", "describe",
           "exclusion_reason"]
