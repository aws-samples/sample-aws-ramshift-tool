"""Read-only inventory and conservative entitlement planning."""
from __future__ import annotations

import json
import re
import urllib.request
from dataclasses import dataclass, field
from typing import Any

import yaml
from botocore.exceptions import ClientError

from ram_migration_common import (
    ACCOUNT, Group, MigrationError, Plan, Router, account_id, error_text,
    managed, pages, tags,
)

CATALOG = "https://docs.aws.amazon.com/ram/latest/userguide/shareable.md"
ACCOUNT_ROOT = re.compile(r"^arn:([a-z0-9-]+):iam::([0-9]{12}):root$")
SERVICE_PRINCIPAL = re.compile(r"^[a-z0-9][a-z0-9.-]*\.amazonaws\.com(?:\.cn)?$")


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
        remainder = re.sub(r"!\[[^\n]*?\]\([^)]*\)", "", cell).strip().lower()
        if codes and (yes == no or remainder not in ("", "yes" if yes else "no")):
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


def policy_semantics(policy: str | dict) -> Any:
    """Canonicalize IAM set-valued fields without relaxing policy constraints."""
    document = json.loads(policy) if isinstance(policy, str) else policy
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
                 overrides: dict, capabilities: dict[str, bool]):
        for consumer in consumers:
            account_id(consumer)
        self.router, self.consumers, self.migration = router, consumers, migration
        self.overrides, self.capabilities = overrides, capabilities

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
                        if prior["ResourceType"] != kind or prior["Policy"] != default["Policy"]:
                            raise MigrationError(f"Non-default permission differs: {permission['arn']}")
                    permission_map[kind] = permission["arn"]
                    snapshots[kind] = default
                available: dict[str, str] = {}
                for resource in resources:
                    resource_arn, kind = resource["arn"], resource["type"]
                    if resource.get("status") != "AVAILABLE":
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
                                      permission_map, available, [arn], snapshots, source_stacks)
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
