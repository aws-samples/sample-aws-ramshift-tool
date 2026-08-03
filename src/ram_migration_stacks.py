"""Additive migration-stack creation and full entitlement verification."""
from __future__ import annotations

import copy
import json
import time

import yaml
from botocore.exceptions import ClientError

from ram_migration_common import (
    PURPOSE, Group, MigrationError, Router, account_id, digest, managed, pages, tags,
)
from ram_migration_discovery import ApprovedGroup, CfnLoader, permission_snapshot, policy_semantics


def stack_name(migration: str, owner: str, region: str) -> str:
    return f"{PURPOSE}-{owner}-{region}-{digest(migration, 8)}"


def template_for(groups: list[Group], migration: str) -> dict:
    resources = {}
    for group in groups:
        account_id(group.owner)
        if not group.resources or not group.consumers or \
                tuple(sorted(set(group.consumers))) != group.consumers or \
                group.owner in group.consumers:
            raise MigrationError("Migration group requires resources and distinct sorted consumers")
        for consumer in group.consumers:
            account_id(consumer)
        if set(group.resources.values()) != set(group.permissions):
            raise MigrationError("Group permissions do not exactly match its resource types")
        for arn in group.resources:
            _owner_arn(arn, group.owner)
        if not group.source_shares:
            raise MigrationError("Migration group has no source lineage")
        if group.logical_id in resources:
            raise MigrationError("Duplicate group identity; merge compatible groups before templating")
        changes = _changes_metadata(group)
        resources[group.logical_id] = {
            "Type": "AWS::RAM::ResourceShare",
            "DeletionPolicy": "Retain",
            "UpdateReplacePolicy": "Retain",
            "Properties": {
                "Name": f"{PURPOSE}-{group.owner}-{group.region}-{digest(migration, 8)}-{group.key}",
                "AllowExternalPrincipals": True,
                "ResourceShareConfiguration": {"RetainSharingOnAccountLeaveOrganization": True},
                "Principals": list(group.consumers),
                "ResourceArns": sorted(group.resources),
                "PermissionArns": sorted(set(group.permissions.values())),
                "Tags": [
                    {"Key": "Purpose", "Value": PURPOSE},
                    {"Key": "MigrationId", "Value": migration},
                    {"Key": "OwnerAccount", "Value": group.owner},
                    {"Key": "EntitlementHash", "Value": group.key},
                    {"Key": "RetirementPolicy", "Value": "VerifyReplacementAccessFirst"},
                ],
            },
            "Metadata": {
                "SourceShareArns": sorted(set(group.source_shares)),
                "SourceStackIds": sorted(set(getattr(group, "source_stacks", []))),
                "OwnerRegion": group.region,
                "ResourceTypes": dict(sorted(group.resources.items())),
                "PermissionTypes": dict(group.permissions),
                "PermissionSnapshots": copy.deepcopy(getattr(group, "permission_snapshots", {})),
            },
        }
        if changes:
            resources[group.logical_id]["Metadata"]["PermissionChanges"] = changes
    return {"AWSTemplateFormatVersion": "2010-09-09",
            "Description": "Additive RAM migration sharing; underlying resources are never created here.",
            "Resources": resources}


CHANGE_KEYS = ("SourceShareArn", "PermissionArn", "ResourceType", "FromVersion",
               "ToVersion", "FromPolicySha256", "ToPolicySha256", "ApprovalId")
_CHANGE_FIELDS = ("share", "permission_arn", "resource_type", "from_version",
                  "to_version", "from_policy_sha256", "to_policy_sha256", "approval_id")


def _changes_metadata(group: Group) -> list[dict]:
    """Owner-side, durable evidence of each approved permission change."""
    rows = []
    for change in getattr(group, "permission_changes", []):
        row = dict(zip(CHANGE_KEYS, (change[f] for f in _CHANGE_FIELDS)))
        if row["SourceShareArn"] not in group.source_shares or \
                group.permissions.get(row["ResourceType"]) != row["PermissionArn"]:
            raise MigrationError("Approved permission change does not belong to its entitlement group")
        rows.append(row)
    return sorted(rows, key=lambda r: (r["SourceShareArn"], r["PermissionArn"]))


def changes_from_metadata(metadata: dict) -> list[dict]:
    return [dict(zip(_CHANGE_FIELDS, (row[k] for k in CHANGE_KEYS)))
            for row in metadata.get("PermissionChanges", [])]


def _owner_arn(arn: str, owner: str) -> None:
    parts = arn.split(":")
    if len(parts) < 6 or parts[0] != "arn" or parts[4] != owner:
        raise MigrationError("Resource ARN does not belong to its approved owner")


def _validate_resource(logical: str, item: dict, migration: str,
                       owner: str | None = None) -> None:
    properties = item.get("Properties", {})
    values = tags(properties.get("Tags", []))
    resource_owner = values.get("owneraccount")
    if item.get("Type") != "AWS::RAM::ResourceShare" or \
            not managed(properties.get("Tags", []), migration) or \
            not resource_owner or (owner is not None and resource_owner != owner):
        raise MigrationError(f"Unowned resource in migration template: {logical}")
    account_id(resource_owner)
    identity = values.get("entitlementhash")
    if not identity or logical != "Share" + identity:
        raise MigrationError(f"Invalid entitlement identity in migration template: {logical}")
    if item.get("DeletionPolicy") != "Retain" or item.get("UpdateReplacePolicy") != "Retain":
        raise MigrationError(f"{logical}: migration resource lacks Retain protection")
    if set(item) - {"Type", "Properties", "Metadata", "DeletionPolicy", "UpdateReplacePolicy"}:
        raise MigrationError(f"{logical}: unsupported migration resource attributes")
    if set(properties) != {"Name", "AllowExternalPrincipals", "ResourceShareConfiguration",
                           "Principals", "ResourceArns", "PermissionArns", "Tags"}:
        raise MigrationError(f"{logical}: unsupported migration properties")
    if properties["AllowExternalPrincipals"] is not True or \
            properties["ResourceShareConfiguration"] != {
                "RetainSharingOnAccountLeaveOrganization": True}:
        raise MigrationError(f"{logical}: unsafe retention/external-sharing configuration")
    for field in ("Principals", "ResourceArns", "PermissionArns"):
        value = properties[field]
        if not isinstance(value, list) or not value or \
                any(not isinstance(v, str) or not v for v in value) or \
                len(value) != len(set(value)):
            raise MigrationError(f"{logical}: invalid or duplicate {field}")
    for principal in properties["Principals"]:
        account_id(principal)
        if principal == resource_owner:
            raise MigrationError(f"{logical}: owning account is not a consumer")
    for arn in properties["ResourceArns"]:
        _owner_arn(arn, resource_owner)
    if not isinstance(properties["Name"], str) or not properties["Name"].startswith(PURPOSE + "-"):
        raise MigrationError(f"{logical}: share name has no migration provenance")
    lineage = item.get("Metadata", {}).get("SourceShareArns")
    if not isinstance(lineage, list) or not lineage or any(not isinstance(a, str) for a in lineage):
        raise MigrationError(f"{logical}: source lineage missing")
    metadata = item["Metadata"]
    region, kinds, permissions = (metadata.get("OwnerRegion"), metadata.get("ResourceTypes"),
                                 metadata.get("PermissionTypes"))
    if not isinstance(region, str) or not region or not isinstance(kinds, dict) or \
            not isinstance(permissions, dict) or set(kinds) != set(properties["ResourceArns"]) or \
            any(not isinstance(k, str) or not k for k in kinds.values()) or \
            set(kinds.values()) != set(permissions) or \
            set(permissions.values()) != set(properties["PermissionArns"]):
        raise MigrationError(f"{logical}: approved resource/permission metadata is incomplete")
    identity_group = Group(resource_owner, region, tuple(sorted(properties["Principals"])),
                           permissions, kinds, lineage)
    expected_name = (f"{PURPOSE}-{resource_owner}-{region}-{digest(migration, 8)}-"
                     f"{identity_group.key}")
    if identity_group.logical_id != logical or properties["Name"] != expected_name:
        raise MigrationError(f"{logical}: entitlement identity does not match its approved scope")
    snapshots = metadata.get("PermissionSnapshots", {})
    if not isinstance(snapshots, dict):
        raise MigrationError(f"{logical}: invalid permission approval metadata")
    if snapshots:
        if set(snapshots) != set(permissions) or any(
                not isinstance(snapshots[k], dict) or snapshots[k].get("Arn") != permissions[k] or
                snapshots[k].get("ResourceType") != k or not snapshots[k].get("Version") or
                "Policy" not in snapshots[k] for k in permissions):
            raise MigrationError(f"{logical}: permission approval does not match its approved scope")
        for snapshot in snapshots.values():
            policy_semantics(snapshot["Policy"])
    changes = metadata.get("PermissionChanges", [])
    if not isinstance(changes, list) or any(
            not isinstance(row, dict) or set(row) != set(CHANGE_KEYS) or
            any(not isinstance(row[key], str) or not row[key] for key in CHANGE_KEYS) or
            row["SourceShareArn"] not in lineage or
            permissions.get(row["ResourceType"]) != row["PermissionArn"] or
            (snapshots and snapshots.get(row["ResourceType"], {}).get("Version") != row["ToVersion"])
            for row in changes):
        raise MigrationError(f"{logical}: permission-change approval metadata does not match its scope")
    if len({(row["SourceShareArn"], row["PermissionArn"]) for row in changes}) != len(changes):
        raise MigrationError(f"{logical}: duplicate permission-change approval metadata")


def _validate_template(template: dict, migration: str, owner: str | None = None) -> None:
    if not isinstance(template, dict) or not isinstance(template.get("Resources"), dict):
        raise MigrationError("Migration template has no Resources mapping")
    if set(template) - {"AWSTemplateFormatVersion", "Description", "Resources", "Metadata"}:
        raise MigrationError("Migration template contains unsupported transforms or configuration")
    for logical, item in template["Resources"].items():
        _validate_resource(logical, item, migration, owner)


def additive_template(old: dict, new: dict, migration: str) -> dict:
    """Retain prior groups/resources/consumers even when discovery scope shrinks."""
    _validate_template(old, migration)
    _validate_template(new, migration)
    result = copy.deepcopy(old)
    old_resources = result.setdefault("Resources", {})
    for logical, fresh in new["Resources"].items():
        if logical not in old_resources:
            old_resources[logical] = copy.deepcopy(fresh)
            continue
        prior = old_resources[logical]
        properties = prior.get("Properties", {})
        for field in ("Name", "PermissionArns", "ResourceShareConfiguration",
                      "AllowExternalPrincipals", "Principals", "Tags"):
            if properties.get(field) != fresh["Properties"][field]:
                raise MigrationError(f"Existing share differs in immutable/permission field {field}")
        properties["ResourceArns"] = sorted(set(properties["ResourceArns"] +
                                               fresh["Properties"]["ResourceArns"]))
        lineage = prior.setdefault("Metadata", {}).setdefault("SourceShareArns", [])
        prior["Metadata"]["SourceShareArns"] = sorted(set(lineage + fresh["Metadata"]["SourceShareArns"]))
        prior_metadata, fresh_metadata = prior["Metadata"], fresh["Metadata"]
        prior_metadata["SourceStackIds"] = sorted(set(
            prior_metadata.get("SourceStackIds", []) + fresh_metadata.get("SourceStackIds", [])))
        resource_types = prior_metadata.setdefault("ResourceTypes", {})
        for arn, kind in fresh_metadata.get("ResourceTypes", {}).items():
            if arn in resource_types and resource_types[arn] != kind:
                raise MigrationError(f"{logical}: resource type changed")
            resource_types[arn] = kind
        before, after = (prior_metadata.get("PermissionSnapshots", {}),
                         fresh_metadata.get("PermissionSnapshots", {}))
        if before and after:
            if set(before) != set(after) or any(
                    before[k]["Arn"] != after[k]["Arn"] or before[k]["Policy"] != after[k]["Policy"]
                    for k in before):
                raise MigrationError(f"{logical}: approved managed permission policy changed")
        if not before and after:
            raise MigrationError(f"{logical}: existing permission approval missing; reconcile explicitly")
        recorded = {(row["SourceShareArn"], row["PermissionArn"]): row
                    for row in prior_metadata.get("PermissionChanges", [])}
        for row in fresh_metadata.get("PermissionChanges", []):
            key = (row["SourceShareArn"], row["PermissionArn"])
            if key in recorded and recorded[key] != row:
                raise MigrationError(f"{logical}: recorded permission-change approval differs")
            recorded[key] = row
        if recorded:
            prior_metadata["PermissionChanges"] = [recorded[k] for k in sorted(recorded)]
    return result


def validate_changes(changes: list[dict], proposed: dict, previous: dict | None) -> None:
    """Only additions and non-replacing resource-list growth may be executed."""
    before = (previous or {}).get("Resources", {})
    after = proposed["Resources"]
    if not set(before) <= set(after):
        raise MigrationError("Existing migration resources cannot be removed")
    for entry in changes:
        change = entry.get("ResourceChange", {})
        logical = change.get("LogicalResourceId")
        action = change.get("Action")
        if entry.get("Type") != "Resource" or \
                change.get("ResourceType") != "AWS::RAM::ResourceShare" or \
                logical not in after or action not in ("Add", "Modify") or \
                change.get("Replacement") in ("True", "Conditional") or \
                change.get("PolicyAction") not in (None, "Retain"):
            raise MigrationError(f"Unsafe migration change set rejected: {logical}")
        if action == "Add":
            if logical in before:
                raise MigrationError(f"{logical}: cannot recreate an existing migration share")
            continue
        if logical not in before or change.get("Replacement") != "False":
            raise MigrationError(f"{logical}: replacement safety was not established")
        old_properties, new_properties = before[logical]["Properties"], after[logical]["Properties"]
        for key in set(old_properties) | set(new_properties):
            if key == "ResourceArns":
                if not set(old_properties[key]) <= set(new_properties[key]):
                    raise MigrationError(f"{logical}: resource removal rejected")
            elif old_properties.get(key) != new_properties.get(key):
                raise MigrationError(f"{logical}: property/permission change rejected: {key}")
        scope = set(change.get("Scope", []))
        if not scope <= {"Properties", "Metadata", "DeletionPolicy", "UpdateReplacePolicy"}:
            raise MigrationError(f"{logical}: unsupported change scope")
        details = change.get("Details", [])
        if "Properties" in scope and not details:
            raise MigrationError(f"{logical}: property change details are missing")
        for detail in details:
            target = detail.get("Target", {})
            attribute = target.get("Attribute")
            if target.get("RequiresRecreation") not in (None, "Never") or \
                    detail.get("Evaluation") not in (None, "Static"):
                raise MigrationError(f"{logical}: unresolved or replacing property change")
            if attribute == "Properties":
                if target.get("Name") != "ResourceArns":
                    raise MigrationError(f"{logical}: permission or unapproved property change rejected")
                if target.get("AttributeChangeType") == "Remove":
                    raise MigrationError(f"{logical}: resource removal rejected")
                path = target.get("Path")
                if path is not None and path != "/Properties/ResourceArns" and \
                        not path.startswith("/Properties/ResourceArns/"):
                    raise MigrationError(f"{logical}: conflicting property change path")
            elif attribute not in {"Metadata", "DeletionPolicy", "UpdateReplacePolicy"}:
                raise MigrationError(f"{logical}: unsupported change detail")


class Stacks:
    def __init__(self, router: Router, migration: str, timeout: int = 1800):
        self.router, self.migration, self.timeout = router, migration, timeout

    def existing(self, owner: str, region: str):
        cfn = self.router.client(owner, "cloudformation", region)
        name = stack_name(self.migration, owner, region)
        try:
            stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
        except ClientError as exc:
            if exc.response["Error"]["Code"] == "ValidationError" and \
                    "does not exist" in exc.response["Error"]["Message"].lower():
                return None
            raise
        if not managed(stack.get("Tags", []), self.migration):
            raise MigrationError(f"Stack name belongs to an unowned stack: {name}")
        recorded_owner = tags(stack["Tags"]).get("owneraccount")
        if recorded_owner is not None and recorded_owner != owner:
            raise MigrationError(f"Migration stack owner does not match {owner}")
        return stack

    def _template(self, owner: str, region: str, stack: dict) -> dict:
        body = self.router.client(owner, "cloudformation", region).get_template(
            StackName=stack["StackId"], TemplateStage="Processed")["TemplateBody"]
        template = yaml.load(body, Loader=CfnLoader) if isinstance(body, str) else body
        _validate_template(template, self.migration, owner)
        for logical, item in template["Resources"].items():
            if item["Metadata"]["OwnerRegion"] != region:
                raise MigrationError(f"{logical}: migration template belongs to another Region")
            if not item["Metadata"].get("PermissionSnapshots"):
                raise MigrationError(f"{logical}: existing permission approval missing; reconcile explicitly")
        return template

    def prepare(self, owner: str, region: str, groups: list[Group]) -> tuple[dict, dict | None]:
        old = self.existing(owner, region)
        if any(g.owner != owner or g.region != region for g in groups):
            raise MigrationError("Migration group does not belong to the selected owner/Region")
        fresh = template_for(groups, self.migration)
        if old is not None and old["StackStatus"] not in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
            raise MigrationError(
                f"{old['StackStatus']}: existing migration stack cannot be retried automatically; "
                "inspect and explicitly reconcile the failed/pending operation. "
                "Successful partial resources remain retained; do not delete the stack.")
        ram = self.router.client(owner, "ram", region)
        for group in groups:
            metadata = fresh["Resources"][group.logical_id]["Metadata"]
            snapshots = metadata["PermissionSnapshots"]
            for kind, arn in group.permissions.items():
                current = permission_snapshot(ram, arn)
                if current["ResourceType"] != kind or not current["DefaultVersion"]:
                    raise MigrationError(f"{arn}: permission resource type/default version differs")
                approved = snapshots.get(kind)
                if approved is not None and (approved["Arn"] != arn or
                                             approved["Policy"] != current["Policy"]):
                    raise MigrationError(f"{arn}: managed permission changed since plan approval")
                snapshots[kind] = current
        if old is None:
            return fresh, old
        previous = self._template(owner, region, old)
        return additive_template(previous, fresh, self.migration), old

    def persisted_groups(self, owner: str, region: str) -> list[Group]:
        """Recover the approved entitlement matrix from its owning CFN template."""
        stack = self.existing(owner, region)
        if stack is None:
            raise MigrationError("Migration stack does not exist")
        template = self._template(owner, region, stack)
        ram = self.router.client(owner, "ram", region)
        groups = []
        for logical, item in template["Resources"].items():
            properties, metadata = item["Properties"], item["Metadata"]
            approved_snapshots = metadata.get("PermissionSnapshots", {})
            if not approved_snapshots:
                raise MigrationError(f"{logical}: approved permission policies missing from owning template")
            permissions, snapshots = {}, {}
            for arn in properties["PermissionArns"]:
                matches = [s for s in approved_snapshots.values() if s.get("Arn") == arn]
                if len(matches) != 1:
                    raise MigrationError(f"{logical}: ambiguous approved permission ARN")
                approved = matches[0]
                current = permission_snapshot(ram, arn, approved["Version"])
                kind = current["ResourceType"]
                if approved.get("ResourceType") != kind or \
                        policy_semantics(approved["Policy"]) != current["Policy"] or kind in permissions:
                    raise MigrationError(f"{logical}: approved permission policy/type differs")
                permissions[kind], snapshots[kind] = arn, approved
            if set(approved_snapshots) != set(permissions):
                raise MigrationError(f"{logical}: extra permission approvals in owning template")
            rows = pages(ram, "list_resources", "resources", resourceOwner="SELF",
                         resourceArns=properties["ResourceArns"])
            resources = _resource_inventory(rows, set(properties["ResourceArns"]), owner, region,
                                            owner_side=True)
            recorded_types = metadata.get("ResourceTypes")
            if recorded_types is not None and recorded_types != resources:
                raise MigrationError(f"{logical}: resource types differ from owning template")
            if set(resources.values()) != set(permissions):
                raise MigrationError(f"{logical}: permissions do not match actual RAM resource types")
            if metadata["PermissionTypes"] != permissions:
                raise MigrationError(f"{logical}: permission type metadata differs from RAM permissions")
            group = ApprovedGroup(owner, region, tuple(sorted(properties["Principals"])),
                                  permissions, resources, metadata["SourceShareArns"], snapshots,
                                  metadata.get("SourceStackIds", []),
                                  permission_changes=changes_from_metadata(metadata))
            if group.logical_id != logical:
                raise MigrationError(f"{logical}: template entitlement identity does not match approved grants")
            groups.append(group)
        return groups

    def apply(self, owner: str, region: str, groups: list[Group]) -> str:
        body, old = self.prepare(owner, region, groups)
        text = json.dumps(body, sort_keys=True)
        if len(text.encode()) > 51200:
            raise MigrationError("Migration template exceeds inline CFN limit; split the scope explicitly")
        cfn = self.router.client(owner, "cloudformation", region, write=True)
        previous = self._template(owner, region, old) if old is not None else None
        name = stack_name(self.migration, owner, region)
        change_name = "ram-" + digest(body) + "-" + str(time.time_ns())
        changes = cfn.create_change_set(
            StackName=name, ChangeSetName=change_name, ChangeSetType="UPDATE" if old else "CREATE",
            TemplateBody=text, Description="Additive RAM migration shares",
            Tags=[{"Key": "Purpose", "Value": PURPOSE},
                  {"Key": "MigrationId", "Value": self.migration},
                  {"Key": "OwnerAccount", "Value": owner},
                  {"Key": "RetirementPolicy", "Value": "VerifyReplacementAccessFirst"}])
        deadline = time.monotonic() + self.timeout
        while True:
            status = cfn.describe_change_set(ChangeSetName=changes["Id"], StackName=name)
            if status["Status"] == "FAILED":
                reason = status.get("StatusReason", "")
                if old is not None and ("didn't contain changes" in reason or
                                        "No updates are to be performed" in reason):
                    return name
                raise MigrationError(f"{name}: change set failed: {reason}")
            if status["Status"] == "CREATE_COMPLETE":
                break
            if time.monotonic() >= deadline:
                raise MigrationError(f"{name}: change set timeout; retained for inspection")
            time.sleep(3)
        change_rows = pages(cfn, "describe_change_set", "Changes",
                            ChangeSetName=changes["Id"], StackName=name, IncludePropertyValues=True)
        validate_changes(change_rows, body, previous)
        cfn.execute_change_set(ChangeSetName=changes["Id"], StackName=name, DisableRollback=True)
        next_update = 0.0
        while True:
            stack = cfn.describe_stacks(StackName=name)["Stacks"][0]
            state = stack["StackStatus"]
            if state in ("CREATE_COMPLETE", "UPDATE_COMPLETE"):
                return name
            if not state.endswith("_IN_PROGRESS"):
                raise MigrationError(f"{name}: {state}; successful resources retained. "
                                     f"{stack.get('StackStatusReason', '')}")
            if time.monotonic() >= deadline:
                raise MigrationError(f"{name}: timeout; stack continues and can be resumed")
            if time.monotonic() >= next_update:
                print(f"{owner}/{region}: {name} {state}", flush=True)
                next_update = time.monotonic() + 30
            time.sleep(5)

    def shares(self, owner: str, region: str) -> dict[str, dict]:
        stack = self.existing(owner, region)
        if stack is None:
            raise MigrationError("Migration stack does not exist")
        cfn = self.router.client(owner, "cloudformation", region)
        template = self._template(owner, region, stack)
        rows = pages(cfn, "list_stack_resources", "StackResourceSummaries", StackName=stack["StackId"])
        ram = self.router.client(owner, "ram", region)
        result = {}
        for row in rows:
            if row["ResourceType"] != "AWS::RAM::ResourceShare":
                raise MigrationError("Non-RAM resource in migration stack")
            arn = row.get("PhysicalResourceId")
            if not arn:
                raise MigrationError(f"Migration resource not created: {row['LogicalResourceId']}")
            shares = pages(ram, "get_resource_shares", "resourceShares",
                           resourceOwner="SELF", resourceShareArns=[arn])
            logical = row["LogicalResourceId"]
            if logical not in template["Resources"] or len(shares) != 1 or \
                    not managed(shares[0].get("tags", []), self.migration):
                raise MigrationError("Migration resource ownership verification failed")
            share = shares[0]
            values = tags(share.get("tags", []))
            if share.get("owningAccountId") != owner or \
                    share.get("resourceShareArn") != arn or \
                    values.get("owneraccount") != owner or \
                    values.get("entitlementhash") != logical.removeprefix("Share") or \
                    share.get("name") != template["Resources"][logical]["Properties"]["Name"]:
                raise MigrationError("Migration share provenance differs from owning template")
            if logical in result:
                raise MigrationError("Duplicate migration stack resource")
            result[logical] = share
        if set(result) != set(template["Resources"]):
            raise MigrationError("Migration stack resource inventory is incomplete")
        return result


def accept(router: Router, consumer: str, region: str, allowed: dict[str, str]) -> None:
    """Accept only planned share ARNs from the exact planned sender accounts."""
    account_id(consumer)
    for owner in allowed.values():
        account_id(owner)
    if not allowed:
        return
    ram = router.client(consumer, "ram", region, write=True)
    invitations = pages(ram, "get_resource_share_invitations", "resourceShareInvitations")
    for invitation in invitations:
        arn = invitation["resourceShareArn"]
        if arn not in allowed:
            continue
        if invitation["senderAccountId"] != allowed[arn] or \
                invitation["receiverAccountId"] != consumer:
            raise MigrationError("Invitation owner/receiver mismatch")
        state = invitation["status"]
        if state == "PENDING":
            ram.accept_resource_share_invitation(
                resourceShareInvitationArn=invitation["resourceShareInvitationArn"])
        elif state in ("EXPIRED", "REJECTED"):
            raise MigrationError(f"{arn}: {state}; reissue this script-owned invitation explicitly")
        elif state != "ACCEPTED":
            raise MigrationError(f"{arn}: unexpected invitation status {state}")


def _resource_inventory(rows: list[dict], expected: set[str], owner: str,
                        region: str, *, owner_side: bool = False) -> dict[str, str]:
    resources = {}
    for row in rows:
        arn, kind = row.get("arn"), row.get("type")
        # ListResources(resourceOwner=SELF) omits status; consumer rows must say AVAILABLE.
        status = row.get("status", "AVAILABLE" if owner_side else None)
        if arn not in expected or not isinstance(kind, str) or not kind or \
                status != "AVAILABLE":
            raise MigrationError("RAM resource inventory differs from the approved available resources")
        _owner_arn(arn, owner)
        arn_region = arn.split(":")[3]
        if arn_region and arn_region != region:
            raise MigrationError("RAM resource Region differs from its migration share")
        if arn in resources and resources[arn] != kind:
            raise MigrationError("Ambiguous RAM resource type")
        resources[arn] = kind
    if set(resources) != expected:
        raise MigrationError("Approved RAM resources are missing from the resource inventory")
    return resources


def _exact_associations(rows: list[dict], expected: set[str], arn: str, kind: str) -> None:
    active = {}
    for row in rows:
        if row.get("resourceShareArn") != arn or row.get("associationType") != kind:
            raise MigrationError(f"{arn}: association belongs to a different share/type")
        if row.get("status") == "DISASSOCIATED":
            continue
        entity = row.get("associatedEntity")
        if entity in active:
            raise MigrationError(f"{arn}: ambiguous duplicate {kind.lower()} associations")
        active[entity] = row.get("status")
    if set(active) != expected:
        raise MigrationError(f"{arn}: unexpected or missing {kind.lower()} entitlements")
    if any(status != "ASSOCIATED" for status in active.values()):
        raise MigrationError(f"{arn}: {kind.lower()} associations incomplete: {active}")


def verify_group(router: Router, group: Group, share: dict, migration: str) -> None:
    arn = share["resourceShareArn"]
    _owner_arn(arn, group.owner)
    if arn.split(":")[2:4] != ["ram", group.region]:
        raise MigrationError("Migration share ARN belongs to another service/Region")
    values = tags(share.get("tags", []))
    if share.get("owningAccountId") != group.owner or not managed(share.get("tags", []), migration) or \
            values.get("owneraccount") != group.owner or values.get("entitlementhash") != group.key:
        raise MigrationError("Unexpected share owner or ownership tags")
    expected_name = f"{PURPOSE}-{group.owner}-{group.region}-{digest(migration, 8)}-{group.key}"
    if share.get("name") != expected_name:
        raise MigrationError("Unexpected migration share name")
    if share["status"] != "ACTIVE" or not share.get("allowExternalPrincipals") or \
            share.get("resourceShareConfiguration", {}).get(
                "retainSharingOnAccountLeaveOrganization") is not True:
        raise MigrationError(f"{arn}: migration configuration is not ready")
    ram = router.client(group.owner, "ram", group.region)
    permissions = pages(ram, "list_resource_share_permissions", "permissions", resourceShareArn=arn)
    actual_permissions = {}
    snapshots = getattr(group, "permission_snapshots", {})
    for permission in permissions:
        kind = permission["resourceType"]
        if kind in actual_permissions or group.permissions.get(kind) != permission["arn"] or \
                not permission.get("version"):
            raise MigrationError(f"{arn}: extra, ambiguous, or unapproved permission")
        actual_permissions[kind] = permission["arn"]
        actual = permission_snapshot(ram, permission["arn"], permission["version"])
        approved = snapshots.get(kind)
        if approved is None:
            approved = permission_snapshot(ram, permission["arn"])
            if not approved["DefaultVersion"]:
                raise MigrationError(f"{arn}: default permission version missing")
        if actual["ResourceType"] != kind or approved["Arn"] != permission["arn"] or \
                policy_semantics(approved["Policy"]) != actual["Policy"]:
            raise MigrationError(f"{arn}: permission policy/version differs for {kind}")
    if actual_permissions != group.permissions:
        raise MigrationError(f"{arn}: managed permissions do not exactly match the approved group")
    resources = pages(ram, "get_resource_share_associations", "resourceShareAssociations",
                      associationType="RESOURCE", resourceShareArns=[arn])
    _exact_associations(resources, set(group.resources), arn, "RESOURCE")
    owner_rows = pages(ram, "list_resources", "resources", resourceOwner="SELF",
                       resourceShareArns=[arn])
    if _resource_inventory(owner_rows, set(group.resources), group.owner, group.region,
                           owner_side=True) != group.resources:
        raise MigrationError(f"{arn}: actual resource types differ from approved entitlements")
    principals = pages(ram, "get_resource_share_associations", "resourceShareAssociations",
                       associationType="PRINCIPAL", resourceShareArns=[arn])
    _exact_associations(principals, set(group.consumers), arn, "PRINCIPAL")
    for consumer in group.consumers:
        target = router.client(consumer, "ram", group.region)
        visible = pages(target, "list_resources", "resources", resourceOwner="OTHER-ACCOUNTS",
                        resourceShareArns=[arn])
        if _resource_inventory(visible, set(group.resources), group.owner, group.region) != group.resources:
            raise MigrationError(f"{consumer}: resources/types differ through {arn}")
