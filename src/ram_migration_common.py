"""Authentication, data models and read/write boundaries for RAM migration."""
from __future__ import annotations

import hashlib
import json
import re
import threading
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Callable

import boto3
import botocore.session
from botocore.config import Config
from botocore.credentials import RefreshableCredentials
from botocore.exceptions import ClientError, InvalidConfigError, ProfileNotFound
from botocore.tokens import SSOTokenProvider

PURPOSE = "TemporaryMigrationRAMShares"
TOOL_VERSION = "0.2.0"
CONFIG = Config(retries={"mode": "adaptive", "max_attempts": 8},
                connect_timeout=10, read_timeout=30)
ACCOUNT = re.compile(r"^\d{12}$")
ROLE_ARN = re.compile(r"^arn:(aws|aws-us-gov|aws-cn):iam::(\d{12}):role/[\w+=,.@/-]+$")
READ_PREFIXES = ("get_", "list_", "describe_", "search_", "validate_", "lookup_", "filter_")


class MigrationError(RuntimeError):
    pass


def account_id(value: str) -> str:
    if not isinstance(value, str) or not ACCOUNT.fullmatch(value):
        raise MigrationError(f"Invalid account ID: {value!r}; use a 12-digit string")
    return value


def digest(value: Any, length: int = 16) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True).encode()).hexdigest()[:length]


def timestamp() -> str:
    return datetime.now(timezone.utc).isoformat()


def error_text(exc: Exception) -> str:
    if isinstance(exc, ClientError):
        data = exc.response
        return (f"{data['Error']['Code']}: {data['Error']['Message']} "
                f"(request {data.get('ResponseMetadata', {}).get('RequestId', 'unknown')})")
    return str(exc)


def pages(client: Any, operation: str, key: str, **kwargs: Any) -> list:
    """Support paginated operations even when no SDK paginator is defined."""
    output: list = []
    seen: set[str] = set()
    while True:
        result = getattr(client, operation)(**kwargs)
        output.extend(result.get(key, []))
        token = result.get("nextToken") or result.get("NextToken")
        if not token:
            return output
        if token in seen:
            raise MigrationError(f"Repeated pagination token: {operation}")
        seen.add(token)
        token_name = "nextToken" if result.get("nextToken") else "NextToken"
        kwargs[token_name] = token


class Api:
    """A mandatory API boundary: dry-run clients reject all mutations."""
    def __init__(self, client: Any, write: bool = False):
        self._client, self._write = client, write
        self.meta = client.meta

    def __getattr__(self, name: str):
        if not name.startswith(READ_PREFIXES) and not self._write:
            raise MigrationError(f"Read-only mode rejected API operation {name}")
        return getattr(self._client, name)


@dataclass
class Group:
    owner: str
    region: str
    consumers: tuple[str, ...]
    permissions: dict[str, str]
    resources: dict[str, str] = field(default_factory=dict)
    source_shares: list[str] = field(default_factory=list)

    @property
    def key(self) -> str:
        return digest([self.owner, self.region, self.consumers, self.permissions])

    @property
    def logical_id(self) -> str:
        return "Share" + self.key


@dataclass
class Plan:
    migration: str
    groups: list[Group] = field(default_factory=list)
    blocked: list[str] = field(default_factory=list)
    excluded: list[str] = field(default_factory=list)
    existing: list[dict] = field(default_factory=list)
    # Per-share managed-permission differences (original attached version ->
    # current default), whether or not an approval covers them.
    permission_changes: list[dict] = field(default_factory=list)

    def merge(self, other: "Plan") -> None:
        grouped = {g.key: g for g in self.groups}
        for group in other.groups:
            if group.key in grouped:
                prior = grouped[group.key]
                prior.resources.update(group.resources)
                prior.source_shares = sorted(set(prior.source_shares + group.source_shares))
                if hasattr(prior, "permission_changes") or hasattr(group, "permission_changes"):
                    merged = {c["share"] + c["permission_arn"]: c for c in
                              getattr(prior, "permission_changes", [])
                              + getattr(group, "permission_changes", [])}
                    prior.permission_changes = [merged[k] for k in sorted(merged)]
            else:
                self.groups.append(group)
                grouped[group.key] = group
        self.blocked += other.blocked
        self.excluded += other.excluded
        self.existing += other.existing
        self.permission_changes += other.permission_changes

    def to_dict(self) -> dict:
        return asdict(self)


def tags(items: list[dict]) -> dict[str, str]:
    """Normalize CloudFormation's Key/Value and RAM's key/value tag shapes."""
    values = {}
    for item in items:
        key = item.get("Key", item.get("key"))
        value = item.get("Value", item.get("value"))
        if not isinstance(key, str) or not isinstance(value, str):
            raise MigrationError("Malformed ownership tags returned by AWS")
        normalized = key.lower()
        if normalized in values:
            raise MigrationError(f"Ambiguous ownership tag: {key}")
        values[normalized] = value
    return values


def managed(items: list[dict], migration: str | None = None) -> bool:
    values = tags(items)
    return (values.get("purpose") == PURPOSE
            and (migration is None or values.get("migrationid") == migration))


def check_sdk() -> None:
    model = botocore.session.get_session().get_service_model("ram")
    creation = model.operation_model("CreateResourceShare").input_shape
    cfg = creation.members.get("resourceShareConfiguration")
    shares = model.operation_model("GetResourceShares").output_shape.members["resourceShares"]
    readback = shares.member.members.get("resourceShareConfiguration")
    if not cfg or not readback or \
            "retainSharingOnAccountLeaveOrganization" not in cfg.members or \
            "retainSharingOnAccountLeaveOrganization" not in readback.members:
        raise MigrationError("SDK lacks RAM retention write/readback support; use the isolated environment")


def refresh_session(refresh: Callable[[], dict]) -> boto3.Session:
    bc = botocore.session.get_session()
    bc._credentials = RefreshableCredentials.create_from_metadata(
        metadata=refresh(), refresh_using=refresh, method="ram-migration")
    return boto3.Session(botocore_session=bc)


class Router:
    """Route by verified account identity; never invent or modify role trusts."""
    def __init__(self, profiles: list[str], mappings: dict[str, str],
                 role_name: str | None = None, sso_role: str = "AdministratorAccess"):
        self.profiles, self.mappings = profiles, mappings
        self.role_name, self.sso_role = role_name, sso_role
        self._sessions: dict[str, boto3.Session] = {}
        self._bases: list[boto3.Session] = []
        self._lock = threading.RLock()
        self.identity_profiles: dict[str, str] = {}
        if not profiles:
            raise MigrationError("Supply at least one authenticated AWS profile")
        for account, value in mappings.items():
            account_id(account)
            if not isinstance(value, str) or not value:
                raise MigrationError(f"{account}: profile/role mapping must be a nonempty string")
            if value.startswith("arn:"):
                role = ROLE_ARN.fullmatch(value)
                if role is None or role.group(2) != account:
                    raise MigrationError(f"{account}: mapping must be an IAM role ARN for this account")
        for name in profiles:
            try:
                base = boto3.Session(profile_name=name)
                identity = base.client("sts", region_name=base.region_name or "us-east-1",
                                       config=CONFIG).get_caller_identity()
            except (InvalidConfigError, ProfileNotFound) as exc:
                raise MigrationError(
                    f"{name}: complete 'aws configure sso --profile {name}' and select "
                    "the intended account and administrator role") from exc
            self._bases.append(base)
            account = identity["Account"]
            if account not in mappings or mappings[account] == name:
                self._sessions[account] = base
            self.identity_profiles[identity["Account"]] = name

    def session(self, account: str) -> boto3.Session:
        account_id(account)
        with self._lock:
            if account in self._sessions:
                return self._sessions[account]
            if account in self.mappings:
                value = self.mappings[account]
                if value.startswith("arn:"):
                    candidate = self._assume(value)
                else:
                    candidate = boto3.Session(profile_name=value)
            else:
                candidate = None
                failures = []
                for base in self._bases:
                    try:
                        candidate = self._sso_account(base, account)
                        break
                    except Exception as exc:
                        failures.append(f"{base.profile_name}: {error_text(exc)}")
                if candidate is None and self.role_name:
                    candidate = self._assume(f"arn:aws:iam::{account}:role/{self.role_name}")
                if candidate is None:
                    raise MigrationError(
                        f"{account}: supply an account/profile or role mapping; "
                        + "; ".join(failures))
            identity = candidate.client("sts", config=CONFIG).get_caller_identity()
            if identity["Account"] != account:
                raise MigrationError(f"Caller identity mismatch for {account}")
            self._sessions[account] = candidate
            return candidate

    def _assume(self, arn: str) -> boto3.Session:
        failures = []
        for base in self._bases:
            try:
                sts = base.client("sts", config=CONFIG)
                def refresh(sts=sts):
                    value = sts.assume_role(RoleArn=arn, RoleSessionName="ram-migration",
                                            DurationSeconds=3600)["Credentials"]
                    return {"access_key": value["AccessKeyId"],
                            "secret_key": value["SecretAccessKey"],
                            "token": value["SessionToken"],
                            "expiry_time": value["Expiration"].isoformat()}
                return refresh_session(refresh)
            except ClientError as exc:
                failures.append(f"{base.profile_name}: {error_text(exc)}")
        raise MigrationError(f"Unable to assume configured role {arn}; " + "; ".join(failures))

    def _sso_account(self, base: boto3.Session, account: str) -> boto3.Session:
        if not self.sso_role:
            raise MigrationError("Supply --sso-role or an explicit account/profile or role mapping")
        profile = base.profile_name
        config = base._session.full_config["profiles"].get(profile, {})
        session_name = config.get("sso_session")
        sso = base._session.full_config.get("sso_sessions", {}).get(session_name, config)
        if not sso.get("sso_start_url") or not sso.get("sso_region"):
            raise MigrationError("Base profile is not SSO-enabled")
        provider = SSOTokenProvider(base._session, profile_name=profile)
        token = provider.load_token()
        if token is None:
            raise MigrationError("SSO login required")
        client = base.client("sso", region_name=sso["sso_region"], config=CONFIG)

        def refresh():
            value = client.get_role_credentials(
                accountId=account, roleName=self.sso_role,
                accessToken=token.get_frozen_token().token)["roleCredentials"]
            expiry = datetime.fromtimestamp(value["expiration"] / 1000, timezone.utc)
            return {"access_key": value["accessKeyId"], "secret_key": value["secretAccessKey"],
                    "token": value["sessionToken"], "expiry_time": expiry.isoformat()}
        return refresh_session(refresh)

    def client(self, account: str, service: str, region: str,
               write: bool = False) -> Api:
        with self._lock:
            return Api(self.session(account).client(service, region_name=region, config=CONFIG), write)
