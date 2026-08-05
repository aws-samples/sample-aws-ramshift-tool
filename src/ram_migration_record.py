"""Versioned migration record shared by plan, approve, apply, verify and monitor.

One JSON document per migration ID. ``plan`` writes the reviewed scope and its
blockers, ``approve`` adds bound approvals, ``apply`` captures the original
baseline once and records created shares, ``verify`` appends verification
results. Every write is a new revision in a hash-chained history; a record that
was edited outside the tool fails its integrity check and is refused.
"""
from __future__ import annotations

import contextlib
import copy
import fcntl
import getpass
import hashlib
import json
import os
import socket
from collections import defaultdict
from pathlib import Path
from typing import Any, Callable

from ram_migration_common import TOOL_VERSION, MigrationError, timestamp

SCHEMA = "ram-migration-record/1"
SOURCES = (
    "temporary_migration_ram_shares.py", "ram_migration_common.py",
    "ram_migration_discovery.py", "ram_migration_stacks.py",
    "ram_migration_monitor.py", "ram_migration_record.py",
    "ram_migration_verification.py",
)
# Plan revisions whose scope apply may consume.
APPLICABLE = "PLANNED"


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def tool_identity() -> dict:
    root = Path(__file__).resolve().parent
    hashes = {}
    for name in SOURCES:
        path = root / name
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    return {"version": TOOL_VERSION, "sources_sha256": hashes, "sources_digest": sha256(hashes)}


def operator() -> dict:
    """Local operator identity for the audit trail; never credentials."""
    try:
        user = getpass.getuser()
    except Exception:  # pragma: no cover - platform dependent
        user = None
    try:
        host = socket.gethostname()
    except OSError:  # pragma: no cover - platform dependent
        host = None
    return {"user": user, "host": host}


def new_record(migration: str) -> dict:
    return {
        "schema": SCHEMA,
        "migration_id": migration,
        "revision": 0,
        "created_at": timestamp(),
        "updated_at": None,
        "tool": tool_identity(),
        "scope": None,
        "plan": None,
        "permission_change_requests": [],
        "owner_scope_request": None,
        "approvals": {"permission_changes": [], "owner_scope": []},
        "baseline": None,
        "shares": [],
        "verifications": [],
        "drops": [],
        "completion": None,
        "history": [],
    }


DROP_KINDS = ("original_share", "association", "entitlement", "tgw_attachment", "tgw_route",
              "ipam_allocation", "pca_access", "resolver_endpoint")


def drop_id(kind: str, consumer: str | None, region: str | None, subject: str,
            first_absent_at: str) -> str:
    return hashlib.sha256("|".join(
        [kind, consumer or "", region or "", subject, first_absent_at]).encode()).hexdigest()[:16]


def add_drops(record: dict, drops: list[dict]) -> int:
    """Append drop events once each; failure drops are permanent evidence."""
    known = {d["id"] for d in record.setdefault("drops", [])}
    added = 0
    for drop in drops:
        if drop.get("kind") not in DROP_KINDS or drop.get("severity") not in (
                "informational", "failure"):
            raise MigrationError(f"Unsupported drop event: {drop.get('kind')}/{drop.get('severity')}")
        if drop["kind"] == "original_share" and drop["severity"] != "informational":
            raise MigrationError("Original-share drops are informational")
        if drop["kind"] != "original_share" and drop["severity"] != "failure":
            raise MigrationError("Association and resource drops are failures")
        if drop["id"] not in known:
            record["drops"].append(dict(drop))
            known.add(drop["id"])
            added += 1
    return added


def failure_drops(record: dict) -> list[dict]:
    return [d for d in record.get("drops", []) if d.get("severity") == "failure"]


def _content_digest(record: dict) -> str:
    return sha256({k: v for k, v in record.items() if k != "content_sha256"})


def load(path: Path, migration: str | None = None) -> dict:
    try:
        text = Path(path).read_text(encoding="utf-8")
    except FileNotFoundError:
        raise MigrationError(f"{path}: migration record not found; run plan --record first") from None
    except OSError as exc:
        raise MigrationError(f"{path}: unable to read migration record: {exc}") from exc
    try:
        record = json.loads(text)
    except ValueError as exc:
        raise MigrationError(f"{path}: migration record is not valid JSON") from exc
    if not isinstance(record, dict) or record.get("schema") != SCHEMA:
        raise MigrationError(f"{path}: unsupported migration record schema")
    if record.get("content_sha256") != _content_digest(record):
        raise MigrationError(f"{path}: migration record integrity check failed; it was changed "
                             "outside this tool. Restore the last tool-written revision.")
    if migration is not None and record.get("migration_id") != migration:
        raise MigrationError(f"{path}: record belongs to migration {record.get('migration_id')!r}, "
                             f"not {migration!r}; approvals never transfer between migrations")
    history = record.get("history")
    if not isinstance(history, list) or len(history) != record.get("revision"):
        raise MigrationError(f"{path}: migration record history is incomplete")
    previous = None
    for index, entry in enumerate(history, 1):
        if entry.get("revision") != index or entry.get("previous_sha256") != previous:
            raise MigrationError(f"{path}: migration record history chain is broken at revision {index}")
        previous = entry.get("sha256")
    return record


@contextlib.contextmanager
def _locked(path: Path):
    """Serialize writers (plan, approve, apply, verify, monitor, complete)."""
    lock = Path(path).with_name(f".{Path(path).name}.lock")
    with lock.open("a") as handle:
        fcntl.flock(handle, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(handle, fcntl.LOCK_UN)


def update(path: Path, migration: str, mutate: Callable[[dict], Any], *, mode: str,
           status: str, create: bool = False, **details: Any) -> dict:
    """Read-modify-write the latest revision under a lock.

    Writers express their change as ``mutate(record)`` against the current
    on-disk revision, so a long-running monitor or apply never overwrites
    history or approvals written by another command in the meantime.
    """
    path = Path(path)
    with _locked(path):
        if create and not path.exists():
            record = new_record(migration)
        else:
            record = load(path, migration)
        mutate(record)
        return _write(path, record, mode=mode, status=status, **details)


def save(path: Path, record: dict, *, mode: str, status: str, **details: Any) -> dict:
    """Write ``record`` as the next revision if nobody else wrote in between."""
    path = Path(path)
    with _locked(path):
        if path.exists():
            current = load(path, record.get("migration_id"))
            if current.get("revision") != record.get("revision"):
                raise MigrationError(f"{path}: record changed concurrently (revision "
                                     f"{current.get('revision')} on disk, {record.get('revision')} "
                                     "in memory); re-run the command")
        return _write(path, record, mode=mode, status=status, **details)


def _write(path: Path, record: dict, *, mode: str, status: str, **details: Any) -> dict:
    """Write the next revision atomically; history entries are never rewritten."""
    record = copy.deepcopy(record)
    record["revision"] = int(record.get("revision", 0)) + 1
    record["updated_at"] = timestamp()
    record["tool"] = tool_identity()
    history = record.setdefault("history", [])
    entry = {
        "revision": record["revision"], "mode": mode, "status": status,
        "at": record["updated_at"], "tool_version": TOOL_VERSION,
        "tool_sources_digest": record["tool"]["sources_digest"],
        "operator": operator(), **details,
        "previous_sha256": history[-1]["sha256"] if history else None,
    }
    body = {k: v for k, v in record.items() if k not in ("content_sha256", "history")}
    entry["sha256"] = sha256([entry["previous_sha256"], body,
                              {k: v for k, v in entry.items() if k != "sha256"}])
    history.append(entry)
    record["content_sha256"] = _content_digest(record)
    path = Path(path)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    temporary.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)
    return record


def latest(record: dict, *modes: str) -> dict | None:
    for entry in reversed(record.get("history", [])):
        if entry.get("mode") in modes:
            return entry
    return None


# ---------------------------------------------------------------------------
# Plan identity
# ---------------------------------------------------------------------------

def group_identity(group: Any) -> dict:
    return {
        "owner": group.owner, "region": group.region,
        "consumers": sorted(group.consumers),
        "permissions": dict(sorted(group.permissions.items())),
        "resources": dict(sorted(group.resources.items())),
        "source_shares": sorted(set(group.source_shares)),
        "permission_changes": sorted({c["approval_id"] for c in
                                      getattr(group, "permission_changes", [])}),
    }


def plan_digest(groups: list, scope: dict) -> str:
    """What apply would write, plus the reviewed account-role scope."""
    return sha256({"groups": sorted((group_identity(g) for g in groups),
                                    key=lambda item: canonical(item)),
                   "scope": scope})


# ---------------------------------------------------------------------------
# Permission-change approvals
# ---------------------------------------------------------------------------

CHANGE_FIELDS = ("permission_arn", "resource_type", "from_version", "to_version",
                 "from_policy_sha256", "to_policy_sha256")


def permission_requests(migration: str, changes: list[dict]) -> list[dict]:
    """Aggregate per-share changes into approval requests bound to their shares."""
    grouped: dict[tuple, list[dict]] = defaultdict(list)
    for change in changes:
        grouped[tuple(change[f] for f in CHANGE_FIELDS)].append(change)
    requests = []
    for key, items in sorted(grouped.items()):
        body = {"migration_id": migration, **dict(zip(CHANGE_FIELDS, key)),
                "shares": sorted({item["share"] for item in items})}
        requests.append({
            "id": "pc-" + sha256(body)[:16], **body,
            "owners": sorted({item["owner"] for item in items}),
            "regions": sorted({item["region"] for item in items}),
            "difference": items[0]["difference"],
            "from_policy": items[0]["from_policy"],
            "to_policy": items[0]["to_policy"],
        })
    return requests


def approval_for(approvals: list[dict], migration: str, change: dict) -> dict | None:
    """An approval covers a change only for the same migration, exact versions,
    exact policy hashes and an explicitly listed share."""
    for approval in approvals:
        if approval.get("migration_id") == migration and \
                all(approval.get(f) == change.get(f) for f in CHANGE_FIELDS) and \
                change.get("share") in approval.get("shares", []):
            return approval
    return None


def pending_requests(record: dict) -> list[dict]:
    approvals = record.get("approvals", {}).get("permission_changes", [])
    pending = []
    for request in record.get("permission_change_requests", []):
        uncovered = [s for s in request["shares"]
                     if approval_for(approvals, record["migration_id"],
                                     {**request, "share": s}) is None]
        if uncovered:
            pending.append(request)
    return pending


def approve_permission_change(record: dict, request: dict) -> dict:
    if request.get("migration_id") != record.get("migration_id"):
        raise MigrationError("Permission change request belongs to another migration")
    approval = {
        "approval_id": request["id"],
        **{f: request[f] for f in ("migration_id", *CHANGE_FIELDS, "shares")},
        "difference_sha256": sha256(request["difference"]),
        "approved_at": timestamp(),
        "approved_by": operator(),
        "approved_in_revision": record.get("revision", 0) + 1,
        "basis": "interactive confirmation of the displayed policy comparison",
    }
    record.setdefault("approvals", {}).setdefault("permission_changes", []).append(approval)
    return approval


# ---------------------------------------------------------------------------
# Owner-scope approvals
# ---------------------------------------------------------------------------

def owner_scope_request(migration: str, proposed: dict[str, dict]) -> dict | None:
    if not proposed:
        return None
    body = {"migration_id": migration,
            "owners": sorted(proposed),
            "evidence": {owner: proposed[owner] for owner in sorted(proposed)}}
    return {"id": "os-" + sha256(body)[:16], **body}


def approved_owners(record: dict) -> set[str]:
    owners: set[str] = set()
    for approval in record.get("approvals", {}).get("owner_scope", []):
        if approval.get("migration_id") == record.get("migration_id"):
            owners.update(approval.get("owners", []))
    return owners


def approve_owner_scope(record: dict, request: dict) -> dict:
    if request.get("migration_id") != record.get("migration_id"):
        raise MigrationError("Owner-scope request belongs to another migration")
    approval = {
        "approval_id": request["id"], "migration_id": request["migration_id"],
        "owners": list(request["owners"]), "evidence_sha256": sha256(request["evidence"]),
        "approved_at": timestamp(), "approved_by": operator(),
        "approved_in_revision": record.get("revision", 0) + 1,
        "basis": "interactive confirmation of the proposed owner list; execution scope "
                 "expands only when plan is re-run with these owners and their access mappings",
    }
    record.setdefault("approvals", {}).setdefault("owner_scope", []).append(approval)
    return approval
