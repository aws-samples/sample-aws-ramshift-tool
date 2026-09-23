"""Versioned migration record shared by plan, approve, apply, verify and monitor.

One JSON document per migration ID. ``plan`` writes the reviewed scope and its
blockers, ``approve`` adds bound owner-scope approvals, ``apply`` captures the
original baseline once and records created shares, ``verify`` appends
verification results. Every write is a new revision in a hash-chained history.
Each history entry carries the digest of the record as written in its revision
and hashes only its own fields, and ``load`` re-verifies the whole chain and the
current content before anything uses the record.

Plain SHA-256 makes the record tamper-evident against accidental edits only:
anyone who can write the file can recompute every hash. With a record key in
``RAM_MIGRATION_RECORD_KEY`` (or in the file named by
``RAM_MIGRATION_RECORD_KEY_FILE``) every write also adds an HMAC-SHA256 that
only the key holder can produce, and every load requires it. The contract is
RAM_MIGRATION_RECORD.md section 1.
"""
from __future__ import annotations

import contextlib
import copy
import fcntl
import getpass
import hashlib
import hmac
import json
import os
import socket
from pathlib import Path
from typing import Any, Callable

from ram_migration_common import TOOL_VERSION, MigrationError, timestamp

SCHEMA = "ram-migration-record/2"
# Records written before history entries carried body_sha256. They still load,
# with their chain verified as far as that format allows, and the next write
# upgrades them to SCHEMA.
LEGACY_SCHEMA = "ram-migration-record/1"
SOURCES = (
    "temporary_migration_ram_shares.py", "ram_migration_common.py",
    "ram_migration_discovery.py", "ram_migration_stacks.py",
    "ram_migration_record.py",
    "ram_migration_verification.py", "ram_migration_preflight.py",
)
# Plan revisions whose scope apply may consume.
APPLICABLE = "PLANNED"
# Optional record key: the secret itself, or the path of a file holding it.
# The key is never written to the record.
KEY_ENV = "RAM_MIGRATION_RECORD_KEY"
KEY_FILE_ENV = "RAM_MIGRATION_RECORD_KEY_FILE"
MIN_KEY_BYTES = 16
HMAC_ALGORITHM = "hmac-sha256"
# Top-level fields that protect the content and so are not part of it.
INTEGRITY_FIELDS = ("content_sha256", "content_hmac")


def canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def sha256(value: Any) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _source_identity() -> dict:
    root = Path(__file__).resolve().parent
    hashes = {}
    for name in SOURCES:
        path = root / name
        hashes[name] = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    return {"version": TOOL_VERSION, "sources_sha256": hashes, "sources_digest": sha256(hashes)}


# Hashed once, when the tool starts and imports this module, so the identity
# describes the code that is running. A source file edited or replaced while a
# long plan or apply runs cannot change the digest that run records or compares.
_TOOL_IDENTITY = _source_identity()


def tool_identity() -> dict:
    """Tool version and source digests as of start-up; a fresh copy on every call."""
    return copy.deepcopy(_TOOL_IDENTITY)


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
        "owner_scope_request": None,
        # Records of earlier versions also hold permission_change_requests and
        # approvals.permission_changes; they load, and are kept as history but never read.
        "approvals": {"owner_scope": [], "blockers": []},
        "baseline": None,
        "shares": [],
        "verifications": [],
        "drops": [],
        # complete's per-consumer retirement of temporary access; see retired_consumers.
        "retirements": [],
        "completion": None,
        # Set only when a schema /1 record is upgraded; see _write.
        "legacy_history": None,
        "history": [],
    }


DROP_KINDS = ("original_share", "association", "entitlement", "tgw_attachment", "tgw_route",
              "ipam_allocation", "pca_access", "resolver_endpoint")


def drop_id(kind: str, consumer: str | None, region: str | None, subject: str,
            first_absent_at: str) -> str:
    return hashlib.sha256("|".join(
        [kind, consumer or "", region or "", subject, first_absent_at]).encode()).hexdigest()[:16]


def add_drops(record: dict, drops: list[dict]) -> int:
    """Append each drop once; failure drops are permanent evidence. A drop of the same
    kind, consumer, Region and subject as a recorded one keeps the first detection, so
    repeated verify and monitor runs never duplicate it."""
    known = {d["id"] for d in record.setdefault("drops", [])}
    known |= {_drop_identity(d) for d in record["drops"]}
    added = 0
    for drop in drops:
        if drop.get("kind") not in DROP_KINDS or drop.get("severity") not in (
                "informational", "failure"):
            raise MigrationError(f"Unsupported drop event: {drop.get('kind')}/{drop.get('severity')}")
        if drop["kind"] == "original_share" and drop["severity"] != "informational":
            raise MigrationError("Original-share drops are informational")
        if drop["kind"] != "original_share" and drop["severity"] != "failure":
            raise MigrationError("Association and resource drops are failures")
        if drop["id"] not in known and _drop_identity(drop) not in known:
            record["drops"].append(dict(drop))
            known |= {drop["id"], _drop_identity(drop)}
            added += 1
    return added


def _drop_identity(drop: dict) -> tuple:
    return (drop.get("kind"), drop.get("consumer"), drop.get("region"), drop.get("subject"))


def retired_pairs(record: dict) -> set[tuple[str, str]]:
    """(share ARN, consumer) of every retirement entry: each temporary share complete has
    retired each consumer from."""
    return {(row.get("share_arn"), row.get("consumer")) for row in record.get("retirements") or []}


def retired_consumers(record: dict) -> set[str]:
    """Migrating consumers whose temporary access complete has retired from every recorded
    temporary share that served them. ``retirements`` holds one entry per (share,
    consumer): {consumer, owner, region, logical_id, share_arn, action, at, forced}, where
    action is PRINCIPAL_REMOVED (the share still serves other consumers) or SHARE_DELETED."""
    done = retired_pairs(record)
    serving: dict[str, set[str]] = {}
    for share in record.get("shares", []):
        if share.get("share_arn"):
            for consumer in share.get("consumers", []):
                serving.setdefault(consumer, set()).add(share["share_arn"])
    return {consumer for consumer, arns in serving.items()
            if all((arn, consumer) in done for arn in arns)}


def failure_drops(record: dict) -> list[dict]:
    return [d for d in record.get("drops", []) if d.get("severity") == "failure"]


# ---------------------------------------------------------------------------
# Integrity and authentication
# ---------------------------------------------------------------------------

def _content(record: dict) -> bytes:
    """The bytes content_sha256 and content_hmac cover: the whole document, history included."""
    return canonical({k: v for k, v in record.items() if k not in INTEGRITY_FIELDS})


def _content_digest(record: dict) -> str:
    return hashlib.sha256(_content(record)).hexdigest()


def _body(record: dict) -> dict:
    """The record as written in one revision: everything but its history and integrity fields."""
    return {k: v for k, v in record.items() if k not in (*INTEGRITY_FIELDS, "history")}


def _entry_digest(entry: dict) -> str:
    """A current-format entry hashes only its own fields, so it verifies on its own."""
    return sha256({k: v for k, v in entry.items() if k != "sha256"})


def _legacy_entry_digest(entry: dict, record: dict) -> str:
    """A schema /1 entry hashed the body of its own revision. Only the latest revision of a
    record still in schema /1 has that body, so only that entry can be recomputed."""
    return sha256([entry.get("previous_sha256"), _body(record),
                   {k: v for k, v in entry.items() if k != "sha256"}])


def _record_key() -> bytes | None:
    """The record key from the environment, read on every use; None when none is set."""
    value, name = os.environ.get(KEY_ENV), os.environ.get(KEY_FILE_ENV)
    if value is not None and name is not None:
        raise MigrationError(f"set {KEY_ENV} or {KEY_FILE_ENV}, not both")
    if name is not None:
        try:
            key = Path(name).read_bytes().strip()
        except OSError as exc:
            raise MigrationError(f"{KEY_FILE_ENV}: unable to read the record key file: {exc}") from exc
    elif value is not None:
        key = os.fsencode(value).strip()
    else:
        return None
    if len(key) < MIN_KEY_BYTES:
        raise MigrationError(f"{KEY_FILE_ENV if name is not None else KEY_ENV}: the record key must "
                             f"be at least {MIN_KEY_BYTES} bytes; generate one with "
                             "'openssl rand -hex 32'")
    return key


def _key_id(key: bytes) -> str:
    """Names a key in the record and in errors without revealing it."""
    return hmac.new(key, b"ram-migration-record key id", hashlib.sha256).hexdigest()[:16]


def _content_hmac(key: bytes, content: bytes) -> str:
    return hmac.new(key, content, hashlib.sha256).hexdigest()


def _history_signer(history: Any) -> str | None:
    """Key ID of the latest history entry that was written with a record key."""
    for entry in reversed(history if isinstance(history, list) else []):
        if isinstance(entry, dict) and entry.get("hmac_key_id"):
            return str(entry["hmac_key_id"])
    return None


def _tampered(path: Path, detail: str) -> MigrationError:
    return MigrationError(f"{path}: migration record integrity check failed; it was changed "
                          f"outside this tool. Restore the last tool-written revision. ({detail})")


def _authenticate(path: Path, record: dict, content: bytes) -> None:
    """With a key set, require a content_hmac that verifies; without one, refuse a signed record."""
    key = _record_key()
    mac = record.get("content_hmac")
    signer = _history_signer(record.get("history"))
    if key is None:
        if mac is not None or signer is not None:
            claimed = (mac.get("key_id") if isinstance(mac, dict) else None) or signer
            raise MigrationError(f"{path}: migration record is authenticated with record key "
                                 f"{claimed}; set {KEY_ENV} or {KEY_FILE_ENV} to that key to load it")
        return
    if mac is None:
        if signer is not None:
            raise _tampered(path, f"content_hmac is missing, but revisions were written with "
                                  f"record key {signer}")
        raise MigrationError(f"{path}: migration record is not authenticated, but a record key is "
                             "set; a record written without a key is never trusted once one is set. "
                             f"Continue a migration started without a key with neither {KEY_ENV} "
                             f"nor {KEY_FILE_ENV} set")
    key_id = _key_id(key)
    if not isinstance(mac, dict) or mac.get("algorithm") != HMAC_ALGORITHM or \
            not isinstance(mac.get("value"), str):
        raise _tampered(path, "content_hmac is malformed")
    if mac.get("key_id") != key_id:
        raise MigrationError(f"{path}: migration record is authenticated with record key "
                             f"{mac.get('key_id')}, not with the configured key {key_id}")
    if not hmac.compare_digest(mac["value"].encode(), _content_hmac(key, content).encode()):
        raise _tampered(path, "content_hmac does not verify with the record key")


def _verify_history(path: Path, record: dict) -> None:
    """Every link, every current-format entry hash, and the latest entry against the content."""
    history, revision = record.get("history"), record.get("revision")
    if not isinstance(history, list) or type(revision) is not int or revision < 1 or \
            len(history) != revision:
        raise _tampered(path, "history is incomplete")
    if record.get("schema") == LEGACY_SCHEMA:
        legacy = revision  # every entry predates per-entry body digests
    elif record.get("legacy_history") is None:
        legacy = 0  # created in the current format
    else:
        pinned = record["legacy_history"]
        legacy = pinned.get("revisions") if isinstance(pinned, dict) else None
        if type(legacy) is not int or not 0 < legacy < revision or \
                pinned.get("sha256") != sha256(history[:legacy]):
            raise _tampered(path, "legacy_history does not match the history")
    previous = None
    for index, entry in enumerate(history, 1):
        if not isinstance(entry, dict) or entry.get("revision") != index:
            problem = "the entry is missing or out of sequence"
        elif entry.get("previous_sha256") != previous:
            problem = "previous_sha256 does not match the previous entry"
        elif ("body_sha256" in entry) != (index > legacy):
            problem = "the entry format does not match the record"
        elif index > legacy and entry.get("sha256") != _entry_digest(entry):
            problem = "sha256 does not match the entry"
        else:
            previous = entry.get("sha256")
            continue
        raise _tampered(path, f"history chain is broken at revision {index}: {problem}")
    head = history[-1]
    if legacy < revision:
        problem = None if head.get("body_sha256") == sha256(_body(record)) else \
            "body_sha256 does not match the record"
    else:
        problem = None if head.get("sha256") == _legacy_entry_digest(head, record) else \
            "sha256 does not match the entry and the record"
    if problem:
        raise _tampered(path, f"history chain is broken at revision {revision}: {problem}")


def load(path: Path, migration: str | None = None) -> dict:
    """Read a record and verify all of it; refuse anything this tool did not write."""
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
    if not isinstance(record, dict) or record.get("schema") not in (SCHEMA, LEGACY_SCHEMA):
        raise MigrationError(f"{path}: unsupported migration record schema")
    content = _content(record)
    if record.get("content_sha256") != hashlib.sha256(content).hexdigest():
        raise _tampered(path, "content_sha256 does not match the content")
    _authenticate(path, record, content)
    if migration is not None and record.get("migration_id") != migration:
        raise MigrationError(f"{path}: record belongs to migration {record.get('migration_id')!r}, "
                             f"not {migration!r}; approvals never transfer between migrations")
    _verify_history(path, record)
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
    """Write ``record`` as the next revision only if the file still holds the revision
    ``record`` was read from.

    The check compares the content digest as well as the revision number: a record
    that was deleted and re-created, or restored from a copy, can reach the same
    revision number with other content. A record whose file has gone is never
    re-created from memory.
    """
    path = Path(path)
    with _locked(path):
        if not path.exists():
            if int(record.get("revision") or 0) > 0:
                raise MigrationError(f"{path}: migration record is missing, but the record being "
                                     f"saved is at revision {record.get('revision')}; it was moved or "
                                     "deleted after it was read. Restore it, then re-run the command")
        else:
            current = load(path, record.get("migration_id"))
            if current.get("revision") != record.get("revision"):
                change = (f"revision {current.get('revision')} on disk, {record.get('revision')} "
                          "in memory")
            elif current.get("content_sha256") != record.get("content_sha256"):
                change = f"revision {current.get('revision')} on disk has different content"
            else:
                change = None
            if change:
                raise MigrationError(f"{path}: record changed concurrently ({change}); "
                                     "re-run the command")
        return _write(path, record, mode=mode, status=status, **details)


def _write(path: Path, record: dict, *, mode: str, status: str, **details: Any) -> dict:
    """Write the next revision atomically and durably; history entries are never rewritten.

    A schema /1 record is upgraded: its entries stay as they were written and are
    pinned by ``legacy_history``, and every later entry is in the current format.
    """
    key = _record_key()
    key_id = None if key is None else _key_id(key)
    path = Path(path)
    record = copy.deepcopy(record)
    history = record.setdefault("history", [])
    signer = _history_signer(history)
    if signer is not None and signer != key_id:
        raise MigrationError(f"{path}: the record is authenticated with record key {signer}; "
                             f"set {KEY_ENV} or {KEY_FILE_ENV} to that key to write it")
    if record.get("schema") == LEGACY_SCHEMA and history:
        record["legacy_history"] = {"schema": LEGACY_SCHEMA, "revisions": len(history),
                                    "sha256": sha256(history)}
    record.setdefault("legacy_history", None)
    record.pop("content_hmac", None)
    record["schema"] = SCHEMA
    record["revision"] = int(record.get("revision", 0)) + 1
    record["updated_at"] = timestamp()
    record["tool"] = tool_identity()
    entry = {
        **details,
        # The tool's own fields follow the writer's details, which never replace them.
        "revision": record["revision"], "mode": mode, "status": status,
        "at": record["updated_at"], "tool_version": TOOL_VERSION,
        "tool_sources_digest": record["tool"]["sources_digest"], "operator": operator(),
        "previous_sha256": history[-1]["sha256"] if history else None,
        "body_sha256": sha256(_body(record)),
        "hmac_key_id": key_id,
    }
    entry["sha256"] = _entry_digest(entry)
    history.append(entry)
    content = _content(record)
    record["content_sha256"] = hashlib.sha256(content).hexdigest()
    if key is not None:
        record["content_hmac"] = {"algorithm": HMAC_ALGORITHM, "key_id": key_id,
                                  "value": _content_hmac(key, content)}
    _replace(path, (json.dumps(record, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    return record


def _sync(fd: int) -> None:
    """fsync, then F_FULLFSYNC where the platform has it: on macOS fsync alone can
    leave the data in the drive's cache."""
    os.fsync(fd)
    full = getattr(fcntl, "F_FULLFSYNC", None)
    if full is not None:
        with contextlib.suppress(OSError):  # unsupported, e.g. on network filesystems
            fcntl.fcntl(fd, full)


def _sync_directory(directory: Path) -> None:
    fd = os.open(directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        _sync(fd)
    finally:
        os.close(fd)


def _replace(path: Path, data: bytes) -> None:
    """Replace ``path`` so that, even after a crash, it holds either the previous revision or
    this one, complete. The temporary file never outlives a failure."""
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    replaced = False
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0),
                     0o666)
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            _sync(handle.fileno())
        _sync_directory(path.parent)
        os.replace(temporary, path)
        replaced = True
        _sync_directory(path.parent)
    except BaseException as exc:
        if not replaced:
            with contextlib.suppress(OSError):
                temporary.unlink()
        if not isinstance(exc, OSError):
            raise
        state = ("the new revision is in place but may not survive a crash" if replaced
                 else "the previous revision is unchanged")
        raise MigrationError(f"{path}: unable to write the migration record durably ({exc}); "
                             f"{state}") from exc


def latest(record: dict, *modes: str) -> dict | None:
    for entry in reversed(record.get("history", [])):
        if entry.get("mode") in modes:
            return entry
    return None


# ---------------------------------------------------------------------------
# Plan identity
# ---------------------------------------------------------------------------

def group_identity(group: Any) -> dict:
    result = {
        "owner": group.owner, "region": group.region,
        "consumers": sorted(group.consumers),
        "permissions": dict(sorted(group.permissions.items())),
        "resources": dict(sorted(group.resources.items())),
        "source_shares": sorted(set(group.source_shares)),
    }
    stationary = getattr(group, "stationary_consumers", ())
    if stationary:
        result["stationary_consumers"] = sorted(stationary)
    return result


def plan_digest(groups: list, scope: dict) -> str:
    """What apply would write, plus the reviewed account-role scope."""
    return sha256({"groups": sorted((group_identity(g) for g in groups),
                                    key=lambda item: canonical(item)),
                   "scope": scope})


# ---------------------------------------------------------------------------
# Owner-scope approvals, the only approvals: a managed-permission difference needs none
# ---------------------------------------------------------------------------

def owner_scope_request(migration: str, proposed: dict[str, dict]) -> dict | None:
    if not proposed:
        return None
    body = {"migration_id": migration,
            "owners": sorted(proposed),
            "evidence": {owner: proposed[owner] for owner in sorted(proposed)}}
    return {"id": "os-" + sha256(body)[:16], **body}


def accepted_blockers(record: dict) -> dict[str, dict]:
    """Blocker acceptances by blocker ID; see record_acceptances."""
    return {row["blocker_id"]: row for row in (record.get("approvals") or {}).get("blockers", [])}


def record_acceptances(record: dict, rows: list[dict]) -> list[str]:
    """Append each acceptance once: {blocker_id, category, blocker, consequence,
    accepted_reason, accepted_at, plan_revision}. An acceptance is bound to the blocker's
    exact text (its ID): a blocker that changes is a new blocker and needs its own."""
    accepted = record.setdefault("approvals", {}).setdefault("blockers", [])
    known = {row["blocker_id"] for row in accepted}
    added = []
    for row in rows:
        if row["blocker_id"] not in known:
            accepted.append(dict(row))
            known.add(row["blocker_id"])
            added.append(row["blocker_id"])
    return added


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
