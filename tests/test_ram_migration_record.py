"""Migration-record integrity, authentication, durability, history and approval tests (offline)."""
import errno
import fcntl
import hashlib
import hmac
import importlib.util
import json
import os
import shutil
import stat
import threading
from pathlib import Path

import pytest

import ram_migration_record as rec
from ram_migration_common import TOOL_VERSION, MigrationError, timestamp

MIGRATION = "record-test"
OTHER_MIGRATION = "other-migration"
# Test-only record keys.
KEY = "test-record-key-0123456789abcdef"
OTHER_KEY = "other-record-key-0123456789abcdef"
CHANGE = {"permission_arn": "arn:aws:ram::aws:permission/AWSRAMDefaultPermissionTransitGateway",
          "resource_type": "ec2:TransitGateway", "from_version": "2", "to_version": "3",
          "from_policy_sha256": "a" * 64, "to_policy_sha256": "b" * 64}
SHARE_1 = "arn:aws:ram:us-west-2:000000000001:resource-share/one"
SHARE_2 = "arn:aws:ram:us-west-2:000000000001:resource-share/two"


@pytest.fixture(autouse=True)
def no_record_key(monkeypatch):
    """Every test starts without a record key, whatever the caller's environment holds."""
    monkeypatch.delenv(rec.KEY_ENV, raising=False)
    monkeypatch.delenv(rec.KEY_FILE_ENV, raising=False)


def change(share, **override):
    return {**CHANGE, "owner": "000000000001", "region": "us-west-2", "share": share,
            "difference": {"actions_added": ["Allow ec2:CreateClientVpnEndpoint"]},
            "from_policy": {"Statement": []}, "to_policy": {"Statement": []}, **override}


def written(tmp_path, record=None, *, migration=MIGRATION, name="record.json"):
    path = tmp_path / name
    rec.update(path, migration, lambda r: r.update(record or {}), mode="plan",
               status="PLANNED", create=True)
    return path


def verified(path):
    return rec.update(path, MIGRATION, lambda r: None, mode="verify", status="SHARING_READY")


def approved(tmp_path, name="record.json"):
    """plan --record with one permission change, then approve it, as the CLI does."""
    request, = rec.permission_requests(MIGRATION, [change(SHARE_1)])
    path = written(tmp_path, {"permission_change_requests": [request]}, name=name)
    rec.update(path, MIGRATION, lambda r: rec.approve_permission_change(r, request),
               mode="approve", status="APPROVED", approved=[request["id"]])
    return path


def edited(path, edit):
    """Change the file outside the tool."""
    data = json.loads(path.read_text())
    edit(data)
    path.write_text(json.dumps(data))
    return data


def documented_sha256(value):
    """SHA-256 of canonical JSON, as RAM_MIGRATION_RECORD.md section 1 defines the digests."""
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def body(record):
    return {k: v for k, v in record.items() if k not in ("history", "content_sha256", "content_hmac")}


def rehash_content(data):
    """The re-hashed edit the review reproduced: recompute content_sha256 and nothing else."""
    data["content_sha256"] = documented_sha256(
        {k: v for k, v in data.items() if k not in ("content_sha256", "content_hmac")})


def rehash_everything(data):
    """All that someone without the record key can do: recompute every SHA-256."""
    data["history"][-1]["body_sha256"] = documented_sha256(body(data))
    previous = None
    for entry in data["history"]:
        entry["previous_sha256"] = previous
        entry["sha256"] = documented_sha256({k: v for k, v in entry.items() if k != "sha256"})
        previous = entry["sha256"]
    rehash_content(data)


def temporary_files(directory):
    return [p.name for p in directory.iterdir() if ".tmp-" in p.name]


# ---------------------------------------------------------------------------
# History chain and integrity
# ---------------------------------------------------------------------------

def test_round_trip_history_chain_and_integrity(tmp_path):
    path = written(tmp_path)
    verified(path)
    record = rec.load(path, MIGRATION)
    assert record["schema"] == rec.SCHEMA and record["revision"] == 2
    assert [h["mode"] for h in record["history"]] == ["plan", "verify"]
    assert record["history"][1]["previous_sha256"] == record["history"][0]["sha256"]
    assert record["tool"]["version"] == rec.TOOL_VERSION
    assert record["history"][0]["operator"]["user"]
    assert "content_hmac" not in record and record["history"][1]["hmac_key_id"] is None


def test_every_entry_verifies_on_its_own_with_the_documented_digests(tmp_path):
    path = written(tmp_path)
    revisions = [rec.load(path, MIGRATION)]
    for status in ("SHARING_READY", "SHARING_INCOMPLETE"):
        rec.update(path, MIGRATION, lambda r: r["verifications"].append(status), mode="verify",
                   status=status)
        revisions.append(rec.load(path, MIGRATION))
    record = revisions[-1]
    for entry, as_written in zip(record["history"], revisions, strict=True):
        assert entry["sha256"] == documented_sha256({k: v for k, v in entry.items() if k != "sha256"})
        # Each entry holds the digest of its own revision, so any retained copy can be checked.
        assert entry["body_sha256"] == documented_sha256(body(as_written))
    assert record["content_sha256"] == documented_sha256(
        {k: v for k, v in record.items() if k != "content_sha256"})


def test_record_edited_outside_the_tool_is_refused(tmp_path):
    path = written(tmp_path)
    data = json.loads(path.read_text())
    data["approvals"]["permission_changes"].append({"approval_id": "forged"})
    path.write_text(json.dumps(data))
    with pytest.raises(MigrationError, match="integrity check failed"):
        rec.load(path, MIGRATION)


def test_broken_history_chain_is_refused(tmp_path):
    path = written(tmp_path)
    verified(path)
    data = json.loads(path.read_text())
    data["history"][1]["previous_sha256"] = "0" * 64
    rehash_content(data)
    path.write_text(json.dumps(data))
    with pytest.raises(MigrationError, match="history chain is broken at revision 2"):
        rec.load(path, MIGRATION)


def test_approvals_moved_to_another_migration_are_refused_despite_a_recomputed_content_hash(tmp_path):
    """Review finding: retarget an approval, falsify the approver, recompute content_sha256."""
    path = approved(tmp_path)

    def retarget(data):
        data["migration_id"] = OTHER_MIGRATION
        for approval in data["approvals"]["permission_changes"]:
            approval["migration_id"] = OTHER_MIGRATION
        data["history"][1]["operator"] = {"user": "someone-else", "host": "elsewhere"}
        rehash_content(data)
    data = edited(path, retarget)
    assert rec.approval_for(data["approvals"]["permission_changes"], OTHER_MIGRATION,
                            change(SHARE_1)) is not None  # the forgery would cover the change
    with pytest.raises(MigrationError, match="integrity check failed"):
        rec.load(path, OTHER_MIGRATION)


def test_approvals_copied_between_records_are_refused_despite_a_recomputed_content_hash(tmp_path):
    source = approved(tmp_path, name="source.json")
    request, = rec.permission_requests(OTHER_MIGRATION, [change(SHARE_1)])
    target = written(tmp_path, {"permission_change_requests": [request]},
                     migration=OTHER_MIGRATION, name="target.json")
    copied = [{**approval, "migration_id": OTHER_MIGRATION}
              for approval in rec.load(source, MIGRATION)["approvals"]["permission_changes"]]

    def paste(data):
        data["approvals"]["permission_changes"] = copied
        rehash_content(data)
    edited(target, paste)
    assert rec.approval_for(copied, OTHER_MIGRATION, change(SHARE_1)) is not None
    with pytest.raises(MigrationError, match="body_sha256 does not match the record"):
        rec.load(target, OTHER_MIGRATION)


def test_request_pasted_as_an_approval_is_refused_despite_a_recomputed_content_hash(tmp_path):
    request, = rec.permission_requests(MIGRATION, [change(SHARE_1)])
    path = written(tmp_path, {"permission_change_requests": [request]})

    def paste(data):
        data["approvals"]["permission_changes"].append(dict(request))
        rehash_content(data)
    edited(path, paste)
    with pytest.raises(MigrationError, match="integrity check failed"):
        rec.load(path, MIGRATION)


def edit_plan_tool_digest(data):
    data["history"][0]["tool_sources_digest"] = "0" * 64  # the reviewed plan's sources gate


def edit_and_rehash_first_entry(data):
    data["history"][0]["status"] = "PLANNED-ELSEWHERE"
    data["history"][0]["sha256"] = documented_sha256(
        {k: v for k, v in data["history"][0].items() if k != "sha256"})


def edit_latest_status(data):
    data["history"][-1]["status"] = "PLANNED"


def edit_body_and_rehash_latest_entry(data):
    data["shares"].append({"share_arn": "forged"})
    data["history"][-1]["sha256"] = documented_sha256(
        {k: v for k, v in data["history"][-1].items() if k != "sha256"})


@pytest.mark.parametrize("edit, problem", [
    (edit_plan_tool_digest, "revision 1: sha256 does not match the entry"),
    (edit_and_rehash_first_entry, "revision 2: previous_sha256 does not match the previous entry"),
    (edit_latest_status, "revision 3: sha256 does not match the entry"),
    (edit_body_and_rehash_latest_entry, "revision 3: body_sha256 does not match the record"),
])
def test_edited_history_entry_is_refused_despite_a_recomputed_content_hash(tmp_path, edit, problem):
    path = written(tmp_path)
    verified(path)
    verified(path)

    def tamper(data):
        edit(data)
        rehash_content(data)
    edited(path, tamper)
    with pytest.raises(MigrationError, match=f"history chain is broken at {problem}"):
        rec.load(path, MIGRATION)


def strip_first_body_digest(data):
    del data["history"][0]["body_sha256"]


def claim_previous_format_prefix(data):
    strip_first_body_digest(data)
    data["legacy_history"] = {"schema": rec.LEGACY_SCHEMA, "revisions": 1,
                              "sha256": documented_sha256(data["history"][:1])}


def claim_previous_schema(data):
    data["schema"] = rec.LEGACY_SCHEMA


@pytest.mark.parametrize("edit, problem", [
    (strip_first_body_digest, "history chain is broken at revision 1: the entry format"),
    (claim_previous_format_prefix, "body_sha256 does not match the record"),
    (claim_previous_schema, "history chain is broken at revision 1: the entry format"),
])
def test_entries_cannot_be_downgraded_to_the_previous_format(tmp_path, edit, problem):
    path = written(tmp_path)
    verified(path)

    def tamper(data):
        edit(data)
        rehash_content(data)
    edited(path, tamper)
    with pytest.raises(MigrationError, match=problem):
        rec.load(path, MIGRATION)


def test_record_never_transfers_between_migrations(tmp_path):
    path = written(tmp_path)
    with pytest.raises(MigrationError, match="approvals never transfer"):
        rec.load(path, "earlier-openfinance-migration")


# ---------------------------------------------------------------------------
# Keyed authentication
# ---------------------------------------------------------------------------

def documented_key_id(key):
    return hmac.new(key.encode(), b"ram-migration-record key id", hashlib.sha256).hexdigest()[:16]


def test_record_key_authenticates_every_revision(tmp_path, monkeypatch):
    monkeypatch.setenv(rec.KEY_ENV, KEY)
    path = written(tmp_path)
    verified(path)
    record = rec.load(path, MIGRATION)
    content = json.dumps({k: v for k, v in record.items()
                          if k not in ("content_sha256", "content_hmac")},
                         sort_keys=True, separators=(",", ":")).encode()
    key_id = documented_key_id(KEY)
    assert record["content_hmac"] == {
        "algorithm": "hmac-sha256", "key_id": key_id,
        "value": hmac.new(KEY.encode(), content, hashlib.sha256).hexdigest()}
    assert [h["hmac_key_id"] for h in record["history"]] == [key_id, key_id]
    assert KEY not in path.read_text()


def test_record_key_refuses_an_edit_even_when_every_hash_is_recomputed(tmp_path, monkeypatch):
    def forge(data):
        data["approvals"]["owner_scope"].append({"approval_id": "forged"})
        rehash_everything(data)

    # Without a key the record is tamper-evident against accidental edits only.
    unsigned = written(tmp_path, name="unsigned.json")
    edited(unsigned, forge)
    assert rec.load(unsigned, MIGRATION)["approvals"]["owner_scope"] == [{"approval_id": "forged"}]

    monkeypatch.setenv(rec.KEY_ENV, KEY)
    signed = written(tmp_path, name="signed.json")
    edited(signed, forge)
    with pytest.raises(MigrationError, match="content_hmac does not verify with the record key"):
        rec.load(signed, MIGRATION)


def test_signed_record_without_the_key_fails_closed(tmp_path, monkeypatch):
    monkeypatch.setenv(rec.KEY_ENV, KEY)
    path = written(tmp_path)
    monkeypatch.delenv(rec.KEY_ENV)
    refused = f"authenticated with record key {documented_key_id(KEY)}; set {rec.KEY_ENV}"
    with pytest.raises(MigrationError, match=refused):
        rec.load(path, MIGRATION)
    with pytest.raises(MigrationError, match=refused):
        verified(path)
    # Dropping the MAC does not turn it into an unsigned record: its history was signed.
    edited(path, lambda data: data.pop("content_hmac"))
    with pytest.raises(MigrationError, match=refused):
        rec.load(path, MIGRATION)
    monkeypatch.setenv(rec.KEY_ENV, KEY)
    with pytest.raises(MigrationError, match="content_hmac is missing"):
        rec.load(path, MIGRATION)


@pytest.mark.parametrize("previous_format", [False, True])
def test_unsigned_record_is_refused_while_a_key_is_set(tmp_path, monkeypatch, previous_format):
    path = legacy_record(tmp_path) if previous_format else written(tmp_path)
    before = path.read_bytes()
    monkeypatch.setenv(rec.KEY_ENV, KEY)
    with pytest.raises(MigrationError, match="not authenticated, but a record key is set"):
        rec.load(path, MIGRATION)
    with pytest.raises(MigrationError, match="not authenticated, but a record key is set"):
        verified(path)
    assert path.read_bytes() == before


def test_record_signed_with_another_key_is_refused(tmp_path, monkeypatch):
    monkeypatch.setenv(rec.KEY_ENV, KEY)
    path = written(tmp_path)
    monkeypatch.setenv(rec.KEY_ENV, OTHER_KEY)
    refused = (f"authenticated with record key {documented_key_id(KEY)}, "
               f"not with the configured key {documented_key_id(OTHER_KEY)}")
    with pytest.raises(MigrationError, match=refused):
        rec.load(path, MIGRATION)


def test_record_key_file_is_the_same_key(tmp_path, monkeypatch):
    key_file = tmp_path / "record.key"
    key_file.write_text(KEY + "\n")
    monkeypatch.setenv(rec.KEY_FILE_ENV, str(key_file))
    path = written(tmp_path)
    from_file = rec.load(path, MIGRATION)
    assert from_file["content_hmac"]["key_id"] == documented_key_id(KEY)
    monkeypatch.delenv(rec.KEY_FILE_ENV)
    monkeypatch.setenv(rec.KEY_ENV, KEY)
    assert rec.load(path, MIGRATION) == from_file


@pytest.mark.parametrize("environment, message", [
    ({rec.KEY_ENV: KEY, rec.KEY_FILE_ENV: "record.key"}, "not both"),
    ({rec.KEY_ENV: "too-short"}, "at least 16 bytes"),
    ({rec.KEY_ENV: ""}, "at least 16 bytes"),
    ({rec.KEY_FILE_ENV: "{tmp}/missing.key"}, "unable to read the record key file"),
])
def test_record_key_misconfiguration_fails_closed_and_writes_nothing(tmp_path, monkeypatch,
                                                                     environment, message):
    path = written(tmp_path)
    before = path.read_bytes()
    for name, value in environment.items():
        monkeypatch.setenv(name, value.format(tmp=tmp_path))
    with pytest.raises(MigrationError, match=message):
        rec.load(path, MIGRATION)
    with pytest.raises(MigrationError, match=message):
        verified(path)
    with pytest.raises(MigrationError, match=message):
        written(tmp_path, name="new.json")
    assert path.read_bytes() == before and not (tmp_path / "new.json").exists()


# ---------------------------------------------------------------------------
# Concurrent writers
# ---------------------------------------------------------------------------

def test_update_preserves_concurrent_writes_and_save_detects_them(tmp_path):
    path = written(tmp_path)
    stale = rec.load(path, MIGRATION)
    rec.update(path, MIGRATION, lambda r: r["approvals"]["owner_scope"].append({"x": 1}),
               mode="approve", status="APPROVED")
    with pytest.raises(MigrationError, match="changed concurrently"):
        rec.save(path, stale, mode="verify", status="SHARING_READY")
    rec.update(path, MIGRATION, lambda r: r.__setitem__("shares", [{"share_arn": "s"}]),
               mode="apply", status="SHARING_READY")
    record = rec.load(path, MIGRATION)
    assert record["approvals"]["owner_scope"] == [{"x": 1}] and record["shares"] == [{"share_arn": "s"}]


def test_save_detects_a_record_recreated_at_the_same_revision(tmp_path):
    """Revision numbers do not identify a record; its content digest does."""
    path = written(tmp_path, {"scope": {"owner": "A"}})
    rec.update(path, MIGRATION, lambda r: r["approvals"]["owner_scope"].append({"approval_id": "os-a"}),
               mode="approve", status="APPROVED")
    stale = rec.load(path, MIGRATION)
    path.unlink()
    written(tmp_path, {"scope": {"owner": "B"}})
    rec.update(path, MIGRATION, lambda r: r["approvals"]["owner_scope"].append({"approval_id": "os-b"}),
               mode="approve", status="APPROVED")
    recreated = path.read_bytes()
    assert rec.load(path, MIGRATION)["revision"] == stale["revision"] == 2
    stale["verifications"].append("stale writer")
    with pytest.raises(MigrationError,
                       match=r"changed concurrently \(revision 2 on disk has different content"):
        rec.save(path, stale, mode="verify", status="SHARING_READY")
    assert path.read_bytes() == recreated


def test_save_never_recreates_a_missing_record(tmp_path):
    path = written(tmp_path)
    stale = rec.load(path, MIGRATION)
    path.unlink()
    with pytest.raises(MigrationError, match="missing, but the record being saved is at revision 1"):
        rec.save(path, stale, mode="verify", status="SHARING_READY")
    assert not path.exists()


def test_save_writes_the_next_revision_of_an_unchanged_record(tmp_path):
    path = written(tmp_path)
    current = rec.load(path, MIGRATION)
    current["verifications"].append("result")
    assert rec.save(path, current, mode="verify", status="SHARING_READY")["revision"] == 2
    assert rec.load(path, MIGRATION)["verifications"] == ["result"]
    fresh = tmp_path / "fresh.json"
    assert rec.save(fresh, rec.new_record(MIGRATION), mode="plan", status="PLANNED")["revision"] == 1
    assert rec.load(fresh, MIGRATION)["revision"] == 1


def test_parallel_updates_serialize_without_losing_history(tmp_path):
    path = written(tmp_path)
    errors = []

    def writer(index):
        try:
            rec.update(path, MIGRATION, lambda r: r["verifications"].append(index),
                       mode="verify", status="SHARING_READY")
        except Exception as exc:  # pragma: no cover - surfaced below
            errors.append(exc)
    threads = [threading.Thread(target=writer, args=(i,)) for i in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    record = rec.load(path, MIGRATION)
    assert not errors and record["revision"] == 9
    assert sorted(record["verifications"]) == list(range(8))


# ---------------------------------------------------------------------------
# Durable writes
# ---------------------------------------------------------------------------

def is_directory(fd):
    return stat.S_ISDIR(os.fstat(fd).st_mode)


def test_write_fsyncs_the_file_and_its_directory_around_the_replace(tmp_path, monkeypatch):
    path = written(tmp_path)
    events, full_syncs = [], []
    real_fsync, real_replace, real_fcntl = os.fsync, os.replace, fcntl.fcntl

    def fsync(fd):
        events.append("fsync directory" if is_directory(fd) else "fsync file")
        real_fsync(fd)

    def replace(source, target):
        events.append("replace")
        real_replace(source, target)

    def fcntl_call(fd, command, *args):
        if command == getattr(fcntl, "F_FULLFSYNC", None):
            full_syncs.append(fd)
        return real_fcntl(fd, command, *args)
    monkeypatch.setattr(os, "fsync", fsync)
    monkeypatch.setattr(os, "replace", replace)
    monkeypatch.setattr(fcntl, "fcntl", fcntl_call)
    verified(path)
    assert events == ["fsync file", "fsync directory", "replace", "fsync directory"]
    # macOS: fsync alone leaves data in the drive cache; F_FULLFSYNC follows each fsync.
    assert len(full_syncs) == (3 if hasattr(fcntl, "F_FULLFSYNC") else 0)
    assert rec.load(path, MIGRATION)["revision"] == 2 and temporary_files(tmp_path) == []


@pytest.mark.parametrize("failure", ["file fsync", "directory fsync", "replace", "interrupt"])
def test_failed_write_removes_the_temporary_file_and_keeps_the_previous_revision(
        tmp_path, monkeypatch, failure):
    path = written(tmp_path)
    before = path.read_bytes()
    real_fsync = os.fsync

    def fsync(fd):
        if failure == "interrupt":
            raise KeyboardInterrupt
        if failure == ("directory fsync" if is_directory(fd) else "file fsync"):
            raise OSError(errno.EIO, "Input/output error")
        real_fsync(fd)

    def replace(source, target):
        raise OSError(errno.ENOSPC, "No space left on device")
    with monkeypatch.context() as patched:
        patched.setattr(os, "fsync", fsync)
        if failure == "replace":
            patched.setattr(os, "replace", replace)
        if failure == "interrupt":
            with pytest.raises(KeyboardInterrupt):
                verified(path)
        else:
            with pytest.raises(MigrationError, match="previous revision is unchanged"):
                verified(path)
    assert temporary_files(tmp_path) == []
    assert path.read_bytes() == before and rec.load(path, MIGRATION)["revision"] == 1


def test_failure_after_the_replace_reports_that_the_new_revision_may_not_be_durable(tmp_path,
                                                                                     monkeypatch):
    path = written(tmp_path)
    real_fsync, calls = os.fsync, []

    def fsync(fd):
        calls.append(fd)
        if len(calls) == 3:  # the directory fsync after os.replace
            raise OSError(errno.EIO, "Input/output error")
        real_fsync(fd)
    with monkeypatch.context() as patched:
        patched.setattr(os, "fsync", fsync)
        with pytest.raises(MigrationError, match="new revision is in place but may not survive a crash"):
            verified(path)
    assert temporary_files(tmp_path) == []
    assert rec.load(path, MIGRATION)["revision"] == 2


# ---------------------------------------------------------------------------
# Tool identity
# ---------------------------------------------------------------------------

def test_tool_identity_is_hashed_once_when_the_tool_starts(tmp_path):
    """A source file edited during a long run cannot change the digest that run records."""
    root = Path(rec.__file__).resolve().parent
    tool = tmp_path / "tool"
    tool.mkdir()
    for name in rec.SOURCES:
        if (root / name).is_file():
            shutil.copy(root / name, tool / name)
    spec = importlib.util.spec_from_file_location("ram_migration_record_at_start",
                                                  tool / "ram_migration_record.py")
    started = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(started)
    at_start = started.tool_identity()
    assert started._source_identity() == at_start
    with (tool / "ram_migration_common.py").open("a") as handle:
        handle.write("\n# edited while a long apply runs\n")
    assert started._source_identity()["sources_digest"] != at_start["sources_digest"]
    assert started.tool_identity() == at_start
    started.tool_identity()["sources_sha256"]["ram_migration_common.py"] = "changed by a caller"
    assert started.tool_identity() == at_start
    path = tmp_path / "record.json"
    started.update(path, MIGRATION, lambda r: None, mode="plan", status="PLANNED", create=True)
    record = started.load(path, MIGRATION)
    assert record["tool"] == at_start
    assert record["history"][0]["tool_sources_digest"] == at_start["sources_digest"]


# ---------------------------------------------------------------------------
# Records written in the previous format (schema ram-migration-record/1)
# ---------------------------------------------------------------------------

def legacy_write(path, migration, mutate, *, mode, status, create=False, **details):
    """How a revision was written before entries carried body_sha256 (new_record and _write
    from ram_migration_record.py at commit db30592)."""
    path = Path(path)
    if create and not path.exists():
        record = {"schema": rec.LEGACY_SCHEMA, "migration_id": migration, "revision": 0,
                  "created_at": timestamp(), "updated_at": None, "tool": rec.tool_identity(),
                  "scope": None, "plan": None, "permission_change_requests": [],
                  "owner_scope_request": None,
                  "approvals": {"permission_changes": [], "owner_scope": []},
                  "baseline": None, "shares": [], "verifications": [], "drops": [],
                  "completion": None, "history": []}
    else:
        record = json.loads(path.read_text())
    mutate(record)
    record["revision"] = int(record.get("revision", 0)) + 1
    record["updated_at"] = timestamp()
    record["tool"] = rec.tool_identity()
    history = record.setdefault("history", [])
    entry = {
        "revision": record["revision"], "mode": mode, "status": status,
        "at": record["updated_at"], "tool_version": TOOL_VERSION,
        "tool_sources_digest": record["tool"]["sources_digest"],
        "operator": rec.operator(), **details,
        "previous_sha256": history[-1]["sha256"] if history else None,
    }
    old_body = {k: v for k, v in record.items() if k not in ("content_sha256", "history")}
    entry["sha256"] = rec.sha256([entry["previous_sha256"], old_body,
                                  {k: v for k, v in entry.items() if k != "sha256"}])
    history.append(entry)
    record["content_sha256"] = rec.sha256({k: v for k, v in record.items() if k != "content_sha256"})
    path.write_text(json.dumps(record, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return record


def legacy_record(tmp_path):
    """plan, then approve, written by the previous release."""
    path = tmp_path / "record.json"
    request, = rec.permission_requests(MIGRATION, [change(SHARE_1)])
    legacy_write(path, MIGRATION, lambda r: r.update(permission_change_requests=[request]),
                 mode="plan", status="PLANNED", create=True, plan_digest="d" * 64)
    legacy_write(path, MIGRATION, lambda r: rec.approve_permission_change(r, request),
                 mode="approve", status="APPROVED", approved=[request["id"]])
    return path


def test_previous_format_record_loads_and_the_next_write_upgrades_it(tmp_path):
    path = legacy_record(tmp_path)
    legacy = rec.load(path, MIGRATION)
    assert legacy["schema"] == rec.LEGACY_SCHEMA and legacy["revision"] == 2
    assert rec.approval_for(legacy["approvals"]["permission_changes"], MIGRATION,
                            change(SHARE_1)) is not None
    upgraded = verified(path)
    record = rec.load(path, MIGRATION)
    assert record == upgraded and record["schema"] == rec.SCHEMA and record["revision"] == 3
    assert record["history"][:2] == legacy["history"]  # entries are never rewritten
    assert record["legacy_history"] == {"schema": rec.LEGACY_SCHEMA, "revisions": 2,
                                        "sha256": documented_sha256(legacy["history"])}
    head = record["history"][2]
    assert head["previous_sha256"] == legacy["history"][1]["sha256"]
    assert head["body_sha256"] == documented_sha256(body(record))
    assert head["sha256"] == documented_sha256({k: v for k, v in head.items() if k != "sha256"})
    verified(path)
    assert rec.load(path, MIGRATION)["legacy_history"] == record["legacy_history"]


def edit_legacy_approval(data):
    data["approvals"]["permission_changes"][0]["shares"].append(SHARE_2)


def edit_legacy_latest_entry(data):
    data["history"][-1]["approved"] = ["pc-forged"]


def edit_legacy_link(data):
    data["history"][-1]["previous_sha256"] = "0" * 64


@pytest.mark.parametrize("edit, problem", [
    (edit_legacy_approval, "revision 2: sha256 does not match the entry and the record"),
    (edit_legacy_latest_entry, "revision 2: sha256 does not match the entry and the record"),
    (edit_legacy_link, "revision 2: previous_sha256 does not match the previous entry"),
])
def test_previous_format_record_edits_are_refused(tmp_path, edit, problem):
    """The latest previous-format entry hashed the current body, so it still covers the record."""
    path = legacy_record(tmp_path)

    def tamper(data):
        edit(data)
        rehash_content(data)
    edited(path, tamper)
    with pytest.raises(MigrationError, match=f"history chain is broken at {problem}"):
        rec.load(path, MIGRATION)


def test_previous_format_entries_are_pinned_by_the_upgrade(tmp_path):
    """Older previous-format entries hashed bodies that are no longer stored, so until the
    record is upgraded only their links can be checked. The upgrade pins them as they are."""
    def edit_first_entry(data):
        data["history"][0]["tool_sources_digest"] = "0" * 64
        rehash_content(data)

    (tmp_path / "before").mkdir()
    not_upgraded = legacy_record(tmp_path / "before")
    edited(not_upgraded, edit_first_entry)
    assert rec.load(not_upgraded, MIGRATION)["history"][0]["tool_sources_digest"] == "0" * 64

    (tmp_path / "after").mkdir()
    upgraded = legacy_record(tmp_path / "after")
    verified(upgraded)
    edited(upgraded, edit_first_entry)
    with pytest.raises(MigrationError, match="legacy_history does not match the history"):
        rec.load(upgraded, MIGRATION)


def test_previous_format_entry_after_an_upgrade_is_refused(tmp_path):
    path = legacy_record(tmp_path)
    verified(path)
    legacy_write(path, MIGRATION, lambda r: None, mode="verify", status="SHARING_READY")
    with pytest.raises(MigrationError, match="revision 4: the entry format does not match the record"):
        rec.load(path, MIGRATION)


# ---------------------------------------------------------------------------
# Approval binding
# ---------------------------------------------------------------------------

def test_permission_requests_bind_versions_hashes_shares_and_migration():
    requests = rec.permission_requests(MIGRATION, [change(SHARE_1), change(SHARE_2)])
    request, = requests
    assert request["shares"] == [SHARE_1, SHARE_2]
    assert request["id"].startswith("pc-")
    other = rec.permission_requests("other-migration", [change(SHARE_1), change(SHARE_2)])
    assert other[0]["id"] != request["id"]
    narrower = rec.permission_requests(MIGRATION, [change(SHARE_1)])
    assert narrower[0]["id"] != request["id"]


def test_approval_covers_only_the_exact_change():
    record = {"migration_id": MIGRATION, "revision": 3, "approvals": {"permission_changes": []}}
    request, = rec.permission_requests(MIGRATION, [change(SHARE_1)])
    approval = rec.approve_permission_change(record, request)
    approvals = record["approvals"]["permission_changes"]
    assert approval["approved_in_revision"] == 4 and approval["approved_by"]["user"]
    assert rec.approval_for(approvals, MIGRATION, change(SHARE_1)) is approval
    assert rec.approval_for(approvals, MIGRATION, change(SHARE_2)) is None
    assert rec.approval_for(approvals, "prod-scope", change(SHARE_1)) is None
    for field, value in (("to_version", "4"), ("from_version", "1"),
                         ("to_policy_sha256", "c" * 64), ("from_policy_sha256", "d" * 64),
                         ("permission_arn", "arn:aws:ram::aws:permission/Other")):
        assert rec.approval_for(approvals, MIGRATION, change(SHARE_1, **{field: value})) is None


def test_pending_requests_reflect_uncovered_shares():
    record = {"migration_id": MIGRATION, "revision": 1,
              "approvals": {"permission_changes": []},
              "permission_change_requests": rec.permission_requests(
                  MIGRATION, [change(SHARE_1)])}
    assert len(rec.pending_requests(record)) == 1
    rec.approve_permission_change(record, record["permission_change_requests"][0])
    assert rec.pending_requests(record) == []
    # A later plan that adds a share produces a new request the old approval cannot cover.
    record["permission_change_requests"] = rec.permission_requests(
        MIGRATION, [change(SHARE_1), change(SHARE_2)])
    assert len(rec.pending_requests(record)) == 1


def test_approval_rejects_request_from_another_migration():
    record = {"migration_id": MIGRATION, "revision": 0, "approvals": {"permission_changes": []}}
    request, = rec.permission_requests("other-migration", [change(SHARE_1)])
    with pytest.raises(MigrationError, match="another migration"):
        rec.approve_permission_change(record, request)


def test_retired_consumers_need_every_serving_share_retired():
    record = {"shares": [
        {"share_arn": "arn:a", "consumers": ["111111111111", "222222222222"]},
        {"share_arn": "arn:b", "consumers": ["111111111111"]},
        {"logical_id": "unproven", "consumers": ["333333333333"]}],
        "retirements": [{"share_arn": "arn:a", "consumer": "111111111111"},
                        {"share_arn": "arn:a", "consumer": "222222222222"}]}
    assert rec.retired_consumers(record) == {"222222222222"}
    record["retirements"].append({"share_arn": "arn:b", "consumer": "111111111111"})
    assert rec.retired_consumers(record) == {"111111111111", "222222222222"}
    assert rec.retired_consumers({}) == set()
