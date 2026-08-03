"""Migration-record integrity, history and approval-binding tests (offline)."""
import json
import threading

import pytest

import ram_migration_record as rec
from ram_migration_common import MigrationError

MIGRATION = "record-test"
CHANGE = {"permission_arn": "arn:aws:ram::aws:permission/AWSRAMDefaultPermissionTransitGateway",
          "resource_type": "ec2:TransitGateway", "from_version": "2", "to_version": "3",
          "from_policy_sha256": "a" * 64, "to_policy_sha256": "b" * 64}
SHARE_1 = "arn:aws:ram:us-west-2:000000000001:resource-share/one"
SHARE_2 = "arn:aws:ram:us-west-2:000000000001:resource-share/two"


def change(share, **override):
    return {**CHANGE, "owner": "000000000001", "region": "us-west-2", "share": share,
            "difference": {"actions_added": ["Allow ec2:CreateClientVpnEndpoint"]},
            "from_policy": {"Statement": []}, "to_policy": {"Statement": []}, **override}


def written(tmp_path, record=None):
    path = tmp_path / "record.json"
    rec.update(path, MIGRATION, lambda r: r.update(record or {}), mode="plan",
               status="PLANNED", create=True)
    return path


def test_round_trip_history_chain_and_integrity(tmp_path):
    path = written(tmp_path)
    rec.update(path, MIGRATION, lambda r: None, mode="verify", status="SHARING_READY")
    record = rec.load(path, MIGRATION)
    assert record["revision"] == 2
    assert [h["mode"] for h in record["history"]] == ["plan", "verify"]
    assert record["history"][1]["previous_sha256"] == record["history"][0]["sha256"]
    assert record["tool"]["version"] == rec.TOOL_VERSION
    assert record["history"][0]["operator"]["user"]


def test_record_edited_outside_the_tool_is_refused(tmp_path):
    path = written(tmp_path)
    data = json.loads(path.read_text())
    data["approvals"]["permission_changes"].append({"approval_id": "forged"})
    path.write_text(json.dumps(data))
    with pytest.raises(MigrationError, match="integrity check failed"):
        rec.load(path, MIGRATION)


def test_broken_history_chain_is_refused(tmp_path):
    path = written(tmp_path)
    rec.update(path, MIGRATION, lambda r: None, mode="verify", status="SHARING_READY")
    data = json.loads(path.read_text())
    data["history"][1]["previous_sha256"] = "0" * 64
    data["content_sha256"] = rec._content_digest(data)  # even a re-hashed edit breaks the chain
    path.write_text(json.dumps(data))
    with pytest.raises(MigrationError, match="history chain is broken"):
        rec.load(path, MIGRATION)


def test_record_never_transfers_between_migrations(tmp_path):
    path = written(tmp_path)
    with pytest.raises(MigrationError, match="approvals never transfer"):
        rec.load(path, "earlier-openfinance-migration")


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
