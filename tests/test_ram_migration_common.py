from types import SimpleNamespace

import pytest

from ram_migration_common import (
    PURPOSE, Api, MigrationError, Router, account_id, digest, managed, pages, tags,
)


class Fake:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []
        self.meta = SimpleNamespace()

    def list_items(self, **kwargs):
        self.calls.append(kwargs)
        return next(self.responses)


@pytest.mark.parametrize("token_name", ["NextToken", "nextToken"])
def test_pagination_preserves_case(token_name):
    client = Fake([{"items": [1], token_name: "a"}, {"items": [2]}])
    assert pages(client, "list_items", "items") == [1, 2]
    assert client.calls == [{}, {token_name: "a"}]


def test_repeated_pagination_token_rejected():
    client = Fake([{"items": [], "nextToken": "a"}, {"items": [], "nextToken": "a"}])
    with pytest.raises(MigrationError, match="Repeated pagination"):
        pages(client, "list_items", "items")


def test_readonly_guard_rejects_before_accessing_mutation():
    api = Api(SimpleNamespace(meta=None))
    with pytest.raises(MigrationError, match="Read-only"):
        api.create_resource_share()
    with pytest.raises(MigrationError, match="Read-only"):
        api.associate_resource_share()


def test_cloudtrail_and_log_reads_are_allowed():
    api = Api(SimpleNamespace(meta=None, lookup_events=lambda: [],
                              filter_log_events=lambda: {}))
    assert api.lookup_events() == []
    assert api.filter_log_events() == {}


def test_leading_zero_account():
    assert account_id("400000000001") == "400000000001"


@pytest.mark.parametrize("value", [11045852549, "123", " 400000000001", "1234567890123"])
def test_invalid_accounts_rejected(value):
    with pytest.raises(MigrationError):
        account_id(value)


def test_deterministic_digest_ignores_dictionary_order():
    assert digest({"x": 1, "y": 2}) == digest({"y": 2, "x": 1})


@pytest.mark.parametrize("shape", [("Key", "Value"), ("key", "value")])
def test_ownership_tags_support_cfn_and_ram_shapes(shape):
    key, value = shape
    items = [{key: "Purpose", value: PURPOSE}, {key: "MigrationId", value: "canary"}]
    assert managed(items, "canary")
    assert not managed(items, "different")


def test_ownership_tags_reject_case_conflicts():
    with pytest.raises(MigrationError, match="Ambiguous"):
        tags([{"key": "Purpose", "value": PURPOSE}, {"key": "purpose", "value": "other"}])


def test_ownership_tags_reject_invalid_response():
    with pytest.raises(MigrationError, match="Malformed"):
        tags([{"key": "Purpose"}])


@pytest.mark.parametrize("value", [
    "arn:aws:iam::111111111111:role/admin",
    "arn:aws:iam::123456789012:user/admin",
    "arn:aws:iam",
    "",
    123,
])
def test_invalid_role_mapping_rejected_before_authentication(value):
    with pytest.raises(MigrationError, match="mapping"):
        Router(["unresolved"], {"123456789012": value})


def test_profile_required_before_authentication():
    with pytest.raises(MigrationError, match="profile"):
        Router([], {})


def test_explicit_profile_mapping_takes_precedence_over_base(monkeypatch):
    calls = []

    class Session:
        region_name = "us-east-1"

        def __init__(self, profile_name):
            self.profile_name = profile_name
            calls.append(profile_name)

        def client(self, service, **kwargs):
            assert service == "sts"
            return SimpleNamespace(get_caller_identity=lambda: {"Account": "123456789012"})

    monkeypatch.setattr("ram_migration_common.boto3.Session", Session)
    router = Router(["base-read-only"], {"123456789012": "explicit-admin"})
    assert router.session("123456789012").profile_name == "explicit-admin"
    assert calls == ["base-read-only", "explicit-admin"]


def test_profile_mapping_caller_identity_must_match(monkeypatch):
    class Session:
        region_name = "us-east-1"

        def __init__(self, profile_name):
            self.profile_name = profile_name

        def client(self, service, **kwargs):
            actual = "123456789012" if self.profile_name == "base" else "111111111111"
            return SimpleNamespace(get_caller_identity=lambda: {"Account": actual})

    monkeypatch.setattr("ram_migration_common.boto3.Session", Session)
    router = Router(["base"], {"222222222222": "wrong-account-profile"})
    with pytest.raises(MigrationError, match="identity mismatch"):
        router.session("222222222222")
