"""The readable console view (ram_migration_console). Offline: real raw outputs of a
sandbox run (tests/fixtures/console) are rendered through the reporter, and the CLI runs
with readable=True against the local harness of test_ram_migration_cli."""
from __future__ import annotations

import io
import re
import threading
from pathlib import Path
from types import SimpleNamespace

import pytest

import ram_migration_console as console
import temporary_migration_ram_shares as cli
from ram_migration_console import ReadableReporter
from test_ram_migration_cli import (  # noqa: F401 - fixtures are used by name
    CONSUMER, MIGRATION, OTHER_OWNER, OWNER, REGION, applied, args, complete_args,
    confirm_complete, forbid_real_authentication_or_network, harness, migration_record,
    mode_args, read_record, with_record,
)

FIXTURES = Path(__file__).resolve().parent / "fixtures" / "console"
SANDBOX = "example-migration"
OWNERS = ["400000000006", "400000000017"]
MOVING = "400000000009"
PROMPT = re.compile(r"^(Type [A-Z-]+ \S+ .*?: )(?=\S+=)")
# Everything that matters must stay visible (requirement 2).
MUST_SHOW = re.compile(r"status=(?:BLOCKED|FAILED|INCOMPLETE|CANCELLED|LOSS|INCONCLUSIVE|"
                       r"OVERRIDDEN|NOT_ACCEPTABLE|WARNING|GAP)\b|change=(?:LOST|DEGRADED|UNOBSERVED)")
IDENTIFIERS = re.compile(r"arn:[^\s,;]+|\b\d{12}\b")
POOL = f"arn:aws:ec2:{REGION}:{OWNER}:ipam-pool/test"


# ---------------------------------------------------------------------------
# Rendering real raw outputs
# ---------------------------------------------------------------------------

def reporter(mode, record=None, **context):
    out = io.StringIO()
    report = ReadableReporter(mode, SimpleNamespace(
        migration_id=SANDBOX, record=record, scan_enabled_regions=True, accept_reason=None),
        stream=out)
    defaults = dict(regions=["us-east-1", "us-west-2"], owners=OWNERS, consumers=[MOVING],
                    stationary_consumers=[], excluded_regions=[], excluded_consumers=[],
                    tgw_route_exclusion_reason=None)
    defaults.update(context)
    report.context = SimpleNamespace(**defaults)
    return report, out


def replay(name, mode, tmp_path):
    """Render a fixture as the run would: a confirmation prompt (written by input() on
    the same line as the next event) is preceded by flush()."""
    report, out = reporter(mode, tmp_path / "record.json")
    before_prompt = None
    for line in (FIXTURES / name).read_text().splitlines():
        match = PROMPT.match(line)
        if match:
            report.flush()
            before_prompt = out.getvalue()
            out.write(match.group(1) + "\n")
            line = line[match.end():]
        report.emit(line)
    report.close()
    return out.getvalue(), before_prompt


def raw_lines(name):
    return (FIXTURES / name).read_text().splitlines()


def assert_nothing_that_matters_is_hidden(name, output):
    for line in raw_lines(name):
        if MUST_SHOW.search(line):
            for identifier in IDENTIFIERS.findall(line):
                assert identifier.rstrip(":.") in output, (identifier, line)


def assert_noise_is_summarized(output):
    lines = output.splitlines()
    assert not [line for line in lines if line.startswith(("phase=", "account=", "  resource="))]
    assert "template=" not in output and "capability_provenance" not in output
    assert " kind=" not in output
    assert lines[-1] == console.RAW_HINT


def test_plan_fixture_shows_roles_shares_exclusions_and_result(tmp_path):
    output, prompt = replay("plan-1.txt", "plan", tmp_path)
    assert prompt is None
    assert output.startswith(f"RAMShift plan - migration {SANDBOX}\n"
                             "Regions: us-east-1, us-west-2, plus every Region enabled in each "
                             "owner account\n")
    assert "Checking account access... 3 accounts verified" in output
    assert "Checking what 1 migrating account receives in 17 Regions..." in output
    assert "Inspecting 2 owners in 2 Regions..." in output
    assert re.search(r"400000000006 +Stationary owner", output)
    assert re.search(rf"{MOVING} +Migrating", output)
    assert "1 migrating account receives 26 shares (26 resources) from 2 owners" in output
    assert "Planned temporary shares (5; 4 migration stacks to create)" in output
    assert re.search(rf"400000000017 +us-west-2 +{MOVING} +1 Transit Gateway", output)
    assert re.search(rf"400000000017 +us-west-2 +{MOVING} +7 Resolver rules", output)
    assert "Exclusions (14)" in output
    assert "12  recipients outside this migration are left out: 400000000017" in output
    assert "Result: PLANNED - the plan is ready for review; nothing was written to AWS" in output
    assert "Resources: 26   Access grants: 26   Temporary shares: 5   Exclusions: 14   Blockers: 0" \
        in output
    assert f"Record: {tmp_path / 'record.json'} (revision 1)" in output
    assert "Exit code: 0" in output and "Next step: Review this plan." in output
    assert_noise_is_summarized(output)
    assert len(output.splitlines()) < len(raw_lines("plan-1.txt")) / 2


def test_apply_fixture_shows_what_will_be_created_before_the_prompt_then_progress(tmp_path):
    output, prompt = replay("apply-1.txt", "apply", tmp_path)
    assert "Planned temporary shares (5; 4 migration stacks to create)" in prompt
    assert "Apply creates or updates these migration stacks" in prompt
    assert ("Current state before any change: 51 items observed (26 access grants, 20 Resolver "
            "rule associations,") in prompt
    assert "Result:" not in prompt
    after = output[len(prompt):]
    assert "Planned temporary shares" not in after          # shown once, before the prompt
    assert "Baseline captured: 51 items, complete (record revision 2)" in after
    assert after.count("Migration stack ready: TemporaryMigrationRAMShares-") == 4
    assert "Accepting the share invitations" in after and "Verifying the temporary shares" in after
    # Direct progress prints of the stack module are not events and pass through as they are.
    assert "TemporaryMigrationRAMShares-400000000006-us-east-1-1eb44f56 CREATE_IN_PROGRESS" in after
    assert "Temporary shares (5)" in after
    assert re.search(r"400000000017 +us-west-2 +0956e122-565a-45a8-9662-7719be771d03 +"
                     rf"{MOVING} +1 +verified", after)
    assert "Baseline comparison: INTACT - 0 missing, 0 degraded, 0 read gaps" in after
    assert "still in its baseline organization o-example00001x (not moved yet)" in after
    assert "Not associated: 5 shared Resolver rules had no VPC association" in after
    assert "Result: SHARING_READY - the temporary shares are in place, accepted and verified" in after
    assert "Temporary shares: 5 (5 created, 0 reused)   Invitations accepted: 5" in after
    assert "Exit code: 0" in after and "Next step: Run verify with the same --record" in after
    assert_noise_is_summarized(output)
    assert len(output.splitlines()) < len(raw_lines("apply-1.txt")) / 3


def test_verify_fixtures_show_statuses_organizations_and_retired_accounts(tmp_path):
    output, _ = replay("verify-2-after-enroll.txt", "verify", tmp_path)
    assert "Result: MIGRATION_VALIDATED - every migrating account has left its baseline" in output
    assert "Sharing: SHARING_READY - every temporary share is in place and verified" in output
    assert re.search(rf"{MOVING} +left its baseline organization", output)
    assert "Baseline comparison: INTACT - 0 missing, 0 degraded, 0 read gaps" in output
    assert ("Original share access removed: 400000000009 | 26 resources through 26 shares | "
            "current access=TEMPORARY_ONLY") in " ".join(output.split())
    assert "Exit code: 0" in output
    assert "run complete to retire the temporary access" in " ".join(output.split())
    assert_noise_is_summarized(output)

    output, _ = replay("verify-3-after-complete.txt", "verify", tmp_path)
    assert "Retired accounts (1)" in output
    assert f"{MOVING}  retired 2026-10-15T05:13:51.984983+00:00" in output
    assert "INCOMPLETE: No stored/planned migration entitlements found in the requested scope" \
        in output
    assert "Result: INCOMPLETE" in output and "Exit code: 1" in output
    assert_nothing_that_matters_is_hidden("verify-3-after-complete.txt", output)


@pytest.mark.parametrize("name, organization, changes", [
    ("monitor-2-after-leave.txt", "STANDALONE", "original grants removed=26, shares added=0"),
    ("monitor-7-after-permanent-shares.txt", "o-example00002x",
     "original grants removed=26, shares added=26"),
])
def test_monitor_fixtures(tmp_path, name, organization, changes):
    output, _ = replay(name, "monitor", tmp_path)
    assert output.startswith(f"RAMShift monitor - migration {SANDBOX}\nAccounts: 1\n")
    assert "Baseline: 2026-10-14 22:39:25 UTC" in output
    assert re.search(rf"{MOVING} +{organization} +CHANGED", output)
    assert "Result: CHANGED - Changes detected; the monitored baseline remains intact." in output
    assert "Lost: 0   Degraded: 0   Unobserved: 0   Read gaps: 0" in output
    assert changes in output and "Exit code: 0" in output
    assert "(expected while accounts move; not losses)" in output
    assert_noise_is_summarized(output)


def test_complete_fixture_blocked_keeps_every_failed_check(tmp_path):
    output, _ = replay("complete-1-no-replacement.txt", "complete", tmp_path)
    assert "FAILED CHECKS (26): nothing was retired" in output
    assert "only the temporary share provides access to 26 resources" in output
    assert "Result: BLOCKED - nothing was retired; the checks above failed" in output
    assert "Exit code: 1" in output
    assert_nothing_that_matters_is_hidden("complete-1-no-replacement.txt", output)
    assert_noise_is_summarized(output)


def test_complete_fixture_preview_shows_the_actions_before_the_prompt(tmp_path):
    output, prompt = replay("complete-2-preview.txt", "complete", tmp_path)
    assert "Permanent replacement access found: 26 resources for 400000000009" in prompt
    assert "Planned actions (9; smallest share first, re-verifying after each)" in prompt
    assert prompt.count("DELETE_SHARE") == 5 and prompt.count("DELETE_STACK") == 4
    assert "Result: CANCELLED - the confirmation did not match; nothing was changed" in output
    assert "Exit code: 2" in output and "type the confirmation exactly" in output


def test_complete_fixture_run_shows_each_action_and_the_result(tmp_path):
    output, prompt = replay("complete-3-run.txt", "complete", tmp_path)
    after = output[len(prompt):]
    assert after.count("Deleted temporary share ") == 5
    assert after.count("Deleted migration stack (owner ") == 4
    assert after.count("Re-verifying after action ") == 5     # once per action, not per poll
    assert "Re-verified after each of 5 actions and once more at the end: no read gaps" in after
    assert "Result: COMPLETED" in after and "Deleted temporary shares: 5" in after
    assert "The original baseline is intact for the retired accounts." in after
    assert "Exit code: 0" in after
    assert_noise_is_summarized(output)
    assert len(output.splitlines()) < len(raw_lines("complete-3-run.txt")) / 10


# ---------------------------------------------------------------------------
# What must stay visible, what is summarized, and robustness
# ---------------------------------------------------------------------------

def render(mode, *events, record=None, close=True, **context):
    report, out = reporter(mode, record, **context)
    for event in events:
        report.emit(event)
    if close:
        report.close()
    return out.getvalue()


def test_pre_existing_and_limited_notes_are_information_not_errors():
    output = render(
        "apply",
        "phase=progress stage=observation:baseline-preflight status=STARTED accounts=1 tasks=1",
        f"phase=baseline-preflight kind=entitlement consumer={MOVING} owner={OWNERS[0]} "
        "region=us-east-1 resource_arn=arn:aws:ec2:us-east-1:400000000006:ipam-pool/p via_shares=1",
        f"phase=baseline-preflight status=PRE_EXISTING kind=resolver_association consumer={MOVING} "
        "owner=400000000006 region=us-east-1 resource_arn=arn:aws:route53resolver:us-east-1:"
        "400000000006:resolver-rule/rslvr-rr-1 association_id=a-1 status=FAILED: not COMPLETE "
        "before the migration; recorded as found, never a blocker",
        f"phase=baseline-preflight status=LIMITED account={MOVING} region=us-east-1 "
        "resource=arn:aws:ec2:us-east-1:400000000006:subnet/s-1 type=ec2:Subnet RAM access is "
        "verified; this resource type has no resource-specific health check",
        f"phase=baseline-preflight status=LIMITED account={MOVING} region=us-east-1 "
        "resource=arn:aws:ec2:us-east-1:400000000006:subnet/s-2 type=ec2:Subnet RAM access is "
        "verified; this resource type has no resource-specific health check")
    assert "Recording the current state of 1 account before any change..." in output
    assert "Current state before any change: 1 item observed (1 access grant); no read gaps" in output
    assert "Recorded as found (1): already not healthy or not visible before the migration" in output
    assert re.search(r"Resolver rule association +400000000009 +us-east-1 +arn:aws:route53resolver:"
                     r"\S+rslvr-rr-1 +FAILED \(not COMPLETE\)", output)
    assert "never a blocker" in output and "BLOCKERS" not in output and "PROBLEMS" not in output
    assert "their RAM access is verified): 2 subnets" in output


def test_gaps_losses_warnings_and_problems_are_shown_in_full():
    reason = "AccessDeniedException operation=DescribeTransitGatewayAttachments (request r-1)"
    output = render(
        "verify",
        f"phase=verification status=GAP collector=tgw account={MOVING} region=us-west-2 "
        f"resource=arn:aws:ec2:us-west-2:400000000017:transit-gateway/tgw-1 reason={reason}",
        "phase=verification status=BASELINE_MISSING key=entitlement|400000000009|us-west-2|arn:x missing",
        "phase=verification migration_status=FAILED missing: entitlement|400000000009|us-west-2|arn:x",
        "phase=verification migration_status=FAILED failure drop association a-1 first absent t9",
        "phase=ram-org-prerequisites status=WARNING organization=o-abcdefghij "
        "management_account=111122223333 decision=NOT_MET prerequisite=all-features "
        "feature_set=CONSOLIDATED_BILLING shares=2: sharing with OU or organization principals "
        "needs ALL features; the temporary shares do not, so this never blocks",
        "status=INCOMPLETE owner=400000000017 region=us-west-2 share=arn:aws:ram:us-west-2:"
        "400000000017:resource-share/s-1 consumers=400000000009 phase=verification "
        "UnknownResourceException: share not found",
        "status=FAILED migration=local phase=verification resources_in_plan=1 expected_entitlements=1 "
        "planned_shares=1 created_shares=0 reused_shares=1 accepted_invitations=0 "
        "reused_invitations=0 exclusions=0 blockers=0 verification_failures=1 "
        "sharing_status=SHARING_INCOMPLETE migration_status=FAILED baseline_status=LOSS "
        "baseline_missing=1 baseline_degraded=0 observation_gaps=1")
    flat = " ".join(output.split())
    assert f"Read gap (tgw), account {MOVING}, Region us-west-2" in flat and reason in flat
    assert "LOSSES AGAINST THE BASELINE (1)" in output
    assert "missing: entitlement|400000000009|us-west-2|arn:x: missing" in flat
    assert "- failure drop association a-1 first absent t9" in flat
    assert "WARNING: Organization o-abcdefghij (management account 111122223333): sharing with OU" \
        in flat
    assert "INCOMPLETE: Verifying temporary share s-1 of owner 400000000017 in us-west-2 failed: " \
        "UnknownResourceException: share not found" in flat
    assert "Result: FAILED - access recorded in the baseline was lost" in flat
    assert "Baseline: LOSS (1 missing, 0 degraded, 1 read gap)" in flat
    assert "Exit code: 1" in output


def test_accepted_overridden_and_not_acceptable_lines_are_prominent():
    output = render(
        "plan",
        "phase=preflight status=ACCEPTED blocker=b-0123456789ab category=configuration "
        'accepted_at=2026-10-21T10:00:00+00:00 accepted_reason="Shared separately" '
        'consequence="this share is not bridged" arn:aws:ram:us-east-1:400000000006:'
        "resource-share/s-9: owner=400000000006 region=us-east-1 Original account-facing "
        "consumers are unresolved; provide a principal-map override")
    assert "ACCEPTED BLOCKERS (1)" in output
    assert "ACCEPTED b-0123456789ab  Configuration needed [configuration]" in output
    assert "Accepted 2026-10-21T10:00:00+00:00: Shared separately" in output
    assert "Consequence: this share is not bridged" in output
    assert "provide a principal-map override" in " ".join(output.split())

    report, out = reporter("complete")
    report.emit("phase=complete status=OVERRIDDEN original missing: entitlement|400000000009|r|arn:y")
    report.emit("owner=400000000006 region=us-east-1 phase=complete action=DELETE_SHARE "
                "share=arn:aws:ram:us-east-1:400000000006:resource-share/t-1 "
                "consumers=400000000009 resources=2")
    report.flush()  # before the FORCE-COMPLETE prompt
    output = out.getvalue()
    assert "OVERRIDDEN SAFETY CHECKS (1)" in output
    assert output.index("OVERRIDDEN SAFETY CHECKS") < output.index("Planned actions (1;")
    assert "OVERRIDDEN: Original missing: entitlement|400000000009|r|arn:y" in output

    report, out = reporter("approve", accept_reason="x")
    report.emit('blocker=b-aaaaaaaaaaaa phase=approve status=NOT_ACCEPTABLE category=authentication '
                'why="an account that cannot be authenticated cannot be inspected or written; '
                'supply its access" account=000000000001 phase=authentication status=BLOCKED '
                "ExpiredTokenException: token expired")
    report.emit("migration=local phase=approve status=NOTHING_ACCEPTED no acceptable blocker was chosen")
    report.close()
    flat = " ".join(out.getvalue().split())
    assert "NOT ACCEPTABLE (1)" in flat and "b-aaaaaaaaaaaa" in flat
    assert "Why: an account that cannot be authenticated" in flat
    assert "ExpiredTokenException: token expired" in flat
    assert "Result: NOTHING_ACCEPTED" in flat and "Exit code: 1" in flat


def test_operator_exclusions_are_in_the_header():
    output = render(
        "plan",
        'phase=verification-scope status=EXCLUDED collector=tgw_routes kind=tgw_route '
        'reason="Routes are checked by the network team"',
        "TGW route health and network reachability are outside this verification scope.",
        'phase=recipient-scope status=EXCLUDED accounts=111122223333 reason="Decommissioned"',
        "account=400000000009 phase=authentication status=VERIFIED",
        excluded_regions=["ap-east-1"], exclusion_reason="SCP denies RAM reads there")
    assert "Excluded Regions: ap-east-1 (reason: SCP denies RAM reads there)" in output
    assert "Excluded recipients: 111122223333 (reason: Decommissioned)" in output
    assert "TGW route checks excluded: Routes are checked by the network team" in output
    assert output.count("network reachability") == 1


def test_unrecognized_and_malformed_lines_are_printed_as_received_and_never_raise():
    strange = ["phase=new-thing status=SURPRISE detail=1", 'reason="unterminated', "status=",
               "phase=progress stage=x account=a done=1/1 overall=nope", "=== not an event",
               "phase=plan template={broken json", "événement status=BLOCKED?",
               "owner=1 region=r group=g stack=s consumers= external_principals=true",
               "  resource=orphan-indented-line"]
    report, out = reporter("plan")
    for line in strange:
        report.emit(line)
    output = out.getvalue()
    for line in strange[:7]:
        if line != "owner=1 region=r group=g stack=s consumers= external_principals=true":
            assert line in output.splitlines()
    report.close()
    report.close()  # idempotent
    report.emit("status=BLOCKED after close")
    assert out.getvalue().splitlines()[-1] == "status=BLOCKED after close"


def test_a_failing_section_falls_back_to_the_raw_events(monkeypatch):
    def broken(self):
        raise RuntimeError("synthetic")
    monkeypatch.setattr(ReadableReporter, "_plan_section", broken)
    event = ("owner=400000000006 region=us-east-1 group=g1 stack=S consumers=400000000009 "
             "external_principals=true retain_on_organization_leave=true")
    output = render("plan", event, "phase=plan status=EXCLUDED local empty share")
    assert "The readable summary could not be shown: RuntimeError: synthetic" in output
    assert event in output and "phase=plan status=EXCLUDED local empty share" in output
    # Even a header that cannot be built never raises into the run.
    output = render("plan", "phase=plan status=EXCLUDED local empty share",
                    excluded_regions=[1, 2], exclusion_reason=None)
    assert "phase=plan status=EXCLUDED local empty share" in output


def test_emit_is_thread_safe():
    report, out = reporter("plan")

    def work(index):
        for number in range(200):
            report.emit(f"account={index:06d}{number:06d} phase=authentication status=VERIFIED")
    threads = [threading.Thread(target=work, args=(index,)) for index in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    report.emit("migration=x phase=plan writes=DISABLED")
    report.close()
    assert "Checking account access... 1600 accounts verified" in out.getvalue()


def test_the_blocker_categories_are_the_runs_own():
    ours = [(name, pattern.pattern, pattern.flags) for name, pattern in console.BLOCKER_PATTERNS]
    theirs = [(name, pattern.pattern, pattern.flags) for name, pattern in cli.BLOCKER_PATTERNS]
    assert ours == theirs and console.RECORDED_LOSS == cli.RECORDED_LOSS
    assert set(console.CATEGORY_TITLES) == set(cli.BLOCKER_ACTIONS)


def test_long_text_wraps_with_a_hanging_indent_and_keeps_every_word():
    text = "word " * 60 + "arn:aws:route53resolver:us-east-1:400000000006:resolver-rule/" + "x" * 80
    lines = console.wrap(text, "  ", "    ")
    assert all(len(line) <= console.WIDTH for line in lines[:-1])
    assert lines[1].startswith("    ") and " ".join(" ".join(lines).split()) == " ".join(text.split())


# ---------------------------------------------------------------------------
# main(argv, readable=True) through the CLI harness
# ---------------------------------------------------------------------------

def readable(capsys, argv, input_fn=None, code=None):
    capsys.readouterr()
    result = cli.main(argv, input_fn=input_fn, readable=True)
    if code is not None:
        assert result == code
    return capsys.readouterr().out


class Prompts:
    """input_fn that records what was on screen when each prompt was asked."""

    def __init__(self, capsys, reply):
        self.capsys, self.reply, self.screens, self.events = capsys, reply, [], []

    def __call__(self, prompt):
        self.events.append("prompt")
        self.screens.append(self.capsys.readouterr().out)
        return self.reply(prompt) if callable(self.reply) else self.reply


@pytest.fixture
def flushes(monkeypatch):
    events = []
    original = ReadableReporter.flush

    def flush(self):
        events.append("flush")
        original(self)
    monkeypatch.setattr(ReadableReporter, "flush", flush)
    return events


def test_planned_plan(harness, capsys, migration_record):
    output = readable(capsys, with_record(args(), migration_record), code=0)
    assert output.startswith(f"RAMShift plan - migration {MIGRATION}\nRegions: us-east-1, us-west-2\n")
    assert "Checking account access... 2 accounts verified" in output
    assert re.search(rf"{OWNER} +{REGION} +{CONSUMER} +1 IPAM pool", output)
    assert "Organization policies: ALLOWED - 2 accounts checked" in output
    assert "Result: PLANNED" in output and "Exit code: 0" in output
    assert f"Record: {migration_record} (revision 1)" in " ".join(output.split())
    assert_noise_is_summarized(output)


def test_blocked_plan_with_an_acceptable_blocker(harness, capsys, migration_record):
    harness.receive(owner=OTHER_OWNER)
    output = readable(capsys, with_record(args(), migration_record), code=1)
    blocker, = read_record(migration_record)["plan"]["blocked"]
    identity = cli.blocker_id(blocker)
    flat = " ".join(output.split())
    assert "BLOCKERS (1)" in output
    assert ("Owner outside the approved owner scope [owner-outside-approved-scope]: 1 blocker "
            "(1 owner, 1 share, 1 resource, 1 observation)") in flat
    assert f"1. {identity} Owner {OTHER_OWNER} is outside the approved owner scope" in flat
    assert f"Full text: {blocker}" in flat
    assert "Next step: run approve with the same --record and type the APPROVE-OWNERS token" in flat
    assert (f"      ramshift approve --record {migration_record} --accept-blockers "
            'owner-outside-approved-scope --accept-reason "<reason>"') in output.splitlines()
    assert re.search(rf"{CONSUMER} +{OTHER_OWNER} +{REGION} +original +from owners outside", output)
    assert "Result: BLOCKED - the plan cannot be applied until each blocker above is resolved" in flat
    assert "Exit code: 1" in output
    assert output.index("BLOCKERS (1)") < output.index("Result: BLOCKED")


def test_approve_accept_blockers_shows_each_consequence_before_the_prompt(
        harness, capsys, migration_record, flushes):
    harness.receive(owner=OTHER_OWNER)
    readable(capsys, with_record(args(), migration_record), code=1)
    identity = cli.blocker_id(read_record(migration_record)["plan"]["blocked"][0])
    prompts = Prompts(capsys, lambda prompt: prompt.split("Type ", 1)[1].split(" to accept", 1)[0])
    flushes.clear()
    output = readable(capsys, ["approve", "--record", str(migration_record), "--accept-blockers",
                               "all", "--accept-reason", "Re-shared after the move"], prompts, 0)
    screen = " ".join(prompts.screens[0].split())
    assert flushes == ["flush"] and prompts.events == ["prompt"]
    assert screen.startswith(f"RAMShift approve - migration {MIGRATION}")
    assert f"1. {identity} Owner outside the approved owner scope [owner-outside-approved-scope]" \
        in screen
    assert "Consequence if accepted: that owner's resources are not bridged" in screen
    assert "Reason recorded with each acceptance: Re-shared after the move" in screen
    assert "Result:" not in screen
    flat = " ".join(output.split())
    assert f"Accepted and recorded: {identity}" in flat
    assert "Result: ACCEPTED - the blockers above are accepted and recorded" in flat
    assert "Exit code: 0" in flat and "Next step: Re-run plan with --record: accepted blockers" in flat
    output = readable(capsys, with_record(args(), migration_record), code=0)
    assert "ACCEPTED BLOCKERS (1)" in output and f"ACCEPTED {identity}" in output
    assert "Result: PLANNED" in output and "Accepted blockers: 1" in " ".join(output.split())


def test_apply_shows_the_plan_before_the_prompt_and_progress_after_it(
        harness, capsys, migration_record, flushes):
    readable(capsys, with_record(args(), migration_record), code=0)
    prompts = Prompts(capsys, harness.confirm)
    flushes.clear()
    output = readable(capsys, with_record(args("apply"), migration_record), prompts, 0)
    assert flushes == ["flush"] and prompts.events == ["prompt"]
    screen = prompts.screens[0]
    assert re.search(rf"{OWNER} +{REGION} +{CONSUMER} +1 IPAM pool", screen)
    assert "Apply creates or updates these migration stacks" in screen
    assert "Current state before any change: 1 item observed (1 access grant); no read gaps" in screen
    assert "Result:" not in screen
    assert "Organization policies re-checked: ALLOWED" in output
    assert "Baseline captured: 1 item, complete (record revision 2)" in output
    assert f"Migration stack ready: local-migration-stack (owner {OWNER}, {REGION})" in output
    assert re.search(rf"{OWNER} +{REGION} +temporary-\S+ +{CONSUMER} +1 +verified", output)
    assert "Result: SHARING_READY" in output and "Exit code: 0" in output
    revision = read_record(migration_record)["revision"]
    assert f"Record: {migration_record} (revision {revision})" in " ".join(output.split())
    assert_noise_is_summarized(prompts.screens[0] + output)


def test_verify(harness, capsys, migration_record):
    applied(harness, migration_record)
    output = readable(capsys, mode_args("verify", migration_record), code=0)
    assert "Result: PENDING_MIGRATION - the temporary shares work" in output
    assert re.search(rf"{CONSUMER} +still in its baseline organization o-sourceorg01", output)
    assert "Baseline comparison: INTACT - 0 missing, 0 degraded, 0 read gaps" in output
    assert "Exit code: 0" in output
    assert_noise_is_summarized(output)


def test_monitor(harness, capsys, migration_record):
    applied(harness, migration_record)
    harness.organizations[CONSUMER] = "o-destination1"
    harness.original_lost.add((CONSUMER, REGION, POOL))
    output = readable(capsys, mode_args("monitor", migration_record), code=0)
    assert output.startswith(f"RAMShift monitor - migration {MIGRATION}\nAccounts: 1\n")
    assert re.search(rf"{CONSUMER} +o-destination1 +CHANGED +1 +0 +0 +0", output)
    assert (f"Original share access removed: {CONSUMER} | {REGION} | {POOL} | current "
            "access=TEMPORARY_ONLY") in " ".join(output.split())
    assert "Result: CHANGED" in output and "Exit code: 0" in output
    assert_noise_is_summarized(output)


def test_complete_shows_the_actions_before_the_prompt(harness, capsys, migration_record, flushes):
    applied(harness, migration_record)
    harness.replacement.add((CONSUMER, REGION, POOL))
    prompts = Prompts(capsys, confirm_complete(harness))
    flushes.clear()
    output = readable(capsys, complete_args(migration_record), prompts, 0)
    assert flushes == ["flush"] and prompts.events == ["prompt"]
    screen = prompts.screens[0]
    assert "Permanent replacement access found: 1 resource for 000000000002" in screen
    assert "Planned actions (2; smallest share first, re-verifying after each)" in screen
    assert "DELETE_SHARE" in screen and "DELETE_STACK" in screen and "Result:" not in screen
    assert "Deleted temporary share temporary-" in output
    assert f"Deleted migration stack (owner {OWNER}, {REGION})" in output
    assert "Result: COMPLETED" in output and "Exit code: 0" in output


def test_a_refused_complete_and_a_cancelled_apply_keep_their_exit_codes(
        harness, capsys, migration_record):
    applied(harness, migration_record)
    harness.original_lost.add((CONSUMER, REGION, POOL))
    output = readable(capsys, complete_args(migration_record), code=1)
    assert "FAILED CHECKS (1): nothing was retired" in output and POOL in output
    assert "Exit code: 1" in output
    output = readable(capsys, with_record(args("apply"), migration_record), lambda _p: "no", 2)
    assert "Result: CANCELLED" in output and "Exit code: 2" in output


def test_an_error_is_the_result_with_its_full_reason(harness, capsys):
    output = readable(capsys, args("apply"), code=1)
    assert "Result: BLOCKED - Apply could not run" in output
    assert "Reason: Apply requires --record: the reviewed migration record written by plan" in output
    assert "Exit code: 1" in output


@pytest.mark.parametrize("make", ["plan", "verify"])
def test_raw_output_restores_the_exact_raw_stream(harness, capsys, migration_record, make):
    if make == "plan":
        argv = args()
    else:
        applied(harness, migration_record)
        argv = mode_args("verify", migration_record)
    argv += ["--account-workers", "1", "--region-workers", "1"]  # one event order
    capsys.readouterr()
    assert cli.main(argv) == 0
    raw = capsys.readouterr().out
    assert cli.main(argv + ["--raw-output"], readable=True) == 0
    assert capsys.readouterr().out == raw
    assert "status=" in raw and "RAMShift" not in raw


def test_blockers_with_one_reason_are_listed_compactly_with_the_region_exclusion():
    denied = ("account=000000000002 region={} phase=received-audit status=BLOCKED "
              "operation=GetResourceShares AccessDeniedException: User: arn:aws:sts::000000000002:"
              "assumed-role/Admin/session-{} is not authorized to perform: ram:GetResourceShares on "
              "resource: arn:aws:ram:{}:000000000002:resource-share/* with an explicit deny in a "
              "service control policy: arn:aws:organizations::000000000009:policy/o-abcdefghij/"
              "service_control_policy/p-abc12345 (request r-{})")
    regions = ["eu-west-1", "ap-south-1", "us-east-2"]
    out = io.StringIO()
    report = console.ReadableReporter("plan", None, stream=out)
    for number, region in enumerate(regions):
        reason = denied.format(region, number, region, number)
        report.emit(f"phase=preflight status=BLOCKED {reason} blocker=b-00000000000{number}")
    report.emit("phase=blocker-summary status=BLOCKED blockers=3 categories=1")
    report.emit("phase=blocker-summary category=region-denied-by-policy blockers=3 consumers=1 "
                "next_action=leave the Regions out")
    report.emit("status=BLOCKED migration=m resources_in_plan=0 expected_entitlements=0 "
                "planned_shares=0 created_shares=0 reused_shares=0 accepted_invitations=0 "
                "reused_invitations=0 exclusions=0 blockers=3 verification_failures=0")
    report.close()
    text = out.getvalue()
    assert "3 blockers with the same reason; the first in full:" in text
    assert text.count("is not authorized to perform") == 1
    assert all(f"b-00000000000{n}  account 000000000002, {r}" in text for n, r in enumerate(regions))
    assert "--exclude-regions ap-south-1 eu-west-1 us-east-2 --exclude-reason" in text
