# RAMShift 1.0.0 User Guide

RAMShift keeps accounts connected to shared AWS resources while they move from one AWS
Organization to another, and removes its temporary access safely afterwards.

Contents

1. [How RAMShift works](#1-how-ramshift-works)
2. [Account roles](#2-account-roles)
3. [Installation and setup](#3-installation-and-setup)
4. [Permissions and organization requirements](#4-permissions-and-organization-requirements)
5. [Before you start](#5-before-you-start)
6. [Migration procedure, step by step](#6-migration-procedure-step-by-step)
7. [Mode reference](#7-mode-reference)
8. [Statuses and exit codes](#8-statuses-and-exit-codes)
9. [The migration record](#9-the-migration-record)
10. [Options reference](#10-options-reference)
11. [Stop conditions](#11-stop-conditions)
12. [Never do this](#12-never-do-this)
13. [Troubleshooting and known limitations](#13-troubleshooting-and-known-limitations)
14. [Validation](#14-validation)

---

## 1. How RAMShift works

AWS RAM shares often target an organization or an OU. An account that leaves that OU,
or the organization, stops receiving them. Its Route 53 Resolver rule associations,
Transit Gateway attachments and routes, IPAM allocations and Private CA access break.

RAMShift bridges the move:

1. **plan** (read-only) starts from the moving accounts. It lists everything they
   receive from other accounts in every enabled Region plus us-east-1, decides which
   owner accounts and Regions to inspect, and plans one temporary share per set of
   resources, owner, Region and moving accounts. The plan is written to a **migration
   record**.
2. **apply** creates, in each owner account and Region, one CloudFormation stack named
   `TemporaryMigrationRAMShares-<owner>-<region>-<id>`. Its RAM shares name the moving
   accounts directly as principals, allow external principals, and set *retain sharing
   when the account leaves the organization*, so they keep working after the move.
   Each share is tagged `Purpose=TemporaryMigrationRAMShares` and `MigrationId=<id>`.
   apply accepts the invitations in the moving accounts and records the **baseline**:
   the state of everything the accounts rely on, captured once, immediately before the
   first write.
3. You move the accounts, outside RAMShift. Access continues through the temporary
   shares.
4. **monitor** (on demand) and **verify** compare the current state with the baseline
   whenever you run them.
5. Once permanent sharing exists for the accounts in their new organization,
   **complete** deletes the temporary shares, smallest first, re-checking after each
   deletion that nothing original was lost.

**What RAMShift writes:** apply's CloudFormation stacks and RAM shares in owner
accounts, apply's invitation acceptances in moving accounts, and complete's deletion of
its own temporary shares (or of moving accounts' principals on them) and stacks.
Everything else is read-only. The migration record is a local file.

**What RAMShift never does:** move accounts; change or delete original shares, shared
resources or associations; create IAM roles or change trusts, SCPs, RCPs, permission
sets or AWS profile configuration; create Resolver associations; enable organization
features.

---

## 2. Account roles

You give RAMShift two lists: `--owners` (accounts whose shares are inspected) and
`--consumers` (accounts that move). Every account's role follows from these lists and is
recorded in the record's `scope`:

| Role | Given as | Treatment |
|---|---|---|
| **Migrating consumer** | `--consumers` only | What it receives is inventoried in every enabled Region plus us-east-1. It receives temporary shares. |
| **Stationary owner** | `--owners` only | Its owned shares are inspected. What it receives itself is not audited, because the migration does not affect it. |
| **Migrating owner** | Both lists, or `--consumers` when the account owns RAM shares | It moves *and* shares its own resources. Its owned shares are inspected in every Region it has enabled plus us-east-1, and what it receives is audited like any moving account. |

### Listing an account in both lists

Yes, an account can be listed in both `--owners` and `--consumers`. It is then a
migrating owner. For example:

```bash
ramshift plan --migration-id wave1 --record wave1.json \
  --owners 111111111111 333333333333 \
  --consumers 222222222222 333333333333 \
  --scan-enabled-regions --account-map accounts.json
```

records:

| Account | Role |
|---|---|
| 111111111111 | `stationary_owners`: an owner that stays |
| 333333333333 | `migrating_owners`: moves and shares its own resources |
| 222222222222 | `migrating_consumers`: moves |

Listing it in both is optional. plan lists the shares every moving account owns itself,
in every audited Region (`phase=owned-audit status=OWNED`). A moving account that owns
any share that is not `DELETED` is a migrating owner even when only `--consumers` names
it:

```text
account=333333333333 phase=owned-audit status=MIGRATING_OWNER owned_shares=N regions=...
```

It is added to the owner scope and recorded in `scope.migrating_owners` and
`scope.detected_owners`. A failed read of an account's own shares blocks the plan.

### What a migrating owner gets

- **What it receives from other owners:** temporary shares, like any moving account.
- **Its own resources:** an owner is never a consumer of its own resources; nothing is
  shared back to itself.
- **What it shares with other moving accounts** in the same migration (also in
  `--consumers`): temporary shares from it to them. This is supported.
- **What it shares with accounts that stay behind:** plan blocks:

  ```text
  migrating owner 333333333333 shares with stationary consumers [...]; their access ends
  when the owner leaves its organization and owner-migration continuity is not supported
  by this tool version
  ```

  When the owner leaves its organization, its organization and OU shares stop reaching
  the accounts that stay, and RAMShift 1.0.0 does not bridge that direction. A
  `--principal-map` override never hides a live or configured principal from this
  check. To proceed, either move those accounts in the same migration (add them to
  `--consumers`), or arrange their access separately before the owner moves, outside
  RAMShift, and re-scope the migration.

### Scope in later modes

`verify`, `monitor` and `complete` take owners (stationary and migrating), consumers and
Regions from the record. Any `--owners` or `--regions` you pass must match the record
(`--owners` may leave out detected migrating owners). For `verify`, `--consumers` must
match too. For `monitor` and `complete`, `--consumers` instead chooses which moving
accounts to report on or retire; `--all-accounts` chooses all of them. Accounts served by
a recorded temporary share, or recorded in the baseline, stay selectable even if a later
plan narrowed the scope.

---

## 3. Installation and setup

### Run RAMShift

- Python 3.11 or later on macOS or Linux. On Windows, use WSL (the record lock uses
  POSIX file locking).
- Run it from source, or build a single executable that bundles its dependencies.

From source:

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
alias ramshift="python $PWD/src/temporary_migration_ram_shares.py"
ramshift --version
```

As one executable (a Python zipapp with boto3, botocore and PyYAML inside):

```bash
packaging/build.sh                      # writes dist/ramshift-<version>.pyz
alias ramshift="$PWD/dist/ramshift-1.0.0.pyz"
ramshift --version
```

On first run the executable unpacks itself into `~/.cache/ramshift/<version>-<build>/`.
Set `RAMSHIFT_CACHE` to use another directory. If the `python3` on your PATH is older than
3.11 it stops with a clear message; run it with a newer interpreter.

plan downloads the AWS RAM shareable-resource-type table from the AWS documentation to
decide which resource types can be shared outside an organization, so it needs HTTPS
access to docs.aws.amazon.com.

### Credentials

Every owner account and every moving account must be reachable. RAMShift confirms each
account with STS `GetCallerIdentity` before using it, and never selects a profile on its
own. Choose one approach:

| Approach | Options |
|---|---|
| Map every account (simplest) | `--account-map accounts.json`: `{"111111111111": "network-readonly", "222222222222": "arn:aws:iam::222222222222:role/MigrationRead"}`. Values are profile names or role ARNs in that account; role ARNs need a base `--profile`. Accounts are 12-digit strings. |
| IAM Identity Center | `--profile <base SSO profile>` plus `--sso-role <permission set role>` for unmapped accounts. Run `aws sso login` first. |
| Role assumption | `--profile <base>` plus `--role-name <role>` (the same role name in every account), or `--role-map` |
| Separate source and destination bases | `--source-profile` and `--destination-profile` |

`--profile-map` and `--role-map` are restricted forms of `--account-map`. Mappings that
conflict are refused. Maps hold profile names or role ARNs, never credentials. Role
sessions use a Regional STS endpoint so that opt-in Regions work.

**Access after the move:** `verify`, `monitor` and `complete` read the moving accounts
after they joined the destination organization. Use profiles or roles that work there,
not ones that depend only on membership of the source organization or on the source's
IAM Identity Center.

### Record key (recommended for production)

```bash
openssl rand -hex 32 > ~/secure/ramshift-wave1.key        # keep it outside the record's storage
export RAM_MIGRATION_RECORD_KEY_FILE=~/secure/ramshift-wave1.key
```

With a key (`RAM_MIGRATION_RECORD_KEY`, or `RAM_MIGRATION_RECORD_KEY_FILE`, at least 16
bytes; not both), every record write is signed with HMAC-SHA256 and every read verifies
it. Use one key for the whole life of a record, and set it for every command: a signed
record never loads without its key, and a record started without a key must be continued
without one.

### A convenient shell setup

```bash
set -o pipefail
MIGRATION_ID=wave1
RECORD="records/${MIGRATION_ID}.json"        # the directory must exist
OWNERS="111111111111,333333333333"
CONSUMERS="222222222222,333333333333"
AUTH=(--account-map accounts.json)
mkdir -p records logs
```

Keep `OWNERS`, `CONSUMERS`, the Region options and any `--exclude-regions`,
`--principal-map`, `--capabilities` or `--destination-ou` identical for plan and apply:
the reviewed plan digest covers the planned shares, the account roles and any excluded
Regions.

---

## 4. Permissions and organization requirements

| Mode | Owner accounts | Moving accounts |
|---|---|---|
| plan, verify, monitor | Read: RAM (`Get*`, `List*`), CloudFormation (`DescribeStacks`, `GetTemplate`, `ListStackResources`), Route 53 Resolver rules, associations and endpoints, EC2 TGW attachments and route tables, IPAM pool allocations, ACM PCA, `organizations:DescribeOrganization` | Read: RAM, Route 53 Resolver, EC2, ACM PCA, `ec2:DescribeRegions`, `organizations:DescribeOrganization` |
| apply | `ram:CreateResourceShare` (with external principals), `ram:TagResource`, `ram:AssociateResourceShare`, `cloudformation:CreateChangeSet`, `DescribeChangeSet`, `ExecuteChangeSet` plus the reads | `ram:AcceptResourceShareInvitation`, `ram:GetResourceShareInvitations` |
| complete | `ram:DeleteResourceShare`, `ram:DisassociateResourceShare`, `cloudformation:DeleteStack` plus the reads | Read only |
| approve | None (local) | None |

plan and apply also read AWS Organizations policies through each organization's
management account (`DescribeOrganization`, `ListParents`, `ListPoliciesForTarget`,
`DescribePolicy`, `ListAWSServiceAccessForOrganization`). Map those accounts to
read-only roles.

**Organization-policy preflight.** An administrator role does not prove that SCPs and
RCPs allow a call. plan, and apply both before and after its confirmation, evaluate every
SCP and RCP attached to each account, its OUs and the root, for the requests the
migration makes: apply's writes in each owner account and Region, invitation acceptance
in each moving account, and, with `--destination-ou <OU ARN>`, the reads verify and
monitor need in each moving account on the destination path. The preflight never edits,
attaches or enables anything.

**Organization requirements.**

- The owner's organization must allow RAM sharing with external accounts.
- When an original share uses OU or organization principals, its organization (and the
  destination organization, with `--destination-ou`) must have ALL features enabled and
  RAM trusted access (`ram.amazonaws.com`). plan blocks with
  `phase=ram-org-prerequisites status=BLOCKED` otherwise.

---

## 5. Before you start

| Check | Why |
|---|---|
| A change is approved naming the migration ID, the moving accounts, the owners, the Regions, the target OU and the transfer window | Scope is reviewed, never discovered silently |
| A transfer runbook exists for the account move itself | RAMShift does not move accounts |
| Read access works in both organizations | verify and monitor authenticate every account after each move step |
| A record key is set for every command | The record is the evidence of the migration |
| Change freeze from apply until complete | No changes to the affected Resolver rules, endpoints and associations, TGW attachments and routes, IPAM allocations or Private CAs, and none to the original shares except the permanent sharing of step 8. Any baseline item that disappears is a permanent failure. |

---

## 6. Migration procedure, step by step

### Step 1: plan

```bash
ramshift plan --record "$RECORD" --migration-id "$MIGRATION_ID" \
  --owners "$OWNERS" --consumers "$CONSUMERS" --scan-enabled-regions "${AUTH[@]}" \
  --export-plan logs/plan-1.json | tee logs/plan-1.log
```

Read-only toward AWS. It creates the record. Lines to look for:

| Output | Meaning |
|---|---|
| `account=<id> phase=authentication status=VERIFIED` | STS confirmed the account. Every account must have this line. |
| `account=<id> region=<r> phase=received-regions status=EXCLUDED ...` | A requested Region is not enabled in that account. |
| `... status=EXCLUDED_BY_OPERATOR reason="..."` | A Region you excluded with `--exclude-regions`. |
| `account=<id> phase=owned-audit status=MIGRATING_OWNER owned_shares=N regions=...` | A moving account owns shares: it is a migrating owner. |
| `account=... owner=... share=... phase=received-audit status=<S>` | What a moving account receives (statuses in [section 7.1](#71-plan)). |
| `owner=<id> phase=scope regions=...` | Regions inspected for that owner. |
| `owner=... region=... group=... stack=... consumers=... external_principals=true retain_on_organization_leave=true` | One planned temporary share, followed by its resources and source shares. |
| `phase=plan action=<CREATE or UPDATE_OR_REUSE> template=...` | The exact CloudFormation template. |
| `phase=permission-change status=INFO ...` | The temporary share attaches another permission version than the original. Information only. |
| `phase=permission-change status=WARNING ... grants less than the original share (...)` | Once the original share stops applying, the accounts keep only what the temporary share grants. Tell the account owner. |
| `phase=owner-scope owner=... status=APPROVAL_REQUIRED` | An owner you did not list supplies moving accounts (step 2). |
| `phase=plan status=EXCLUDED ...` | Excluded inventory, with the reason. Review it. |
| `phase=org-policy status=<ALLOWED or BLOCKED> accounts=N denies=N gaps=N ...` | The organization-policy preflight result. |
| `phase=preflight status=BLOCKED ...` and `phase=blocker-summary ...` | Blockers, summarized by category with the next action. |
| `phase=plan record=<path> revision=N status=<PLANNED or BLOCKED> digest=<sha256>` | The record revision written. |
| `status=PLANNED ...` (exit 0) or `status=BLOCKED ...` (exit 1) | Summary. |

Resolving blockers:

| Blocker | Resolution |
|---|---|
| `phase=owner-scope ... APPROVAL_REQUIRED` | Step 2, then add the owner to your account map. |
| `received dependencies are not covered by any planned temporary share` (`NOT_COVERED`) | The owner's share produced no planned share; see that owner's other blockers. Never continue with it: the account would lose that access when it leaves. |
| `migrating owner ... shares with stationary consumers` | See [section 2](#what-a-migrating-owner-gets). Re-scope. |
| `Provide principal-map override to resolve historical organization/OU membership` | Supply a reviewed `--principal-map` naming the intended accounts of that share. |
| `pending intended received entitlements` | Accept or resolve the pending sharing first. |
| `unsupported or unverified external-sharing capability` | That resource type cannot be shared outside an organization; the account would lose it when it leaves. Escalate. |
| `featureSet CREATED_FROM_POLICY` or `PROMOTING_TO_STANDARD` | The owner promotes the share to a standard share as the message says, then re-run plan. Shares that serve only AWS service principals are excluded instead. |
| `AWS RAM allows at most 5000 ... associations per resource share` | Split the moving accounts across migrations. |
| `existing migration stack cannot be retried automatically` | Inspect and reconcile the failed stack. Do not delete it. |
| `phase=org-policy status=BLOCKED decision=EXPLICIT_DENY` or `NO_ALLOW` | An SCP or RCP denies the named actions. Obtain an approved exception from the policy owner, or re-scope. |
| `phase=org-policy status=GAP` | The statement cannot be decided automatically. Review its `status=REVIEW` text with the policy owner. |
| `phase=org-policy status=BLOCKED decision=UNREADABLE` | Map the named management account with read access to AWS Organizations. |
| `phase=ram-org-prerequisites status=BLOCKED` | The organization lacks ALL features or RAM trusted access. Its owner must enable them. |

Regions where RAM reads are denied on purpose (for example by a Control Tower Region
deny control) block the plan until you exclude them explicitly:
`--exclude-regions eu-central-1 ap-south-1 --exclude-reason "Region deny control"`.
Nothing in an excluded Region is inspected, and every summary line says so. us-east-1
(RAM's global home) cannot be excluded.

### Step 2: approve proposed owners

Only when step 1 shows `phase=owner-scope ... status=APPROVAL_REQUIRED`. No AWS access.

```bash
ramshift approve --record "$RECORD" --migration-id "$MIGRATION_ID" | tee logs/approve-1.log
```

It prints each proposed owner's unique resources, observations, shares, pending shares,
Regions, consumers and resource types, then asks you to type
`APPROVE-OWNERS <migration-id> <request-id>`.

| Output | Meaning |
|---|---|
| `status=CONFIRMED`, then `approval=<id> phase=approve status=APPROVED` | Recorded. Exit 0. |
| `status=NOT_APPROVED confirmation did not match` | Not recorded. Exit 2. |
| `status=NOTHING_PENDING` | Nothing to approve. Exit 0. |
| `the record changed during review` | Another command wrote the record. Re-run approve. |

Permission-version differences never need approval.

### Step 3: plan again

Repeat step 1 (log `logs/plan-2.*`), adding access mappings for the approved owners. The
record adds them to the scope (`phase=owner-scope status=APPROVED owners=... source=record`).
New owners can raise new blockers. Repeat steps 2 and 3 until the plan is clean.

Continue only when the run prints `status=PLANNED` and exits 0. Note the revision and
digest, and back up the record.

### Step 4: apply

```bash
ramshift apply --record "$RECORD" --migration-id "$MIGRATION_ID" \
  --owners "$OWNERS" --consumers "$CONSUMERS" --scan-enabled-regions "${AUTH[@]}" \
  | tee logs/apply-1.log
```

Use exactly the inputs of the reviewed plan. Before the prompt, check:

- `phase=baseline-preflight kind=...` lines: the original state that becomes the
  baseline (entitlements, Resolver associations with `status=COMPLETE`, endpoints, TGW
  attachments and routes, IPAM allocations, PCA access).
- No `phase=baseline-preflight status=GAP` line.
- No `phase=preflight status=BLOCKED`. A `phase=reviewed-record ...` blocker means the
  live state or the RAMShift build differs from the reviewed plan: go back to step 3.

Then type `APPLY <migration-id>`. Any other reply prints `status=CANCELLED` and exits 2
without AWS writes.

| Output after confirmation | Meaning |
|---|---|
| `phase=baseline status=CAPTURED items=N complete=true revision=N` | Baseline recorded before any write (first apply only). `complete=false` is a stop condition. |
| `phase=write-gate status=OPEN plan_revision=N revision=N` | The record still holds the reviewed plan revision. |
| `phase=preflight status=BLOCKED ...` | Something changed after review; nothing was written. |
| `phase=record status=STACK_COMPLETE revision=N stack_shares=N` | That stack's shares are in the record. |
| `phase=creation status=COMPLETE stack=...` | Stack created or updated. |
| `phase=acceptance status=ASSOCIATED` | The moving account accepted the share. |
| `phase=verification status=VERIFIED resources=N` | The share is verified for that account. |
| `status=NOT_ASSOCIATED ...` | That Resolver rule had no association before the migration. Information; sharing never creates associations. |

Success is exit 0 with `status=SHARING_READY ... migration_status=PENDING_MIGRATION
baseline_status=INTACT`. `status=INCOMPLETE` (exit 1) keeps the successful shares; fix
the listed failure and re-run apply. Expired or rejected invitations, rejected change
sets and failed stacks need explicit reconciliation; RAMShift never deletes a share or
revokes an accepted principal to recover. Back up the record.

### Step 5: verify (the gate before moving anything)

```bash
ramshift verify --record "$RECORD" --migration-id "$MIGRATION_ID" "${AUTH[@]}" | tee logs/verify-premove.log
```

The gate passes only with exit 0 and `status=PENDING_MIGRATION ... sharing_status=SHARING_READY
baseline_status=INTACT baseline_missing=0 baseline_degraded=0 observation_gaps=0`, and a
`phase=verification status=VERIFIED` line for every share and account. Run it again
immediately before step 6.

### Step 6: move the accounts, with a monitor report after every step

The move happens outside RAMShift. Before it, and after each of its steps, run:

```bash
STEP=before-move    # after-deregister, after-leave, after-join, after-ou-move, after-enroll
ramshift monitor --record "$RECORD" --migration-id "$MIGRATION_ID" "${AUTH[@]}" \
  --consumers "$CONSUMERS" | tee "logs/monitor-${STEP}.log"
```

The `before-move` report must end `status=UNCHANGED exit_code=0`. Continue each step
only on exit 0.

A Control Tower to Control Tower move typically runs:

| Move step | Expected monitor report |
|---|---|
| 1. Move the account from its source OU to the source root (Control Tower deregistration) | `status=CHANGED`; each original share that targeted the OU shows `change=ORIGINAL_SHARE_DROPPED ... access=TEMPORARY_ONLY`; `lost=0 degraded=0` |
| 2. Leave the source organization | `organization_now=STANDALONE`; shares that depended on organization membership drop too; `lost=0` |
| 3. While standalone, remove the source landing zone's leftovers: its `StackSet-AWSControlTowerBP-*` stacks, its `StackSet-AWSControlTowerExecutionRole-*` stack and `AWSControlTowerManagedRule` (below) | `lost=0`, `recorded_drops=0` |
| 4. Accept the destination organization's invitation | `organization_now=<destination o-id>`, `lost=0` |
| 5. Move the account into the destination OU | `lost=0` |
| 6. Enroll it in the destination landing zone and wait for success | `lost=0` |

Reports after step 1 stay `CHANGED`, because the organization and the dropped original
shares differ from the baseline; a drop already recorded is not recorded again.
`status=LOSS` (exit 1) or `INCONCLUSIVE` (exit 3) is a stop condition. Record every
operation, request and handshake ID with UTC times.

**`AWSControlTowerManagedRule`.** If the destination landing zone has a different home
Region from the source, enrollment fails with:

```text
AWS Control Tower cannot create or delete the AWSControlTowerManagedRule EventBridge managed rule, because it was created from a different AWS home region. To continue, force delete the AWSControlTowerManagedRule in all AWS regions that were previously governed by AWS Control Tower and then try again.
```

Remove it in every Region the source landing zone governed, with the moving account's
own credentials, preferably while the account is standalone. Delete only the rule named
`AWSControlTowerManagedRule` whose `ManagedBy` is `controltower.amazonaws.com`:

```bash
MEMBER_PROFILE=<moving-account-profile>
for REGION in <every-region-the-source-landing-zone-governed>; do
  RULE=$(aws events list-rules --profile "$MEMBER_PROFILE" --region "$REGION" \
    --name-prefix AWSControlTowerManagedRule \
    --query "Rules[?Name=='AWSControlTowerManagedRule' && ManagedBy=='controltower.amazonaws.com'].Name" \
    --output text)
  [ "$RULE" = AWSControlTowerManagedRule ] || { echo "$REGION: no managed rule"; continue; }
  for TARGET in $(aws events list-targets-by-rule --profile "$MEMBER_PROFILE" --region "$REGION" \
      --rule AWSControlTowerManagedRule --query 'Targets[].Id' --output text); do
    aws events remove-targets --profile "$MEMBER_PROFILE" --region "$REGION" \
      --rule AWSControlTowerManagedRule --ids "$TARGET" --force
  done
  aws events delete-rule --profile "$MEMBER_PROFILE" --region "$REGION" \
    --name AWSControlTowerManagedRule --force
done
```

If enrollment already failed with that message, do the same and retry it. These are
writes in the moving account that belong to your transfer runbook; RAMShift never reads
or changes Control Tower resources.

### Step 7: verify after the move

Run step 5's command again once enrollment has succeeded.

| Result | Exit | Meaning |
|---|---|---|
| `MIGRATION_VALIDATED`, `SHARING_READY` | 0 | Every account is outside its baseline organization, the baseline is intact with no gaps, and no failure drop exists. Continue. |
| `PENDING_MIGRATION` | 0 | An account is still in its baseline organization. |
| `INCONCLUSIVE` | 3 | Read the `migration_status=INCONCLUSIVE` lines, fix access, re-run. Never run complete on this result. |
| `FAILED` | 1 | `BASELINE_...` and `failure drop ...` lines name the lost items. Incident; the drop is permanent. |
| `SHARING_INCOMPLETE` | 1 | A temporary share failed verification. |

`change=ORIGINAL_SHARE_DROPPED` lines are expected after the move. `MIGRATION_VALIDATED`
covers the recorded RAM and resource state, not Control Tower enrollment; confirm
enrollment from your transfer records.

### Step 8: permanent sharing

The resource owners grant each moved account access again through a permanent share
that RAMShift did not create: by changing the original shares or with another approved
share. Owners in a different organization from the account can only share with account
principals, with external sharing allowed, and the account accepts each invitation.
RAMShift does not create, change or accept those shares.

Then run a monitor report. A new permanent share shows as `change=SHARE_ADDED ...
access=REPLACEMENT`; an entitlement whose original share was restored no longer shows
`change=ORIGINAL_SHARE_DROPPED`. `access=TEMPORARY_ONLY` means no permanent path yet.

### Step 9: complete

Retire the accounts whose permanent sharing exists, one or several at a time, or all:

```bash
ramshift complete --record "$RECORD" --migration-id "$MIGRATION_ID" "${AUTH[@]}" \
  --consumers 222222222222 | tee logs/complete-1.log        # or --all-accounts
```

Accounts not named keep their temporary shares. Before the prompt:

| Output | Meaning |
|---|---|
| `consumer=<id> phase=complete status=ALREADY_RETIRED at=...` | Retired by an earlier run; skipped. |
| `consumer=<id> phase=complete status=NO_TEMPORARY_SHARES ...` | No temporary share serves that account; skipped. |
| `phase=complete-preflight kind=...` | The named accounts' current state, compared with the baseline. |
| `phase=replacement status=COVERED consumer=... resource=...` | A permanent path exists for that resource. |
| `phase=complete status=BLOCKED ...` then `status=BLOCKED ... temporary shares retained` | Refused. Exit 1. Nothing deleted. |
| `action=DELETE_SHARE share=... consumers=... resources=N` | The share serves no other account and will be deleted. |
| `action=REMOVE_PRINCIPALS share=... consumers=... retained_consumers=...` | The share keeps serving other accounts; only the named accounts are removed from it. |
| `action=DELETE_STACK stack=...` | A stack this run empties, deleted at the end. |
| `status=NOTHING_TO_RETIRE ...` | Nothing left to retire. Exit 0. |

Then type `COMPLETE <migration-id>`; any other reply cancels (exit 2, nothing written),
which is also how to review the checks without changing anything. Actions run one share
at a time, smallest first: the first is the canary. Each `status=SHARE_DELETED` or
`status=PRINCIPALS_REMOVED` is recorded at once and followed by `complete-settle-N`
observations, immediately and then every 30 seconds or less until `--settle-seconds`
(default 300) have passed. The first loss, read gap or uncovered resource stops the run
(`status=FAILED`, exit 1) and keeps the remaining shares. A final check covers every
affected share, then each emptied stack is deleted (`status=STACK_DELETED`).

```text
status=PARTIALLY_COMPLETED migration=... deleted_shares=N deleted_stacks=N removed_principals=N
retired_accounts=... remaining_accounts=... original baseline intact
```

means other accounts keep temporary access; run step 9 for them later. The run that
retires the last account prints `status=COMPLETED ... remaining_accounts=none`; later
runs print `ALREADY_COMPLETE`. Once any account is retired, apply refuses this migration
ID; plan further temporary shares under a new migration ID and record.

**Forced completion.** Only under an approved risk acceptance for exactly these accounts,
add `--force`. Each failed organization-read, baseline, original-state, failure-drop or
replacement-access check is printed as `phase=complete status=OVERRIDDEN <problem>`, and
the prompt becomes `FORCE-COMPLETE <migration-id>`: the named accounts may lose access.
After each action the state is observed once; losses are reported, recorded as failure
drops, and the run continues. The summary adds `forced=true overridden=N`. `--force`
never overrides authentication, record-versus-stack or ownership checks
(`status=NOT_OVERRIDDEN`), and never touches anything but this migration's temporary
shares and stacks. When nothing fails, `--force` changes nothing.

### Evidence to keep

The record and its backups (history, every verify and monitor result, every drop), the
`logs/` directory, and the Organizations and Control Tower operation, request and
handshake IDs with UTC times. No file may contain credentials or session tokens.

---

## 7. Mode reference

### 7.1 plan

Scope follows what the moving accounts actually receive:

1. For each moving account, plan reads its enabled Regions and lists every share it
   receives from other accounts, with the resources in each.
2. Owner Regions inspected are `--regions`, every Region where a moving account receives
   that owner's `ACTIVE` or `PENDING` shares, and all enabled Regions with
   `--scan-enabled-regions`. A migrating owner is always inspected in all its enabled
   Regions plus us-east-1.
3. Every `ACTIVE` received share with resources from an in-scope owner must be covered by
   a planned temporary share for the same account, owner, Region and resource; otherwise
   it is a `NOT_COVERED` blocker.
4. An owner outside `--owners` becomes one aggregated proposal per owner, approved with
   `approve`. A receiving account cannot re-share received resources, so only the owner
   can bridge them.

Received-share statuses (`phase=received-audit status=...`):

| Status | Meaning |
|---|---|
| `OWNER_INCLUDED` | Active dependency from an in-scope owner, covered by the plan or blocked in discovery. |
| `CURRENT_MIGRATION` | This migration's own temporary share. Excluded. |
| `RECOVERED_EXTERNAL` | The account is already an associated external principal of the original share: access that does not depend on organization membership. Excluded; never duplicated or modified. |
| `NOT_COVERED` | Active dependency without a planned temporary share. Blocker. |
| `OUTSIDE_OWNER_SCOPE` | The owner is not in scope. Part of the owner-scope proposal. |
| `BLOCKED` | A pending share, a resource that is not available, an owner Region outside scope, or a mismatch with the deployed migration. |
| `EXCLUDED` | An empty or inactive share. No access is inferred. |

**Permission versions.** AWS attaches only the current default version of a managed
permission to a new share, so a temporary share always receives the current default; an
older version is never pinned. When an original share attaches another version whose
policy differs, plan and apply print, once per permission and version pair:

```text
phase=permission-change status=INFO permission=<arn> resource_type=<type> version=<from>-><to> from_policy_sha256=<sha256> to_policy_sha256=<sha256> shares=N
  grants more: ... / grants less: ... / no semantic change
  BROADENED|NARROWED|CHANGED <effect> <action>: before on ...; after on ...
  share=<original share ARN> applies_to=new temporary share (receives the current default)
```

and `status=WARNING ... the temporary share grants less than the original share` when
it does. A difference never blocks and needs no approval; original shares are never
modified. A temporary share that already exists keeps the version it was created with;
when AWS publishes a newer default, plan notes it (`status=DEFAULT_CHANGED`) and nothing
changes. The differences are kept in the record (`plan.permission_changes`).

### 7.2 apply

apply blocks (`phase=reviewed-record ...`) unless: the latest plan revision is
`PLANNED`; the RAMShift build is the one that planned (a new build needs a new plan);
live entitlements and account roles still produce the reviewed plan digest; and
`--destination-ou` matches the reviewed plan. Before the prompt it observes the original
state; when no baseline exists yet it blocks on any read gap, any unhealthy item (an
association not `COMPLETE`, an endpoint not `OPERATIONAL`, an attachment not `available`,
a route not `active`, a PCA read not `OK`) or a resource not visible to its account.
After `APPLY <id>` it rebuilds every template, re-reads the organization policies and
observes the original state again; any change blocks with nothing written. Under the
record lock it checks that the record still holds the reviewed revision, and records the
baseline once. A later apply never replaces or extends the baseline, and blocks each
entitlement the baseline does not cover (`phase=baseline-scope`): plan those under a new
migration. Writes run through one CloudFormation change set per owner and Region;
change sets that would delete, replace or remove access from an existing temporary share
are rejected. Each moving account accepts only the planned shares from the planned
owner.

### 7.3 verify

Read-only toward AWS. It loads the planned shares from the migration stacks, verifies
every temporary share (in its stack, `ACTIVE`, external, retaining, exactly the planned
permissions, resources and principals, and visible to every account), observes the
current state, compares it with the baseline and records the result. Accounts complete
has retired are out of scope (`status=RETIRED`). Statuses are in [section 8](#8-statuses-and-exit-codes).

### 7.4 monitor

```bash
ramshift monitor --record R --migration-id ID (--consumers C1 [C2 ...] | --all-accounts) <access options>
```

An on-demand report, run at any time. It is read-only in AWS and writes only the record.
It observes exactly the baseline's entitlements of the chosen accounts and the baseline
items that belong to them, and reads each account's organization. Without a complete
baseline it reports `INCONCLUSIVE` without observing anything.

| Line | Meaning |
|---|---|
| `migration=<id> phase=monitor status=STARTED consumers=... baseline_captured_at=... baseline_items=N` | The baseline compared with |
| `phase=monitor kind=<kind> ...`, `phase=monitor status=GAP ...` | The current observation and each read gap |
| `consumer=<id> phase=monitor organization_at_baseline=<org> organization_now=<org> organization_change=UNCHANGED\|CHANGED\|UNKNOWN` | Organization then and now (`STANDALONE` between organizations); `temporary_access=RETIRED` once complete retired the account |
| `... change=ORIGINAL_SHARE_DROPPED share=<arn> access=<access>` | That original share no longer lists the resource for the account. Expected while it moves. |
| `... change=SHARE_ADDED share=<arn> access=<access>` | A share that is not a temporary share of this migration lists the resource now, for example permanent sharing |
| `phase=monitor change=LOST key=<key> ...` | A baseline item is missing (failure) |
| `phase=monitor change=DEGRADED key=<key> reasons=[...] ...` | A baseline item is present but unhealthy (failure) |
| `phase=monitor change=ADDED key=<key> ...` | An item the baseline does not hold |
| `phase=monitor change=UNOBSERVED key=<key> reasons=[...]` | A read gap hides a baseline item |
| `consumer=<id> phase=monitor original_share_drops=N shares_added=N lost=N degraded=N added=N unobserved=N` | Counts per account |
| `status=<status> migration=<id> phase=monitor consumers=... ... gaps=N recorded_drops=N revision=N exit_code=N` | Summary |

`access` is what lists the resource for the account now: `ORIGINAL` (an original share
of the baseline), `REPLACEMENT` (another share that is not a temporary share of this
migration), `TEMPORARY_ONLY` or `NONE`.

| Status | Exit | When |
|---|---|---|
| `LOSS` | 1 | A baseline item is lost or degraded |
| `INCONCLUSIVE` | 3 | No complete baseline, an account the baseline does not cover or that cannot be authenticated, a read gap, or an unreadable organization |
| `CHANGED` | 0 | Only expected changes: organization, dropped original shares, added shares or items |
| `UNCHANGED` | 0 | Nothing differs from the baseline |

Each run is recorded with its drops: a failure drop for each lost or degraded item, and
an informational `original_share` drop for each original share and account. A drop with
the same kind, account, Region and subject is recorded once. If the record cannot be
written, the report still prints with `phase=record status=NOT_RECORDED` and the run
never exits 0.

### 7.5 complete

For each chosen account, a temporary share serving it is deleted when it serves no other
account that is not retired; otherwise only the chosen accounts' principals are removed.
A stack is deleted once every share in it is deleted. Before any write, for the chosen
accounts only, complete checks:

1. Authentication, and that the record's shares, the stacks' entitlements and the live
   share ARNs agree for every stack it writes to. Never overridden.
2. The accounts' organizations can be read, a complete baseline covers them and their
   resources, and their current comparison is intact with no gaps.
3. No failure drop names them.
4. Every resource a temporary share gives them is also visible through another `ACTIVE`
   share that is not a temporary share of any migration (`phase=replacement status=COVERED`).

Without `--force` a failed check refuses the run with nothing deleted. RAMShift's delete
operations refuse any share that is not this migration's temporary share, and a stack is
deleted only when it holds no share.

### 7.6 Baseline items and loss rules

| Item | Loss when |
|---|---|
| Entitlement (a resource visible to an account) | No longer visible through any active received share |
| Resolver rule association | Absent, or status not `COMPLETE`, or its VPC or rule changed |
| Resolver endpoint | Was `OPERATIONAL` and is not, or an IP that was `ATTACHED` is not |
| TGW attachment | Absent, state not `available`, owner association left `associated`, or its TGW or VPC changed |
| TGW route | Absent, or state not `active` |
| IPAM allocation | Absent, or its account or CIDR changed |
| Private CA access | CA left `ACTIVE`, or the account's read is no longer `OK` |

A read gap never counts as success: an item it hides is unobserved, not present.

---

## 8. Statuses and exit codes

| Mode | 0 | 1 | 2 | 3 |
|---|---|---|---|---|
| plan | `PLANNED` | `BLOCKED` | - | - |
| approve | Approved, or `NOTHING_PENDING` | Error (missing plan, integrity check) | Not approved | - |
| apply | `SHARING_READY` | `BLOCKED`, or `INCOMPLETE` (successful shares kept) | `CANCELLED` (no AWS writes) | - |
| verify | `MIGRATION_VALIDATED` or `PENDING_MIGRATION` with `SHARING_READY`; `ALREADY_COMPLETE` | `FAILED`, `SHARING_INCOMPLETE`, `BLOCKED` | - | `INCONCLUSIVE` |
| monitor | `UNCHANGED`, `CHANGED` | `LOSS`, `BLOCKED`, or not recorded (`NOT_RECORDED`) | - | `INCONCLUSIVE` |
| complete | `COMPLETED`, `PARTIALLY_COMPLETED`, `NOTHING_TO_RETIRE`, `ALREADY_COMPLETE` | `BLOCKED` (nothing deleted) or `FAILED` (stopped, remaining shares kept) | `CANCELLED` (no AWS writes) | - |

verify's migration status, in precedence order: `FAILED` (a failure drop is recorded, or
a baseline item is missing or degraded now); `INCONCLUSIVE` (no or an incomplete
baseline, an account or resource the baseline does not cover, a read gap, an unreadable
organization); `PENDING_MIGRATION` (intact, an account still in its baseline
organization); `MIGRATION_VALIDATED` (intact, every account outside its baseline
organization; a standalone account between organizations counts as outside).

In every mode, an interrupt (Ctrl-C) exits 130 with `status=INCOMPLETE Interrupted;
existing temporary shares are retained`. An input, record, credential or AWS error exits
1 with `status=BLOCKED <reason>`, except after apply's write gate opened: then
`status=INCOMPLETE <reason>`, and the record holds the outcome and the shares read back.
A run that ends before or at a confirmation prompt has written nothing to AWS. There is
no flag that skips a confirmation.

---

## 9. The migration record

One JSON file per migration ID, written only by RAMShift:

| Section | Written by | Content |
|---|---|---|
| `scope` | plan | Account roles, Regions, excluded Regions, approved and proposed owners |
| `plan` | plan | Status, digest, planned shares, blockers, exclusions, permission differences, templates, received inventory, organization-policy preflight |
| `owner_scope_request`, `approvals` | plan, approve | Owner-scope proposals and their bound approvals |
| `baseline` | apply | The original state, captured once before the first write |
| `shares` | apply | The temporary shares created; entries are never removed |
| `verifications` | apply, verify, monitor | Append-only results |
| `drops` | apply, verify, monitor, complete | Lost items (permanent failures) and dropped original shares (informational), each recorded once |
| `retirements` | complete | One entry per temporary share and account retired, and whether `--force` was used |
| `completion` | complete | Set once no account remains |
| `history` | every writer | Revision, mode, status, operator, RAMShift version and build digest |

Every write appends a hash-chained history revision and replaces the file atomically;
writers serialize through a `.<record>.lock` file beside it. A record changed outside
RAMShift fails to load (`integrity check failed`); restore the last RAMShift-written
copy. With a record key (section 3), every write is also signed.

Back up the record after every step. The baseline cannot be recaptured: a new record
would capture the state at its next apply, not the original pre-migration state. Keep
records in versioned, write-protected storage.

---

## 10. Options reference

| Option | Modes | Meaning |
|---|---|---|
| `--migration-id ID` | all | 1-128 letters, digits, `.`, `_` or `-`, starting with a letter or digit. Part of every stack and share name. |
| `--record PATH` | all | The migration record. plan creates it (its directory must exist). |
| `--owners IDs` (alias `--accounts`) | plan, apply | Owner accounts whose shares are inspected. Spaces or commas. |
| `--consumers IDs` | plan, apply; monitor, complete | Moving accounts; for monitor and complete, the accounts to report on or retire |
| `--all-accounts` | monitor, complete | Every moving account in the record. One of `--consumers` and `--all-accounts` is required. |
| `--force` | complete | See step 9 |
| `--regions R ...` | plan, apply | Regions to inspect; us-east-1 is always included |
| `--scan-enabled-regions` | plan, apply | Also inspect every enabled Region of each owner |
| `--exclude-regions R ... --exclude-reason TEXT` | plan, apply (verify, complete must match) | Enabled Regions left out, with a mandatory one-line reason; recorded and shown in every summary |
| `--destination-ou ARN` | plan, apply | `arn:aws:organizations::<management-account>:ou/<o-id>/<ou-id>` (or the root): also evaluate that path's SCPs and RCPs. apply needs the value plan recorded. |
| `--account-map`, `--profile-map`, `--role-map` | all | JSON object or file: account ID to profile name or role ARN |
| `--profile`, `--source-profile`, `--destination-profile` | all | Base profiles (repeatable `--profile`) |
| `--sso-role ROLE`, `--role-name ROLE` | all | How to reach unmapped accounts; no default is assumed |
| `--principal-map` | plan, apply | JSON: original share ARN to the account IDs it is intended for (for historical OU or organization membership). It cannot broaden role, user or service restrictions. |
| `--capabilities` | plan, apply | JSON: resource type to boolean; can only restrict the AWS external-sharing catalog |
| `--account-workers N`, `--region-workers N` | all | Concurrency, 1-64, default 4 |
| `--share-workers N` | plan, apply | Concurrent share inspections per owner Region, 1-16, default 4 |
| `--timeout S`, `--retry-limit N`, `--poll-interval S` | all | Defaults 1800 s, 20 attempts, 2 s |
| `--settle-seconds S` | complete | Re-verification time after each action, default 300 |
| `--export-plan FILE` | plan, apply | Write the full plan as JSON (never over the record) |
| `--interactive` | all | Prompt for missing inputs even without a terminal (prompts are automatic in a terminal) |
| `--version` | - | Print the version |

---

## 11. Stop conditions

Stop and escalate on any of these; none is fixed by retrying with different options.

| Signal | Meaning | Action |
|---|---|---|
| `phase=authentication status=BLOCKED` | An account cannot be confirmed as itself | Fix its access mapping and re-run |
| `integrity check failed` | The record was edited outside RAMShift | Restore the last RAMShift-written copy; never hand-edit it |
| `migrating owner ... shares with stationary consumers` | Owner migration toward staying accounts is not supported | Re-scope (section 2) |
| `phase=baseline-scope status=BLOCKED` | A re-plan adds something the baseline does not cover | Plan it under a new migration |
| `unsupported or unverified external-sharing capability` | That resource type cannot be bridged | Escalate |
| `phase=baseline status=CAPTURED ... complete=false` | A resource type has no state collector | That migration can never be validated or completed by RAMShift |
| apply exits 1, or step 5 is not `PENDING_MIGRATION` + `SHARING_READY` | The temporary path is not proven | Do not start the move |
| monitor exits 3 | The report could not compare everything | Fix the cause shown and re-run before the next move step |
| monitor `LOSS` or verify `FAILED` | A baseline item was lost | Incident; the failure drop is permanent |
| `phase=record status=NOT_RECORDED` | The report was not recorded | Fix record access (path, lock, key) and re-run monitor |
| `only the temporary share provides access` | No permanent path yet | Finish step 8 first |
| complete `status=FAILED` | A loss after an action, or a failed action | Incident; the remaining shares are kept and every retirement is recorded |
| `phase=complete status=OVERRIDDEN` | `--force` let a failed check through | Stop unless an approved risk acceptance covers exactly this |

---

## 12. Never do this

- Edit, move or delete the record or its `.lock` file during a migration.
- Run apply and complete for the same migration at the same time.
- Delete migration stacks or temporary shares by hand, or delete a failed stack to retry.
- Start the move on anything but a passed step 5, or continue it past a `LOSS` report or
  an `INCONCLUSIVE` one that was not re-run to exit 0.
- Run complete on `INCONCLUSIVE`, `FAILED` or a missing replacement path, or
  `complete --force` without an approved risk acceptance.
- Treat `SHARING_READY` or `MIGRATION_VALIDATED` alone as Control Tower acceptance.

---

## 13. Troubleshooting and known limitations

- **`INCONCLUSIVE`:** read the `status=GAP` and `change=UNOBSERVED` lines. Usually an SCP
  denies a read or a profile cannot reach an account. Nothing is assumed from an unread
  item.
- **`monitor --all-accounts` is `INCONCLUSIVE`** when the record includes a moving
  account that receives nothing, for example a migrating owner. Name the accounts that
  receive resources with `--consumers`.
- **A deletion interrupted midway** can leave a share deleted in AWS but not yet recorded
  as retired. Re-run complete; if it reports a stored-plan error for that share, keep the
  record and contact support.
- **A default permission version that changes between plan and apply** is attached as
  the new default and reported as information.
- **Resolver rules with no association before the migration** are reported as
  `NOT_ASSOCIATED`, never as losses; sharing does not create associations.
- **`MIGRATION_VALIDATED`** covers the recorded RAM and resource state, not Control Tower
  enrollment.
- **Windows** is not supported natively; use WSL.

---

## 14. Validation

- 1,089 automated offline tests cover discovery, stacks, the record, verification,
  monitor, complete and the organization-policy preflight.
- A full Control Tower to Control Tower move was run in test accounts: before the move
  `UNCHANGED`; after leaving the source OU and organization all 26 original shares showed
  `ORIGINAL_SHARE_DROPPED` with `access=TEMPORARY_ONLY` and nothing was lost; after
  joining, the OU move and enrollment nothing was lost; verify reported
  `MIGRATION_VALIDATED`; complete refused without permanent sharing (26 blockers), then,
  after permanent sharing, deleted 5 temporary shares and 4 stacks with the baseline
  intact (`COMPLETED`).
