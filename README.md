# RAMShift: keep AWS RAM shared-resource access while accounts move between AWS Organizations

When an AWS account leaves an organizational unit (OU) or an AWS Organization, the AWS
Resource Access Manager (AWS RAM) shares that target that OU or organization stop applying
to it. Shared Amazon Route 53 Resolver rules, AWS Transit Gateways, Amazon VPC IP Address
Manager (IPAM) pools and AWS Private Certificate Authority CAs disappear from the account,
and its DNS resolution and routing break.

RAMShift is a command-line sample that bridges that move:

1. **plan** (read-only) finds, starting from the accounts that move, every resource they
   receive through an organization or OU share, in every enabled Region.
2. **apply** creates, in each owner account and Region, one AWS CloudFormation stack of
   temporary RAM shares that name the moving accounts directly and keep sharing when an
   account leaves its organization. It records the state of everything the accounts rely
   on before the first write (the baseline).
3. You move the accounts. Access continues through the temporary shares.
4. **monitor** and **verify** compare the current state with the baseline at any time.
5. **complete** removes the temporary shares once permanent sharing exists in the new
   organization and nothing original was lost.

RAMShift never moves accounts, never changes or deletes original shares, and never creates
IAM roles or changes trusts, service control policies (SCPs) or Resolver associations.

> This is sample code. Review it, and test it in non-production accounts, before you use
> it with production workloads. You are responsible for the AWS resources it creates and
> for testing, securing and optimizing it for your use case.

## Requirements

- Python 3.11 or later on macOS or Linux (on Windows, use WSL).
- AWS CLI profiles (AWS IAM Identity Center or IAM roles) that reach every owner account and
  every moving account. Read-only access is enough for `plan`, `verify` and `monitor`; see
  [docs/USER_GUIDE.md](docs/USER_GUIDE.md) section 4 for the permissions each mode needs.

## Install

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt
alias ramshift="python $PWD/src/temporary_migration_ram_shares.py"
ramshift --version
```

Or build one self-contained executable (a Python zipapp that bundles boto3, botocore and
PyYAML, with their licenses):

```bash
packaging/build.sh                 # writes dist/ramshift-<version>.pyz
```

## Quick start

```bash
# accounts.json maps each account ID to the AWS CLI profile that reaches it, for example
# {"111111111111": "network-hub", "222222222222": "app-account"}

# 1. Plan (read-only): what the moving accounts need, written to a migration record
ramshift plan --migration-id wave1 --record wave1.json \
  --owners 111111111111 --consumers 222222222222 --scan-enabled-regions \
  --account-map accounts.json

# 2. If plan proposes owners you did not list, approve them; if it reports blockers you
#    decide to accept, accept them (each consequence is shown and recorded). Then plan again.
ramshift approve --record wave1.json --migration-id wave1
ramshift approve --record wave1.json --migration-id wave1 \
  --accept-blockers <blocker IDs or a category> --accept-reason "<why>"

# 3. Apply (before moving anything): create the temporary shares; type APPLY wave1
ramshift apply --migration-id wave1 --record wave1.json \
  --owners 111111111111 --consumers 222222222222 --scan-enabled-regions \
  --account-map accounts.json

# 4. Verify: expect SHARING_READY and PENDING_MIGRATION
ramshift verify --record wave1.json --migration-id wave1 --account-map accounts.json

# 5. Move the accounts (outside RAMShift). After each step, see what changed:
ramshift monitor --record wave1.json --migration-id wave1 --all-accounts --account-map accounts.json

# 6. After the move, verify again (expect MIGRATION_VALIDATED), then set up permanent
#    sharing for the new organization (outside RAMShift).

# 7. Retire the temporary access, per account or for all; type COMPLETE wave1
ramshift complete --record wave1.json --migration-id wave1 --consumers 222222222222 \
  --account-map accounts.json
```

RAMShift prints a readable view by default; add `--raw-output` for the technical event
stream (one `key=value` line per event) for logs and tooling.

The migration record (`wave1.json` above) holds account IDs and the state of your shared
resources. Keep it private and out of version control.

## Exit codes

| Code | Meaning |
|---|---|
| 0 | Success (`PLANNED`, `SHARING_READY`, `PENDING_MIGRATION`, `MIGRATION_VALIDATED`, `UNCHANGED`, `CHANGED`, `COMPLETED`) |
| 1 | Blocked or failed |
| 2 | Cancelled: the confirmation did not match; nothing was written |
| 3 | Inconclusive: something could not be read; nothing is assumed |

## Documentation

[docs/USER_GUIDE.md](docs/USER_GUIDE.md) covers every mode, option, status and output line,
the permissions, the migration record, the step-by-step procedure (including moves between
AWS Control Tower landing zones), troubleshooting and known limitations.

## Tests

```bash
pip install -r requirements-dev.txt
python -m pytest -q tests
```

The tests run offline; they make no AWS calls.

## Security

See [CONTRIBUTING](CONTRIBUTING.md#security-issue-notifications) for more information.

## License

This library is licensed under the MIT-0 License. See the [LICENSE](LICENSE) file.
