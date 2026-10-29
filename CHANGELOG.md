# Changelog

## 1.1.0

First public release.

- `plan`: discovers, from the moving accounts, everything they receive through organization
  and OU shares in every enabled Region; proposes owners outside the given scope for
  approval; evaluates the SCPs and resource control policies (RCPs) on the source path and,
  with `--destination-ou`, on the destination path.
- Blockers come with an ID, a category and the next action. Conditions the move cannot
  change (state that was already unhealthy, shares that grant nothing now, resource types
  without a health check) are recorded, never blockers. `approve --accept-blockers`
  accepts a blocker with a recorded reason and consequence.
- `apply`: temporary account-targeted shares that keep sharing when an account leaves its
  organization, one CloudFormation stack per owner and Region; invitation acceptance; a
  one-time pre-migration baseline.
- `verify` and `monitor`: sharing readiness and an on-demand comparison with the baseline.
- `complete`: per-account or whole-migration retirement of the temporary access, gated on
  intact original state and permanent replacement access, with an explicit `--force`.
- Accounts in both `--owners` and `--consumers` (migrating owners): their stationary
  recipients keep access through account-level temporary shares.
- A readable console view for every mode (`--raw-output` for the event stream), and a
  tamper-evident migration record with a plain-language summary.
