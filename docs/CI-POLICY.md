# CI resource policy

This workflow policy separates documentation checks from unchanged runtime builds. It does not change application behavior, dependencies, release versions, published assets, account budgets or repository protection.

- Push validation targets the default `main` branch; pull requests retain validation without an extra feature-branch push run. Existing tag patterns are preserved. Manual dispatch requests full native checks except the exact tooling-only tag
  tooling-actionlint-v1.7.12-go1.26.11-r1, whose native/release jobs are explicitly excluded.
- A narrow documentation allowlist gets real UTF-8/framing, Markdown fence/relative-link and frozen-evidence JSON checks, plus policy contract tests and pinned actionlint. It does not run .NET/C++ builds or upload native artifacts. This is not an exhaustive prose/security audit.
- Runtime/configuration/fixtures/licenses/provenance/pipeline changes and unknown/failed Git comparisons always require the original native checks. Source, Windows/Linux execution, native package inspection and release/provenance commands remain present. App tags and ordinary manual runs cannot take the docs-only route. The one
  exact tooling tag selects ci_policy only and is excluded from push triggers.
- Lightweight checks also statically read the explicit source-package inventories where present, without importing the packager. A new unallowlisted document, symlink mode or computed/unknown inventory cannot hide behind docs-only success.
- Main, tag and manual runs have unique concurrency groups. A docs push cannot replace an earlier pending source run. Only superseded PR runs may be cancelled; classification uses the complete PR delta from its merge base.
- Matrix native jobs use `max-parallel: 1`; Book Replay keeps its two separately defined platform jobs. This is a per-workflow limit, not an account-wide cap. Rollouts are staged rather than starting fourteen heavy runs together.
- Existing native job timeouts remain. Previously unbounded native and comparison/release jobs receive finite timeouts. No source test is replaced by an artificial green check.
- Routine source/PR jobs still build, extract and execute the original native packages, but do not upload the large `bundle-*`, `binary-*` or `tested-*` archives. Finite proof receipts remain. Tag/manual runtime-review runs still upload those required archives; small `checked-source-*` pairs remain on ordinary runs because downstream byte-comparison jobs consume them. No source/native check or release gate is replaced by this upload saving.
- Future Actions uploads retain ordinary source/PR artifacts for **3 days**, and tag/manual review artifacts for **7 days**. These are temporary CI artifacts. Published release archives, checksums, signatures and keys are separate and remain immutable.
- New retention does not delete old artifacts or logs. No artifact/cache deletion, paid capacity, self-hosted runner, account permission or budget change is performed by this policy. Any historical cleanup requires a separately reviewed inventory and explicit authorization.

The ci_policy job uses standard Windows2025, Python's standard library and the
exact source-pinned sealed maintainer actionlint1.7.12 archive from this repo's
tooling release. Explicit import and default lint use actual bounded Job children;
ordinary lint never downloads/falls back. No local compiler/auditor/bootstrap is
required. The old upstream vendor executable remains unexecuted by this profile.
Optional external ShellCheck/Pyflakes are not claimed. Account storage usage is
not inferred from one repository's artifact byte count.

## Proposed preview.3 transport and draft route

Source preparation adds an ephemeral exact source-held SDK11 catalog guard.
The catalog currently says METADATA_ONLY_NOT_EXECUTABLE and fails closed until
actual producer qualification supplies its measured identities. SDK setup alone
is insufficient. The native job transports one matching official archive,
maximum512MiB compressed and4GiB expanded; two native jobs per event therefore
use at most1GiB raw and8GiB expanded temporary SDK data. SDK trees/archives are
never cached, uploaded as Actions artifacts or included in a support release.

The original109-case inventory and17 extracted-package checks remain. Four
separate literal apphost compatibility cases compare full JSON/wire/text and
CSV outputs, allowing only version/toolBuild identity differences. Existing
job deadlines and sequential native matrix remain: policy5min, each native15min,
draft aggregation5min. The later exact publication proposal permits at most one
app-tag event40raw runner-minutes plus one main integration event35raw minutes,
zero manual dispatches/retries and zero SDK cache/artifact bytes. No CI event is
authorized or claimed by these source edits.

Aggregation creates a private draft. A known-key operator signs downloaded
checksums and verifies six exact draft assets, then obtains the exact public
publish gate. Standard hosted .NET jobs do not inherit local SDK kernel caps;
only actual observed controls may be claimed. Local project04 remains4GiB,
CPU<=2,64tasks/processes and Linux swap0, with actual child membership before
execution and owned terminal evidence. No project06 128-task exception applies.

## Proposed supported-host qualification exception

Only workflow_dispatch with mode sdk11-ci-qualification selects this source
proposal's exception. ci_policy is skipped and verify explicitly accepts that
skipped dependency. The two existing rows are windows-2025 and ubuntu-24.04,
max-parallel1, 15min each, no fail-fast between qualification RIDs. Product,
tested-* and release steps are explicitly skipped. The existing proof-RID
artifact selects a successful host fact or a sanitized <=32KiB failure summary, within <=8MiB total and three-day retention. The failure upload uses always(); it does not turn the failed job green or create a host fact. No SDK
cache, binary artifact or additional job is introduced. Ordinary events retain
the original ci_policy steps and classification; ordinary native checks execute
the same original recipes inside consumer04's aggregate controller. Named
workflow steps verify its completed stage receipts. An unbound consumer fails
closed. This changes no required repository protection setting.

The earlier app-tag/main-only public budget above describes the separate app
publication proposal. The qualification exception has its own future exact gate
and at most two sequential 900-second rows (1800s total); it is not an authorized
dispatch. Isolated policy/YAML/lint and event-truth-table checks are pending
before any public mutation. Full details: [supported hosts](SDK11_SUPPORTED_HOSTS.md).
