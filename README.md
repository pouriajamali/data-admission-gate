# Data Admission Gate

A bounded companion to the public Integrity Lab CSV validator. Four separate
policy axes make the decision inspectable: declared-grid coverage, freshness
relative to an explicit historical asOf, provenance decision and data-use decision.
**A quality pass or an owner assertion is not authenticity or legal-rights proof.**

The original reusable companion is [MIT](LICENSE); public dependencies retain
their separate full notices. [Preview v0.1.0-preview.1 and downloads](https://github.com/pouriajamali/data-admission-gate/releases/tag/v0.1.0-preview.1)
provide Windows/Linux x64 bundles and source. Verify the signed checksums before
extraction; missing signature assets mean incomplete publication. Software licensing
does not prove ownership or legal use rights of input data. Customer-specific code,
data, configuration, deployments and unpublished commercial additions stay private.

## Run the generated example

The preview includes self-contained Windows x64 and Ubuntu24.04/glibc x64
directory bundles. No installed .NET SDK is required to run those bundles; native
OS prerequisites still apply. Verify the local signed checksum manifest first,
using [current online verification guide](https://github.com/pouriajamali/data-admission-gate/blob/main/PROVENANCE.md), then extract the whole directory.

```powershell
.\admission.exe --version
.\admission.exe demo .\demo-new
.\admission.exe assess .\demo-new\clean-acknowledged-bundle .\report-hold-new
.\admission.exe assess .\demo-new\clean-acknowledged-bundle .\report-ack-new --ack-owner-decision
```

```sh
./admission --version
./admission demo ./demo-new
./admission assess ./demo-new/clean-acknowledged-bundle ./report-hold-new
./admission assess ./demo-new/clean-acknowledged-bundle ./report-ack-new --ack-owner-decision
```

Use fresh output names. The same generated bundle produces HOLD/exit2 without
acknowledgment and ADMIT/exit0 under an explicit synthetic owner assertion. The
other demo cases preserve missing/stale, wrong-binding and license-denial REJECT
outcomes. Demo exit0 means all five expected outcomes matched, not that every
fixture is admissible or any real rights were verified.

Read `summary.json` and `summary.txt` in each report, and the demo's summary.
`csv-private/accepted.jsonl` and `quarantine.jsonl` contain parsed input values;
keep them private. Main summaries contain hashes/generic counts and codes,
not raw rows, owner labels, secrets or absolute input paths. Share invented data
only. Nothing is sent to a network, account, trading platform or remote service.

## What PASS actually means

| Result | Its limited meaning | What stays unproven |
|---|---|---|
| coverage PASS | Accepted rows exactly match the caller's explicit timestamp grid | External/market/source completeness |
| freshness PASS | Latest accepted timestamp is within the threshold of declared asOf | Actual source freshness and clock accuracy |
| provenance PASS | Correctly bound owner assertion was explicitly acknowledged | Identity and source authenticity |
| useLicense PASS | Same owner assertion allows this exact dataset/policy for offline-analysis | Ownership, legal rights, any other purpose |

Coverage/freshness use **accepted rows only**. A quarantined OHLC row may contain
a valid-looking timestamp; it cannot make data fresh or cover a slot. Quarantines
are a separate hard rejection. Absent/unacknowledged/unknown owner decisions keep
their axes UNKNOWN. Wrong dataset/policy/purpose bindings are hard REJECT even
without acknowledgment; malformed decision files are incomplete. Ack applies only
to that invocation and never overrides failed mechanical checks.

ADMIT requires row quality and all four policy axes PASS; any known failure gives
REJECT, otherwise UNKNOWN gives HOLD. ADMIT performs no downstream action.
Identity/authenticity/legal rights always remain NOT_PROVEN. Data-use decisions
are separate from the MIT license of this software.

## Unreleased preview.2 source — partial local validation

The current source adds a more explicit human report and has local build/unit
evidence. Full acceptance is pending; the preview.1 downloads above remain the
published baseline.
It preserves the JSON v1 contract and ADMIT/HOLD/REJECT decision rules.

The proposed `summary.txt` shows each of `rowQuality`, `coverage`, `freshness`,
`provenance` and `useLicense` with its status, basis and reason. It also prints the
declared historical asOf, latest accepted timestamp, age and threshold. A displayed
PASS describes that axis's policy basis; it does not verify authenticity, legal
rights, external completeness or actual source freshness.

The new independent oracle uses one invented row at `2026-01-01T00:02:00Z`, an
explicit one-slot grid, asOf `2026-01-01T00:03:00Z` and a 60-second threshold.
Its literal expectations are:

| Bound owner assertion | Per-invocation ACK | Expected policy result |
|---|---|---|
| provenance unknown; useLicense allow | yes | HOLD/2, although row quality, coverage, freshness and useLicense PASS |
| provenance allow; useLicense allow | yes | ADMIT/0; identity/authenticity/legal rights still NOT_PROVEN |
| provenance allow; useLicense unknown | yes | HOLD/2 |
| exact same allow/allow bundle bytes as the second case | no | HOLD/2; both owner axes UNKNOWN |

Local evidence: Windows units **107 passed, 0 failed, 2 skipped** (symlink
privilege and Linux-only FIFO). On 2026-11-12 the complete unchanged Ubuntu/WSL
suite passed **109 passed, 0 failed, 0 skipped**, including the FIFO regression
using the approved native-filesystem fixture. All four literal CLI oracles passed.
The fixture evidence was exported and verified before owned cleanup; the actual
SDK child inherited a 4GiB memory/zero-swap, two-CPU, 64-task cgroup. This replaces
the earlier Windows-mounted-fixture failure; it does not establish clean-OS or
packaged apphost acceptance.

All twelve CI-policy checks passed, retaining the original ten classification
checks. The local maintainer actionlint1.7.12 build is now admitted by exact
source/compiler/module/binary/proof identity. Four fresh builds produced two
byte-identical outputs per target. Source and exact-binary analyses completed
for Windows and Linux; all36 metadata matches have target-specific dispositions.
The imported Windows SDK DNS source is tied to its exact upstream-fixed blob.
All90 original tooling notice texts are retained separately from the app runtime.

The same50 negative vectors passed in normal Python, `-O`, and real
`PYTHONOPTIMIZE=2`: **150 rejections, zero candidate executions**. Actual version,
fixed valid/invalid YAML, default and direct lint controls then passed on both
native hosts under4GiB/two-CPU/64-task supervision, with zero Linux swap. The old
vendor executable remains unexecuted. Missing, mutated or unadmitted input still
fails closed. See [tooling recipe and limits](docs/ACTIONLINT-BUILD.md).

Packaging disables extra runtime/targeting-pack downloads for frameworks the
console project does not reference; its declared .NETCore runtime and NuGet
auditing remain enabled. Each extracted self-contained app archive has a separate17-check acceptance
suite, including an independent literal unknown-provenance/HOLD counterexample.
Locked restores, native Release builds and exact runtime-package
signature/content/notices observations exist; the observed official-feed
snapshot had no range matching either selected10.0.15 runtime package. This is
scoped version evidence, not general security certification. Exact candidate
archive acceptance, signatures, CI, actual downloads and public metadata are
separate delivery checks. The shared linter handoff does not establish them.
No preview.2 public download is claimed by these local results.


## Supported local bundle

Flat directory: `input.csv`, `policy.json`, optionally `owner-decision.json`.
Exact names/case only, no other members/directories/observed links/network paths.
CSV reuses the exact public `ohlc-csv-v1` validator: UTC physical-line records,
header `timestamp,open,high,low,close,volume`, fixed price scale2/volume scale0,
no rounding or calendar/timezone inference. Input1MiB/1000 rows/4096 bytes per row.

The policy has an explicit sorted unique grid, asOf and age threshold. The owner
decision binds exact dataset/policy SHA256 and purpose. See the precise
[contract](docs/CONTRACT.md) for JSON fields/caps and acknowledgment semantics.
The source snapshot includes optional-file absence: observed late additions,
removals or byte changes make the assessment incomplete before final main JSON.
No hostile-filesystem atomicity/security sandbox is claimed.

Exit0 ADMIT or expected demo; exit2 completed HOLD/REJECT; exit1 incomplete,
malformed/unsupported/I/O/report failure. Missing/pending/partial files are not a
completed admission. Vendor file-fatal header/framing/empty/no-data is incomplete;
completed all-quarantined input is REJECT even when freshness is UNKNOWN.

## Decisions and proof

- `decision-binding-*-ack-*`, `decision-malformed-even-without-ack`: syntax and
  binding checks apply without acknowledgment; a stale assertion cannot authorize.
- `late-snapshot-*`: optional-file presence/absence and exact byte changes are
  rechecked before final main JSON. This is observed consistency, not hostile-FS proof.
- `all-quarantined-nonnull-record-never-freshness`, `quarantine-outlier-cannot-fake-latest`:
  rejected rows cannot enter grid/freshness facts.
- `actual-1000-record-output-bounds`: exact scaled Int64 boundaries, output file
  inventory and conservative byte limits; no performance benchmark.
- `report-*`, `artifact-*`: report/marker/inventory failures are incomplete.

Published preview.1 uses SDK10.0.403/runtime10.0.14. The UNRELEASED preview.2
source pins SDK10.0.404/runtime10.0.15; local restore/build/units and both runtime
identities are observed. Native archive packaging and full acceptance are pending.
No external application packages, framework
cloud integrations, CSV rewrite, real account/API, live feed, arbitrary executable,
plugin, force-admit, reset or deployment option.

```sh
dotnet restore tests/Admission.Tests --locked-mode
dotnet run --project tests/Admission.Tests -c Release --no-restore -- --work artifacts/tests-new
```

The [comparison](docs/COMPARISON.md) explains overlap with GX/Soda and the existing
Integrity Lab. Four unmodified public CSV files and their full MIT license are
pinned in `vendor/integrity-csv/PINS.json`; byte guards reject changed copies.
See [notices](NOTICE.md), [contributing](CONTRIBUTING.md) and [output bounds](docs/BOUNDS.md).
Original work uses AI assistance; no exclusive-authorship/independent-skill,
novelty, demand, revenue or production-safety claim.

Reusable showcase code is intended for later public review. Customer-specific
code/data/configuration/deployment, secrets and unpublished commercial additions
belong in separate private work. No private/shared/employer source, tests, data,
schema, contracts or ideas were transferred. CV/profile and existing repos/releases
remain outside this work.

Documentation update: v0.1.0-preview.1 runtime/source archives remain exact79b55551092ba427c457c8e87eb094b31ebe81be, including their historical raw-key guide. Use the current online guide above for immutable release-key retrieval. Archive/tag/SUMS/signature bytes are unchanged.

[CI resource policy](docs/CI-POLICY.md): documentation-only changes get real lightweight document/pipeline checks; source, tag and manual runs retain native validation. Published runtime tags and release assets remain unchanged.

## Source readability

The source readability baseline expanded compact C# layout for review while
preserving syntax, token values, comments and directives. The current UNRELEASED
preview.2 source additionally changes human report text as described above; it
has the partial local evidence above. Published preview.1 links identify its frozen runtime
release. No performance claim follows from either layout or report text.

Pinned vendor sources retain their original bytes and are excluded from formatting.

To reproduce a published package, use its exact original runtime source: [v0.1.0-preview.1 source](https://github.com/pouriajamali/data-admission-gate/tree/79b55551092ba427c457c8e87eb094b31ebe81be) (`79b55551092ba427c457c8e87eb094b31ebe81be`). Later `main` layout is reviewed separately from those frozen release commits.
