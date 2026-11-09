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
using [PROVENANCE.md](PROVENANCE.md), then extract the whole directory.

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

SDK10.0.403, bundled runtime10.0.14. No external application packages, framework
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
