# Data Admission Gate

A CSV can pass row checks and still have missing timestamps, stale data or an
unacknowledged owner decision. This offline .NET 11 / C# 15 CLI reports
**ADMIT, HOLD or REJECT**
for an explicit dataset and policy, with the reason for each decision.

A bounded companion to the public Integrity Lab CSV validator. Four separate
policy axes make the decision inspectable: declared-grid coverage, freshness
relative to an explicit historical asOf, provenance decision and data-use decision.
**A quality pass or an owner assertion is not authenticity or legal-rights proof.**

[Current preview.3 release](https://github.com/pouriajamali/data-admission-gate/releases/tag/v0.1.0-preview.3)
· [Exact tested runtime source](https://github.com/pouriajamali/data-admission-gate/tree/e48e0bf5ca550fc736c2f6f551c34347f54c00ff)
· [Input/report contract](docs/CONTRACT.md)

## Smallest runnable example

Download the [Windows x64 ZIP](https://github.com/pouriajamali/data-admission-gate/releases/download/v0.1.0-preview.3/data-admission-gate-v0.1.0-preview.3-win-x64.zip)
or [Linux x64 tar.gz](https://github.com/pouriajamali/data-admission-gate/releases/download/v0.1.0-preview.3/data-admission-gate-v0.1.0-preview.3-linux-x64.tar.gz),
[verify the signed checksums](PROVENANCE.md), then extract the whole directory.
Run from that directory with a fresh output name; no installed SDK is required.

Windows PowerShell:

```powershell
.\admission.exe demo .\demo-new
```

Linux shell:

```sh
./admission demo ./demo-new
```

Expected: exit **0**, JSON outcome `EXPECTED_OUTCOMES_OBSERVED`, and
`demo-new/summary.json` plus `demo-new/summary.txt`. The generated cases are:

| Synthetic case | Expected policy outcome |
|---|---|
| Clean rows; owner decision unacknowledged | HOLD |
| Same clean rows; bound owner decision acknowledged | ADMIT |
| Missing timestamps and stale rows | REJECT |
| Owner decision bound to the wrong dataset | REJECT |
| Owner decision denies this data use | REJECT |

Demo success means those five expected outcomes matched. ADMIT performs no
downstream action and does not establish identity, authenticity or legal rights.
This is a local synthetic example, not a performance or production claim.

The original reusable companion is [MIT](LICENSE); public dependencies retain
their separate full notices. [Current preview.3 release and downloads](https://github.com/pouriajamali/data-admission-gate/releases/tag/v0.1.0-preview.3)
provide Windows/Linux x64 bundles and source. Verify the signed checksums before
extraction; missing signature assets mean incomplete publication. Software licensing
does not prove ownership or legal use rights of input data. Customer-specific code,
data, configuration, deployments and unpublished commercial additions stay private.

## Install preview.3

Download and extract the whole matching archive after verifying the
[signed checksums](https://github.com/pouriajamali/data-admission-gate/releases/download/v0.1.0-preview.3/SHA256SUMS.txt)
using [PROVENANCE.md](PROVENANCE.md):

- [Windows x64 ZIP](https://github.com/pouriajamali/data-admission-gate/releases/download/v0.1.0-preview.3/data-admission-gate-v0.1.0-preview.3-win-x64.zip)
- [Linux x64 tar.gz](https://github.com/pouriajamali/data-admission-gate/releases/download/v0.1.0-preview.3/data-admission-gate-v0.1.0-preview.3-linux-x64.tar.gz)
- [Exact tested source ZIP](https://github.com/pouriajamali/data-admission-gate/releases/download/v0.1.0-preview.3/data-admission-gate-v0.1.0-preview.3-source.zip)
- [Local delivery receipt](https://github.com/pouriajamali/data-admission-gate/releases/download/v0.1.0-preview.3/LOCAL-DELIVERY-RECEIPT.json),
  [checksum signature](https://github.com/pouriajamali/data-admission-gate/releases/download/v0.1.0-preview.3/SHA256SUMS.txt.sig) and [public key](https://github.com/pouriajamali/data-admission-gate/releases/download/v0.1.0-preview.3/SIGNING-PUBLIC-KEY.pub)

These runtime archives and their source ZIP bind to signed tag
`v0.1.0-preview.3`, commit `e48e0bf5ca550fc736c2f6f551c34347f54c00ff`.
Later main documentation does not relabel them. Self-contained apps still need
the runtime's native OS/CPU prerequisites. The release used Ubuntu24.04/WSL2 and
an experimental Windows26H2/build26300.9974 host; formal .NET11 support for that
Windows build is **NOT_CONFIRMED**. See [release notes](docs/RELEASE-v0.1.0-preview.3.md)
and [servicing/acceptance boundaries](docs/SDK11_DELIVERY_HISTORY.md#preview3-technology-and-acceptance).

## Run the generated example

The quick start above created `demo-new`. Reuse that bundle below and choose
fresh report directories; do not regenerate the same output directory.

The preview includes self-contained Windows x64 and Ubuntu24.04/glibc x64
directory bundles. No installed .NET SDK is required to run those bundles; native
OS prerequisites still apply. Verify the local signed checksum manifest first,
using [current online verification guide](https://github.com/pouriajamali/data-admission-gate/blob/main/PROVENANCE.md), then extract the whole directory.

```powershell
.\admission.exe --version
.\admission.exe assess .\demo-new\clean-acknowledged-bundle .\report-hold-new
.\admission.exe assess .\demo-new\clean-acknowledged-bundle .\report-ack-new --ack-owner-decision
```

```sh
./admission --version
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

## Historical release evidence

[Preview.2 report, local checks and tooling history](docs/SDK11_DELIVERY_HISTORY.md#preview2-report-and-evidence)
retain their original source, date and host boundaries. Current preview.3
[servicing and acceptance](docs/SDK11_DELIVERY_HISTORY.md#preview3-technology-and-acceptance)
and [release notes](docs/RELEASE-v0.1.0-preview.3.md) identify its separate evidence.

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

Historical preview.1 uses SDK10.0.403/runtime10.0.14. Preview.2 source and
matching-host self-contained archives use SDK10.0.404/runtime10.0.15.
Use its exact signed tag and source archive when reproducing the release.
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

Actions are `NOT_RUN_PER_OWNER_INSTRUCTION`; this presentation edit uses local
documentation checks only.

[CI resource policy](docs/CI-POLICY.md): documentation-only changes get real lightweight document/pipeline checks; source, tag and manual runs retain native validation. Published runtime tags and release assets remain unchanged.

## Source readability

The source readability baseline expanded compact C# layout for review while
preserving syntax, token values, comments and directives. Preview.2 additionally
changes human report text as described above. Its tag identifies its frozen
runtime source; main may contain subsequent documentation. No performance claim
follows from either layout or report text.

Pinned vendor sources retain their original bytes and are excluded from formatting.

Reproduce preview.2 from [its exact runtime source](https://github.com/pouriajamali/data-admission-gate/tree/b1012c1dec61c8d1a23cd604a77b36fb0062f0b0).
[Historical preview.1 source](https://github.com/pouriajamali/data-admission-gate/tree/79b55551092ba427c457c8e87eb094b31ebe81be)
and its six release assets remain unchanged. Later main documentation is separate
from each frozen runtime commit.

## Build-time sealed linter

Fresh CI/contributor lint imports the exact reviewed public sealed archive; no
producer drive/private receipts or local compiler are required. Managed task
checkouts retain the canonical gate. See [native profile and signed input setup](docs/ACTIONLINT-BUILD.md).
The [five-asset tooling release](https://github.com/pouriajamali/data-admission-gate/releases/tag/tooling-actionlint-v1.7.12-go1.26.11-r1)
and [single producer CI](https://github.com/pouriajamali/data-admission-gate/actions/runs/43275123686)
have actual download/signature and Windows import/default-lint Job evidence.
This tooling result is separate from app native verification and consumer05/06.


Windows local test boundary: this experimental host cannot create the refused-file
symlink fixture. That case is separately `LOCAL_SYMLINK_PRIVILEGE` skipped,
in addition to `LINUX_ONLY` FIFO. Counts retain the109-case inventory; the
release receipt separates actual new cases, exact healthy-case reuse and skips.
No Developer Mode, privilege, path guard or security setting is changed.

[Retained runtime bytes and separate offline finalization](docs/SDK11_OFFLINE_FINALIZATION.md)
records the exact native test sources, two Windows host skips and the distinction
between preserved original envelope HOLDs and fresh offline input verification.
