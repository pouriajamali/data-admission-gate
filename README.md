# Data Admission Gate

A bounded companion to the public Integrity Lab CSV validator. Four separate
policy axes make the decision inspectable: declared-grid coverage, freshness
relative to an explicit historical asOf, provenance decision and data-use decision.
**A quality pass or an owner assertion is not authenticity or legal-rights proof.**

The original reusable companion is [MIT](LICENSE); public dependencies retain
their separate full notices. [Preview v0.1.0-preview.2 and downloads](https://github.com/pouriajamali/data-admission-gate/releases/tag/v0.1.0-preview.2)
provide Windows/Linux x64 bundles and source. Verify the signed checksums before
extraction; missing signature assets mean incomplete publication. Software licensing
does not prove ownership or legal use rights of input data. Customer-specific code,
data, configuration, deployments and unpublished commercial additions stay private.

## Unreleased technology maintenance source

This branch prepares `0.1.0-preview.3` for SDK11.0.100, net11.0,
runtime11.0.0 and stable C#15. It changes framework/version metadata and
qualification tooling, while preserving the v1 input/report contracts,
fixed integer CSV scales and ADMIT/HOLD/REJECT rules. It introduces no new
application feature or performance claim.

SDK11 archive admission and native/application compatibility are pending.
The existing preview.2 downloads below remain the verified published baseline;
results in its evidence section are historical preview.2 results. No preview.3
binary, signature or download is published by this source preparation.
.NET11 requires an x86-64-v2 CPU. Windows x64 and Ubuntu24.04/glibc x64 are the
proposed matching-host targets; actual qualified OS/native prerequisites will
be recorded before delivery. An extracted self-contained bundle does not
require an installed SDK, but still requires its documented CPU/OS prerequisites.

See the [technology scope and current limits](docs/TECH-REFRESH-20261114.md)
and [unreleased preview.3 note](docs/RELEASE-v0.1.0-preview.3.md).

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

## Preview.2 report and evidence

The preview.2 app tag and its runtime/source archives are bound to signed commit
b1012c1dec61c8d1a23cd604a77b36fb0062f0b0, tree
09c3bf9b6da12eacdb6df903b2cc9452e9a620a0. The release notes link its exact
Windows/Linux hosted native verification and actual archive checks. Later main
documentation is separate from these frozen app assets.

Earlier private localCandidate archives and their17-check receipts belong to
9893583976da8d5042d063cabc58f65885001858. They were neither relabelled nor uploaded.
Public archives were produced and checked by the exact app-tag pipeline.
It preserves the JSON v1 contract and ADMIT/HOLD/REJECT decision rules.

The preview.2 `summary.txt` shows each of `rowQuality`, `coverage`, `freshness`,
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
The local results retain their original commit/host boundary; public delivery
is established separately by the exact app-tag CI and six verified release assets.


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

## Proposed SDK11 supported hosted route

The [supported host source candidate](docs/SDK11_SUPPORTED_HOSTS.md) prepares
Windows Server2025 and Ubuntu24.04 producer qualification and consumer04's own
host admission. It is untested, unapplied source; SDK_READY remains false.
Normal admission stays closed until exact accepted per-RID facts and independent
consumer caps/source/contract checks exist. Existing preview.2 assets remain the
verified release; no SDK11 app or new download is claimed.

Final source correction covers bounded own-unit failure cleanup, sanitized
failure receipts in existing proof artifacts and the fixed Windows Git path.
Coordinator's108 source-value denials are scoped to Windows Python, not native
host/SDK acceptance. All native behavior remains UNKNOWN.

## Private Windows host-diagnostic source proposal after run43920284996

The Linux host fact757abf2d remains immutable evidence from source803eb716,
Ubuntu24.04 job133485418032: eight SDK commands exited0 with its own observed
4GiB/64tasks/CPU2/swap0 and terminal0. It is reused without another Linux run.
Global SDK_READY stays false and product/consumer compatibility is unproven.
Windows job133485418698 failed stage0/Q_HOST_OS before SDK; owned population0
was observed. Its exact failed subpredicate and actual ImageOS environment
value are UNKNOWN; an alias mismatch is only an inference from the runner log.
The private proposal records bounded actual metadata and predicate booleans
before denial and preserves them in sanitized failure proof. It proposes only
the documented win25-vs2026 variant at exact ImageVersion20261103.298.1 while
retaining raw observed ImageOS, Server2025 registry/build26100, x64/pointer64,
productType3, named hosted Windows context and all existing CPU/caps/trust
requirements. Unknown/other/future variants fail closed; nothing is relabelled
win25. The frozen63e typed success schema is unchanged. No new source is applied
or tested by this note; retry requires a new exact Windows-only gate and must
not replay Linux or turn the global ready predicate true.

Windows diagnostic source functions passed the focused V01..V08 synthetic
normal/-O/env2 checks, including invalid metadata preserving primary failure;
these are SDK-free source checks, not actual Windows predicate observations.
The next qualification-only source route selects exactly one existing Windows
row, with a mode-aware900s profile (60/120/180/480/60), same4GiB/64/CPU2 and
existing proof-win-x64 <=8MiB/3days. Linux/ci_policy/release are excluded only
from that mode; ordinary two-row/policy routes remain. Linux fact757abf2d from
803eb716 is immutable and reused without replay. Global SDK_READY remains false.
No public push, dispatch, SDK/native/product qualification or release is
authorized or claimed by this source candidate.

The private Windows source correction normalizes recorded PathLike argv to the
same strings already used to launch the command. It also preserves at most six
owned relative module/function/line frames, <=4KiB total, through existing
failure receipts, without locals/arguments/source lines/absolute paths/env/raw
TypeError text. Pure mocked source checks passed; the actual failed run43929153631
TypeError origin remains UNKNOWN. This is no SDK/native/CI/product PASS claim.
Linux803eb/fact757ab remains immutable; global SDK_READY stays false.

Windows run43941068797 on source5feab6e failed at stage3, CHILD_NONZERO:1,
with at least one SDK attempt; failed command, completed count and cause remain
UNKNOWN. This source diagnostic adds fixed-command/completed-exit0 receipt
bindings, bounded process/log hashes and allowlisted reason codes; 60 new
synthetic checks passed in each of normal/-O modes. Raw output is excluded.
No Windows qualification or product PASS; Linux803eb/fact757ab stays immutable,
SDK_READY=false, and no further SDK/native/CI execution is claimed here.

Actual Windows run43948776669 (db748) failed restore/index5: the prior five
SDK commands exited0; restore exited1 without timeout, with owned population0.
Build/hello were not run; the restore cause remains UNKNOWN. This
OBSERVABILITY_ONLY source change classifies thirteen literal .NET exceptions
and a finite list of explicitly labelled HResult/Win32 codes, stripping bounded
SGR colour only in the classifier copy. New68 normal and68 -O fixture checks
passed; no raw log/path/URL/env/args are exported. Recipe, environment, caps,
SDK pins and eight commands remain unchanged. No Windows/product PASS claim.

The [shared normal SDK input source proposal](docs/SDK11_SHARED_NORMAL_INPUT.md) supplies one callable
Linux normal-input implementation and accepted producer fact/authority pair for
all six own controllers. Windows normal input stays denied. New SDK-free
synthetic normal/-O boundaries were checked; no shared source was applied or SDK
fetch/materialization/product run performed. Each owner still needs exact own
source/profile/held-current-cap admission and original product/delivery gates.

Producer04 has a separate root-dispatched SDK0 discovery entry in
`tools/curate_dotnet11_inputs.py`, bound to the exact signed handoff/profile.
It uses the unchanged0959 Windows Job helper for three fixed Linux nupkg DATA
files only: whole180s, file40s, terminal reserve30s,4GiB/64/CPU2,disk256MiB,
proof8MiB and canonical9120 lease. ZIP entries are streamed, never fully
extracted or executed; bounded original CMS/nuspec/notices remain data.
Raw signed hashes, declared feed policy hashes and normalized NuGet identity
stay separate. CMS trust, normalized identity and advisories stay UNKNOWN;
SDK/graph/product phases stay closed, product UNBOUND and Windows on HOLD.
StageA new offline fixtures passed85 in each normal/-O mode; no actual GET or
native Job/SDK was run by those fixtures. The manager alone dispatches StageB.

The separate `range-candidate-sdk0` SOURCE mode designs one future suffix GET
only (bytes41943040-42270531,327492B). It requires a new exact signed-source
gate,206 and exact single Content-Range/Length, identity/no transfer/multipart;
200/416/header mismatch stop before body reads. The old41943040B prefix is held
read-only and guarded by identity/stat/hash, then copied to fresh O_EXCL output;
no old data is appended, overwritten or deleted. Fullcandidate actual SHA512
must equal the fixed opaque policy before third-package ZIP/CMS DATA inspection.
Without an original strong validator, HTTPRepresentationContinuity stays UNKNOWN
and the result stays BYTE_CANDIDATE_UNTRUSTED, not authenticity/normalized/trust
admission. New18 fixtures passed per normal/-O mode; old85 and files0/1 were not
replayed.40s/file,whole180s/30s terminal reserve,4GiB/64/CPU2,combined old+fresh
disk256MiB,proof8MiB and canonical9120 lease remain. No actual Range GET/Job/SDK
is authorized or executed by this source candidate; Windows remains HOLD.

Linux input curation has a separate inert source mode. Its same-command NuGet
Content hash parser, closed config and finite static-response helpers do not
admit packages. The method feasibility gate currently stops before SDK or
network: complete current CRL coverage and scoped network denial are unbound.
See docs/SDK11_SHARED_NORMAL_INPUT.md. Windows qualification remains HOLD.

The local Linux curation method candidate now implements a finite OpenSSL3 CRL
supplement, exact-own-unit network denial/witness and the adapted public10
advisory patterns. Source preparation is not actual PKI/kernel/SDK acceptance.
All runtime paths require one exact-source activation and current-input guards.

The local curation source correction retains all four actual private locks,
consumed NuGet metadata and generated config/props in the existing 8 MiB proof.
Metadata HTTP now runs in an owned held child under one absolute 10-second
supervised request window, including startup and terminal handling. Runtime
remains inactive until exact-source activation.

Own04 causal Linux SOURCE correction (048f, no runtime retry): forward only the actual parent GITHUB_WORKSPACE after exact presence/equality with current resolved checkout, unchanged. Preserve original source-bound AdmissionError/finite literal codes, at most3 cause/context nodes and10 mapped frames in a <=16KiB typed record through early transport and cleanup; no message/path/env/header/content text. Existing8MiB proof and original caps/clocks unchanged. Frozen d9c CTX_KEYS actually contains15 names (the allowance prose says16); record its exact observed keys/types/presence/digests without changing that interface. Explicit stage entry is not HTTP start or completed bytes; absent results stay UNKNOWN. Existing immutable private capsule from071a may be consumed by a separately gated later HEAD only with exact release448158592/asset757707680/name/size/SHA256/producer/receipts/three-raw provenance. No new capsule, trust, SDK/CI or product/Windows admission. Historical run44021304386 cause remains UNKNOWN; the workspace omission is a source finding only.
