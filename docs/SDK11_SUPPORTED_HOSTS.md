# SDK11 supported hosted CI source candidate

Status: source proposal only. Executable sources remain inert and unapplied; no SDK/native/CI was run. SDK_READY remains false. Existing preview.2 downloads and
their historical verification retain their original version and host boundary.

## Producer and consumer responsibilities

Producer04 proposes two existing sequential verify rows: windows-2025/win-x64
and ubuntu-24.04/linux-x64. Each row has one 900-second outer budget: startup,
checkout and existing Python 60s; acquisition 120s; extraction 180s; eight fixed
SDK commands together 480s; terminal observation and proof upload 60s. The
qualification event skips ci_policy, all product checks, tested-* uploads and
release. Ordinary policy classification and protection remain required.

Every acquisition, extraction, SDK and product descendant must have actual
4GiB memory, at most two CPU cores and 64 processes/tasks; Linux additionally
requires swap0 and a nonroot worker. Windows uses an owned kill-on-close Job,
suspended-child membership/readback and retained process creation identity.
Ubuntu uses only the existing sudo/systemd-run OS starter for one owned system
unit, fixed User/Group, stopped-child/pidfd membership and ExecStopPost outcome
before collection. No installation, user daemon, linger or host policy change
is proposed. Existing hosted shell/Python startup is an explicit trusted image
bootstrap boundary outside the target aggregate. Actual image/tool hashes and
versions must be measured. Python and CPU checks precede SDK targets. Windows
uses the fixed reviewed CPUID thunk with RW-to-RX pages and restored affinity;
Ubuntu checks all logical CPU flag sets. There is no extra .NET bootstrap.

The frozen typed schema is tools/dotnet11-host-qualification.schema.json,
urn:pouria:dotnet11-host-qualification:v1. qualifiedOn records the immutable
producer run/job/instance. Consumer admittedFor binds its own host class, RID,
SDK, member manifest, contract, source pins, controller and resource profile.
The current consumer job may differ; it must independently observe its actual
host, CPU, UID, kernel caps and child membership. A producer receipt cannot
supply another job's kernel evidence. Each consumer owner prepares its own
controller. This candidate changes only producer04 and consumer04 source.

Reviewed archive catalogs have state REVIEWED_TYPED_ARCHIVE_INPUT_NOT_EXECUTED
and are usable only by the fixed qualification controllers. They are not
accepted normal SDK catalogs. The existing check_dotnet11.py and metadata-only
normal lock remain unchanged and deny execution. Consumer04 admission stays
UNBOUND_NO_CONSUMER_SDK_TARGETS; producer fact bindings and contract are null.
A later exact gate must supply accepted host facts/catalogs and source pins.
One accepted RID can progress its matching consumer independently; all original
RIDs, 109-case inventory, 17 archive checks and four semantic/wire oracles remain
required for final delivery. Producer qualification does not pass those tests.

Each producer uses only its existing proof-RID artifact, at most 8MiB, retained three days. Success selects the actual host fact; failure selects a sanitized <=32KiB failure summary with source/run/job/stage/cause and observed terminal/ExecStopPost state, or explicit UNKNOWN. A failure never creates a qualification fact or PASS. SDK archives/trees are neither cached nor uploaded. There
are no new jobs, SDK support releases or binary artifacts. Global SDK_READY is
false. The local Linux R3 admission is retired/STOP and its partial tree remains
unqualified; the local Windows 26H2 host is UNKNOWN/excluded from this route.

## Validation and remaining gates

Our validation covers static source identities, AST/JSON/YAML and changed failure/event checks. Coordinator review separately observed 108 literal source-value denials in 12 fresh Windows Python3.12.10 processes for both RID values and modes0/1/2, with zero SDK/network spawns. That evidence is reused at its original source/Windows-value scope; it is not Linux-native or hosted execution. No SDK/native checks, Git mutation, dispatch or public update occurred. Future isolated policy/YAML/lint
checks must cover ordinary docs/source/tag/manual/tooling-tag events and the
special skipped-needs route before any public source mutation. Planned new
SDK-free denials are 12 cases in three actual optimization modes per producer
host and six cases in those modes per consumer host, plus an own SDK0 marker.
Previously closed evidence is reused only with its original identity.

Actual pre-execution caps, root-starter behavior, failure cleanup, stage budgets,
CPU thunk, publisher/native dependencies and full terminal population require
fresh authorized native evidence. A failure without complete terminal proof
must remain HOLD; a configured timeout is not proof of native exit. Candidate
source is untested and must not be treated as runtime qualification.

Before a public operation, obtain the next exact coordinator gate, run the
isolated source/policy/schema/YAML checks, sign the exact source and bind the
real commit on codex/sdk11-supported-ci-qualification-20261116. Qualification
uses workflow_dispatch mode sdk11-ci-qualification plus that expected_commit.
Reconcile an ambiguous response by reading run/jobs/head SHA/artifact identities
before any retry. No main merge is part of this proposal. Product locks, pack
identity/signatures/notices/advisories, frozen Oracle version allowance and
private-draft/sign/verify/publication gates remain separate prerequisites.

References: [supported OS](https://github.com/dotnet/core/blob/main/release-notes/11.0/supported-os.md),
[hosted Windows image](https://github.com/actions/runner-images/blob/main/images/windows/Windows2025-Readme.md),
[systemd service outcomes](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html).
These are design references; future run-specific measurements remain required.

The final source correction puts both Linux Popen paths through one narrow
owned-unit supervisor and finally cleanup. Before launch, the random unit must
be absent; its fixed Description binds the generation. Cleanup may stop only
that observed generation, signal the original pidfd and terminate/kill only the
original Popen. It lasts at most50s and ends by outer890s, within the existing
final60 reserve. Missing population/cause/terminal observations remain UNKNOWN
and HOLD. ExecStopPost records actual remaining population, including nonzero,
before collection. Native cleanup behavior is untested. Windows consumer PATH
now includes only the fixed existing C:/Program Files/Git/cmd in addition to
the already bounded SDK/OS paths; no ambient PATH or tool download is used.

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
