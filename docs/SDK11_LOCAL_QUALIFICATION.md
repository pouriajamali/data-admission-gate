# Local Ubuntu 24 qualification delta

Owner policy 2026-11-17 authorizes a valid local replacement for Actions.
`tools/qualify_dotnet11_local_linux.py` reuses the pinned Linux child runner, held MainPID/pidfd and per-child cgroup
witnesses, with the already used local direct cgroup OS starter method. It does not modify the frozen
CI schema, common transport API or historical facts. No CI environment is forged.
The historical `admission04-sdk11-ci-` cgroup suffix remains because the
existing child runner validates that random generation-bound group identity.

The candidate observes Ubuntu 24.04 x64, actual WSL2 kernel, systemd and nonroot
uid/gid separately. Ubuntu 24.04 is in the [official supported OS list](https://github.com/dotnet/core/blob/main/release-notes/11.0/supported-os.json).
[WSL2](https://learn.microsoft.com/en-us/windows/wsl/compare-versions) provides a
Linux kernel; that fact is not a new vendor support certification for this host.
The local envelope never passes itself off as the CI schema or consumer admission.

It reuses exactly `/home/ubuntu/.frl01-sdk-qja56iv8/sdk`, read only, against the
existing reviewed official archive/member catalog: 6,015 physical files, complete
hash/namespace/mode checks before and after, critical identity before each SDK
command. No SDK download, extraction, installation, private key or healthy denial
suite replay is performed. Each consumer still requires its own current source,
MainPID/start, kernel limits, clock, packages and product evidence.

Limits remain 4 GiB memory, zero swap, 64 tasks and CPU quota 2, 900 seconds whole,
840 seconds work, final 60 seconds terminal reserve. Eight original qualification
SDK commands share the existing 480 second aggregate stage; private data is at
most 2 GiB and JSON/log proof at most 8 MiB. Startup is bounded by 60 seconds.
The direct cgroup cleanup requires the original Popen and pidfd terminal and
actual zero population. Only its random owned cgroup may be killed/removed;
no daemon, password, truststore or ancestor setting changes. A missing proof is HOLD. The canonical
project lease must be acquired by the Windows operator before invocation and may
be released only after that terminal proof. No foreign lease may be reset.

Current status: source prepared; this document does not claim a successful local
run, product tests, RID locks, package acceptance or preview.3 release. CI is not
run by owner instruction. The published preview.2 remains the delivery baseline.

The first local starter stopped before worker creation because `sudo -n` required
a password; SDK executions were zero, original launcher terminal and no owned
unit/population were observed. Its receipt/lease release are retained. The causal
repair invokes the existing fixed direct cgroup method as WSL root solely for OS
control, entering the new capped group and dropping all supplementary groups,
GID/UID to 1000 before Python worker execution. All SDK/native work remains
nonroot. Existing enabled controllers are required; none are enabled by this
delta. The 6 local host boundary tests passed; execution remains pending.

The direct starter proved nonroot4GiB/64/CPU2/swap0 and complete Popen/pidfd/zero-
population teardown. Its first worker stopped before SDK at Git exit128: the
Windows-created worktree `.git` points to `E:/.../worktrees/repo3`. The exact own
pointer is now translated into explicit Linux `--git-dir` and `--work-tree`
arguments, with `GIT_OPTIONAL_LOCKS=0`. No `.git` file/config/index is rewritten;
other pointers are rejected. Nine bounded source tests cover both host and
worktree boundaries. Actual SDK qualification is still pending.

## Observed Linux completion and scoped Windows04 input

Linux signed source d3d0c91 completed eight fixed qualification SDK commands
on actual Ubuntu24.04.5/WSL2, nonroot uid/gid1000. The whole local operator took
87.828s, peak cgroup memory975106048B,4GiB/64/CPU2/swap0; held MainPID/start,
pidfd terminal and population0 are recorded. Seventy-three exported proof files
retain all eight command process hashes. This is local qualification only; the
immutable common62 and CI schema bytes remain unchanged.

The human separately authorized one experimental Windows04 qualification on
26H2/build26300.9974 (call_82e9689938c64cbdb74f7e75b4bef33c). Only04 is in scope.
`qualify_dotnet11_local_windows04.py` reuses the existing Windows Job helper,
PSF-signed Python bootstrap, full5480 member verification, CPUID, Microsoft
Authenticode with timestamps, retained critical image handles and the eight
fixed SDK commands under4GiB/64/CPU2,900/840 whole/work and480s SDK aggregate.
The existing SDK tree is reused; no download/extraction, CI environment, schema,
key, security setting or global environment change is made. Private empty
ProgramFiles directories reuse the existing NuGet workaround. Six new boundary
cases pass. Windows execution remains pending and formal .NET11 support for
this exact Windows build is NOT_CONFIRMED. Product acceptance remains separate.

The Windows bootstrap on0b04d73 stopped before lease/worker/SDK: inherited
PSModulePath prevented native Windows PowerShell5 from loading its security
module. A sanitized subprocess using only the existing system module path
returned PSF signature Valid/exit0. Only this bootstrap environment is corrected;
no machine/user environment or security setting changes. Eight SDK commands
remain unconsumed by that preflight failure.

## Concrete Windows continuation proposal (not yet authorized)

Source ec5cd55 completed the first five SDK commands. Restore failed at
NuGet.targets with null path1. Its4GiB/64/CPU2 Job ended in7.547s,95,019,008B peak,
with population0 and exact lease release. Six SDK attempts are consumed.

The existing successful Windows environment repair supplies five private empty
roots: PROGRAMFILES(X86), PROGRAMFILES, PROGRAMDATA, APPDATA, LOCALAPPDATA. The
local wrapper had supplied only the first two. It now supplies the remaining
three per process; no host/user config is inherited or altered.

The prepared `--resume-three` path requires a NEW explicit numerical approval
file and hash; it cannot execute with the old8-attempt grant. It reuses the exact
five healthy process/output hashes and previous native Microsoft publisher
report, rechecking SDK full physical identity and current source/host/CPUID/Job.
Only restore/build/hello run. The proposal is3 new SDK commands,9 total attempts
(including the failed restore), new bounded300s row/240s work/180s SDK aggregate/
60s terminal reserve and unchanged4GiB/64/CPU2. The prior7.547s execution is
retained, so combined executed row time is at most307.547s. The new row and
composite source/command history are explicit, never presented as one successful
original8-attempt run. No healthy five-command replay, download or new SDK is
allowed. Ten host/numerical boundary tests pass. No continuation has run.
