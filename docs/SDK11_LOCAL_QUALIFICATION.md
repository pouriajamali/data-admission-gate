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
