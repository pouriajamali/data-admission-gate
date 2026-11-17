# Local Ubuntu 24 qualification delta

Owner policy 2026-11-17 authorizes a valid local replacement for Actions.
`tools/qualify_dotnet11_local_linux.py` reuses the pinned fixed Linux supervisor,
held MainPID/pidfd and per-child cgroup witnesses. It does not modify the frozen
CI schema, common transport API or historical facts. No CI environment is forged.
The historical `admission04-sdk11-ci-` unit prefix remains solely because the
existing supervisor validates that random generation-bound unit identity.

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
The existing exact-unit cleanup requires the original launcher and pidfd terminal,
zero population and nonroot stop observer. A missing proof is HOLD. The canonical
project lease must be acquired by the Windows operator before invocation and may
be released only after that terminal proof. No foreign lease may be reset.

Current status: source prepared; this document does not claim a successful local
run, product tests, RID locks, package acceptance or preview.3 release. CI is not
run by owner instruction. The published preview.2 remains the delivery baseline.
