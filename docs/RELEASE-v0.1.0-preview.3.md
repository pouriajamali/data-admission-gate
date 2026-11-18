# v0.1.0-preview.3 - .NET11/C#15 technology preview

This maintenance version targets SDK11.0.100, net11.0, runtime11.0.0 and C#15.
The v1 contracts, parser/vendor pins, fixed numeric scales and ADMIT/HOLD/REJECT
rules are unchanged. No new feature, speed or general security claim is made.
Identity/authenticity/legal rights remain NOT_PROVEN after ADMIT.

The release's local receipt binds the tested commit to each actual native
Windows/Linux x64 self-contained archive, the exact source archive and SHA256.
Acceptance retains the109-case inventory (Windows skips the Linux-only FIFO case and, when local privilege is absent, the symlink-creation case),
17 checks on each extracted native package and four literal actual-apphost
compatibility cases per OS. Publication requires those actual results; old
preview.2 receipts are not preview.3 evidence.

The local environments are Ubuntu24.04.5/WSL2 and experimental Windows26H2,
build26300.9974. Formal .NET11 support on that Windows build is NOT_CONFIRMED.
Self-contained apps still require the runtime's native OS/CPU prerequisites;
.NET11 requires x86-64-v2. No clean-OS or vendor certification is claimed.

GitHub Actions are NOT_RUN_PER_OWNER_INSTRUCTION. The exact preview.3 tag is
excluded from push-triggered Actions; main, PR, other tags, security and branch
protection are unchanged. Native acceptance and package checks run locally
under the recorded per-OS caps and actual terminal teardown.

The six distributable/signing assets are win-x64 ZIP, linux-x64 tar.gz,
exact source ZIP, SHA256SUMS.txt, its SSH file-namespace signature and the known
trusted public key. A supplemental local delivery receipt accompanies them.
Verify the known key fingerprint and checksum signature before extraction:
`SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU`.
This is checksum signing, not Authenticode signing of the application.

The software is MIT; bundled dependency/runtime notices retain their own terms.
Software licensing never establishes input-data ownership or legal use rights.
See README, PROVENANCE and bundled notices. Historical tooling/input checkpoints
are retained separately in [SDK11_DELIVERY_HISTORY.md](SDK11_DELIVERY_HISTORY.md).

Windows local test boundary: this experimental host cannot create the refused-file
symlink fixture. That case is separately `LOCAL_SYMLINK_PRIVILEGE` skipped,
in addition to `LINUX_ONLY` FIFO. Counts retain the109-case inventory; the
release receipt separates actual new cases, exact healthy-case reuse and skips.
No Developer Mode, privilege, path guard or security setting is changed.

Runtime/source archives bind to tested e48e0bf5ca550fc736c2f6f551c34347f54c00ff.
Separate bounded offline finalization tooling is later source; both original
postcheck envelope HOLDs remain unchanged. Publication requires actual per-OS
offline final receipts. See SDK11_OFFLINE_FINALIZATION.md for the exact boundary.

## Published delivery

[Public preview.3 release](https://github.com/pouriajamali/data-admission-gate/releases/tag/v0.1.0-preview.3)
contains all seven signed-payload/signing assets. Each was downloaded from the
private draft before publication and again anonymously from its public stable
download URL, with exact size/SHA256 matching and the downloaded SSH checksum
signature verified against the independently known fingerprint above.

The immutable runtime/source commit is `e48e0bf5ca550fc736c2f6f551c34347f54c00ff`;
the separate fresh offline finalization tooling source is
`671d954bf3640afbb541c407f765674b27f087f5`. Later source
`ebe8358b3abed35cbf5881276df8278f5c8f3f50` adds a shared-input verification
correction, not a rebuild of these application packages.
Linux has 109 PASS / 0 FAIL / 0 SKIP; Windows has 107 PASS / 0 FAIL / 2 SKIP,
with the exact103 healthy-case reuse and four new original oracle results
separately attributed in the public receipt. Both have 17 package checks and
four actual-apphost literal compatibility cases. Original postcheck HOLDs and
their unretained denied request target (UNKNOWN) remain unchanged; both later
zero-request offline finalizations completed under fresh own-source/PID/caps
and actual terminal evidence. No GitHub Actions ran for this release.

| Archive | SHA256 |
|---|---|
| Windows x64 ZIP | `24daa8328285e98a6937a2f43fceb4e08c89bdee217ffddd10844f4d4bfb4396` |
| Linux x64 tar.gz | `364184c80e8024921f64131a4aa57156f63af35e6af8e0cb7d366a040dde3cab` |
| Exact source ZIP | `cb36f5d24f98452ed0dfaad904afa4b346e99cad280c9418cb3535e4c445df93` |
