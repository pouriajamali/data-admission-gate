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
