# v0.1.0-preview.2 — Data Admission Gate

The human report shows each axis status, basis and reason plus historical asOf,
latest accepted timestamp, age and threshold. JSON v1, ADMIT/HOLD/REJECT rules,
input/report bounds and the four pinned Integrity CSV sources are unchanged.
Owner decisions never establish identity, authenticity or legal rights; those
remain NOT_PROVEN. Coverage is DECLARED_GRID_ONLY and freshness DECLARED_ASOF_ONLY.

The signed app tag binds source b1012c1dec61c8d1a23cd604a77b36fb0062f0b0 and tree
09c3bf9b6da12eacdb6df903b2cc9452e9a620a0. [Exact app-tag native CI](https://github.com/pouriajamali/data-admission-gate/actions/runs/43282198464)
checks locked source tests, then separately builds/extracts and exercises each
matching-host archive with its17-check suite, including unknown-provenance/HOLD.
The self-contained targets are Windows x64 and Ubuntu24.04/glibc x64, using
SDK10.0.404/runtime10.0.15. They require native OS prerequisites, not an installed SDK.
The tested runtime archives are aggregated without rebuilding; source ZIP is the
exact tag commit. Their manifests must say sourceCommit b1012c1 and localCandidate=false.

Earlier private localCandidate artifacts and their17-check receipts on each OS
belong to9893583976da8d5042d063cabc58f65885001858 and were not relabelled/uploaded.
The earlier observed hosts are not clean-OS proof. Local Windows107/0/2 and Linux
109/0/0 evidence and four independent literal CLI oracles retain that original
scope; the exact hosted run linked above supplies its own source/OS observations.

Six named assets comprise two runtime archives, exact source ZIP, SHA256SUMS.txt,
SHA256SUMS.txt.sig and SIGNING-PUBLIC-KEY.pub. Download all from this exact release.
Verify the key against independently trusted fingerprint
SHA256:AgU5bZlJSjUu0KsWMmVEEr+BfXpcMVNroTA33bHcQdU, then verify the exact checksum
bytes using SSH file namespace/principal pouriajamali and check all three archives.
Use the online PROVENANCE.md with tag/filenames v0.1.0-preview.2. A co-downloaded key
alone does not prove identity. Missing signature assets mean incomplete delivery.
SSH provenance is not Authenticode. The frozen b1012c1 packaged README/release note
records its earlier local-validation state; this release page and current online
README/provenance guide provide the later public-delivery result.

[Separate build-time tooling](https://github.com/pouriajamali/data-admission-gate/releases/tag/tooling-actionlint-v1.7.12-go1.26.11-r1)
and [producer import/default-lint CI](https://github.com/pouriajamali/data-admission-gate/actions/runs/43275123686)
are independently delivered. They do not prove app runtime acceptance or consumer05/06.
Original MIT and dependency notices remain; copied vulnerability data separately
retains CC-BY-4.0 attribution. Existing preview.1 assets/signatures remain immutable.

No real feeds/accounts, downstream action, trading, performance, production-safety,
legal-rights certification or independent-skill claim. Parsed CSV output remains private.
