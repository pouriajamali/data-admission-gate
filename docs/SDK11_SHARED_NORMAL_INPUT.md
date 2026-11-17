# Shared SDK11 normal input source interface

Current common source contains independently accepted Linux and Windows SDK producer histories. Windows qualification source86dcda2c/CI44083510897 and Linux native curation source793ec500/CI44082565011 are preserved as historical facts. Both RIDs require each consumer own exact source/profile/current host/held caps/original deadline before transport. Global SDK_READY remains false.

The single callable API is unchanged; its field-level interface is in [SDK11_SHARED_INPUT_INTERFACE.json](SDK11_SHARED_INPUT_INTERFACE.json). Windows uses one source-pinned adapter behind this API; frozen63e schema and qualification catalogs are unchanged. The Linux execution path and Linux history row are preserved. Current normal catalog is tools/sdk11-normal-inputs.lock.json; separate tools/sdk11-native-inputs.lock.json contains exactly three accepted Linux nupkg facts and portable original notices/CMS/member inventories/evidence. A Windows SDK host fact does not grant native nupkg admission.

Source-only adapter fixtures passed normal and -O, with wrong source/fact/caps/PID/clock denials and mocked native-deadline outcomes. The new Windows adapter itself has not been exercised inside a consumer runtime yet; each consumer own existing gate does that without replaying healthy SDK qualification. No SDK/restore/qualification/key operation was performed to build this common source. Product04 remains closed. Existing releases/signatures and other product/client versions are unchanged.

The following earlier-stage notes are retained as history; their Windows-denied/unobserved statements are superseded only by the current accepted histories above.

The callable API is `transport(rid, directory, context) -> (sdk_path, receipt)`
in tools/check_dotnet11.py. `inspect_sdk(rid, root, context)` rechecks data only.
The complete field-level context/profile/caps interface and exact common hashes
are in the producer's INTERFACE.json delivery record. This function has a real
fixed implementation, not a callback or a per-consumer transport template.

Call from the own tracked controller inside its held nonroot system-service
main worker. Before network, the module validates frozen63e consumerAdmission,
accepted fact/authority/catalog and raw/member/alias identities, current clean
Git HEAD/tree/source table, tracked controller/contract/profile bytes, current
job/instance/UID/PID/start/cgroup, exact own kernel limits and held preExec
witness. It independently reads the own service's actual bounded lifetime and
control-group teardown settings. It does not use producer04's caps as authority
for another project. Actual bootstrap and CPU-v2 are measured on the caller.

Every operation shares the caller's original absolute monotonic deadline:
source/hash/read, network, raw bytes,7055 headers,1830 independent regular-copy
aliases, fsync, full namespace/body/mode/critical/notices verification and
failure cleanup. Existing stricter alarm is preserved without resetting elapsed
time. The original materializer/guard bytes are reused unchanged. A cleanup
that cannot finish within the same deadline retains a partial/HOLD; the caller's
actual own supervisor must establish final terminal state. No path is returned
on failure. No SDK command or publisher/native/product acceptance is performed.

Success returns the private SDK path and a typed input receipt to the own capped
caller. No GITHUB_PATH/GITHUB_ENV/globalPATH writes or SDK cache/artifact upload
occurs. The caller must retain its original budget:01/04/06<=900s,02<=720s,
03/05<=1200s including all input, SDK and product work; caps come from its own
reviewed profile. A producer qualification receipt is not app compatibility.

New synthetic source-value cases passed in normal/-O; no old108/144/96 tests or
eight-command qualification were replayed. Actual fetch/materialization/current
kernel behavior remains unexecuted by this source-preparation task. All six own
bindings and the next consolidated exact source/runtime/public gate are still
required. Existing preview.2 releases and original109/17/4 product checks remain
separate. Adjacent scoped Git attributes preserve exact accepted-proof bytes.

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

### Complete Linux curation source candidate (2026-11-16)

Contract f19c85da binds the existing three raw inputs and seven future SDK
operations. `--curation-admission` selects a dedicated Linux purpose and leaves
product UNBOUND guards intact. The profile is SOURCE_CANDIDATE_METHOD_HOLD_NO_RUNTIME.
The mode stops before worker launch, SDK transport or target/network operations.
No runtime JSON can waive this source-bound feasibility decision.

The pure helper parses exactly one successful English verify package block and
one canonical 64-byte base64 Content hash from that same command. Released SDK
output remains unobserved; a different format holds rather than borrowing raw
SHA512 or running another SDK operation. The three signature-only vectors precede
native input admission; four graph vectors follow all-input acceptance.

Config serialization requires signatures, exact primary/repository signer pins,
a private local raw source, no fallback packages and a specific loopback audit
source. The frozen response dispatcher cannot forward, resolve DNS or CONNECT;
OCSP is unavailable locally and never treated as valid revocation evidence.
It is a pure component; no live server or kernel-deny transition is claimed.

The reviewed mechanism does not yet bind a per-certificate current CRL signature,
validity/serial coverage report from these seven commands, a scoped kernel-deny
transition with witnesses, or the causal project10 advisory range helper. The
Linux runtime path therefore remains closed. No custom crypto, trust-store change,
eighth SDK operation or assumed proxy consumption is introduced.

Graph planning adds an explicit DirectoryBuildPropsPath argument to the same four
restore operations; generated props retain the original project props and put obj
and project extensions under per-flavor/per-project private directories. This
causal argv delta requires the final exact-source review; locks remain private.

Retention counts original metadata plus other proof against 8 MiB before SDK.
Scratch uses exact SDK inventory plus native/cache/capsule allocation under the
smaller applicable owner cap, never more than 2 GiB. Source scratch remains 256 MiB.
Actual current metadata sizes, target free space, kernel method, SDK output and
trust/advisory/servicing status are UNEXECUTED or UNKNOWN. The source candidate and
checkpoint retain the concrete ledger, finite route and conditional launch plan.

### Finite method amendment from d50d (2026-11-16)

Amendment 0ced5ea8 replaces the three prototype method blockers with pinned
implementation and actual-input runtime guards. Only OpenSSL version (2 seconds)
and two current-CRL verify operations (10 seconds each) are added as OS work,
inside the same own04 cgroup and original stage deadlines. They supplement
current X509/CRL chain coverage; NuGet still owns CMS/RFC3161/code-signing/content
hash verification through the same three signature-only commands. No eighth SDK
operation, crypto formula, fetched trust anchor or system trust change is used.

Original CMS SID mapping includes issuer+serial and subject-key identifiers.
The exact eight-certificate pool, author9A1B/repository1F4B and observed shared
TSA2DA0 are data bindings, not trust. CRL issuer/AKI, explicit nextUpdate/current
time, complete chain coverage and duplicate-issuer equality are guarded before
the native verifier; unsupported delta/indirect/scope ambiguity holds. Native
exit/results/constructed-chain/actual libcrypto evidence must pass at runtime.

At a second held-worker handshake the trusted parent may change only the exact
nonce unit. One set-property and one show are followed by read-only BPF queries
on that cgroup. New ingress/egress attachments, unchanged stopped PID/start/boot/
limits, loopback-positive and permission-denied negative peer witness are all
required. Timeout/unreachable/property-only evidence cannot pass; unsupported
kernel behavior holds. Prefetch sockets close before transition, with no external
FDs passed to the seven children. A frozen loopback PKI/audit dispatcher has no
forwarding/CONNECT/trust mutation; unknown requests poison the phase.

The seven public10 patterns are adapted as source data with c49f provenance,
using own04 limits/origins/clock/accounting. No producer10 module/runtime or caps
are imported. Complete snapshots and current servicing remain mandatory. Their
original bytes plus all proof must fit 8 MiB before SDK signature work; overflow
holds and does not authorize an extra artifact.

The prepared profile and inventory use the unchanged common interface operational
source-review states so its exact tracked-file preflight can operate after root
activation. These source configuration fields do not authorize runtime: the
separate exact source/tree/profile/amendment/run/nonce/lease/input gate is checked
first. Old own-normal profile and product route remain PROPOSED/UNBOUND.

An opt-in Linux selector (default false) reuses the existing verify job and proof
artifact with 3-day retention. It suppresses product/Windows/qualification work
for that purpose. The root-approved handoff SHA binds the private draft input
asset and nonce; only declared server-assigned run/path fields are resolved into
exclusive admission files. The existing CI token is used only for the exact
asset transfer, never SDK environment or output. One HTTPS GitHub API response
may hand off to its returned release-assets HTTPS URL with credentials removed;
no retry or arbitrary redirect is allowed. This is private input transport, not
a native NuGet body reGET or metadata allowlist expansion.

Actual OpenSSL version/binary/libcrypto/CRL results, effective root store, kernel
policy, deny witness, current metadata retention/free space and SDK output remain
UNEXECUTED/UNKNOWN until the single final-source runtime activation. Negative
permission errno is intentionally stricter than a timeout; inability to witness
it closes the phase. Source mocks are not real crypto or kernel qualification.

### Causal R1/R2 correction from 7d9a (2026-11-16)

Consolidated review107c remains valid for unchanged f021 source and prior18 mock
receipts. R1 adds fixed-path snapshots for the exact four private graph locks,
each selected .nupkg.metadata actually read, generated NuGet config and both
graph props. Actual original byte hashes/file identities are captured when
consumed, checked again at publication and retained as original bytes. Missing,
changed, unexpected-path or oversized evidence holds; package/SDK bodies are
excluded. Success requires all four locks/configs; failure manifests identify
partial or unavailable durable evidence without claiming complete graph proof.

The original 2 MiB reserve for other reports is supplemented by a 671744-byte
worst-case reserve for these durable files before SDK work. This is inside the
existing combined8 MiB proof ceiling; no extra artifact or budget is created.
Metadata process control evidence is counted in the actual metadata directory.

R2 wraps each metadata request in one absolute window no longer than10 seconds,
starting before helper/open/resolver/connect/TLS/headers. Only an existing
held-child primitive inside the same own04 cgroup may run the one-shot HTTP
helper. Its work stop reserves200ms for terminal handling within that window.
The parent also arms an absolute main-process alarm, covering startup, zero-body
responses, errors, copying and return. It restores only the original phase
alarm remaining time; expiry is typed HOLD, with no retry or fresh420/900 clock.
No new unit, privilege, probe, GET, cap or qualifier is introduced.

Only three new synthetic causal groups per normal/O are used for this correction;
old18/24/common suites are not replayed. Real HTTP/SDK/OpenSSL/kernel/capsule/draft/
CI/push remain unexecuted until the revised exact signed-source activation.

Own04 causal Linux SOURCE correction (048f, no runtime retry): forward only the actual parent GITHUB_WORKSPACE after exact presence/equality with current resolved checkout, unchanged. Preserve original source-bound AdmissionError/finite literal codes, at most3 cause/context nodes and10 mapped frames in a <=16KiB typed record through early transport and cleanup; no message/path/env/header/content text. Existing8MiB proof and original caps/clocks unchanged. Frozen d9c CTX_KEYS actually contains15 names (the allowance prose says16); record its exact observed keys/types/presence/digests without changing that interface. Explicit stage entry is not HTTP start or completed bytes; absent results stay UNKNOWN. Existing immutable private capsule from071a may be consumed by a separately gated later HEAD only with exact release448158592/asset757707680/name/size/SHA256/producer/receipts/three-raw provenance. No new capsule, trust, SDK/CI or product/Windows admission. Historical run44021304386 cause remains UNKNOWN; the workspace omission is a source finding only.

PUBLIC_ORIGINALS_V1 SOURCE amendment (1eb4): only a separately activated new exact Linux source/run may GET the three fixed public originals once each (3GET,1inflight,45s each/135s aggregate inside original420/840/900), with identity TLS/no proxy/auth/token/redirect/range/retry/fallback, <=64KiB streaming and exact size/SHA256/SHA512 before readonly raw admission. Same512MiB body/2GiB smaller disk/4GiB64CPU2swap0/8MiB proof/23metadata/7SDK/3OpenSSL; capsule allocation removed, no other reserve increase. Existing capsule/draft remains immutable historical provenance. No public-body GET now. Actual405 run44027199682 verified the SDK input transport only (6015files,SDK0), then CAPSULE_API_STATUS; its HTTP status remains UNKNOWN. New finite safe HTTP diagnostics are not retroactive evidence. Original f19/0ced/COMMON/15context keys and Windows branch stay unchanged. Token injection/creation/read/cleanup removed only from this public route; unexpected token-dependent config HOLDs without reading a secret value. No CI/push/SDK/native/HTTP/controller or product acceptance in SOURCE.

Advisory namespace SOURCE correction (08a1): actual run44040643220 verified shared SDK input and three public originals (HTTP200/exact60404733B/SHA256+SHA512/natural children), then the legacy-only URI guard rejected the retained official VulnerabilityInfo6.7.0 declaration https://api.nuget.org/v3/vulnerabilities/index.json. This is a concrete namespace mismatch, not evidence of outage/signature failure or completed audit. New immutable own04 namespace companion permits only the ONE index actually declared by current service, chosen from that exact URI or legacy https://api.nuget.org/v3-vulnerabilities/index.json; never fallback or both. Full original index closes1..8 exact distinct page IDs/names in /v3/vulnerabilities/ or /v3-vulnerabilities/, canonical segments/.json, no self-reference/query/alias/foreign origin; every page fetch and advisory_guard requires that exact tuple and full snapshot. Low+ ranges/all native+graph dependencies, freshness/retained originals/23GET/10s/420/8MiB and every SDK/native/resource/trust rule unchanged. Retained9431B service is source fixture only, not a fresh runtime snapshot. Parent f19/0ced/public002a and public10 origin/license/source history remain immutable. Old70a/104/b7/5f9 gates closed; no HTTP/SDK/CI/push or product/SDK_READY/Windows acceptance from this source.


### Metadata framing diagnostic SOURCE candidate (2026-11-17)

The a9 run stopped at the first metadata request with typed METADATA_HTTP_FRAMING; the actual status and header predicate remain UNKNOWN_NOT_RETAINED. Child OS exit 0 proves process termination only. The actual helper is now registered by source-bound module/class identity for safe original-cause retention; foreign same-name classes remain unknown.

An explicit METADATA_SERVICE_FRAMING_DIAGNOSTIC_ONLY selector uses the existing manual Linux curation row and the same bounded metadata helper: at most one GET of https://api.nuget.org/v3/index.json, 10 seconds within original worker 70 plus terminal reserve 60 (total 130), raw plus decoded 2 MiB, private scratch 32 MiB, proof 8 MiB/3 days, and unchanged 4 GiB/64 tasks/2 CPUs/swap 0. Finite status/header-count/encoding categories are observed before the original guards; raw headers and exception text are not emitted. No framing waiver, retry, redirect, fallback, SDK/archive/raw-package acquisition, OpenSSL, other metadata, advisory or graph audit follows.

SERVICE_REQUEST_ACCEPTED_DIAGNOSTIC_ONLY and FRAMING_OBSERVED_GUARD_HOLD describe only this diagnostic; semantic Hold is distinct from OS success. Missing, unknown, forced, late or over-budget evidence remains Hold. FULL_PRODUCER_CURATION remains the default with the previous complete method/caps intact and a separate mandatory execution-mode/profile gate. All previous gates are consumed/closed. This source candidate does not authorize any request, Job, SDK command, CI, push, full producer or Windows/product acceptance.

Before the diagnostic worker is continued, one bounded same-unit kernel-clock readback must prove activation plus RuntimeMax no later than the original 70-second end. Unknown or late readback remains Hold; no new clock is started. One detection byte stays inside the combined 2 MiB ceiling. Source allocation including Git data is checked within the existing 256 MiB source cap.


### Strict metadata chunk framing correction (2026-11-17)

The single SDK-free service diagnostic (run 44065565191/1, exact a5a329d) observed HTTP 200, expected URL, one chunked transfer coding, no Content-Length, and one gzip content coding. It stopped before application body reads at the original no-transfer-coding guard. CI/process success was diagnostic completion only; no input was admitted.

The full producer now opts into a strict HTTP/1.1 chunk parser for that valid framing: exactly one chunked coding with no Content-Length or Trailer header, <=65536 chunks, <=16 hexadecimal size digits, original body bounds, exact CRLF, no chunk extensions or trailers, and mandatory final zero chunk. Ambiguous, malformed, incomplete or over-budget framing remains Hold. Original TLS/origin/status/freshness/single-gzip/strict-JSON, raw3 byte/hash/CMS/normalization, complete advisory/locks/notices, actual host/caps and deadlines remain mandatory. Public raw transport and the SDK-free diagnostic no-TE guard are unchanged. No additional diagnostic request is authorized by this fix.


### Completed-body transport closure correction (2026-11-17)

The 4a659ff run retained UNKNOWN after 1262 application bytes; stderr was empty and the original exception was not retained. A closure-aware offline HTTPResponse fixture reproduces the same partial-count/UNKNOWN signature: parsing the valid final zero chunk closes the transport before returning the final nonempty payload, then the old loop sets timeout on that closed transport. The correction exits only after explicit valid zero termination, closed response and exact declared payload count. Incomplete or malformed chunks remain Hold. This offline cause proof does not retroactively recover the unknown exception from the old run.

Loaded helper classes are bound immediately by verified module identity, so later loads cannot erase the original Hold identity. Child failures retain only a finite trusted exception category/errno and fixed operation; no exception message, raw header/body excerpt or private value is emitted. Original supported-source/current-host/caps, framing/gzip/JSON, signatures/normalized/advisory/lock/notice, deadlines and retention requirements remain mandatory. No online diagnostic is repeated; input acceptance still requires its own exact corrected full run.


### Servicing release precedence correction (2026-11-17)

Retained official channel11 metadata from run44071519118/1 still names SDK11.0.100/runtime11.0.0, stable release2026-11-10 and active support. Three older security-tagged RC rows caused the old inequality test to misclassify them as later releases. The guard now reuses the reviewed stable-versus-bound version ordering: historical prereleases are lower than stable, while actual later security versions remain Hold. Canonical bounded versions, required release fields and exact consistent latest pointers/current release are checked; missing or malformed metadata remains Hold. SDK/runtime pins, freshness, complete advisories, CMS/PKI/normalization, locks/notices and every cap remain unchanged. No online diagnostic or healthy SDK replay is added.

Known HTTP, URL, TLS and protocol exceptions now retain only exact trusted type categories, bounded numeric status/errno/verification code and fixed operation. No exception reason, URL value, raw header/body or private error text is exposed. Malformed service/repository objects fail with existing fixed Hold codes. This closes a concrete avoidable-UNKNOWN branch before the one permitted full run.

Scoped03 input correction: run44076031612 passed strict metadata framing and retained natural terminality, then held on a direct name-only CRL distribution point. The source now matches that fullName to certificate CRL distribution points per RFC5280 6.3.3(b)(2). Delta, indirect and restricted-reason/type CRLs remain denied; OpenSSL/NuGet signature and revocation checks remain required. Focused data regression passed; this note is not runtime/input admission.

The scoped CRL path requires a critical IDP containing only direct fullName URI scope. Unsupported critical CRL extensions and noncanonical critical flags fail closed. Selected certificate DP/issuer/AKI coverage, freshness, original-byte OpenSSL verification and independent NuGet CMS verification remain mandatory. Unique exact SDK trust anchors take precedence over cross-sign alternatives, matching OpenSSL trusted-first chain construction; untrusted ambiguity remains denied. These source guards alone do not admit input or qualify Windows.

Run44079482133 passed selected-chain structural CRL coverage, then held at the bounded network witness before native signature verification. The single negative probe now uses one zero-payload UDP sendto to the same already-bound official peer IP/443, allowing the local cgroup egress permission error to propagate without TCP SYN retries. Only actual EPERM/EACCES plus the unchanged unit generation, new ingress/egress attachments, policy readback and loopback positive can pass; timeout, unreachable, successful send or unknown result remain Hold. The three-second/stage540 bounds and deny policy are unchanged. Source fixtures do not establish runtime denial or package admission.

Run44080745735 observed actual EPERM under the owned current BPF policy and passed both OpenSSL current-CRL chain operations. The first NuGet command then held on scratch type/ownership. Curation SDK commands now disable unused runtime diagnostic IPC and the initial CLI banner. Scratch links, foreign owners, sockets, FIFOs and other special types are still denied, with distinct source-bound finite cause codes; every allocated block and the existing byte cap remain enforced. The previous rejected entry category was not retained. No package CMS/normalization/graph admission is established by these source changes.

Run44081883307 passed the network/native/scratch guards and the first actual NuGet verify command, then the report parser held because four signature/timestamp role labels also begin with Verifying. Only those four exact observed role labels are excluded from the package-header count. Exactly one package identity/hash/success, exact ordering/canonical content hash, original raw binding and all issue/exit/stderr guards remain required. Retained-report regression and malformed/duplicate/warning/unknown-role negatives passed; this correction alone does not admit all packages or graphs.

Current Linux input result: [CI44082565011](https://github.com/pouriajamali/data-admission-gate/actions/runs/44082565011) succeeded at source793ec500b49f7358025b0e99d27d26746f18c91e. All three actual NuGet signature/content-hash operations and four own04 graph restores passed, with current CRL/native chain, owned network denial, original notices, complete applicable advisory and natural terminality. A local immutable input-fact handoff covers only Microsoft.AspNetCore.App.Runtime.linux-x64, Microsoft.NETCore.App.Host.linux-x64 and Microsoft.NETCore.App.Runtime.linux-x6411.0.0; raw signed hashes and normalized NuGet content hashes remain separate. Its SHA256 is b94a8d74cd6290b17c2e063d0d15ddab04c086f5a9b41120e5c53ee01c7671df. The artifact upload omitted two hidden217-byte .nupkg.metadata files; their bodies were reconstructed solely from recorded public metadata fields and exactly matched the original recorded SHA256 and sizes. The downloaded artifact was preserved, and no healthy restore was replayed. This is not a product release or Windows qualification. Consumer01/02/03 own source/input/caps gates and any additional package closure remain required. Windows input production currently belongs to the separately authorized owner01 execution; no duplicate Windows or recipient diagnostic is started here.
