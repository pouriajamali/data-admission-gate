# Shared SDK11 normal input source interface

This is one producer04-owned source proposal for all six own controllers.
It has not been applied or used to fetch, materialize or execute an SDK.
Only Linux fact757abf2d and acceptance0452e1f3 are admitted source inputs;
Windows has no accepted normal input and is denied. Global SDK_READY is false.
Producer803eb history and all frozen qualification catalogs remain unchanged.

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
