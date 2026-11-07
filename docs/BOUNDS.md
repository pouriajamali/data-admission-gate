# Conservative bounds and observed checks

Input is capped while reading: CSV1MiB, policy128KiB, decision16KiB; at most three
known flat bundle members, JSON depth8 and policy grid1000. The vendored Stream
validator receives fixed1MiB/1000-record/4096-record-byte limits. Its code is not
forked to add new parsing rules.

Vendor private output inventory is exactly run.lock (0bytes), accepted.jsonl and
quarantine.jsonl (each <=1MiB), summary.json (<=64KiB). Their aggregate must be
<=2MiB both after production and immediately before final main JSON. Changes or
extra members are incomplete. Output hashes are recorded, without raw row values.

Conservative size argument for the pinned producer: each row decision has fixed
property names and fixed reason/field vocabulary, SHA25664 ASCII characters,
bounded line/offset/byte-length integers, and either null or one CSV record.
That record contains a20-character timestamp and five normalized signed Int64
strings of at most20 characters. Even allowing64 characters each for reason/field,
20digits per numeric metadata and256 bytes of JSON syntax/property names, one
ASCII decision line is below1024 bytes. The reader enforces1024 bytes including
LF per decision line; the two output partitions together contain <=1000 rows.
Thus <=1,024,000 decision bytes +65,536 summary bytes +0lock bytes <2MiB. Actual
byte/inventory/count checks verify the bound before admission. Unexpected producer
format/growth fails incomplete; no truncated green output.

The main report has no row array or arbitrary owner/reference text. Its grid/error
detail is exact counts and <=20 fixed diagnostic codes. Actual serialized UTF8
JSON is checked <=128KiB and text <=32KiB before creation of pending files and
final rename. The1000-record Int64-boundary regression exercises the large case.
No measurement of throughput, latency, peak memory or performance advantage follows.

These are application bounds on a known local profile. A hostile filesystem/native
runtime, indefinite OS I/O or unobserved change between final checks is not claimed
to be isolated atomically. Reports bind the observed bytes and declared context.
