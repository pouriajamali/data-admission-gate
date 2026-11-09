# Offline admission companion v1

Profile admission-ohlc-csv-v1; purpose offline-analysis; fixed public OHLC CSV
price scale2/volume scale0. Reuses unmodified vendor revision/pins, not a new parser.

Flat case-sensitive bundle: input.csv <=1MiB/1000 data rows/4096-byte records;
policy.json <=128KiB and optional owner-decision.json <=16KiB. No other member,
directory, observed link/reparse point/nonregular file or network path. Strict
JSON/depth8/exact fields/duplicate-key rejection; no trimming, numeric coercion,
timezone/calendar inference or live input.

Policy exact fields:

```json
{"schema":"data-admission-policy-v1","profile":"admission-ohlc-csv-v1","purpose":"offline-analysis","asOf":"2026-01-01T00:02:00Z","maxAgeSeconds":60,"expectedTimestamps":["2026-01-01T00:00:00Z","2026-01-01T00:01:00Z","2026-01-01T00:02:00Z"]}
```

Timestamps are exact UTC yyyy-MM-ddTHH:mm:ssZ. Expected grid1..1000 unique ascending
slots; no inferred calendar. maxAgeSeconds is digits-only integer0..604800. asOf
is caller-declared historical context, not a verified current/source clock.

Optional owner decision exact fields: schema=owner-decision-v1, datasetSha256,
policySha256, purpose, ownerLabel, evidenceRefs, provenance, useLicense. Hashes64
lowercase hex; ownerLabel and <=8 unique evidenceRefs use
[A-Za-z0-9][A-Za-z0-9_-]{0,63} with absolute anchors. References are labels only,
not URLs/imported files or independently authenticated evidence. Decisions are
allow/deny/unknown separately for provenance/useLicense. Owner label is not identity
verification. Software license/publication authority is entirely separate.

Parse and check all decision bindings even without --ack-owner-decision. A wrong
dataset/policy/purpose is hard completed REJECT; malformed structure is incomplete.
Without explicit per-invocation acknowledgment, valid owner assertions stay UNKNOWN.
Acknowledged allow yields PASS with basis OWNER_DECISION_ACCEPTED, deny FAIL and
unknown UNKNOWN. Identity/authenticity/legal rights always remain NOT_PROVEN.

Grid/freshness use vendor accepted.jsonl rows only. Quarantine.Record can be
nonnull but never participates. Coverage counts missing declared slots, unexpected
accepted rows, duplicates and nonascending transitions independently, with <=20
generic examples. Coverage PASS means accepted rows exactly match DECLARED_GRID_ONLY;
external/source/market completeness stays NOT_PROVEN. Quarantines independently
make rowQuality FAIL; they are explicitly counted as excluded from accepted coverage.

Freshness uses latest accepted timestamp versus declared asOf. Negative age is
future/FAIL, age greater than threshold stale/FAIL, otherwise PASS. No accepted
timestamp is UNKNOWN. Basis DECLARED_ASOF_ONLY; source freshness/clock accuracy not
proven. Header/framing/empty/no-data failures are incomplete1. A completed
all-quarantined CSV is REJECT2 even with freshness UNKNOWN.

ADMIT/exit0 requires row quality and all four policy axes PASS, correct decision
binding and successful complete report. Known failure gives REJECT/exit2; remaining
UNKNOWN gives HOLD/exit2. Malformed/unsupported/I/O/report failure gives incomplete1.
No owner assertion overrides mechanical failure, quarantine or binding mismatch.
No operation connects/trades/repairs/executes a downstream release or authenticates
data/ownership. Demo exit0 only means its five expected outcomes were observed.

Capture exact input bytes/members, including optional-file absence. Evaluate from
that captured buffer, hash those same bytes, and recheck exact membership/hashes
before final main JSON. Observed late add/remove/change is incomplete1 and cannot
publish final ADMIT. Separate fresh marked output; pending text/JSON and JSON last.
Do not treat vendor private artifacts or pending/missing main report as complete.
No hostile-filesystem atomic snapshot or security-sandbox guarantee.

Main JSON <=128KiB/text <=32KiB; exactly four vendor artifact files with aggregate
<=2MiB and individual caps, verified before final main JSON. See BOUNDS.md. Main
report includes schema/version/build, exact input/policy/optional-decision hashes,
ack/binding/basis, four statuses/counts/asOf/vendor revision and unproven flags.
It excludes raw rows/owner labels/absolute private paths/raw exceptions. Private
CSV artifacts contain parsed input values and must not be published from real data.

Original reusable software MIT; vendored public MIT grants/notices remain.
Public reusable sample, with customer
code/data/config/deployments/secrets/commercial unpublished additions private. No
shared/private/employer source, tests, schemas, contracts or ideas were transferred.
