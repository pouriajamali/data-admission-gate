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

## Unreleased preview.2 human explanation and literal oracle — partial local validation

The unreleased source changes human text; the decision combiner and JSON v1 remain unchanged.
After the existing overall status line, `summary.txt` adds exactly five lines in
rowQuality, coverage, freshness, provenance, useLicense order:

```text
<axis> <Status>; basis <Basis>; reason <Reason>
```

It then adds the following context and scope lines, retaining every existing
caution. Numbers use invariant decimal formatting; an absent latest accepted
timestamp is `NONE` and an unknown age is `UNKNOWN`. The context comes only from
the already evaluated accepted rows and explicit policy, never the current clock.

```text
Freshness context: asOf <AsOf>; latestAccepted <LatestAccepted-or-NONE>; ageSeconds <AgeSeconds-or-UNKNOWN>; thresholdSeconds <ThresholdSeconds>
Decision meaning: offline policy only; PASS is not authenticity, legal-rights or actual-source-freshness proof.
```

The independent four-case oracle's exact UTF8 input files end with one LF, no BOM:

```text
timestamp,open,high,low,close,volume
2026-01-01T00:02:00Z,100.00,102.00,99.00,101.00,5
```

```json
{"schema":"data-admission-policy-v1","profile":"admission-ohlc-csv-v1","purpose":"offline-analysis","asOf":"2026-01-01T00:03:00Z","maxAgeSeconds":60,"expectedTimestamps":["2026-01-01T00:02:00Z"]}
```

Each well-formed owner-decision-v1 assertion binds the independently SHA256-hashed
CSV/policy bytes and offline-analysis purpose. `ORACLE_SYNTHETIC_OWNER` and
`LABEL_ONLY_NOT_AUTHENTICATED` are invented labels, not identity or evidence proof.
Every vector expects rowQuality/coverage/freshness PASS, one accepted/expected row,
no quarantines or grid discrepancies, age60 and threshold60, and a binding match.

| Case | provenance / useLicense | ACK | Expected owner statuses | Outcome / exit |
|---|---|---|---|---|
| ORACLE-01 | unknown / allow | yes | UNKNOWN / PASS | HOLD / 2 |
| ORACLE-02 | allow / allow | yes | PASS / PASS | ADMIT / 0 |
| ORACLE-03 | allow / unknown | yes | PASS / UNKNOWN | HOLD / 2 |
| ORACLE-04 | exact ORACLE-02 bytes | no | UNKNOWN / UNKNOWN | HOLD / 2 |

Acknowledged owner axes retain basis OWNER_DECISION_ACCEPTED with the respective
OWNER_ASSERTION_UNKNOWN/OWNER_ASSERTION_ALLOW reason. Case04 instead expects basis
UNACKNOWLEDGED_OWNER_ASSERTION and EXPLICIT_ACK_REQUIRED for both owner axes. All
identity/authenticity/legalRights/externalCompleteness/actualSourceFreshness and
clockAccuracy fields stay NOT_PROVEN; csvSourceProvenance stays UNVERIFIED, even
when policy outcome is ADMIT. These are policy outcomes, never aggregate PASS.

The oracle compares literal outcomes, axis values/reasons, historical context and
full text against actual CLI output and the saved JSON. It also checks exact
input-byte/member preservation, no pending final report and existing byte caps.
The extracted-package counterexample separately supplies its own literal input
and checks HOLD with an unknown provenance axis despite four other axes PASS.
All four CLI oracle cases passed on the observed Windows and Ubuntu/WSL hosts.
The full suites observed Windows107pass/0fail/2skip and, on 2026-11-12,
Linux109pass/0fail/0skip. The complete unchanged Linux suite used an approved
native-filesystem FIFO fixture with actual SDK-child cgroup membership, bounded
resources, verified evidence export and owned cleanup. The extracted-package
counterexample belongs to the separate17-check extracted-archive acceptance suite.
Application source tests do not establish archive acceptance, clean-OS
compatibility or security certification. Build-time actionlint now has local
source/binary admission,150 optimized-mode rejections and both native
valid/invalid/default/direct controls; public distribution and CI remain separate.
See [ACTIONLINT-BUILD.md](ACTIONLINT-BUILD.md) and README for the tooling boundary.
