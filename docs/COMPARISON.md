# Existing baselines and the small extension

Reviewed2026-11-07, documentation/source only; no competitor install, integration
test, benchmark, exhaustive feature-absence audit or novelty/demand claim.

[GX validation definitions, observed docs1.24.1](https://docs.greatexpectations.io/docs/core/run_validations/create_a_validation_definition/)
associate data batch definitions with expectation suites and run validations.
Data expectations and validation orchestration are established capabilities.

[Soda Core v4, pinned official README](https://github.com/sodadata/soda-core/blob/1aa894651be90bd6996284fdb398bd4b9ec39d47/README.md)
describes YAML schema/data contracts with CLI/Python verification locally or in
pipelines and optional cloud integration. Its [current docs home](https://docs.soda.io/)
also describes contracts and source/target data reconciliation. Legacy v3 search
pages were not treated as the current baseline. Some deeper docs were unavailable
through the reader; this is not proof any capability is absent.

[Integrity Lab, pinned public revision](https://github.com/pouriajamali/market-data-integrity-lab/tree/eecf14a1fdeecedb55ceb6c4947ac57e70bd4a41)
already implements the exact offline OHLC CSV checks, quarantines and raw input
hash binding used here. Its CSV provenance is UNVERIFIED and ordering/dedup/
completeness are NOT_CHECKED. Separate sequence/recovery experiments are not
actual market/source completeness certificates.

A new generic quality engine would overlap. This companion therefore reuses four
unmodified public CSV/hash/reader files and adds a small explicit admission record:
declared grid/asOf checks, separate UNKNOWN/owner-assertion decisions, exact byte/
purpose binding, negative outcomes and ready .NET bundles. It does not claim GX or
Soda cannot express these rules, or to invent quality, contracts or freshness.
No existing Integrity repository/release is modified by this isolated prototype.
