# `mu_exec` Ingest V1

## Scope

This contract pins the first live producer slice for `mu_exec` ingest.

- `zkperf` is the proposal producer.
- `ghidra` is the grounding producer.
- `mu_exec` is the first admissibility-bearing object.

Trace does not emit violations. Grounding does not emit runtime claims.
Invariant evaluation is the only step that may promote a grounded witness into
an execution-law failure.

## Producer Envelopes

### Trace Proposal Fact

`TraceProposalFact` records one observed execution fact and stays
proposal-only.

- Canonical identity: `fact_id`
- Runtime lineage: `run_id`, `t_index`, `pid`, `tid`
- Observed operation: `actor`, `op`, `obj_hint`
- Scalar payload: `value_int`, `value_str`
- Evidence only: `quals`, `provenance`

Forbidden at this layer:

- vulnerability labels
- severity claims
- authority conclusions

### IR Grounding Fact

`IRGroundingFact` records grounded object semantics from a Ghidra-derived IR
slice.

- Canonical identity: `fact_id`, `obj_id`
- Grounded semantics: `obj_kind`, `capacity`, `field_offset`, `field_width`
- Lifetime grounding: `lifetime_kind`
- Boundary grounding: `authority_kind`, `carrier_kind`
- Evidence only: `aliases`, `provenance`

## Linkage Rule

`LinkageWitness` is the seam between proposal and grounding.

- Trace proposes object lineage.
- IR grounds object semantics.
- `mu` exists only when the linkage scores clear threshold and at least one
  invariant family is derivable.

Current invariant families:

- `buffer_extent`
- `lifetime`
- `authority_boundary`

## Identity Rule

- Canonical IDs are stable ingest identities.
- Provenance fields are append-only receipts backing those identities.
- Provenance is not the semantic identity layer.

## Current Fixture Pair

- [Trace fixture](../../tests/fixtures/zkperf_trace_min.json)
- [Grounding fixture](../../tests/fixtures/ghidra_grounding_min.json)

These fixtures pin the first `alloc -> free -> read` slice with enough IR
grounding to derive extent, lifetime, and authority-boundary families.
