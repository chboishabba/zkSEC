# Milestone 15 — ARTEX defensive interoperability and efficacy

Status: planned, 2026-11-24. M14 remains the implemented fixture-backed baseline (41 focused tests and 74 full-suite tests recorded historically; not rerun here).

## Gates
| Gate | Deliverable | Priority | Status |
|---|---|---|---|
| M15-A | Read-only local observation envelope | P0 | Open |
| M15-B | Dual graph normalization and bidirectional source anchors | P0 | Open |
| M15-C | Reuse TraceProposalFact, LinkageWitness and MuExecWitness | P0 | Open |
| M15-D | Independent zkPerf witness correspondence | P0 | Open |
| M15-E | Indexed residual and collision accounting | P0 | Open |
| M15-F | Deterministic invariant and authority evaluation | P0 | Open |
| M15-G | Independent efficacy corpus and comparative evaluation | P0 | Open |
| M15-H | Selective-disclosure receipts | P1 | Open |
| M15-I | SLR/ITIR producer-neutral correspondence | P1 | Open |

Existing producers/consumers: [M14](MILESTONE_14.md), [V1 ingest](producer_contracts/mu_exec_ingest_v1.md), [M12](MILESTONE_12.md), src/zksec/ingest_types.py, build_mu_exec_from_ingest.py, mu_exec.py, admissibility.py, routing.py, reporting.py, adapters/contracts.py. Preserve canonical actor, capability, scope and approval boundaries. ARTEX labels and trace facts are proposals, never authority. IR grounding plus invariant evaluation remains necessary for grounded violations. No new execution or egress adapter.

## Independent efficacy protocol (P0)
Adapt the dual-graph, iterative observation and coverage methodology described in [ARTEX Global](https://github.com/jiwoochris/artex-global/blob/main/README.md#system-architecture) and its [defensive guide](https://github.com/jiwoochris/artex-global/blob/main/docs/defense-en.md). Attribution: upstream ARTEX / Autumn-27 and global edition / jiwoochris, AGPL-3.0. This is methodology reuse, not imported code or a claim of equivalent capability.

Use only offline synthetic fixtures and prerecorded sanitized observations; no autonomous offensive execution, live targets, real credentials or outbound network access. Independent fixture oracle declares expected invariants and labels before evaluation. Freeze corpus, seeds, producer versions, budget and expected outcomes; separate development and held-out sets. Compare fixed baseline, observation-only, witness-only, grounded fusion and full policy evaluation on the same fixtures. Iterative rounds may select additional pre-existing fixture evidence, never execute external tools. Record both graphs, anchors, coverage frontier and unresolved residuals at every round.

Report counts and denominators: true/false positives, true/false negatives, unresolved positives/negatives separately; precision, recall (including unresolved positives in denominator), abstention, coverage, decision latency, witness overhead, reproducibility and evidence completeness. Undefined ratios remain undefined. Compare paired cases and report uncertainty; no superiority claim without measured results. Include benign matched controls, missing/conflicting/duplicate evidence, stale timestamps, invalid commitments, identity ambiguity, and unsupported authority assertions. Mandatory acceptance: zero unauthorized promotions, no network/process execution introduced into zkSEC, deterministic replay, no silent residual deletion, and no false claims of complete coverage. Detection accuracy targets to be preregistered before held-out evaluation.

Observer collisions: if O(s1)=O(s2) for different oracle labels, test whether independent W separates the pair; if not, preserve unresolved. Report collision counts before/after fusion rather than assuming additional telemetry implies knowledge. H(t,k) retains asset identities, events, witnesses, grounding and residuals; t denotes source time, k refinement round, distinct from ingest time. Signed verdict -1 violation, 0 unresolved, +1 admissible applies only to a named invariant and scope; retain typed zero reasons. A proof over a commitment does not prove capture authenticity or completeness.

## Companion roadmap
[zkPerf witness efficacy roadmap](https://github.com/chboishabba/zkperf/blob/docs/artex-defensive-efficacy-20261124/docs/ARTEX_DEFENSIVE_EFFICACY.md). Deliver local import schema, versioned fixtures, paired benchmark receipts and limitations report. No implementation or acceptance run claimed by this roadmap.
