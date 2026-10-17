# DA51 evidence boundary in zkSEC

`zkSEC` consumes the shared DA51 `0xDA51 [16|4|44]` address ABI. The normative formal owner is `dashi_lean4/DA51/Core.lean`; `zkSEC` is a security-boundary consumer, not an ABI authority.

Type 8 (`atlasEntry`) uses `[level:4][biome:4][status:4][serial:12][reserved:20]`. `src/zksec/da51.py` validates the address and atlas fields. `src/zksec/da51_provenance.py` adds the producer-owned artifact envelope.

Three layers remain distinct:

1. DA51 address identity;
2. type-specific data semantics;
3. producer/artifact provenance.

The optional `FormalRuntimeEvidenceLink` adds cross-system provenance coordinates such as formal demand, proof obligation, statement digest, and artifact revision. Those fields are joins only. They do not import theorem authority or produce a security result.

```text
DA51 identity/status
  + optional formal demand/evidence refs
  + optional zkperf/eBPF/runtime evidence
  -> security-input provenance
  -> existing zkSEC grounding/linkage/invariant logic
  -> only then a separately justified security conclusion may exist
```

The following implications are forbidden:

```text
DA51 status/address != vulnerability
formal theorem/proof link != vulnerability
formal theorem/proof link != security severity
zkperf trace/benchmark != exploitability
runtime/eBPF observation != security conclusion
artifact/CID/URI != security authority
provenance link != authorization
```

None of these layers alone grants vulnerability, severity, exploitability, authorization, admissibility, theorem truth, literature authority or ZK validity. The existing zkSEC grounding/linkage/invariant path remains the only path that can promote proposal evidence into a security conclusion.

`fixtures/da51_v1.json` pins all 23 atlas addresses, decoded vectors, malformed cases and the identity/provenance/authority separation contract shared with `dashi_lean4`, `dashi_agda` and `zkperf`.
