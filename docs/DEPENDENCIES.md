# Dependency Map

This document captures adjacent repositories and files relevant to `zkSEC`.

## Primary Relevant Adjacent Repos
1. `/home/c/Documents/code/ITIR-suite`
- Use for canonical chat context ingestion and resolution tooling.

2. `/home/c/Documents/code/zos-server`
- Use for security architecture references and capability-governed controls.

3. `/home/c/Documents/code/zkperf`
- Use for proof/witness and performance-verification patterns.

4. `/home/c/Documents/code/ipfs-dasl`
- Use for differential harness and conformance workflow patterns.

## Additional Relevant Surfaces
- `/home/c/Documents/code/kant-zk-pastebin`
- Relevant to ZOS-related deployment and IPFS-facing workflow integration.

- `/home/c/Documents/code/litellm-config.yaml`
- Relevant only as incident context due to the recent LiteLLM compromise event.
- Treat as a security reference input, not a direct implementation dependency.

## Local Surface Invariants
- This repo is expected to be policy and orchestration oriented only; it is not expected to perform outbound network access.
- Any concrete outbound execution is intentionally outside this surface until an explicit adapter boundary is added.
- Resource handling in the policy surface is read-only metadata validation only.
  A request/resource scope must match adapter-defined roots, and suspicious secret-like
  material in request text is denied before execution can enter readiness.

## Standards and Evidence Mapping
- `docs/GOVERNANCE_ALIGNMENT.md` captures explicit traceability against requested standards and surfaces (ITIL/ISO/NIST/AI RMF/Six Sigma/C4/PlantUML).
- Update this mapping when any milestone adds a new compliance evidence artifact.

## Runtime Trace Reference
- For local verification of syscall/surface behavior (outside this sandbox), use `../zkperf` capture scripts:
  - `scripts/record-language.sh` for strace-perf capture with timing.
  - `scripts/record-http.sh` and `examples/http-witness.sh` for network-focused syscall traces.
- Also use the adjacent zkperf runtime/witness sources as the canonical behavior definitions for these traces:
- `../zkperf/src/witness.rs` (perf+strace parsing and expected syscall profile)
- `../zkperf/src/bin/record.rs` (record pipeline + DA51 shard emission)
- `../zkperf/src/bin/service.rs` (perf attach/detach daemon boundaries)
- `../zkperf/zkperf-witness/src/lib.rs` (perf counter and violation model)
- `../zkperf/docs/RECORDING_TOOLS.md` (trace surface contracts and workflow)
- `../zkperf/docs/NEED_FOR_INTROSPECTION.md` (full witness-layer trace requirements)

## Recent Verified Evidence
- `PYTHONPATH=src strace -f -o /tmp/zksec_pytest_trace_m11.txt -s 2048 -e trace=!network,execve,connect,recvfrom,sendto,openat,open,read,write python -m pytest -q` → `54 passed`.
- `PYTHONPATH=src strace -f -o /tmp/zksec_cli_trace_m11.txt -s 2048 -e trace=!network,execve,connect,recvfrom,sendto,openat,open,read,write python -m zksec.cli --adapter zos_server --action read --actor operator --source managed --risk low --format json` → exits `0` with JSON output.
- `cd ../zkperf && ./scripts/record-http.sh http://example.com /tmp/zkperf_http_example.strace` → network syscalls (`socket`,`connect`,`sendto`,`recvfrom`) observed in `/tmp/zkperf_http_example.strace/http_example.com.strace.log`.

## Actor & Legitimacy Surface Constraints
- Treat all public/externally sourced signals as proposal-only, matching `../ITIR-suite/docs/planning/itir_public_repo_security_discovery_contract_20260407.md`:
  - public findings can trigger follow obligations and triage, not direct remediation.
- Treat action execution lanes as managed/authorized classes only, consistent with
  `../ITIR-suite/docs/planning/itir_windows_compliance_mcp_contract_20260407.md` and
  `../ITIR-suite/docs/planning/itir_linux_compliance_mcp_contract_20260407.md` (if present):
  - target identity must be verified,
  - scope must be authorized,
  - rollback must be known,
  - execution must be receipt-backed.
- Never allow silent authority crossing; keep explicit promotion receipts for any write/authority transfer.
- This includes untrusted or unexpected actor channels: candidate inputs can be surfaced,
  but high-authority state mutations remain blocked until actor legitimacy and receipt
  preconditions pass.
- Model this as a maintainer-vuln prevention check:
  untrusted contributors (or unexpected actor channels) can create candidate surfaces, but cannot alter high-authority state without explicit receipt-bound approval flow.
