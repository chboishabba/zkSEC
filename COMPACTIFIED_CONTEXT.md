# COMPACTIFIED_CONTEXT

Last updated: 2026-04-19 (Australia/Brisbane)

## Resolved Chat Context
- Title: LiteLLM hack analysis
- Online UUID: 69ce0ac6-dd2c-839f-8b84-a0d397285f90
- Canonical thread ID: 130c635a73d780dfb0552107cc0a77a77d4cfea9
- Source used: db (after direct online UUID pull into canonical archive)
- Canonical DB: /home/c/chat_archive.sqlite
- Decision reason: db_match_found

## Main Topics / Decisions Pulled
- Security posture should be capability-governed, not only transform-governed.
- Default architecture direction should be local-first and sandboxed.
- Remote intelligence usage should be reduced, bounded, and privacy-preserving.
- Tooling and action execution should be confirmation-gated and least-privilege.

## Additional Resolved Chat Context
- Title: Language Model Security
- Online UUID: 69e43a82-9fc0-839f-a022-cbf28c6c6a5f
- Canonical thread ID: a70ae3942d8e8f440ec62db62464775e8979d6c4
- Source used: db (after direct online UUID pull into canonical archive)
- Canonical DB: /home/c/chat_archive.sqlite
- Decision reason: db_match_found (title_exact after UUID ingest)

## Main Topics / Decisions Pulled From Language Model Security
- `trace`, `zkperf`, and `strace` are proposal-only evidence surfaces and do not
  by themselves constitute a verified violation.
- `IR` and binary semantics are the grounding layer that materializes `mu_exec`
  as a concrete execution interaction witness.
- Security violations should be derived from invariant failure over grounded
  `mu_exec`, rather than from hand-written vulnerability labels.
- A normalized zkSEC stack should read:
  `code/binary/trace -> Phi_exec -> mu_exec -> epsilon_exec -> kappa_sec -> Admk_sec -> vulnerability witness`.
- The refreshed thread now sharpens the next milestone from generic grounding
  into a concrete `mu_exec` extractor pipeline: `ghidra + trace`, where trace
  proposes candidate links, IR grounds the materialized witness, and invariant
  evaluation is the point where a violation becomes real.
- The extractor output should be a deterministic stream of grounded execution
  interaction witnesses rather than vulnerability labels, with unresolved links
  staying unresolved instead of being force-classified.

## Adjacent Relevance Decisions
- Primary relevant repos confirmed: `../ITIR-suite`, `../zos-server`, `../zkperf`, `../ipfs-dasl`.
- Additional relevant surface confirmed: `../kant-zk-pastebin` (ZOS-related deployment/IPFS flows).
- `../litellm-config.yaml` is treated as incident-context input only, based on the recent LiteLLM compromise discussion.

## Security Baseline Alignment from ITIR
- Informed by `ITIR-suite` public discovery contract: public discovery may propose risk only, but cannot authorize remediation by itself.
- Consequential action must pass explicit managed-host controls.
- Security controls should preserve provenance and reason-code based receipts.

## Adapter-Routing Baseline
- Added bounded routing for adjacent adapters.
- Adapter action execution now requires both policy gate and adapter contract permission.
- Known contracts are currently `../zos-server` and `../kant-zk-pastebin`.
- Added execution directive conversion and deterministic reporting as Milestone 04/05.
- Added CLI entrypoint and integration harness as Milestone 06.

## Local Repo Intent
- Initialize this repository as the working area for `zkSEC`.
- Keep context synchronized with canonical chat metadata before design or implementation changes.
- Follow strict sequencing: Docs -> TODO -> Code -> Changelog.
- Use Milestone 13 as the completed witness-boundary checkpoint.
- Use Milestone 14 to design and stage the concrete `mu_exec` extractor
  pipeline around `ghidra + trace` proposal/grounding separation before adding
  real local extractor ingestion.
