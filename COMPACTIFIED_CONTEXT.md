# COMPACTIFIED_CONTEXT

Last updated: 2026-04-07 (Australia/Brisbane)

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
