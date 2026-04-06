# zkSEC

`zkSEC` is initialized as a local workspace for security-oriented architecture and implementation work.

## Operating Rules
- Start from canonical context (`COMPACTIFIED_CONTEXT.md`) before major decisions.
- Keep one canonical chat archive at `/home/c/chat_archive.sqlite`.
- Use the workflow: Docs -> TODO -> Code -> Changelog.

## Relevant Adjacent Surfaces
- `../ITIR-suite`
- `../zos-server`
- `../zkperf`
- `../ipfs-dasl`
- `../kant-zk-pastebin` (relevant to ZOS-related flows)
- `../litellm-config.yaml` (incident-context relevance only, due to recent LiteLLM hack)

See `docs/DEPENDENCIES.md` for details.

## Current Status
- Repository initialized on 2026-04-07.
- Initial context pulled from ChatGPT thread: `LiteLLM hack analysis`.
- Milestone 01 scaffold defined in `docs/MILESTONE_01.md`.
- Milestones 02 and 03 complete: security gate, adapter contracts, and adapter-aware routing.
- Milestones 04 and 05 now in place: execution directives and deterministic reporting.
- Milestone 06 in place: CLI flow and integration harness.
