# Milestone 07: No-Syscall Surface Verification

## Objective
Add a hard local verification step that enforces zkSEC's decision surface does not import or invoke common outbound-network/process APIs.

## Concrete Files
- `tests/test_syscall_guard.py`
- `docs/DEPENDENCIES.md`
- `docs/MILESTONE_07.md`
- `TODO.md`
- `CHANGELOG.md`

## Design
- Keep enforcement as static analysis over source files to avoid needing ptrace/strace in the current CI sandbox.
- For runtime deep verification, reference `../zkperf` scripts that capture `strace` network traces
  (`scripts/record-language.sh`, `scripts/record-http.sh`) as external validation mode.
- For adjacent zkperf behavior grounding, also reference the adjacent witness runtime source:
  - `../zkperf/src/witness.rs` and `../zkperf/src/bin/record.rs` define the trace
    ingestion and witness generation contract.
  - `../zkperf/src/bin/service.rs` and `../zkperf/zkperf-witness/src/lib.rs` define
    boundary instrumentation, allowed syscall/context constraints, and violation logic.

## Acceptance Checks
1. New test rejects `socket`/`requests`/`urllib`/`subprocess`/`os.system` style imports in `src/zksec`.
2. New test rejects direct calls to known process/network APIs in expression form.
3. `docs/DEPENDENCIES.md` references `../zkperf` trace scripts as the strace/network observability path.
4. Changelog records the added verification layer.

## Runtime Evidence (Manual Check)
- `PYTHONPATH=src strace -f -o /tmp/zksec_pytest_trace_m11.txt -s 2048 -e trace=!network,execve,connect,recvfrom,sendto,openat,open,read,write python -m pytest -q`
- Result: `54 passed` for the full test suite.
  - Key lines: only `execve` entries from interpreter launch resolution; no `socket`, `connect`, `sendto`, `sendmsg`, or `recvfrom`.
- `PYTHONPATH=src strace -f -o /tmp/zksec_cli_trace_m11.txt -s 2048 -e trace=!network,execve,connect,recvfrom,sendto,openat,open,read,write python -m zksec.cli --adapter zos_server --action read --actor operator --source managed --risk low --format json`
  - Result: CLI exits with status `0` and JSON output.
  - Trace contains no network/process signatures beyond startup `execve`.
- `cd ../zkperf && ./scripts/record-http.sh http://example.com /tmp/zkperf_http_example.strace && ls /tmp/zkperf_http_example.strace/http_example.com.strace.log`
  - Result: explicit network syscalls observed (`socket`, `connect`, `sendto`, `recvfrom`), with evidence collected in `/tmp/zkperf_http_example.strace/http_example.com.strace.log`.
- `scripts/record-http.sh` and `scripts/record-language.sh` are used as the zkperf entry points for witness-style captures; depending on invocation they write logs to script-chosen output directories (for example `/tmp/zkperf_http_example.strace`).
- Relevant adjacent zkperf evidence artifacts:
  - `../zkperf/docs/RECORDING_TOOLS.md` and `../zkperf/README.md` for workflow mapping.
  - `../zkperf/docs/NEED_FOR_INTROSPECTION.md` for full-chain trace/layer requirements.
  - `/tmp/zkperf_http_example.strace/http_example.com.strace.log` for explicit network syscall witnesses.
- Trace artifacts captured at runtime on 2026-04-07:
- `/tmp/zksec_pytest_trace_m11.txt`
- `/tmp/zksec_cli_trace_m11.txt`
- `/tmp/zkperf_http_example.strace/http_example.com.strace.log`
