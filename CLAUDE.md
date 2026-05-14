# CLAUDE.md — AI-Assisted Development Guide

Context for AI coding assistants (Claude Code, Cursor, Copilot, etc.) working on ghosttype.

## What this project is

ghosttype is a local forensic scanner for authorized red team and DLP use. It finds AI tool conversation files on macOS, hands the extracted text to TruffleHog for detection + live verification, and writes a structured report (JSON + CSV) with each finding linked to its source file.

Authorized use only. See THREAT-MODEL.md.

## Architecture in 30 seconds

Plugin-style discovery + TruffleHog subprocess for detection/verification. One Python module per target AI tool implements the `Scanner` ABC. The orchestrator collects extracted text chunks and passes them to `trufflehog_engine.scan_chunks`, which shells out to the real TruffleHog binary in `filesystem` mode and parses NDJSON results back into `Finding`s. Click CLI on top.

```
ghosttype/
├── cli.py                 # click CLI - all user-facing flags
├── scanner.py             # Orchestrator - wires scanners → engine → findings
├── trufflehog_engine.py   # TruffleHog subprocess wrapper (NEW in 0.3.0)
├── models.py              # dataclasses: ConversationRecord, TextChunk, Finding
├── report.py              # write_json, write_csv, copy_sources
└── scanners/
    ├── base.py            # Scanner ABC with _base_path @abstractmethod
    ├── claude_code.py     # ~/.claude/projects/ JSONL + history + tasks
    ├── cursor.py          # SQLite state.vscdb (global + workspace storage)
    ├── codex.py           # ~/.codex/ SQLite
    ├── chatgpt.py         # AES-128-CBC .data files (Keychain-backed)
    └── claude.py          # Stub - pending storage format research
```

## Key conventions

- Python 3.11+, Black (88 cols)
- Type hints throughout; dataclasses for data models
- Always activate `.venv` before running Python: `source .venv/bin/activate && ...`
- No hardcoded paths — use `pathlib.Path` and `Path.home()`
- TruffleHog is the source of truth for what counts as a credential. If a credential type isn't detected, upgrade TruffleHog; do NOT re-add an in-tree pattern catalog.
- The engine layer is pure-ish (only I/O is the subprocess + temp dir); independently testable with `subprocess.run` mocked
- Tests go in `tests/` mirroring the package structure
- Fixtures in `tests/fixtures/` — never use real credentials. Use obviously fake patterns that nevertheless pass TruffleHog's entropy filter (e.g. mixed-case ASCII).

## What to read before changing specific areas

- **Adding a scanner:** ARCHITECTURE.md (Scanner interface), RESEARCH.md (storage locations)
- **Engine internals:** ARCHITECTURE.md (TruffleHog engine section), `ghosttype/trufflehog_engine.py`. NDJSON shape: `{SourceMetadata.Data.Filesystem.{file,line}, DetectorName, Verified, Raw, RawV2, ExtraData, VerificationError?}`.
- **Output format:** `ghosttype/report.py` — `_FIELDS` list, `_finding_to_dict()`
- **CLI flags:** `ghosttype/cli.py` — all options are on the `scan()` function

## Don't

- Don't add regex patterns to ghosttype. The engine is TruffleHog. If verification matters, the detector belongs in TruffleHog upstream.
- Don't silently fall back to regex-only if TruffleHog is missing. Fail loudly with the install URL.
- Don't ship any code that hits a network endpoint other than via the TruffleHog subprocess. ghosttype itself does no network I/O.

## Current state

v0.3.0. 76 tests. Run `ghosttype doctor` to confirm TruffleHog is wired up. Run `ghosttype scan --no-verification --output -` for a fast offline sanity check.
