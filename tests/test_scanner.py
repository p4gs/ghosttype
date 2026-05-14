"""Orchestrator tests: mock the engine boundary so we don't shell out to trufflehog."""
from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ghosttype.models import ConversationRecord, Finding, TextChunk
from ghosttype.scanner import Orchestrator


@pytest.fixture
def mock_scanner(tmp_path):
    src = tmp_path / "session.jsonl"
    src.write_text("x\n")
    rec = ConversationRecord(
        source_path=src,
        tool="fake_tool",
        conversation_id="conv-1",
        created_at=datetime.now(timezone.utc),
        raw={},
    )
    chunk = TextChunk(
        text="GITHUB_TOKEN=ghp_xxx",
        position="line:1",
        record=rec,
    )
    scanner = MagicMock()
    scanner.name = "fake_tool"
    scanner.is_available.return_value = True
    scanner.discover.return_value = [rec]
    scanner.extract_text.return_value = [chunk]
    return scanner, rec


def _make_finding(tool: str, value: str, source_path: Path, verified=False) -> Finding:
    return Finding(
        tool=tool,
        secret_type="github",
        secret_value=value,
        file_path=source_path,
        position="line:1",
        confidence="verified" if verified else "unverified",
        context=value,
        discovered_at=datetime.now(timezone.utc),
        severity="critical" if verified else "high",
        verified=verified,
        detector_name="Github",
    )


def test_orchestrator_runs_available_scanners(mock_scanner):
    scanner, rec = mock_scanner
    expected = _make_finding("fake_tool", "ghp_xxx", rec.source_path, verified=True)
    with patch(
        "ghosttype.scanner.scan_chunks", return_value=[expected]
    ) as engine:
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run()
    engine.assert_called_once()
    assert len(findings) == 1
    assert findings[0].tool == "fake_tool"
    assert findings[0].detector_name == "Github"
    assert findings[0].verified is True


def test_orchestrator_skips_unavailable_scanners(mock_scanner):
    scanner, _ = mock_scanner
    scanner.is_available.return_value = False
    with patch("ghosttype.scanner.scan_chunks") as engine:
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run()
    engine.assert_not_called()
    assert findings == []


def test_orchestrator_deduplicates_same_secret_same_file(mock_scanner):
    scanner, rec = mock_scanner
    finding1 = _make_finding("fake_tool", "ghp_xxx", rec.source_path)
    finding2 = _make_finding("fake_tool", "ghp_xxx", rec.source_path)
    with patch("ghosttype.scanner.scan_chunks", return_value=[finding1, finding2]):
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run()
    assert len(findings) == 1


def test_orchestrator_tool_filter_excludes(mock_scanner):
    scanner, _ = mock_scanner
    with patch("ghosttype.scanner.scan_chunks") as engine:
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run(tool_filter="other_tool")
    engine.assert_not_called()
    assert findings == []


def test_orchestrator_tool_filter_matches(mock_scanner):
    scanner, rec = mock_scanner
    expected = _make_finding("fake_tool", "ghp_xxx", rec.source_path)
    with patch("ghosttype.scanner.scan_chunks", return_value=[expected]):
        orch = Orchestrator(scanners=[scanner])
        findings = orch.run(tool_filter="fake_tool")
    assert len(findings) == 1


def test_orchestrator_passes_verify_flag(mock_scanner):
    scanner, _ = mock_scanner
    with patch("ghosttype.scanner.scan_chunks", return_value=[]) as engine:
        orch = Orchestrator(scanners=[scanner], verify=False, only_verified=True)
        orch.run()
    _, kwargs = engine.call_args
    assert kwargs["verify"] is False
    assert kwargs["only_verified"] is True


def test_orchestrator_max_age_filter(mock_scanner, tmp_path):
    scanner, _ = mock_scanner
    # Replace record with one that's >7 days old
    old_rec = ConversationRecord(
        source_path=tmp_path / "old.jsonl",
        tool="fake_tool",
        conversation_id="old",
        created_at=datetime(2020, 1, 1, tzinfo=timezone.utc),
        raw={},
    )
    (tmp_path / "old.jsonl").write_text("x")
    scanner.discover.return_value = [old_rec]
    with patch("ghosttype.scanner.scan_chunks", return_value=[]) as engine:
        orch = Orchestrator(scanners=[scanner], max_age_days=7)
        orch.run()
    engine.assert_not_called()
