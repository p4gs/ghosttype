import csv
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from ghosttype.models import Finding
from ghosttype.report import copy_sources, write_csv, write_json


@pytest.fixture
def findings(tmp_path):
    src = tmp_path / "session.jsonl"
    src.write_text('{"type":"user","message":{"content":"hi"}}\n')
    now = datetime(2026, 1, 1, 12, 0, 0, tzinfo=timezone.utc)
    return [
        Finding(
            tool="claude_code",
            secret_type="aws",
            secret_value="AKIA00000000000000000",
            file_path=src,
            position="line:1",
            confidence="verified",
            context="key = AKIA00000000000000000",
            discovered_at=now,
            severity="critical",
            verified=True,
            detector_name="AWS",
            extra_data={"resource_type": "Access key"},
        )
    ]


def test_write_json_creates_valid_file(tmp_path, findings):
    out = tmp_path / "findings.json"
    write_json(findings, out, redact=False)
    data = json.loads(out.read_text())
    assert len(data) == 1
    assert data[0]["secret_value"] == "AKIA00000000000000000"
    assert data[0]["tool"] == "claude_code"
    assert data[0]["confidence"] == "verified"
    assert data[0]["verified"] is True
    assert data[0]["detector_name"] == "AWS"
    assert data[0]["extra_data"]["resource_type"] == "Access key"


def test_write_json_redacts_when_requested(tmp_path, findings):
    out = tmp_path / "findings.json"
    write_json(findings, out, redact=True)
    data = json.loads(out.read_text())
    assert data[0]["secret_value"] == "***REDACTED***"


def test_write_csv_redacts_by_default(tmp_path, findings):
    out = tmp_path / "findings.csv"
    write_csv(findings, out, redact=True)
    with out.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["secret_value"] == "***REDACTED***"
    assert rows[0]["tool"] == "claude_code"
    assert rows[0]["verified"] in {"True", "true"}
    assert rows[0]["detector_name"] == "AWS"
    # extra_data is JSON-encoded into one cell
    assert json.loads(rows[0]["extra_data"])["resource_type"] == "Access key"


def test_write_csv_no_redact_shows_value(tmp_path, findings):
    out = tmp_path / "findings.csv"
    write_csv(findings, out, redact=False)
    with out.open(newline="", encoding="utf-8") as fh:
        rows = list(csv.DictReader(fh))
    assert rows[0]["secret_value"] == "AKIA00000000000000000"


def test_copy_sources_copies_jsonl_file(tmp_path, findings):
    sources_dir = tmp_path / "sources"
    copy_sources(findings, sources_dir)
    copied = list((sources_dir / "claude_code").iterdir())
    assert len(copied) == 1
    assert copied[0].suffix == ".jsonl"


def test_copy_sources_deduplicates_same_file(tmp_path, findings):
    doubled = findings + [
        Finding(
            tool=findings[0].tool,
            secret_type="openai",
            secret_value="sk-xxxx",
            file_path=findings[0].file_path,
            position="line:2",
            confidence="unverified",
            context="token = sk-xxxx",
            discovered_at=findings[0].discovered_at,
            verified=False,
            detector_name="OpenAI",
        )
    ]
    sources_dir = tmp_path / "sources"
    copy_sources(doubled, sources_dir)
    copied = list((sources_dir / "claude_code").iterdir())
    assert len(copied) == 1
