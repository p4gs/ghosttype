from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any


@dataclass
class ConversationRecord:
    source_path: Path
    tool: str
    conversation_id: str
    created_at: datetime | None
    raw: Any  # dict or bytes depending on scanner


@dataclass
class TextChunk:
    text: str
    position: str  # "line:N" for JSONL; "<row_key>:<char_offset>" for SQLite
    record: ConversationRecord


@dataclass
class Finding:
    tool: str
    secret_type: str  # detector name lowercased, e.g. "github", "aws"
    secret_value: str
    file_path: Path
    position: str
    confidence: str  # "verified" or "unverified"
    context: str
    discovered_at: datetime
    severity: str = "medium"
    verified: bool = False
    detector_name: str = ""  # raw TruffleHog DetectorName, e.g. "Github"
    verification_error: str | None = None
    extra_data: dict[str, Any] = field(default_factory=dict)
