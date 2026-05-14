from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from ghosttype.models import ConversationRecord, Finding
from ghosttype.scanners.base import Scanner
from ghosttype.trufflehog_engine import (
    DEFAULT_CONTEXT_WINDOW,
    DEFAULT_TIMEOUT_SECONDS,
    scan_chunks,
)

logger = logging.getLogger(__name__)


class Orchestrator:
    """Discover conversation files via per-tool scanners, then hand the
    extracted text to the TruffleHog engine for detection + verification."""

    def __init__(
        self,
        scanners: list[Scanner] | None = None,
        context_window: int = DEFAULT_CONTEXT_WINDOW,
        max_age_days: int | None = None,
        *,
        verify: bool = True,
        only_verified: bool = False,
        trufflehog_binary: str | None = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        if scanners is None:
            from ghosttype.scanners import SCANNERS
            self._scanners = SCANNERS
        else:
            self._scanners = scanners
        self._context_window = context_window
        self._max_age_days = max_age_days
        self._verify = verify
        self._only_verified = only_verified
        self._trufflehog_binary = trufflehog_binary
        self._timeout = timeout
        self.files_scanned: int = 0

    def run(self, tool_filter: str | None = None) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str, str]] = set()
        self.files_scanned = 0
        cutoff: datetime | None = None
        if self._max_age_days is not None:
            cutoff = datetime.now(timezone.utc) - timedelta(days=self._max_age_days)

        for scanner in self._scanners:
            if tool_filter and scanner.name != tool_filter:
                continue
            if not scanner.is_available():
                continue
            try:
                records: list[ConversationRecord] = scanner.discover()
            except Exception:
                logger.warning(
                    "Scanner %s failed during discover", scanner.name, exc_info=True
                )
                continue

            if cutoff is not None:
                records = [
                    r for r in records if r.created_at is None or r.created_at >= cutoff
                ]
            if not records:
                continue
            self.files_scanned += len({r.source_path for r in records})

            chunks = []
            for record in records:
                try:
                    chunks.extend(scanner.extract_text(record))
                except Exception:
                    logger.warning(
                        "Scanner %s failed extracting %s",
                        scanner.name,
                        record.source_path,
                        exc_info=True,
                    )
                    continue
            if not chunks:
                continue

            scanner_findings = scan_chunks(
                scanner.name,
                chunks,
                verify=self._verify,
                only_verified=self._only_verified,
                binary=self._trufflehog_binary,
                timeout=self._timeout,
                context_window=self._context_window,
            )

            for f in scanner_findings:
                dedup_key = (f.secret_value, str(f.file_path), f.secret_type)
                if dedup_key in seen:
                    continue
                seen.add(dedup_key)
                findings.append(f)

        # verified first, then by detector
        findings.sort(key=lambda f: (0 if f.verified else 1, f.secret_type))
        return findings
