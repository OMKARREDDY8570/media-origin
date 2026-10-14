"""Bounded JSON report serialization."""

from __future__ import annotations

import json
from typing import Any

MAX_EXPORT_BYTES = 1_000_000


def export_json(report: dict[str, Any]) -> bytes:
    """Serialize a report without Telegram identifiers or oversized output."""
    data = json.dumps(report, ensure_ascii=False, indent=2, sort_keys=True).encode("utf-8")
    if len(data) > MAX_EXPORT_BYTES:
        raise ValueError("The JSON report exceeds the export size limit.")
    return data
