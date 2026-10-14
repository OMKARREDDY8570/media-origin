"""Evidence-based observations and explicit limitations."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any


def build_observations(metadata: dict[str, Any], c2pa: dict[str, Any]) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    if metadata.get("status") == "NOT DETECTED":
        findings.append(
            {
                "finding": "No common EXIF or XMP metadata was detected.",
                "evidence_source": "Pillow metadata inspection",
                "interpretation": "The file did not expose those metadata fields to this inspection.",
                "limitation": "Metadata can be absent for many benign reasons; this does not prove editing.",
            }
        )
    timestamps = [
        item for item in metadata.get("timestamps", []) if item.get("value") is not None
    ]
    parsed: list[datetime] = []
    for timestamp in timestamps:
        try:
            value = str(timestamp["value"])
            try:
                parsed_value = datetime.fromisoformat(value.replace("Z", "+00:00"))
            except ValueError:
                parsed_value = datetime.strptime(value[:19], "%Y:%m:%d %H:%M:%S")
            offset = timestamp.get("timezone_offset")
            if parsed_value.tzinfo is None and isinstance(offset, str):
                try:
                    parsed_value = datetime.fromisoformat(f"{parsed_value.isoformat()}{offset}")
                except ValueError:
                    pass
            parsed.append(parsed_value)
        except (TypeError, ValueError, KeyError):
            continue
    if len(parsed) > 1 and len({item.tzinfo is not None for item in parsed}) == 1:
        normalized = [
            item.astimezone(timezone.utc) if item.tzinfo else item
            for item in parsed
        ]
        if max(normalized) - min(normalized) > timedelta(days=1):
            findings.append(
                {
                    "finding": "Available metadata timestamps differ by more than one day.",
                    "evidence_source": "Timestamp fields listed in metadata",
                    "interpretation": "The recorded values are not temporally consistent.",
                    "limitation": "Different timestamp fields have different meanings and can be altered; this is not proof of tampering.",
                }
            )
    if c2pa.get("status") == "INVALID":
        findings.append(
            {
                "finding": "The C2PA SDK reported one or more validation errors.",
                "evidence_source": "Official C2PA SDK validation report",
                "interpretation": "Review individual validation issues in the C2PA section.",
                "limitation": "An invalid or untrusted credential does not prove that the image itself is fake.",
            }
        )
    return findings
