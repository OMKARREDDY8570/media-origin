"""Readable Telegram text report formatting."""

from __future__ import annotations

from typing import Any


TELEGRAM_SAFE_MESSAGE_LENGTH = 3_800


def _display(value: Any, absent: str = "Not present") -> str:
    if value is None or value == "" or value == [] or value == {}:
        return absent
    text = str(value).replace("\n", " ").replace("\r", " ")
    return "".join(character if ord(character) >= 32 else " " for character in text)[:500]


def build_report(report: dict[str, Any]) -> list[str]:
    file_info = report["file"]
    metadata = report["metadata"]
    c2pa = report["c2pa"]
    lines = [
        "ORIGINTRACE",
        "IMAGE FORENSICS REPORT",
        "",
        "FILE SUMMARY",
        f"Filename: {_display(file_info.get('filename'))}",
        f"Detected format: {_display(file_info.get('format'))}",
        f"Dimensions: {_display(file_info.get('dimensions'))}",
        f"Color mode: {_display(file_info.get('color_mode'))}",
        f"File size: {_display(file_info.get('size_bytes'))} bytes",
        f"SHA-256: {_display(file_info.get('sha256'))}",
        "",
        "PROVENANCE",
        f"C2PA status: {_display(c2pa.get('status'), 'Unavailable')}",
        f"Manifest: {_display(c2pa.get('active_manifest'))}",
        f"Signing issuer: {_display(c2pa.get('signature_issuer'))}",
        f"Signing timestamp: {_display(c2pa.get('signature_timestamp'))}",
        f"Signature integrity: {_display(c2pa.get('signature_integrity'), 'Not verified')}",
        f"Certificate trust: {_display(c2pa.get('certificate_trust'), 'Not verified')}",
        f"Signer identity: {_display(c2pa.get('signer_identity'), 'Not verified')}",
        f"Manifest software: {_display(c2pa.get('claim_generator'))}",
        f"Declared software: {_display(metadata.get('software'))}",
        f"Recorded actions: {_display(c2pa.get('assertions'))}",
        f"Validation issues: {_display(c2pa.get('validation_issues'), 'None reported')}",
        "",
        "METADATA",
        f"Capture/metadata timestamps: {_display(metadata.get('timestamps'))}",
        f"Camera make/model: {_display(metadata.get('make'))} / {_display(metadata.get('model'))}",
        f"Lens: {_display(metadata.get('lens'))}",
        f"GPS: {_display(metadata.get('gps'), 'Not detected')}",
        f"Metadata inspection: {_display(metadata.get('status'))}",
        "",
        "FORENSIC OBSERVATIONS",
    ]
    observations = report.get("observations", [])
    if not observations:
        lines.append("No specific inconsistencies were detected by the available checks.")
    warnings = metadata.get("warnings", [])
    if warnings:
        lines.extend(f"- Inspection limitation: {_display(warning)}" for warning in warnings[:5])
    for finding in observations[:10]:
        lines.extend(
            [
                f"- {finding.get('finding', 'Observation')}",
                f"  Evidence: {finding.get('evidence_source', 'Not specified')}",
                f"  Limitation: {finding.get('limitation', 'Interpret cautiously.')}",
            ]
        )
    lines.extend(
        [
            "",
            "ASSESSMENT",
            "Known: the file properties and metadata shown above were observed in the submitted bytes.",
            "Unknown: whether metadata is complete or historically accurate, and whether an untrusted issuer is who they claim to be.",
            "Cannot conclude: whether the image is real, fake, edited, or AI-generated from these checks alone.",
            f"Report generated: {_display(report.get('analysis_timestamp'))}",
            f"Analysis version: {_display(report.get('application', {}).get('version'))}",
        ]
    )
    return _split_lines(lines, TELEGRAM_SAFE_MESSAGE_LENGTH)


def _split_lines(lines: list[str], limit: int) -> list[str]:
    chunks: list[str] = []
    current = ""
    for line in lines:
        candidate = f"{current}\n{line}" if current else line
        if len(candidate) > limit and current:
            chunks.append(current)
            current = line
        else:
            current = candidate
        while len(current) > limit:
            chunks.append(current[:limit])
            current = current[limit:]
    if current:
        chunks.append(current)
    return chunks
