"""Readable Telegram text report formatting."""

from __future__ import annotations

import json
from typing import Any


TELEGRAM_SAFE_MESSAGE_LENGTH = 3_800


def _display(value: Any, absent: str = "Not present") -> str:
    if value is None or value == "" or value == [] or value == {}:
        return absent
    if isinstance(value, dict):
        text = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    elif isinstance(value, list):
        text = json.dumps(value, ensure_ascii=True, separators=(",", ":"))
    else:
        text = str(value)
    text = text.replace("\n", " ").replace("\r", " ")
    return "".join(character if ord(character) >= 32 else " " for character in text)[:500]


def _format_dimensions(value: Any) -> str:
    if isinstance(value, (list, tuple)) and len(value) == 2:
        return f"{_display(value[0])} x {_display(value[1])}"
    return _display(value)


def _format_software(software: Any) -> str:
    if not isinstance(software, list):
        return _display(software)
    entries = []
    for item in software[:5]:
        if isinstance(item, dict):
            source = item.get("source", "Declared")
            value = item.get("value")
            if value is not None:
                entries.append(f"{source}: {_display(value)}")
    return "; ".join(entries) if entries else "Not present"


def _format_timestamps(timestamps: Any) -> str:
    if not isinstance(timestamps, list):
        return _display(timestamps)
    entries = []
    for item in timestamps[:8]:
        if isinstance(item, dict):
            source = item.get("source", "Timestamp")
            value = item.get("value")
            offset = item.get("timezone_offset")
            if value is not None:
                suffix = f" {offset}" if offset else ""
                entries.append(f"{source}: {_display(value)}{suffix}")
    return "; ".join(entries) if entries else "Not present"


def _format_gps(gps: Any) -> str:
    if not isinstance(gps, dict):
        return _display(gps, "Not detected")
    coordinates = gps.get("coordinates")
    if isinstance(coordinates, dict):
        latitude = coordinates.get("latitude")
        longitude = coordinates.get("longitude")
        if latitude is not None and longitude is not None:
            result = f"{latitude}, {longitude}"
            if gps.get("altitude_meters") is not None:
                result += f" (altitude {gps['altitude_meters']} m)"
            return result
    if gps.get("parse_error"):
        return "Present, but coordinates could not be decoded"
    return "Present, coordinates unavailable" if gps.get("status") == "PRESENT" else "Not detected"


def _format_assertions(assertions: Any) -> str:
    if not isinstance(assertions, list):
        return _display(assertions)
    descriptions = []
    for assertion in assertions:
        if not isinstance(assertion, dict):
            continue
        data = assertion.get("data")
        actions = data.get("actions") if isinstance(data, dict) else None
        if not isinstance(actions, list):
            label = assertion.get("label")
            if label:
                descriptions.append(str(label))
            continue
        for action in actions[:8]:
            if not isinstance(action, dict):
                continue
            description = str(action.get("action", assertion.get("label", "Action")))
            when = action.get("when")
            agent = action.get("softwareAgent")
            if when:
                description += f" at {when}"
            if isinstance(agent, dict) and agent.get("name"):
                description += f" ({agent['name']}"
                if agent.get("version"):
                    description += f" {agent['version']}"
                description += ")"
            if action.get("digitalSourceType"):
                description += f"; source type {action['digitalSourceType']}"
            descriptions.append(description)
    return "; ".join(descriptions[:8]) if descriptions else "Not present"


def _format_validation(c2pa: dict[str, Any]) -> str:
    failures = c2pa.get("validation_issues", [])
    successes = c2pa.get("validation_successes", [])
    informational = c2pa.get("validation_informational", [])
    counts = []
    if successes:
        counts.append(f"{len(successes)} successful")
    if failures:
        counts.append(f"{len(failures)} failed")
    if informational:
        counts.append(f"{len(informational)} informational")
    if not counts:
        return "Not reported" if c2pa.get("status") != "NOT DETECTED" else "None reported"
    summary = ", ".join(counts)
    codes = [
        item["code"]
        for item in failures[:5]
        if isinstance(item, dict) and isinstance(item.get("code"), str)
    ]
    if codes:
        summary += "; failures: " + ", ".join(codes)
    return summary


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
        f"Dimensions: {_format_dimensions(file_info.get('dimensions'))}",
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
        f"Declared software: {_format_software(metadata.get('software'))}",
        f"Recorded actions: {_format_assertions(c2pa.get('assertions'))}",
        f"Validation results: {_format_validation(c2pa)}",
        "",
        "METADATA",
        f"Capture/metadata timestamps: {_format_timestamps(metadata.get('timestamps'))}",
        f"Camera make/model: {_display(metadata.get('make'))} / {_display(metadata.get('model'))}",
        f"Lens: {_display(metadata.get('lens'))}",
        f"GPS: {_format_gps(metadata.get('gps'))}",
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
