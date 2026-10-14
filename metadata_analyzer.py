"""Best-effort local metadata extraction for supported raster images."""

from __future__ import annotations

import json
import logging
import shutil
import subprocess
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from PIL import Image, ExifTags

logger = logging.getLogger(__name__)
MAX_METADATA_FIELDS = 100
MAX_METADATA_VALUE_LENGTH = 2_000
SENSITIVE_TAG_PARTS = (
    "serialnumber",
    "bodyserialnumber",
    "cameraowner",
    "ownername",
    "artist",
    "byline",
    "copyright",
    "usercomment",
    "imageuniqueid",
    "contact",
)

EXIF_NAMES = {tag_id: name for tag_id, name in ExifTags.TAGS.items()}
GPS_NAMES = {tag_id: name for tag_id, name in ExifTags.GPSTAGS.items()}


def _safe_value(value: Any) -> Any:
    if isinstance(value, bytes):
        return value[:256].hex()
    if isinstance(value, dict):
        return {
            str(key)[:100]: _safe_value(item)
            for key, item in list(value.items())[:MAX_METADATA_FIELDS]
            if not any(part in str(key).lower().replace(" ", "") for part in SENSITIVE_TAG_PARTS)
        }
    if isinstance(value, (list, tuple)):
        return [_safe_value(item) for item in list(value)[:MAX_METADATA_FIELDS]]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value[:MAX_METADATA_VALUE_LENGTH] if isinstance(value, str) else value
    return str(value)[:MAX_METADATA_VALUE_LENGTH]


def _dms_to_degrees(value: Any, reference: Any) -> float | None:
    try:
        degrees, minutes, seconds = (float(part) for part in value)
        result = degrees + minutes / 60 + seconds / 3600
        if str(reference).upper() in ("S", "W"):
            result *= -1
        return round(result, 7)
    except (TypeError, ValueError, ZeroDivisionError):
        return None


def _extract_exif(exif: Any) -> tuple[dict[str, Any], dict[str, Any]]:
    fields: dict[str, Any] = {}
    gps: dict[str, Any] = {}
    for tag_id, value in exif.items():
        name = EXIF_NAMES.get(tag_id, f"Tag_{tag_id}")
        if name == "GPSInfo":
            try:
                raw_gps = value
                if hasattr(value, "items"):
                    gps_tags = {
                        GPS_NAMES.get(key, str(key)): item for key, item in value.items()
                    }
                else:
                    gps_tags = {}
                latitude = _dms_to_degrees(
                    gps_tags.get("GPSLatitude"), gps_tags.get("GPSLatitudeRef")
                )
                longitude = _dms_to_degrees(
                    gps_tags.get("GPSLongitude"), gps_tags.get("GPSLongitudeRef")
                )
                if latitude is not None and longitude is not None:
                    gps["coordinates"] = {"latitude": latitude, "longitude": longitude}
                gps["fields"] = _safe_value(gps_tags)
                if not gps_tags and raw_gps is not None:
                    gps["fields"] = _safe_value(raw_gps)
            except (TypeError, ValueError):
                gps["parse_error"] = "GPS metadata could not be decoded."
        else:
            if not any(part in name.lower().replace(" ", "") for part in SENSITIVE_TAG_PARTS):
                fields[name] = _safe_value(value)
    return fields, gps


def _parse_xmp(raw: Any) -> dict[str, Any]:
    if isinstance(raw, bytes):
        raw = raw[:256_000].decode("utf-8", errors="replace")
    if not isinstance(raw, str) or not raw.strip():
        return {}
    try:
        root = ET.fromstring(raw[:256_000])
    except ET.ParseError:
        return {"parse_error": "XMP data was present but malformed."}
    result: dict[str, Any] = {}
    parents = {child: parent for parent in root.iter() for child in parent}
    for element in root.iter():
        local_name = element.tag.rsplit("}", 1)[-1]
        normalized_name = local_name.lower().replace(" ", "")
        ancestors = []
        parent = parents.get(element)
        while parent is not None:
            ancestors.append(parent.tag.rsplit("}", 1)[-1].lower().replace(" ", ""))
            parent = parents.get(parent)
        if any(
            part in normalized_name or any(part in ancestor for ancestor in ancestors)
            for part in SENSITIVE_TAG_PARTS
        ):
            continue
        if "creator" in normalized_name and not any(
            allowed in normalized_name for allowed in ("creatortool", "softwareagent")
        ):
            continue
        if element.text and element.text.strip():
            result[local_name] = element.text.strip()[:MAX_METADATA_VALUE_LENGTH]
        for key, value in element.attrib.items():
            result[f"{element.tag.rsplit('}', 1)[-1]}.{key.rsplit('}', 1)[-1]}"] = value[
                :MAX_METADATA_VALUE_LENGTH
            ]
    return dict(list(result.items())[:MAX_METADATA_FIELDS])


def _extract_exiftool(path: Path) -> tuple[dict[str, Any] | None, str | None]:
    executable = shutil.which("exiftool")
    if not executable:
        return None, "ExifTool is not installed; IPTC extraction may be incomplete."
    try:
        result = subprocess.run(
            [executable, "-json", "-G", "-n", "--", str(path)],
            check=False,
            capture_output=True,
            text=True,
            timeout=8,
            shell=False,
        )
    except subprocess.TimeoutExpired:
        return None, "ExifTool inspection exceeded its time limit."
    except OSError as exc:
        logger.warning("ExifTool could not be started: %s", type(exc).__name__)
        return None, "ExifTool could not be started."
    if result.returncode != 0:
        return None, "ExifTool could not parse the file metadata."
    try:
        data = json.loads(result.stdout)
        return data[0] if data and isinstance(data[0], dict) else {}, None
    except (json.JSONDecodeError, IndexError, TypeError):
        return None, "ExifTool returned malformed metadata."


def analyze_metadata(path: Path) -> dict[str, Any]:
    """Extract bounded metadata; failures remain local to this inspection stage."""
    result: dict[str, Any] = {
        "status": "PRESENT",
        "exif": {},
        "xmp": {},
        "iptc": {},
        "timestamps": [],
        "software": [],
        "gps": {"status": "NOT DETECTED"},
        "warnings": [],
    }
    try:
        with Image.open(path) as image:
            result["color_mode"] = image.mode
            result["dimensions"] = list(image.size)
            try:
                result["exif"], gps = _extract_exif(image.getexif())
                if gps:
                    result["gps"] = {"status": "PRESENT", **gps}
            except (OSError, ValueError, TypeError) as exc:
                result["warnings"].append(f"EXIF inspection failed ({type(exc).__name__}).")
            for key in ("xmp", "XML:com.adobe.xmp"):
                if key in image.info:
                    result["xmp"] = _parse_xmp(image.info[key])
                    break
            info = dict(image.info)
            result["embedded_thumbnail"] = (
                "PRESENT" if "thumbnail" in info or "THUMBNAIL" in info else "NOT DETECTED"
            )
    except (OSError, ValueError) as exc:
        return {
            **result,
            "status": "INCONCLUSIVE",
            "warnings": [f"Metadata image parsing failed ({type(exc).__name__})."],
        }

    external, warning = _extract_exiftool(path)
    if warning:
        result["warnings"].append(warning)
    if external:
        for key, value in external.items():
            if key.startswith("IPTC:") and not any(
                part in key.lower().replace(" ", "") for part in SENSITIVE_TAG_PARTS
            ):
                result["iptc"][key] = _safe_value(value)
        # ExifTool's grouped fields add extraction coverage while retaining their source.
        for key, value in external.items():
            if any(word in key.lower() for word in ("datetime", "datecreated", "createdate")):
                result["timestamps"].append({"source": f"ExifTool {key}", "value": _safe_value(value)})
            if key.lower().endswith(":software") or key.lower().endswith(":processingsoftware"):
                result["software"].append(
                    {"source": f"ExifTool {key}", "value": _safe_value(value), "kind": "declared"}
                )

    timestamp_tags = {
        "DateTimeOriginal": ("capture timestamp", "OffsetTimeOriginal"),
        "DateTimeDigitized": ("metadata digitization timestamp", "OffsetTimeDigitized"),
        "DateTime": ("file metadata modification timestamp", "OffsetTime"),
    }
    for tag, (meaning, offset_tag) in timestamp_tags.items():
        value = result["exif"].get(tag)
        if value is not None:
            timestamp = {
                "source": f"EXIF {tag}",
                "meaning": meaning,
                "value": _safe_value(value),
            }
            offset = result["exif"].get(offset_tag)
            if offset is not None:
                timestamp["timezone_offset"] = _safe_value(offset)
            result["timestamps"].append(
                timestamp
            )
    for name, value in result["xmp"].items():
        normalized = name.lower()
        if any(part in normalized for part in ("datecreated", "createdate", "modifydate", "metadatadate")):
            result["timestamps"].append(
                {"source": f"XMP {name}", "meaning": "XMP date value", "value": _safe_value(value)}
            )
        if any(part in normalized for part in ("creatortool", "softwareagent")):
            result["software"].append(
                {"source": f"XMP {name}", "value": _safe_value(value), "kind": "declared"}
            )
    for key, meaning in (("Make", "camera make"), ("Model", "camera model"), ("LensModel", "lens")):
        if key in result["exif"]:
            result[key.lower()] = result["exif"][key]
    if "Software" in result["exif"]:
        result["software"].append(
            {"source": "EXIF Software", "value": result["exif"]["Software"], "kind": "declared"}
        )
    if not result["exif"] and not result["xmp"] and not result["iptc"]:
        result["status"] = "NOT DETECTED"
    result["analyzed_at"] = datetime.now(timezone.utc).isoformat()
    return result
