"""Safe names and short-lived file storage for uploaded media."""

from __future__ import annotations

import re
import tempfile
from pathlib import Path
from typing import BinaryIO


def sanitize_filename(filename: str | None) -> str:
    """Return a bounded display-only filename without path components."""
    name = (filename or "image").replace("\\", "/").split("/")[-1]
    name = re.sub(r"[^A-Za-z0-9._-]+", "_", name).strip("._")
    return (name[:120] or "image")


def temporary_image(suffix: str = "") -> tempfile.TemporaryDirectory[str]:
    """Create an isolated directory with an unpredictable path."""
    normalized = suffix if re.fullmatch(r"\.[A-Za-z0-9]{1,8}", suffix) else ""
    directory = tempfile.TemporaryDirectory(prefix="origintrace-")
    Path(directory.name, f"upload{normalized}").touch()
    return directory


def copy_limited(source: BinaryIO, destination: Path, max_bytes: int) -> int:
    """Copy a stream to a private temporary path, stopping at the byte limit."""
    total = 0
    with destination.open("wb") as target:
        while chunk := source.read(64 * 1024):
            total += len(chunk)
            if total > max_bytes:
                raise ValueError("The uploaded file exceeds the size limit.")
            target.write(chunk)
    return total
