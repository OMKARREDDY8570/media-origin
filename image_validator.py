"""Validation of untrusted image files using their contents, not their names."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from PIL import Image, UnidentifiedImageError


SUPPORTED_FORMATS = {
    "JPEG": ".jpg",
    "PNG": ".png",
    "WEBP": ".webp",
    "TIFF": ".tiff",
    "BMP": ".bmp",
    "GIF": ".gif",
}


class ImageValidationError(ValueError):
    """An uploaded file is not a supported, well-formed image."""


@dataclass(frozen=True)
class ValidatedImage:
    format: str
    extension: str
    width: int
    height: int
    mode: str
    frame_count: int


def validate_image(path: Path, max_bytes: int, max_pixels: int) -> ValidatedImage:
    """Verify file size, actual image encoding, and decoded dimensions."""
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise ImageValidationError("The uploaded file could not be read.") from exc
    if size <= 0:
        raise ImageValidationError("The uploaded file is empty.")
    if size > max_bytes:
        raise ImageValidationError("The image exceeds the upload size limit.")

    try:
        with Image.open(path) as image:
            image_format = image.format
            if image_format not in SUPPORTED_FORMATS:
                raise ImageValidationError("This image format is not supported.")
            width, height = image.size
            if width <= 0 or height <= 0 or width * height > max_pixels:
                raise ImageValidationError("The image dimensions exceed the processing limit.")
            image.verify()
        with Image.open(path) as image:
            image.load()
            return ValidatedImage(
                format=image_format,
                extension=SUPPORTED_FORMATS[image_format],
                width=width,
                height=height,
                mode=image.mode,
                frame_count=getattr(image, "n_frames", 1),
            )
    except ImageValidationError:
        raise
    except (UnidentifiedImageError, OSError, SyntaxError, Image.DecompressionBombError) as exc:
        raise ImageValidationError("The file is malformed or is not a valid image.") from exc
