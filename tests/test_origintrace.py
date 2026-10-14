import asyncio
import hashlib
import json
from pathlib import Path
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from PIL import Image

from c2pa_analyzer import analyze_c2pa
from config import Config
from image_validator import ImageValidationError, validate_image
from json_exporter import export_json
from main import _analyze_file, _cleanup_after_analysis, build_application, handle_image
from metadata_analyzer import _parse_xmp, analyze_metadata
from report_builder import TELEGRAM_SAFE_MESSAGE_LENGTH, build_report
from safe_files import sanitize_filename, temporary_image


def make_image(path: Path, image_format: str = "JPEG") -> None:
    Image.new("RGB", (16, 12), color=(40, 80, 120)).save(path, format=image_format)


@pytest.mark.parametrize(
    ("image_format", "expected"),
    [("JPEG", "JPEG"), ("PNG", "PNG"), ("WEBP", "WEBP"), ("TIFF", "TIFF")],
)
def test_supported_image_formats(tmp_path: Path, image_format: str, expected: str) -> None:
    path = tmp_path / "image"
    make_image(path, image_format)
    result = validate_image(path, 1_000_000, 10_000)
    assert result.format == expected
    assert (result.width, result.height) == (16, 12)


def test_image_without_metadata_and_missing_timestamps(tmp_path: Path) -> None:
    path = tmp_path / "plain.png"
    make_image(path, "PNG")
    result = analyze_metadata(path)
    assert result["timestamps"] == []
    assert result["status"] == "NOT DETECTED"
    assert result["gps"]["status"] == "NOT DETECTED"


def test_exif_timestamps_preserve_source_and_timezone_offset(tmp_path: Path) -> None:
    path = tmp_path / "timestamp.jpg"
    exif = Image.Exif()
    exif[36867] = "2024:03:04 05:06:07"
    exif[36881] = "+05:30"
    Image.new("RGB", (16, 12)).save(path, format="JPEG", exif=exif)
    result = analyze_metadata(path)
    capture = next(item for item in result["timestamps"] if item["source"] == "EXIF DateTimeOriginal")
    assert capture["value"] == "2024:03:04 05:06:07"
    assert capture["timezone_offset"] == "+05:30"


def test_gps_ifd_pointer_is_decoded_as_coordinates(tmp_path: Path) -> None:
    path = tmp_path / "gps.jpg"
    exif = Image.Exif()
    exif[34853] = {
        1: "N",
        2: (12.0, 34.0, 56.0),
        3: "W",
        4: (98.0, 45.0, 12.0),
        5: 0,
        6: 10.5,
    }
    Image.new("RGB", (16, 12)).save(path, format="JPEG", exif=exif)
    result = analyze_metadata(path)
    assert result["gps"]["status"] == "PRESENT"
    assert result["gps"]["coordinates"] == {
        "latitude": 12.5822222,
        "longitude": -98.7533333,
    }
    assert "fields" not in result["gps"]
    assert result["status"] == "PRESENT"


def test_rejects_unsupported_and_malformed_files(tmp_path: Path) -> None:
    path = tmp_path / "archive.zip"
    path.write_bytes(b"PK\x03\x04")
    with pytest.raises(ImageValidationError):
        validate_image(path, 1_000, 10_000)
    path.write_bytes(b"not an image")
    with pytest.raises(ImageValidationError):
        validate_image(path, 1_000, 10_000)


def test_rejects_oversized_file_and_pixel_dimensions(tmp_path: Path) -> None:
    path = tmp_path / "large.png"
    make_image(path, "PNG")
    with pytest.raises(ImageValidationError, match="size limit"):
        validate_image(path, 10, 10_000)
    with pytest.raises(ImageValidationError, match="dimensions"):
        validate_image(path, 1_000_000, 10)


def test_sanitize_filename_removes_path_components() -> None:
    assert sanitize_filename("../../secret image.jpg") == "secret_image.jpg"
    assert sanitize_filename("C:\\private\\image.png") == "image.png"
    assert len(sanitize_filename("a" * 200 + ".jpg")) <= 120


def test_temporary_directory_is_removed() -> None:
    with temporary_image(".jpg") as directory:
        path = Path(directory, "upload.jpg")
        assert path.exists()
        path.write_bytes(b"temporary")
    assert not Path(directory).exists()


def test_timed_out_analysis_defers_cleanup_until_worker_finishes() -> None:
    async def exercise() -> str:
        directory = temporary_image(".jpg")
        path = Path(directory.name, "upload.jpg")
        task = asyncio.create_task(asyncio.to_thread(time.sleep, 0.03))
        try:
            await asyncio.wait_for(asyncio.shield(task), timeout=0.001)
        except asyncio.TimeoutError:
            task.add_done_callback(
                lambda completed: _cleanup_after_analysis(completed, directory)
            )
        assert path.exists()
        await task
        await asyncio.sleep(0)
        return directory.name

    directory_path = asyncio.run(exercise())
    assert not Path(directory_path).exists()


def test_c2pa_missing_sdk_is_unavailable() -> None:
    with patch("c2pa_analyzer.importlib.import_module", side_effect=ImportError):
        result = analyze_c2pa(Path("unused.jpg"))
    assert result["status"] == "UNAVAILABLE"


def test_c2pa_sdk_initialization_failure_is_unavailable() -> None:
    module = SimpleNamespace(
        Settings=SimpleNamespace(from_dict=lambda _config: (_ for _ in ()).throw(OSError("native init")))
    )
    with patch("c2pa_analyzer.importlib.import_module", return_value=module):
        result = analyze_c2pa(Path("unused.jpg"))
    assert result["status"] == "UNAVAILABLE"


def _fake_c2pa_module(manifest_store: dict) -> SimpleNamespace:
    class Resource:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return False

    class Settings:
        @classmethod
        def from_dict(cls, config):
            assert config["verify"]["remote_manifest_fetch"] is False
            return cls()

    class Context(Resource):
        def __init__(self, _settings):
            pass

    class Reader(Resource):
        def __init__(self, _path, context):
            assert context is not None

        def json(self):
            return json.dumps(manifest_store)

    return SimpleNamespace(Settings=Settings, Context=Context, Reader=Reader)


def test_c2pa_parsed_manifest_without_errors_is_not_claimed_verified(tmp_path: Path) -> None:
    path = tmp_path / "image.jpg"
    path.touch()
    module = _fake_c2pa_module(
        {
            "active_manifest": "claim",
            "manifests": {
                "claim": {
                    "title": "sample",
                    "claim_generator": "test app",
                    "signature_info": {"issuer": "Example", "time": "2025-01-01T00:00:00Z"},
                }
            },
            "validation_status": {
                "activeManifest": {
                    "success": [
                        {"code": "claimSignature.validated"},
                        {"code": "signingCredential.trusted"},
                        {"code": "assertion.dataHash.match"},
                    ],
                    "informational": [{"code": "timeStamp.validated"}],
                }
            },
        }
    )
    with patch("c2pa_analyzer.importlib.import_module", return_value=module):
        result = analyze_c2pa(path)
    assert result["status"] == "PRESENT"
    assert result["signature_issuer"] == "Example"
    assert result["signature_integrity"] == "VERIFIED"
    assert result["certificate_trust"] == "VERIFIED"
    assert len(result["validation_successes"]) == 3
    assert len(result["validation_informational"]) == 1
    assert result["validation_issues"] == []
    assert result["remote_retrieval"] == "DISABLED"


def test_c2pa_validation_issues_are_reported_invalid(tmp_path: Path) -> None:
    path = tmp_path / "image.jpg"
    path.touch()
    module = _fake_c2pa_module(
        {
            "active_manifest": "claim",
            "validation_status": {
                "activeManifest": {
                    "success": [{"code": "claimSignature.validated"}],
                    "failure": [{"code": "assertion.dataHash.mismatch"}],
                }
            },
            "manifests": {"claim": {"assertions": []}},
        }
    )
    with patch("c2pa_analyzer.importlib.import_module", return_value=module):
        result = analyze_c2pa(path)
    assert result["status"] == "INVALID"
    assert result["signature_integrity"] == "VERIFIED"
    assert result["validation_issues"][0]["code"] == "assertion.dataHash.mismatch"


def test_c2pa_malformed_manifest_json_is_inconclusive(tmp_path: Path) -> None:
    path = tmp_path / "image.jpg"
    path.touch()
    module = _fake_c2pa_module({})
    module.Reader.json = lambda _reader: "{invalid"
    with patch("c2pa_analyzer.importlib.import_module", return_value=module):
        result = analyze_c2pa(path)
    assert result["status"] == "INCONCLUSIVE"


def test_c2pa_unsigned_file_is_not_marked_valid(tmp_path: Path) -> None:
    path = tmp_path / "unsigned.png"
    make_image(path, "PNG")
    result = analyze_c2pa(path)
    assert result["status"] == "NOT DETECTED"
    assert result["credential"] == "NOT DETECTED"
    assert result["remote_retrieval"] == "DISABLED"


def test_malformed_xmp_is_reported_without_stopping_metadata_analysis() -> None:
    assert _parse_xmp(b"<x:xmpmeta><broken>") == {
        "parse_error": "XMP data was present but malformed."
    }


def test_json_export_is_valid_and_contains_no_user_identity() -> None:
    report = {"application": {"name": "OriginTrace"}, "file": {"sha256": "abc"}}
    decoded = json.loads(export_json(report))
    assert decoded == report
    assert "telegram_user" not in decoded


def test_report_splits_at_telegram_limit() -> None:
    report = {
        "file": {"filename": "photo.jpg", "format": "JPEG", "dimensions": [10, 10], "size_bytes": 1, "sha256": "a"},
        "metadata": {"timestamps": [], "software": [], "gps": {"status": "NOT DETECTED"}},
        "c2pa": {"status": "NOT DETECTED"},
        "observations": [
            {
                "finding": f"Finding {index} " + ("x" * 500),
                "evidence_source": "fixture",
                "limitation": "inconclusive",
            }
            for index in range(20)
        ],
        "analysis_timestamp": "2025-01-01T00:00:00+00:00",
        "application": {"version": "1.0.0"},
    }
    chunks = build_report(report)
    assert len(chunks) > 1
    assert all(len(chunk) <= TELEGRAM_SAFE_MESSAGE_LENGTH for chunk in chunks)
    assert "ASSESSMENT" in chunks[-1]


def test_report_formats_gps_software_actions_and_validation_compactly() -> None:
    report = {
        "file": {
            "filename": "face.jpg",
            "format": "JPEG",
            "dimensions": [1280, 720],
            "size_bytes": 1000,
            "sha256": "abc",
        },
        "metadata": {
            "software": [{"source": "EXIF Software", "value": "Windows 10", "kind": "declared"}],
            "timestamps": [],
            "gps": {
                "status": "PRESENT",
                "coordinates": {"latitude": 12.5, "longitude": -98.75},
            },
            "status": "PRESENT",
        },
        "c2pa": {
            "status": "PRESENT",
            "active_manifest": "claim",
            "signature_integrity": "VERIFIED",
            "certificate_trust": "NOT VERIFIED",
            "assertions": [
                {
                    "label": "c2pa.actions.v2",
                    "data": {
                        "actions": [
                            {
                                "action": "c2pa.created",
                                "softwareAgent": {"name": "ChatGPT", "version": "image-v1"},
                                "digitalSourceType": "trainedAlgorithmicMedia",
                            }
                        ]
                    },
                }
            ],
            "validation_successes": [{"code": f"check.{index}.validated"} for index in range(30)],
            "validation_issues": [],
            "validation_informational": [],
        },
        "analysis_timestamp": "2025-01-01T00:00:00+00:00",
        "application": {"version": "1.0"},
    }
    text = "\n".join(build_report(report))
    assert "Dimensions: 1280 x 720" in text
    assert "GPS: 12.5, -98.75" in text
    assert "EXIF Software: Windows 10" in text
    assert "c2pa.created (ChatGPT image-v1)" in text
    assert "30 successful" in text
    assert "check.0.validated" not in text
    assert "8354" not in text


def test_end_to_end_analysis_hash_and_report(tmp_path: Path) -> None:
    path = tmp_path / "sample.jpg"
    make_image(path)
    validated = validate_image(path, 1_000_000, 10_000)
    result = _analyze_file(path, "sample.jpg", Config("test-token"), validated)
    expected = hashlib.sha256(path.read_bytes()).hexdigest()
    assert result["file"]["sha256"] == expected
    assert json.loads(export_json(result))["file"]["format"] == "JPEG"
    assert build_report(result)


def test_independent_analysis_stage_failure_is_reported(tmp_path: Path) -> None:
    path = tmp_path / "sample.png"
    make_image(path, "PNG")
    validated = validate_image(path, 1_000_000, 10_000)
    with (
        patch("main.analyze_metadata", side_effect=RuntimeError("metadata failure")),
        patch("main.analyze_c2pa", return_value={"status": "NOT DETECTED"}),
    ):
        report = _analyze_file(path, "sample.png", Config("test-token"), validated)
    assert report["metadata"]["status"] == "UNAVAILABLE"
    assert report["c2pa"]["status"] == "NOT DETECTED"
    assert report["errors"] == [{"stage": "metadata", "error": "RuntimeError"}]


def test_telegram_handlers_build_without_network_or_token_validation() -> None:
    application = build_application(Config("123:fake-token"))
    command_names = {
        command
        for group_handlers in application.handlers.values()
        for handler in group_handlers
        if hasattr(handler, "commands")
        for command in handler.commands
    }
    assert {"start", "help", "analyze", "privacy", "about"} <= command_names


def test_image_handler_mocks_telegram_io_and_cleans_temp_files(tmp_path: Path) -> None:
    sample = tmp_path / "mock-upload.png"
    make_image(sample, "PNG")
    payload = sample.read_bytes()
    downloaded: list[Path] = []

    async def download_to_drive(*, custom_path: Path) -> Path:
        downloaded.append(custom_path)
        custom_path.write_bytes(payload)
        return custom_path

    telegram_file = SimpleNamespace(
        file_size=len(payload),
        file_name="user-image.png",
        mime_type="image/png",
        get_file=AsyncMock(
            return_value=SimpleNamespace(download_to_drive=download_to_drive)
        ),
    )
    status_message = SimpleNamespace(
        delete=AsyncMock(),
        edit_text=AsyncMock(),
    )
    message = SimpleNamespace(
        photo=[],
        document=telegram_file,
        reply_text=AsyncMock(return_value=status_message),
        reply_document=AsyncMock(),
    )
    application = SimpleNamespace(
        bot_data={
            "origintrace_config": Config("test-token"),
            "analysis_semaphore": asyncio.Semaphore(1),
        }
    )
    context = SimpleNamespace(application=application)
    update = SimpleNamespace(
        message=message,
        effective_user=SimpleNamespace(id=123),
    )

    with patch("main.analyze_c2pa", return_value={"status": "NOT DETECTED"}):
        asyncio.run(handle_image(update, context))

    telegram_file.get_file.assert_awaited_once()
    message.reply_document.assert_awaited_once()
    status_message.delete.assert_awaited_once()
    assert downloaded and not downloaded[0].exists()
