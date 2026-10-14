"""OriginTrace Telegram bot entry point."""

from __future__ import annotations

import asyncio
import hashlib
import io
import logging
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from telegram import Update
from telegram.ext import (
    Application,
    CommandHandler,
    ContextTypes,
    MessageHandler,
    filters,
)

from c2pa_analyzer import analyze_c2pa
from config import Config
from forensic_checks import build_observations
from image_validator import ImageValidationError, ValidatedImage, validate_image
from json_exporter import export_json
from metadata_analyzer import analyze_metadata
from report_builder import build_report
from safe_files import sanitize_filename, temporary_image

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s %(message)s",
)
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("httpcore").setLevel(logging.WARNING)
logger = logging.getLogger("origintrace")

WELCOME = (
    "OriginTrace examines image-file metadata and C2PA Content Credentials where available. "
    "Send a photo or image document to receive a forensic report and JSON export. "
    "It does not determine whether an image is real, fake, or AI-generated."
)


def _config(application: Application) -> Config:
    config = application.bot_data.get("origintrace_config")
    if not isinstance(config, Config):
        raise RuntimeError("OriginTrace configuration is not initialized.")
    return config


async def start(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    del context
    if update.message:
        await update.message.reply_text(f"Welcome to OriginTrace.\n\n{WELCOME}\n\nUse /help for details.")


async def help_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    del context
    if update.message:
        await update.message.reply_text(
            "Commands: /start, /help, /analyze, /privacy, /about.\n"
            "Send a photo or image document (up to 15 MiB). Supported formats: JPEG, PNG, WEBP, TIFF, BMP, GIF. "
            "Analysis is local apart from Telegram's file-delivery service. C2PA verification depends on SDK support."
        )


async def analyze_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    del context
    if update.message:
        await update.message.reply_text(
            "Submit an image as a Telegram photo or image document. For best evidence fidelity, use an image document "
            "to avoid Telegram photo resizing or recompression."
        )


async def privacy_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    del context
    if update.message:
        await update.message.reply_text(
            "OriginTrace downloads an image to a randomized temporary directory, analyzes it locally, sends the "
            "report and JSON document, then removes temporary files. No image or report is intentionally retained. "
            "No external metadata or AI service is used; C2PA remote manifest retrieval is disabled. Logs do not "
            "include image contents, tokens, GPS, or user IDs. Telegram processes the message and controls its own "
            "chat history; OriginTrace cannot delete copies already delivered to Telegram."
        )


async def about_command(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    del context
    if update.message:
        await update.message.reply_text(
            "OriginTrace is an evidence-based image-file inspection bot. It reports file hashes, available metadata, "
            "and C2PA SDK results without producing a real/fake verdict. Missing metadata or credentials do not prove "
            "editing. AI-image detection is not implemented."
        )


def _uploaded_image(update: Update) -> tuple[Any, str] | None:
    message = update.message
    if not message:
        return None
    if message.photo:
        return message.photo[-1], "photo.jpg"
    document = message.document
    if document and (document.mime_type or "").lower().startswith("image/"):
        return document, document.file_name or "image"
    return None


async def handle_image(update: Update, context: ContextTypes.DEFAULT_TYPE) -> None:
    message = update.message
    if not message:
        return
    config = _config(context.application)
    upload = _uploaded_image(update)
    if upload is None:
        await message.reply_text("Please submit a photo or an image document. Compressed files and other documents are not accepted.")
        return
    telegram_file, display_name = upload
    if telegram_file.file_size and telegram_file.file_size > config.max_upload_bytes:
        await message.reply_text("This image exceeds the 15 MiB upload limit.")
        return

    user_id = update.effective_user.id if update.effective_user else None
    now = time.monotonic()
    previous = context.application.bot_data.setdefault("last_request", {})
    stale_before = now - config.request_interval_seconds
    for stale_user in [key for key, timestamp in previous.items() if timestamp < stale_before]:
        del previous[stale_user]
    if user_id is not None and now - previous.get(user_id, 0) < config.request_interval_seconds:
        await message.reply_text("Please wait a few seconds before submitting another image.")
        return
    if user_id is not None:
        previous[user_id] = now
    semaphore: asyncio.Semaphore = context.application.bot_data["analysis_semaphore"]
    status_message = await message.reply_text("Image received. Starting local file analysis…")
    try:
        async with semaphore:
            temp_directory = temporary_image()
            deferred_cleanup = False
            try:
                temp_dir = Path(temp_directory.name)
                original = temp_dir / "download"
                tg_file = await telegram_file.get_file()
                await tg_file.download_to_drive(custom_path=original)
                if original.stat().st_size > config.max_upload_bytes:
                    raise ImageValidationError("The downloaded file exceeds the upload size limit.")
                validated = validate_image(original, config.max_upload_bytes, config.max_image_pixels)
                analysis_path = temp_dir / f"image{validated.extension}"
                original.replace(analysis_path)
                analysis_task = asyncio.create_task(
                    asyncio.to_thread(
                        _analyze_file,
                        analysis_path,
                        sanitize_filename(display_name),
                        config,
                        validated,
                    ),
                )
                try:
                    report = await asyncio.wait_for(
                        asyncio.shield(analysis_task),
                        timeout=config.processing_timeout_seconds,
                    )
                except (asyncio.TimeoutError, asyncio.CancelledError):
                    deferred_cleanup = True
                    analysis_task.add_done_callback(
                        lambda completed: _cleanup_after_analysis(completed, temp_directory)
                    )
                    raise
            finally:
                if not deferred_cleanup:
                    temp_directory.cleanup()
            for chunk in build_report(report):
                await message.reply_text(chunk)
            document = io.BytesIO(export_json(report))
            document.name = f"origintrace-{report['analysis_id']}.json"
            await message.reply_document(document, caption="Structured OriginTrace analysis (JSON).")
        await status_message.delete()
    except ImageValidationError as exc:
        await status_message.edit_text(str(exc))
    except asyncio.TimeoutError:
        await status_message.edit_text("Analysis exceeded the processing time limit. No report was produced.")
    except Exception as exc:
        logger.warning("Image analysis failed: %s", type(exc).__name__)
        await status_message.edit_text("Analysis could not be completed. Please try another supported image.")


def _cleanup_after_analysis(
    task: asyncio.Task[Any], temp_directory: tempfile.TemporaryDirectory[str]
) -> None:
    try:
        task.result()
    except asyncio.CancelledError:
        logger.warning("Background analysis was cancelled after handler timeout.")
    except Exception as exc:
        logger.warning("Background analysis ended after handler timeout: %s", type(exc).__name__)
    finally:
        try:
            temp_directory.cleanup()
        except OSError as exc:
            logger.error("Temporary analysis directory cleanup failed: %s", type(exc).__name__)


def _analyze_file(
    path: Path, filename: str, config: Config, validated: ValidatedImage
) -> dict[str, Any]:
    content_hash = hashlib.sha256()
    with path.open("rb") as file_handle:
        for chunk in iter(lambda: file_handle.read(1024 * 1024), b""):
            content_hash.update(chunk)
    warnings: list[dict[str, str]] = []
    try:
        metadata = analyze_metadata(path)
    except Exception as exc:
        logger.warning("Metadata stage failed: %s", type(exc).__name__)
        metadata = {"status": "UNAVAILABLE", "warnings": [], "software": [], "timestamps": []}
        warnings.append({"stage": "metadata", "error": type(exc).__name__})
    try:
        c2pa = analyze_c2pa(path)
    except Exception as exc:
        logger.warning("C2PA stage failed: %s", type(exc).__name__)
        c2pa = {"status": "UNAVAILABLE", "reason": "C2PA inspection failed."}
        warnings.append({"stage": "c2pa", "error": type(exc).__name__})
    return {
        "application": {"name": "OriginTrace", "version": config.analysis_version},
        "analysis_id": str(uuid.uuid4()),
        "analysis_timestamp": datetime.now(timezone.utc).isoformat(),
        "file": {
            "filename": filename,
            "format": validated.format,
            "dimensions": [validated.width, validated.height],
            "size_bytes": path.stat().st_size,
            "color_mode": validated.mode,
            "frame_count": validated.frame_count,
            "sha256": content_hash.hexdigest(),
        },
        "metadata": metadata,
        "c2pa": c2pa,
        "observations": build_observations(metadata, c2pa),
        "limitations": [
            "Image authenticity and AI generation cannot be determined by this version.",
            "Metadata can be missing, changed, or incomplete and is not independently authenticated.",
            "C2PA support depends on the installed SDK's native library and supported formats.",
        ],
        "errors": warnings,
    }


def build_application(config: Config) -> Application:
    application = Application.builder().token(config.telegram_bot_token).build()
    application.bot_data["origintrace_config"] = config
    application.bot_data["analysis_semaphore"] = asyncio.Semaphore(config.max_concurrent_analyses)
    for command, callback in (
        ("start", start),
        ("help", help_command),
        ("analyze", analyze_command),
        ("privacy", privacy_command),
        ("about", about_command),
    ):
        application.add_handler(CommandHandler(command, callback))
    application.add_handler(
        MessageHandler(filters.PHOTO | filters.Document.IMAGE, handle_image)
    )
    application.add_error_handler(_handle_error)
    return application


async def _handle_error(update: object, context: ContextTypes.DEFAULT_TYPE) -> None:
    del update
    error = context.error
    logger.error("Telegram update failed: %s", type(error).__name__ if error else "unknown error")


def main() -> None:
    config = Config.from_environment()
    application = build_application(config)
    logger.info("Starting OriginTrace polling bot.")
    application.run_polling(allowed_updates=Update.ALL_TYPES)


if __name__ == "__main__":
    main()
