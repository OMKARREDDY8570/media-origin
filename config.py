"""Environment-backed application settings."""

from __future__ import annotations

import os
from dataclasses import dataclass

from dotenv import load_dotenv

load_dotenv(".env.local")
load_dotenv()


@dataclass(frozen=True)
class Config:
    telegram_bot_token: str
    max_upload_bytes: int = 15 * 1024 * 1024
    max_image_pixels: int = 40_000_000
    max_concurrent_analyses: int = 3
    request_interval_seconds: int = 10
    processing_timeout_seconds: int = 45
    analysis_version: str = "1.0.0"

    @classmethod
    def from_environment(cls) -> "Config":
        token = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
        if not token:
            raise ValueError("TELEGRAM_BOT_TOKEN is required.")
        return cls(telegram_bot_token=token)
