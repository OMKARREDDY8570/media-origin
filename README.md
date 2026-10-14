# OriginTrace

OriginTrace is an asynchronous Telegram bot that inspects image-file evidence locally. It reports the detected image encoding, dimensions, SHA-256, available EXIF/XMP metadata and (when ExifTool is available) IPTC data, plus the official C2PA SDK's manifest and validation report when that SDK works on the host.

It is not an image-authenticity classifier. Absence of metadata or C2PA credentials does not mean an image is fake, and AI-generated image detection is not implemented.

## Requirements

- Python 3.10 or newer. Python 3.11 or 3.12 is recommended for the broadest native-wheel compatibility.
- A Telegram bot token created with [BotFather](https://t.me/BotFather).
- Optional ExifTool executable for extra IPTC/XMP metadata extraction.
- The pinned `c2pa-python` SDK is attempted independently; if its native library cannot load, C2PA is marked unavailable and other analysis continues.

## Windows installation

From this directory in PowerShell:

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
python -m pip install -r requirements-dev.txt
Copy-Item .env.example .env.local
```

Edit `.env.local` and set `TELEGRAM_BOT_TOKEN` to the token from BotFather. The app also loads `.env` as a fallback. Do not share or commit either file.

Install ExifTool separately from its official distribution if desired, ensure `exiftool` is on `PATH`, then verify with `exiftool -ver`. It is optional and never launched through a shell. The C2PA SDK includes a native component; verify its import and real file behavior using:

```powershell
python -c "import c2pa; print('c2pa SDK import succeeded')"
python -m pytest -q
python main.py
```

The unit and local end-to-end tests do not require a Telegram token or network access. A real polling run requires a valid token and outbound access to Telegram.

## Bot setup and commands

1. Open BotFather in Telegram, send `/newbot`, follow the naming prompts, and copy its token.
2. Put the token in `.env.local` (or `.env`) locally or in a protected environment variable on the host.
3. Run `python main.py`.
4. Send `/start` and a photo or image document.

Implemented commands are `/start`, `/help`, `/analyze`, `/privacy`, and `/about`. The bot accepts JPEG, PNG, WEBP, TIFF, BMP, and GIF up to 15 MiB and 40 million pixels. Upload an image as a document when preserving the original bytes matters; Telegram photos may be resized or recompressed before the bot receives them.

## Processing and evidence limits

Uploads are checked by Pillow against the encoded contents and decoded dimensions. Each analysis uses an unpredictable temporary directory and removes it when processing completes. The bot does not intentionally persist uploaded images or export files. Telegram still receives and processes the user's message and the bot's reply; deletion from Telegram chat history is controlled by the user, not this application.

ExifTool is optional. Without it, Pillow supplies image/EXIF/XMP-visible fields, but IPTC inspection may be incomplete. GPS coordinates, when found, remain in the local JSON/report flow and are never geocoded or sent to an external service.

The C2PA adapter uses `c2pa.Reader` on the downloaded file and extracts the SDK report. Remote manifest retrieval is disabled. A parsed manifest is not treated as verified: absence of reported validation errors is not by itself proof of certificate trust or signer identity. The exact accepted file types depend on the installed C2PA native library. See [C2PA Python usage](https://github.com/contentauth/c2pa-python/blob/main/docs/usage.md) and [C2PA supported formats](https://github.com/contentauth/c2pa-rs/blob/main/docs/supported-formats.md). A version-pinned SDK does not guarantee its native dependency is operational on every account.

## Testing

`python -m pytest -q` generates local JPEG, PNG, WEBP, and TIFF sample fixtures, validates metadata/hash/report flows, tests malformed and oversized inputs, JSON serialization, report splitting, temporary-directory cleanup, and a mocked Telegram upload/report workflow. A valid signed C2PA fixture is not bundled; signed-manifest behavior must be verified against an independently sourced fixture on the deployment runtime. C2PA unsigned-image analysis is exercised when the native SDK is functional and otherwise reports its actual availability state.

Generated JSON examples for the supported fixture formats are stored under [examples/reports](./examples/reports). They are reports for synthetic sample images and do not demonstrate authenticity verification.

## Deployment

See [PYTHONANYWHERE.md](./PYTHONANYWHERE.md) for long-polling options, environment setup, native dependency caveats, and recovery instructions.
