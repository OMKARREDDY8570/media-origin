# PythonAnywhere deployment

OriginTrace uses Telegram long polling and does not need a web server or database. PythonAnywhere account features, Python versions, outbound network allow-lists, and always-on process availability vary by plan and can change. Confirm the current details in the account dashboard and the official [PythonAnywhere help pages](https://help.pythonanywhere.com/) before deployment.

## 1. Prepare the account

1. Create a PythonAnywhere account and open a Bash console.
2. Check the interpreters shown by PythonAnywhere and choose a supported Python 3.10+ version (prefer 3.11/3.12 where available and compatible native wheels exist).
3. Clone or upload this project to a private directory. Keep `.env` out of source control.
4. Create a virtual environment using the host's selected interpreter:

   ```bash
   cd ~/origintrace
   python3.12 -m venv .venv
   source .venv/bin/activate
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

   Replace `python3.12` with an interpreter actually offered by the account.

5. In the PythonAnywhere dashboard, use its environment-variable feature if available; otherwise store `.env` in the private project directory with owner-only permissions and never commit it. Set `TELEGRAM_BOT_TOKEN` to the BotFather token.
6. Check outbound access to Telegram using the account's supported network policy. Free accounts may have restricted outbound hosts; an account may need an eligible plan or a permitted Telegram API endpoint. Do not attempt to bypass the account's network restrictions.
7. Check SDK capabilities:

   ```bash
   .venv/bin/python -c 'import telegram; print(telegram.__version__)'
   .venv/bin/python -c 'import c2pa; print("C2PA import OK")'
   ```

   If C2PA import fails because the platform cannot load the bundled native library, keep the optional stage unavailable and use other analyses. Do not report C2PA verification as successful. ExifTool is optional; use it only if you can install it from an approved source and `exiftool -ver` works in the account shell.

## 2. Run the bot

Long polling must remain active to receive updates. If the account offers an **Always-on task** feature, create one with:

- Command: `/home/<your-username>/origintrace/.venv/bin/python /home/<your-username>/origintrace/main.py`
- Working directory: `/home/<your-username>/origintrace`

Use the account's documented task controls and logs to start, stop, and diagnose it. Always-on tasks may be restricted to paid plans; do not assume a free account can run a persistent polling process.

If the account has no always-on process support, a scheduled task can only run the process for its allowed scheduled duration. It is not a reliable replacement for a continuously available polling bot and may miss updates while stopped. Check current account limits before using it; do not run overlapping polling processes with the same token.

## 3. Verify and diagnose

Run a local import test and automated tests in the virtualenv before enabling polling:

```bash
.venv/bin/python -m pytest -q
.venv/bin/python -c 'from config import Config; print("application modules import")'
```

Start the task, message `/start`, then submit a small JPEG as a document. Check the task log for startup, outbound connection, or dependency errors. The bot logs exception classes and stage status but intentionally avoids logging image data, metadata, tokens, and Telegram user IDs.

## Limitations and troubleshooting

- **Polling connection fails:** verify token configuration, account outbound access, Telegram API availability, and that no second process is polling the same token.
- **C2PA unavailable:** verify the `c2pa-python==0.38.0` installation and native import under the same interpreter/account used by the task. Native wheels and system-library support vary; a successful `pip install` alone is not proof that Reader validation works.
- **ExifTool warnings:** this optional system binary may not be available or permitted on a given account. Pillow-based analysis still works; IPTC coverage may be incomplete.
- **Process stops:** confirm whether the account plan supports always-on tasks and inspect its scheduled-task/runtime limits. A scheduled task cannot provide continuous long polling if the account stops it.
- **No signed-credential fixture shipped:** test unsigned images and the unavailable-SDK fallback locally. Obtain a known signed fixture through an approved source and test the installed host SDK before making deployment-specific validation claims.
- **Cleanup after an unexpected termination:** normal runs remove their randomized temporary directory in a context manager. If the process is killed abruptly, inspect only the dedicated system temp directory for stale `origintrace-*` folders and remove old OriginTrace-only folders manually. Never delete unrelated temporary files.
