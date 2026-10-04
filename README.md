# HexiKeys

![HexiKeys wordmark: hexi followed by a key](assets/hexikeys-wordmark.png)

A standalone Windows password and secret vault by **Hexxis Studios**, with optional HexiGrid integration.

**Early public preview (0.1.0-alpha).** This app is still being tested and has not had an independent security audit. Keep separate encrypted backups; don't treat this preview as a substitute for a proven password manager for critical accounts.

## Download and run

Get **HexiKeys.exe** from the [latest GitHub release](https://github.com/Hexxis-Studios/HexiKeys/releases/latest). Download it into its own folder and run it. It is a portable Windows app, not an installer. No Python installation is required for the packaged app. The executable is not code-signed; Windows may identify its publisher as unknown. Verify the SHA-256 checksum from the release before deciding whether to run it.

## Features

- Passwords, API keys, tokens, recovery phrases, backup codes and secure notes with custom fields.
- AES-256-GCM encryption with Scrypt key derivation for new vaults.
- Encrypted backup/restore and master-password changes with encrypted safety copies.
- Password generator, private-field masking, non-secret search and reviewed JSON/text/local Windows OCR imports.
- Ten-minute inactivity lock and thirty-second copied-secret cleanup when the clipboard has not changed.
- Optional, explicit local HexiGrid pairing and scoped field-use approvals. HexiKeys remains usable on its own.

## Your vault

New accounts store data in `%APPDATA%\HexiKeys\vault.dat`. Existing SimpleVault accounts continue using their original location. Branding changes do not migrate or discard vaults. Legacy encryption is upgraded only after successful unlock, with an encrypted safety copy.

A forgotten master password cannot be recovered. Older backups keep their original password after rotation. Keep backups private. Never publish your vault, backup files or HexiGrid pairing material. See [SECURITY.md](SECURITY.md).

## Develop and build

Use Python 3.14 with Tcl/Tk installed on Windows:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-build.txt
.\.venv\Scripts\python.exe scripts/generate_icon.py
.\.venv\Scripts\python.exe -m unittest discover -s tests -v
.\.venv\Scripts\python.exe app.py
.\build.ps1
```

Tests use synthetic entries and temporary directories, never a personal vault. The build includes the approved hexi + key wordmark. Runtime vault and pairing files are not bundled.

## License

No open-source license has been selected. Public source access alone does not grant permission to redistribute or relicense the software. Contact Hexxis Studios for reuse requests.
