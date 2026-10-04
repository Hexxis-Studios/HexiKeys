"""Crash-safe file storage for encrypted HexiKeys vaults."""

import json
import os
import tempfile
from datetime import datetime
from pathlib import Path

from vault_crypto import MAX_VAULT_BYTES, decrypt_vault, encrypt_vault


MAX_VAULT_FILE_BYTES = (MAX_VAULT_BYTES * 4 // 3) + (1024 * 1024)


def read_encrypted_blob(path):
    path = Path(path)
    with path.open("rb") as stream:
        raw = stream.read(MAX_VAULT_FILE_BYTES + 1)
    if not raw or len(raw) > MAX_VAULT_FILE_BYTES:
        raise ValueError("Vault file size is invalid")
    try:
        blob = json.loads(raw.decode("utf-8"))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Vault file is damaged or has an unsupported format") from exc
    if not isinstance(blob, dict):
        raise ValueError("Vault file has an unsupported format")
    return blob


def load_vault(path, password):
    blob = read_encrypted_blob(path)
    return decrypt_vault(blob, password), blob.get("version")


def _preserve_legacy_blob(path):
    """Create a unique byte-for-byte encrypted backup before replacing a v1 vault."""
    raw = path.read_bytes()
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    backup = path.with_name(f"{path.stem}.legacy-v1-{stamp}{path.suffix}.bak")
    with backup.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    return backup


def copy_encrypted_vault(source, destination, password):
    """Atomically copy an encrypted vault without exposing its plaintext."""
    source = Path(source)
    destination = Path(destination)
    if source.resolve() == destination.resolve():
        raise ValueError("Choose a different file for the encrypted backup")
    load_vault(source, password)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temp_path = None
    try:
        with source.open("rb") as original, tempfile.NamedTemporaryFile(
            mode="wb", prefix=f".{destination.name}.", suffix=".tmp", dir=destination.parent, delete=False
        ) as stream:
            temp_path = Path(stream.name)
            copied = 0
            while True:
                chunk = original.read(min(1024 * 1024, MAX_VAULT_FILE_BYTES - copied + 1))
                if not chunk:
                    break
                copied += len(chunk)
                if copied > MAX_VAULT_FILE_BYTES:
                    raise ValueError("Vault file size is invalid")
                stream.write(chunk)
            stream.flush()
            os.fsync(stream.fileno())
        load_vault(temp_path, password)
        os.replace(temp_path, destination)
        temp_path = None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
    return destination


def create_encrypted_backup(source, password, label="backup"):
    """Keep a unique encrypted safety copy beside the source vault."""
    source = Path(source)
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S-%f")
    destination = source.with_name(f"{source.stem}.{label}-{stamp}{source.suffix}.bak")
    return copy_encrypted_vault(source, destination, password)


def save_vault(path, payload, password):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    legacy_backup = None
    if path.exists():
        existing = read_encrypted_blob(path)
        if existing.get("version") == 1:
            legacy_backup = _preserve_legacy_blob(path)

    blob = encrypt_vault(payload, password)
    serialized = json.dumps(blob, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(serialized) > MAX_VAULT_FILE_BYTES:
        raise ValueError("Encrypted vault file is too large to save")

    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="wb", prefix=f".{path.name}.", suffix=".tmp", dir=path.parent, delete=False) as stream:
            temp_path = Path(stream.name)
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp_path, path)
        temp_path = None
    finally:
        if temp_path is not None:
            try:
                temp_path.unlink(missing_ok=True)
            except OSError:
                pass
    return legacy_backup
