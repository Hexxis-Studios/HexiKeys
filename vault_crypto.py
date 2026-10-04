"""Versioned encryption for HexiKeys vault files.

Version 1 is read-only compatibility for the original SimpleVault files.
New writes use Scrypt and AES-256-GCM from the maintained cryptography package.
"""

import base64
import hashlib
import hmac
import json
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


MAX_VAULT_BYTES = 64 * 1024 * 1024
V2_SCRYPT_N = 2**15
V2_SCRYPT_R = 8
V2_SCRYPT_P = 1
V2_SALT_BYTES = 16
V2_NONCE_BYTES = 12
V2_AAD = b"HexiKeys encrypted vault format v2"
LEGACY_PBKDF2_ROUNDS = 240_000


class VaultAuthenticationError(ValueError):
    """The encrypted vault could not be authenticated with this password."""


def _b64encode(value):
    return base64.b64encode(value).decode("ascii")


def _b64decode(value, *, expected_length=None):
    if not isinstance(value, str):
        raise ValueError("Invalid vault encoding")
    try:
        decoded = base64.b64decode(value.encode("ascii"), validate=True)
    except (ValueError, UnicodeError) as exc:
        raise ValueError("Invalid vault encoding") from exc
    if expected_length is not None and len(decoded) != expected_length:
        raise ValueError("Invalid vault encoding length")
    return decoded


def _password_bytes(password):
    if not isinstance(password, str) or not password:
        raise ValueError("Master password is required")
    encoded = password.encode("utf-8")
    if len(encoded) > 4096:
        raise ValueError("Master password is too long")
    return encoded


def _derive_v2_key(password, salt):
    return hashlib.scrypt(
        _password_bytes(password),
        salt=salt,
        n=V2_SCRYPT_N,
        r=V2_SCRYPT_R,
        p=V2_SCRYPT_P,
        dklen=32,
        maxmem=128 * 1024 * 1024,
    )


def _validate_payload(payload):
    if not isinstance(payload, dict) or not isinstance(payload.get("entries"), list):
        raise ValueError("Vault contents have an unsupported format")
    if len(payload["entries"]) > 100_000:
        raise ValueError("Vault contains too many entries")
    for entry in payload["entries"]:
        if not isinstance(entry, dict):
            raise ValueError("Vault contains an invalid entry")
        if not isinstance(entry.get("id"), str) or not isinstance(entry.get("title"), str):
            raise ValueError("Vault contains an invalid entry")
        fields = entry.get("fields", [])
        if not isinstance(fields, list):
            raise ValueError("Vault contains invalid entry fields")
        for field in fields:
            if not isinstance(field, dict) or not isinstance(field.get("label"), str) or not isinstance(field.get("value"), str):
                raise ValueError("Vault contains an invalid field")
    return payload


def encrypt_vault(payload, password):
    _validate_payload(payload)
    plaintext = json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    if len(plaintext) > MAX_VAULT_BYTES:
        raise ValueError("Vault is too large to save")
    salt = secrets.token_bytes(V2_SALT_BYTES)
    nonce = secrets.token_bytes(V2_NONCE_BYTES)
    ciphertext = AESGCM(_derive_v2_key(password, salt)).encrypt(nonce, plaintext, V2_AAD)
    return {
        "format": "HexiKeysVault",
        "version": 2,
        "kdf": {"name": "scrypt", "n": V2_SCRYPT_N, "r": V2_SCRYPT_R, "p": V2_SCRYPT_P},
        "cipher": "AES-256-GCM",
        "salt": _b64encode(salt),
        "nonce": _b64encode(nonce),
        "data": _b64encode(ciphertext),
    }


def _decrypt_v1(blob, password):
    try:
        salt = _b64decode(blob["salt"], expected_length=16)
        nonce = _b64decode(blob["nonce"], expected_length=16)
        ciphertext = _b64decode(blob["data"])
        tag = _b64decode(blob["tag"], expected_length=32)
    except (KeyError, TypeError) as exc:
        raise ValueError("Invalid legacy vault format") from exc
    key = hashlib.pbkdf2_hmac("sha256", _password_bytes(password), salt, LEGACY_PBKDF2_ROUNDS, 32)
    expected_tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected_tag):
        raise VaultAuthenticationError("Wrong master password or vault authentication failed")
    stream = bytearray()
    counter = 0
    while len(stream) < len(ciphertext):
        stream.extend(hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
        counter += 1
    plaintext = bytes(a ^ b for a, b in zip(ciphertext, stream))
    try:
        return _validate_payload(json.loads(plaintext.decode("utf-8")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Legacy vault contents are damaged") from exc


def decrypt_vault(blob, password):
    if not isinstance(blob, dict) or type(blob.get("version")) is not int:
        raise ValueError("Unsupported vault format")
    if blob["version"] == 1:
        return _decrypt_v1(blob, password)
    if blob["version"] != 2 or blob.get("format") != "HexiKeysVault":
        raise ValueError("Unsupported vault format")
    kdf = blob.get("kdf")
    if kdf != {"name": "scrypt", "n": V2_SCRYPT_N, "r": V2_SCRYPT_R, "p": V2_SCRYPT_P}:
        raise ValueError("Unsupported vault key-derivation parameters")
    if blob.get("cipher") != "AES-256-GCM":
        raise ValueError("Unsupported vault encryption")
    salt = _b64decode(blob.get("salt"), expected_length=V2_SALT_BYTES)
    nonce = _b64decode(blob.get("nonce"), expected_length=V2_NONCE_BYTES)
    ciphertext = _b64decode(blob.get("data"))
    if len(ciphertext) < 16 or len(ciphertext) > MAX_VAULT_BYTES + 16:
        raise ValueError("Vault data size is invalid")
    try:
        plaintext = AESGCM(_derive_v2_key(password, salt)).decrypt(nonce, ciphertext, V2_AAD)
    except InvalidTag as exc:
        raise VaultAuthenticationError("Wrong master password or vault authentication failed") from exc
    try:
        return _validate_payload(json.loads(plaintext.decode("utf-8")))
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("Vault contents are damaged") from exc
