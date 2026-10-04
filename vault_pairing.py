"""Create a local, current-user-protected HexiGrid pairing descriptor.

The descriptor is an import handoff, not a pairing flow: app-level consent and
authorization must be completed by the caller before this helper is invoked.
DPAPI protects the bytes at rest for this Windows user; it does not isolate
them from another process running as the same user.
"""

import base64
import json
import os
import re
import secrets
import stat
import subprocess
import tempfile
from pathlib import Path


DESCRIPTOR_FILENAME = "hexikeys-pairing.dpapi"
DESCRIPTOR_VERSION = 1
MAX_DESCRIPTOR_BYTES = 4096
PIPE_ID_RE = re.compile(r"hexikeys-[0-9a-f]{32}\Z")
HMAC_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
_CURRENT_SID_RE = re.compile(r"S-1-(?:[0-9]+-)*[0-9]+")


def pairing_descriptor_path(data_dir):
    """Return the fixed descriptor path under the configured data directory."""
    return Path(data_dir) / DESCRIPTOR_FILENAME


def _run_dpapi(plaintext, *, protect):
    if os.name != "nt":
        raise RuntimeError("Windows CurrentUser DPAPI is unavailable.")
    if not isinstance(plaintext, bytes) or len(plaintext) > MAX_DESCRIPTOR_BYTES:
        raise ValueError("Pairing descriptor is invalid.")

    operation = "Protect" if protect else "Unprotect"
    script = (
        "$ErrorActionPreference='Stop'; Add-Type -AssemblyName System.Security; "
        "$encoded=[Console]::In.ReadToEnd(); "
        "$inputBytes=[Convert]::FromBase64String($encoded); "
        f"$outputBytes=[Security.Cryptography.ProtectedData]::{operation}("
        "$inputBytes,$null,[Security.Cryptography.DataProtectionScope]::CurrentUser); "
        "[Console]::Out.Write([Convert]::ToBase64String($outputBytes))"
    )
    try:
        result = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
            input=base64.b64encode(plaintext),
            capture_output=True,
            check=False,
            timeout=15,
            shell=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError("Windows CurrentUser DPAPI operation failed.") from exc
    if result.returncode != 0:
        raise RuntimeError("Windows CurrentUser DPAPI operation failed.")
    try:
        protected = base64.b64decode(result.stdout.strip(), validate=True)
    except (ValueError, base64.binascii.Error) as exc:
        raise RuntimeError("Windows CurrentUser DPAPI operation failed.") from exc
    if not protected or len(protected) > MAX_DESCRIPTOR_BYTES:
        raise RuntimeError("Windows CurrentUser DPAPI operation failed.")
    return protected


def protect_current_user(plaintext):
    """Protect bytes with Windows DPAPI CurrentUser, passing data only on stdin."""
    return _run_dpapi(plaintext, protect=True)


def unprotect_current_user(ciphertext):
    """Unprotect bytes with Windows DPAPI CurrentUser, passing data only on stdin."""
    return _run_dpapi(ciphertext, protect=False)


def _restrict_to_current_user(path):
    """Disable inherited ACLs and grant full control only to the current SID."""
    if os.name != "nt":
        raise RuntimeError("A Windows current-user ACL is unavailable.")
    try:
        identity = subprocess.run(
            ["whoami.exe", "/user", "/fo", "csv", "/nh"],
            capture_output=True,
            check=False,
            timeout=10,
            shell=False,
        )
        if identity.returncode != 0:
            raise RuntimeError
        sids = _CURRENT_SID_RE.findall(identity.stdout.decode("utf-8", errors="replace"))
        if len(sids) != 1:
            raise RuntimeError
        result = subprocess.run(
            ["icacls.exe", os.fspath(path), "/inheritance:r", "/grant:r", f"*{sids[0]}:(F)"],
            capture_output=True,
            check=False,
            timeout=10,
            shell=False,
        )
        if result.returncode != 0:
            raise RuntimeError
    except (OSError, subprocess.TimeoutExpired, RuntimeError) as exc:
        raise RuntimeError("Could not restrict pairing descriptor access.") from exc


def _descriptor_payload(pipe_id, hmac_key):
    if not isinstance(pipe_id, str) or not PIPE_ID_RE.fullmatch(pipe_id):
        raise ValueError("Pairing pipe ID is invalid.")
    if not isinstance(hmac_key, str) or not HMAC_KEY_RE.fullmatch(hmac_key):
        raise ValueError("Pairing key is invalid.")
    return json.dumps(
        {"version": DESCRIPTOR_VERSION, "pipeId": pipe_id, "hmacKey": hmac_key},
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("ascii")


def _read_previous_descriptor(target):
    try:
        info = target.lstat()
    except FileNotFoundError:
        return None
    if target.is_symlink() or not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > MAX_DESCRIPTOR_BYTES:
        raise ValueError("Existing pairing descriptor is invalid.")
    with target.open("rb") as stream:
        raw = stream.read(MAX_DESCRIPTOR_BYTES + 1)
    if not raw or len(raw) > MAX_DESCRIPTOR_BYTES:
        raise ValueError("Existing pairing descriptor is invalid.")
    return raw


def _stage_protected_descriptor(target, protected, restrict_acl):
    fd, pending_name = tempfile.mkstemp(
        prefix=f".{DESCRIPTOR_FILENAME}.", suffix=".pending", dir=target.parent
    )
    os.close(fd)
    pending = Path(pending_name)
    try:
        # Apply the final ACL to the staging file before writing any bytes.
        restrict_acl(pending)
        with pending.open("wb") as stream:
            stream.write(protected)
            stream.flush()
            os.fsync(stream.fileno())
        return pending
    except Exception:
        try:
            pending.unlink(missing_ok=True)
        except OSError:
            pass
        raise


def _publish_pending(pending, target, replace):
    replace(os.fspath(pending), os.fspath(target))


def _restore_descriptor_snapshot(target, previous, attempted_new, restrict_acl):
    current = _read_previous_descriptor(target)
    if current == previous:
        return
    if current != attempted_new:
        raise RuntimeError("Pairing descriptor changed during rollback.")
    if previous is None:
        target.unlink(missing_ok=True)
        return
    pending = _stage_protected_descriptor(target, previous, restrict_acl)
    try:
        os.replace(os.fspath(pending), os.fspath(target))
        pending = None
    finally:
        if pending is not None:
            try:
                pending.unlink(missing_ok=True)
            except OSError:
                pass


def _validated_material(pipe_id, hmac_key):
    if isinstance(hmac_key, str):
        if not HMAC_KEY_RE.fullmatch(hmac_key):
            raise ValueError("Pairing key is invalid.")
        key_bytes = bytes.fromhex(hmac_key)
        key_hex = hmac_key
    elif isinstance(hmac_key, (bytes, bytearray, memoryview)):
        key_bytes = bytes(hmac_key)
        if len(key_bytes) != 32:
            raise ValueError("Pairing key is invalid.")
        key_hex = key_bytes.hex()
    else:
        raise ValueError("Pairing key is invalid.")
    payload = _descriptor_payload(pipe_id, key_hex)
    return payload, key_bytes, key_hex


def create_pairing_descriptor(
    data_dir,
    *,
    protect=protect_current_user,
    restrict_acl=_restrict_to_current_user,
    pipe_id_factory=None,
    key_factory=None,
    replace=os.replace,
):
    """Atomically publish a protected descriptor and return only its pipe ID.

    The injectable functions keep disk and protection failures testable. A
    production caller must use the defaults, after obtaining explicit consent.
    """
    pipe_id = (pipe_id_factory or (lambda: "hexikeys-" + secrets.token_hex(16)))()
    hmac_key = (key_factory or (lambda: secrets.token_hex(32)))()
    plaintext, _key_bytes, _key_hex = _validated_material(pipe_id, hmac_key)
    protected = protect(plaintext)
    if not isinstance(protected, bytes) or not protected or len(protected) > MAX_DESCRIPTOR_BYTES:
        raise RuntimeError("Windows CurrentUser DPAPI returned an invalid descriptor.")
    target = pairing_descriptor_path(data_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    pending = _stage_protected_descriptor(target, protected, restrict_acl)
    try:
        _publish_pending(pending, target, replace)
        pending = None
    finally:
        if pending is not None:
            try:
                pending.unlink(missing_ok=True)
            except OSError:
                pass
    return pipe_id


def create_pairing_material(
    data_dir,
    *,
    persist,
    rollback,
    protect=protect_current_user,
    restrict_acl=_restrict_to_current_user,
    pipe_id_factory=None,
    key_factory=None,
    replace=os.replace,
):
    """Persist matching encrypted-vault metadata and DPAPI descriptor atomically.

    ``persist`` receives ``{version, pipeId, hmacKey}``, where ``hmacKey`` is
    transient 32-byte key material, and must atomically commit it to the
    existing encrypted vault. It returns an opaque rollback token; if it raises,
    it must leave the prior vault state unchanged. The helper
    stages the protected descriptor first, calls ``persist``, then publishes
    the descriptor. If publication fails, ``rollback(token)`` must restore the
    exact encrypted-vault state it replaced. The key is never returned or
    logged; this helper returns only the safe pipe ID.
    """
    if not callable(persist) or not callable(rollback):
        raise TypeError("Pairing persistence and rollback callbacks are required.")
    pipe_id = (pipe_id_factory or (lambda: "hexikeys-" + secrets.token_hex(16)))()
    hmac_key = (key_factory or (lambda: secrets.token_hex(32)))()
    plaintext, key_bytes, _key_hex = _validated_material(pipe_id, hmac_key)
    protected = protect(plaintext)
    if not isinstance(protected, bytes) or not protected or len(protected) > MAX_DESCRIPTOR_BYTES:
        raise RuntimeError("Windows CurrentUser DPAPI returned an invalid descriptor.")

    target = pairing_descriptor_path(data_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    previous_descriptor = _read_previous_descriptor(target)
    pending = _stage_protected_descriptor(target, protected, restrict_acl)
    rollback_token = None
    persisted = False
    try:
        rollback_token = persist({"version": DESCRIPTOR_VERSION, "pipeId": pipe_id, "hmacKey": key_bytes})
        persisted = True
        _publish_pending(pending, target, replace)
        pending = None
    except Exception as publish_error:
        if persisted:
            rollback_errors = []
            try:
                _restore_descriptor_snapshot(target, previous_descriptor, protected, restrict_acl)
            except Exception as descriptor_rollback_error:
                rollback_errors.append(descriptor_rollback_error)
            try:
                rollback(rollback_token)
            except Exception as vault_rollback_error:
                rollback_errors.append(vault_rollback_error)
            if rollback_errors:
                raise RuntimeError("Pairing publication failed and rollback could not be confirmed.") from rollback_errors[0]
        raise publish_error
    finally:
        if pending is not None:
            try:
                pending.unlink(missing_ok=True)
            except OSError:
                pass
    return pipe_id


def restore_pairing_descriptor(
    data_dir,
    *,
    pipe_id,
    hmac_key,
    protect=protect_current_user,
    unprotect=unprotect_current_user,
    restrict_acl=_restrict_to_current_user,
    replace=os.replace,
):
    """Reseal existing encrypted-vault material without rotating the pairing."""
    plaintext, _key_bytes, _key_hex = _validated_material(pipe_id, hmac_key)
    target = pairing_descriptor_path(data_dir)
    target.parent.mkdir(parents=True, exist_ok=True)
    existing = _read_previous_descriptor(target)
    if existing is not None:
        try:
            opened = unprotect(existing)
        except Exception as exc:
            raise ValueError("Existing pairing descriptor cannot be verified.") from exc
        if opened != plaintext:
            raise ValueError("Existing pairing descriptor belongs to a different pairing.")
        return pipe_id

    protected = protect(plaintext)
    if not isinstance(protected, bytes) or not protected or len(protected) > MAX_DESCRIPTOR_BYTES:
        raise RuntimeError("Windows CurrentUser DPAPI returned an invalid descriptor.")
    pending = _stage_protected_descriptor(target, protected, restrict_acl)
    try:
        _publish_pending(pending, target, replace)
        pending = None
    finally:
        if pending is not None:
            try:
                pending.unlink(missing_ok=True)
            except OSError:
                pass
    return pipe_id


def remove_pairing_descriptor(data_dir):
    """Remove the fixed handoff file without following a descriptor symlink."""
    pairing_descriptor_path(data_dir).unlink(missing_ok=True)
