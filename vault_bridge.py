"""Authenticated, current-logon Windows named-pipe bridge for HexiKeys.

This module deliberately has no vault-file access and no unauthenticated
pairing endpoint. The embedding HexiKeys host supplies callbacks for the
already-unlocked vault and durable encrypted persistence. Only the trusted
local host should hold the pairing key or call the consume operation.

Wire format: a four-byte big-endian length followed by a UTF-8 JSON envelope.
The envelope carries a base64-encoded UTF-8 JSON payload and an HMAC-SHA256
over protocol direction, version, nonce, and the exact payload bytes. Python
pickle and arbitrary exception text are never used on the wire.
"""

from __future__ import annotations

import base64
import binascii
import ctypes
import ctypes.wintypes
import hashlib
import hmac
import json
import os
import re
import struct
import threading
import time
from collections import OrderedDict
from typing import Callable


MAX_FRAME_BYTES = 64 * 1024
MAX_SECRET_BYTES = 48 * 1024
MAX_REQUEST_SECONDS = 5.0
MAX_WORKERS = 8
PIPE_NAME_RE = re.compile(r"hexikeys-[0-9a-f]{32}\Z")
NONCE_RE = re.compile(r"[0-9a-f]{64}\Z")
MAC_RE = re.compile(r"[0-9a-f]{64}\Z")
_REQUEST_FIELDS = frozenset({
    "grantId", "requestId", "connectorId", "capabilityId", "taskId",
    "origin", "path", "method", "header", "prefix",
})
_FIELD_LIMITS = {
    "grantId": 32,
    "requestId": 32,
    "connectorId": 63,
    "capabilityId": 63,
    "taskId": 128,
    "origin": 300,
    "path": 2048,
    "method": 12,
    "header": 88,
    "prefix": 64,
}
NEW_ITEM_CATEGORIES = (
    "Password", "API key", "Token", "Recovery phrase", "Backup codes",
    "License key", "Secure note", "Screenshot OCR", "Other",
)
_NEW_ITEM_REQUEST_FIELDS = frozenset({
    "requestId", "title", "category", "fieldLabel", "requestedBy", "expiresAt",
})
_NEW_ITEM_REQUEST_ID_RE = re.compile(r"[0-9a-f]{32}\Z")


def validate_new_item_request(payload: object, *, now: int | None = None) -> dict:
    """Validate the non-secret request that opens the owner-controlled item form."""
    if not isinstance(payload, dict) or set(payload) != {"op", *_NEW_ITEM_REQUEST_FIELDS}:
        raise ValueError("invalid")
    if payload.get("op") != "request-new-item":
        raise ValueError("invalid")
    request_id = payload.get("requestId")
    if not isinstance(request_id, str) or not _NEW_ITEM_REQUEST_ID_RE.fullmatch(request_id):
        raise ValueError("invalid")
    for key, limit in (("title", 120), ("fieldLabel", 80), ("requestedBy", 120)):
        value = payload.get(key)
        if (not isinstance(value, str) or not value.strip() or len(value) > limit
                or any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in value)):
            raise ValueError("invalid")
    if payload.get("category") not in NEW_ITEM_CATEGORIES:
        raise ValueError("invalid")
    expires_at = payload.get("expiresAt")
    current_time = int(time.time()) if now is None else now
    if (type(expires_at) is not int or type(current_time) is not int
            or not current_time < expires_at <= current_time + 60):
        raise ValueError("invalid")
    return dict(payload)


class VaultBridgeError(RuntimeError):
    """A transport startup or lifecycle error with no vault content."""


class _Denied(Exception):
    pass


class _Locked(Exception):
    pass


class _Unavailable(Exception):
    pass


class _StorageUnavailable(Exception):
    pass


def _json_bytes(value: object) -> bytes:
    return json.dumps(
        value,
        ensure_ascii=False,
        separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8")


def _mac_input(direction: bytes, nonce: str, payload_b64: str) -> bytes:
    return direction + b"\0v1\0" + nonce.encode("ascii") + b"\0" + payload_b64.encode("ascii")


def _decode_payload(payload_b64: object) -> object:
    if not isinstance(payload_b64, str) or len(payload_b64) > (MAX_FRAME_BYTES * 4 // 3 + 8):
        raise ValueError("invalid")
    try:
        raw = base64.b64decode(payload_b64, validate=True)
        if base64.b64encode(raw).decode("ascii") != payload_b64:
            raise ValueError("invalid")
        return json.loads(raw.decode("utf-8"))
    except (ValueError, UnicodeError, binascii.Error, json.JSONDecodeError):
        raise ValueError("invalid") from None


def _envelope(key: bytes, direction: bytes, nonce: str, payload: object) -> bytes:
    payload_b64 = base64.b64encode(_json_bytes(payload)).decode("ascii")
    signature = hmac.new(key, _mac_input(direction, nonce, payload_b64), hashlib.sha256).hexdigest()
    return _json_bytes({"v": 1, "nonce": nonce, "payload": payload_b64, "mac": signature})


def _validate_request_payload(payload: object) -> dict:
    if not isinstance(payload, dict):
        raise _Denied()
    if set(payload) == {"op", *_NEW_ITEM_REQUEST_FIELDS}:
        try:
            return validate_new_item_request(payload)
        except (TypeError, ValueError):
            raise _Denied() from None
    if set(payload) not in ({"op"}, {"op", "offset", "limit"}, {"op", *_REQUEST_FIELDS}):
        raise _Denied()
    operation = payload.get("op")
    if operation == "status" and set(payload) in ({"op"}, {"op", "offset", "limit"}):
        offset = payload.get("offset", 0)
        limit = payload.get("limit", 16)
        if type(offset) is not int or not 0 <= offset <= 1000 or type(limit) is not int or not 1 <= limit <= 24:
            raise _Denied()
        return {"op": "status", "offset": offset, "limit": limit}
    if operation != "consume" or set(payload) != {"op", *_REQUEST_FIELDS}:
        raise _Denied()
    request = {key: payload[key] for key in _REQUEST_FIELDS}
    for key, limit in _FIELD_LIMITS.items():
        value = request.get(key)
        if not isinstance(value, str) or (key != "prefix" and not value) or len(value) > limit:
            raise _Denied()
    return {"op": "consume", **request}


class _Win32:
    """Small ctypes surface for explicit-DACL, overlapped named pipes."""

    def __init__(self) -> None:
        if os.name != "nt":
            raise VaultBridgeError("The HexiKeys bridge requires Windows named pipes.")
        self.k32 = ctypes.WinDLL("kernel32", use_last_error=True)
        self.a32 = ctypes.WinDLL("advapi32", use_last_error=True)

        wintypes = ctypes.wintypes
        self.DWORD = wintypes.DWORD
        self.BOOL = wintypes.BOOL
        self.HANDLE = wintypes.HANDLE
        self.LPWSTR = wintypes.LPWSTR
        self.LPCWSTR = wintypes.LPCWSTR
        self.LPVOID = wintypes.LPVOID

        class SECURITY_ATTRIBUTES(ctypes.Structure):
            _fields_ = [
                ("nLength", self.DWORD),
                ("lpSecurityDescriptor", self.LPVOID),
                ("bInheritHandle", self.BOOL),
            ]

        class OVERLAPPED(ctypes.Structure):
            _fields_ = [
                ("Internal", ctypes.c_size_t),
                ("InternalHigh", ctypes.c_size_t),
                ("Offset", self.DWORD),
                ("OffsetHigh", self.DWORD),
                ("hEvent", self.HANDLE),
            ]

        self.SECURITY_ATTRIBUTES = SECURITY_ATTRIBUTES
        self.OVERLAPPED = OVERLAPPED
        self._bind()

    def _bind(self) -> None:
        k32, a32 = self.k32, self.a32
        k32.GetCurrentProcess.restype = self.HANDLE
        k32.CreateEventW.argtypes = [self.LPVOID, self.BOOL, self.BOOL, self.LPCWSTR]
        k32.CreateEventW.restype = self.HANDLE
        k32.CloseHandle.argtypes = [self.HANDLE]
        k32.CloseHandle.restype = self.BOOL
        k32.CreateNamedPipeW.argtypes = [
            self.LPCWSTR, self.DWORD, self.DWORD, self.DWORD,
            self.DWORD, self.DWORD, self.DWORD,
            ctypes.POINTER(self.SECURITY_ATTRIBUTES),
        ]
        k32.CreateNamedPipeW.restype = self.HANDLE
        k32.ConnectNamedPipe.argtypes = [self.HANDLE, ctypes.POINTER(self.OVERLAPPED)]
        k32.ConnectNamedPipe.restype = self.BOOL
        k32.DisconnectNamedPipe.argtypes = [self.HANDLE]
        k32.DisconnectNamedPipe.restype = self.BOOL
        k32.CancelIoEx.argtypes = [self.HANDLE, ctypes.POINTER(self.OVERLAPPED)]
        k32.CancelIoEx.restype = self.BOOL
        k32.WaitForSingleObject.argtypes = [self.HANDLE, self.DWORD]
        k32.WaitForSingleObject.restype = self.DWORD
        k32.ReadFile.argtypes = [self.HANDLE, self.LPVOID, self.DWORD, ctypes.POINTER(self.DWORD), ctypes.POINTER(self.OVERLAPPED)]
        k32.ReadFile.restype = self.BOOL
        k32.WriteFile.argtypes = [self.HANDLE, self.LPVOID, self.DWORD, ctypes.POINTER(self.DWORD), ctypes.POINTER(self.OVERLAPPED)]
        k32.WriteFile.restype = self.BOOL
        k32.GetOverlappedResult.argtypes = [self.HANDLE, ctypes.POINTER(self.OVERLAPPED), ctypes.POINTER(self.DWORD), self.BOOL]
        k32.GetOverlappedResult.restype = self.BOOL
        k32.LocalFree.argtypes = [self.LPVOID]
        k32.LocalFree.restype = self.LPVOID

        a32.OpenProcessToken.argtypes = [self.HANDLE, self.DWORD, ctypes.POINTER(self.HANDLE)]
        a32.OpenProcessToken.restype = self.BOOL
        a32.GetTokenInformation.argtypes = [self.HANDLE, ctypes.c_int, self.LPVOID, self.DWORD, ctypes.POINTER(self.DWORD)]
        a32.GetTokenInformation.restype = self.BOOL
        a32.ConvertSidToStringSidW.argtypes = [self.LPVOID, ctypes.POINTER(self.LPWSTR)]
        a32.ConvertSidToStringSidW.restype = self.BOOL
        a32.ConvertStringSecurityDescriptorToSecurityDescriptorW.argtypes = [
            self.LPCWSTR, self.DWORD, ctypes.POINTER(self.LPVOID), ctypes.POINTER(self.DWORD),
        ]
        a32.ConvertStringSecurityDescriptorToSecurityDescriptorW.restype = self.BOOL

    def create_event(self):
        handle = self.k32.CreateEventW(None, True, False, None)
        if not handle:
            raise VaultBridgeError("Windows could not create a bridge event.")
        return handle

    def current_logon_sid_sddl(self) -> str:
        token = self.HANDLE()
        if not self.a32.OpenProcessToken(self.k32.GetCurrentProcess(), 0x0008, ctypes.byref(token)):
            raise VaultBridgeError("Windows could not read the current logon identity.")
        try:
            needed = self.DWORD(0)
            self.a32.GetTokenInformation(token, 2, None, 0, ctypes.byref(needed))
            if not needed.value or needed.value > 1024 * 1024:
                raise VaultBridgeError("Windows returned invalid logon identity data.")
            groups_buf = ctypes.create_string_buffer(needed.value)
            if not self.a32.GetTokenInformation(token, 2, groups_buf, needed.value, ctypes.byref(needed)):
                raise VaultBridgeError("Windows could not read the current logon identity.")

            class SID_AND_ATTRIBUTES(ctypes.Structure):
                _fields_ = [("Sid", self.LPVOID), ("Attributes", self.DWORD)]

            class TOKEN_GROUPS(ctypes.Structure):
                _fields_ = [("GroupCount", self.DWORD), ("Groups", SID_AND_ATTRIBUTES * 1)]

            count = ctypes.cast(groups_buf, ctypes.POINTER(TOKEN_GROUPS)).contents.GroupCount
            if count > 4096:
                raise VaultBridgeError("Windows returned invalid logon identity data.")
            groups_offset = TOKEN_GROUPS.Groups.offset
            group_size = ctypes.sizeof(SID_AND_ATTRIBUTES)
            found_sid = None
            for index in range(count):
                address = ctypes.addressof(groups_buf) + groups_offset + index * group_size
                group = ctypes.cast(address, ctypes.POINTER(SID_AND_ATTRIBUTES)).contents
                if group.Attributes & 0xC0000000 == 0xC0000000:
                    found_sid = group.Sid
                    break
            if found_sid is None:
                raise VaultBridgeError("Windows did not provide a current logon identity.")
            sid_string = self.LPWSTR()
            if not self.a32.ConvertSidToStringSidW(found_sid, ctypes.byref(sid_string)):
                raise VaultBridgeError("Windows could not encode the current logon identity.")
            try:
                if not sid_string.value or not re.fullmatch(r"S-1-(?:[0-9]+-)+[0-9]+", sid_string.value):
                    raise VaultBridgeError("Windows returned an invalid current logon identity.")
                return f"D:P(A;;GA;;;{sid_string.value})"
            finally:
                self.k32.LocalFree(ctypes.cast(sid_string, self.LPVOID))
        finally:
            self.k32.CloseHandle(token)

    def create_security_attributes(self, sddl: str):
        descriptor = self.LPVOID()
        if not self.a32.ConvertStringSecurityDescriptorToSecurityDescriptorW(
            sddl, 1, ctypes.byref(descriptor), None
        ):
            raise VaultBridgeError("Windows could not secure the local bridge pipe.")
        attrs = self.SECURITY_ATTRIBUTES()
        attrs.nLength = ctypes.sizeof(attrs)
        attrs.lpSecurityDescriptor = descriptor
        attrs.bInheritHandle = False
        return attrs, descriptor

    def create_pipe(self, path: str, attrs, max_instances: int, *, first_instance: bool):
        pipe_access = 0x00000003 | 0x40000000  # duplex + overlapped
        if first_instance:
            pipe_access |= 0x00080000
        pipe_mode = 0x00000000 | 0x00000000 | 0x00000008  # byte mode + reject remote clients
        handle = self.k32.CreateNamedPipeW(
            path, pipe_access, pipe_mode, max_instances, 4096, 4096, 0, ctypes.byref(attrs)
        )
        invalid = ctypes.c_void_p(-1).value
        if not handle or ctypes.cast(handle, ctypes.c_void_p).value == invalid:
            raise VaultBridgeError("Windows could not create the secured local bridge pipe.")
        return handle


class VaultBridgeServer:
    """Serve authenticated status and scoped credential-use requests locally.

    `get_status` must return `{"available": bool, "unlocked": bool}` and
    defaults to locked/unavailable. `get_vault` returns the host's current
    decrypted vault only while unlocked. `persist_candidate` must durably
    save the candidate encrypted vault. `authorize_release(request, receipt)`
    must recheck the exact owner session, effective policy, and vault generation;
    it is called after persistence and again immediately before the response.
    All callbacks run on bounded pipe worker threads. A Tk host must marshal
    them to its owning thread without blocking that thread in `close()`; call
    `stop()` there and poll `wait_closed(0)` while the event loop keeps running.
    No callback error text is returned or logged.

    A timeout can occur after a use was durably recorded. Hosts must not
    transparently retry a consume with a new request ID; encrypted grant state
    enforces the original request ID even after the bounded pipe nonce cache expires.
    """

    def __init__(
        self,
        pipe_id: str,
        pairing_key: bytes,
        *,
        get_status: Callable[[], dict] | None = None,
        get_vault: Callable[[], dict | None] | None = None,
        persist_candidate: Callable[[dict], object] | None = None,
        authorize_release: Callable[[dict, dict], bool] | None = None,
        request_new_item: Callable[[dict], dict] | None = None,
        request_timeout: float = MAX_REQUEST_SECONDS,
        max_workers: int = 4,
    ) -> None:
        if not isinstance(pipe_id, str) or not PIPE_NAME_RE.fullmatch(pipe_id):
            raise ValueError("Use a local HexiKeys pipe name.")
        if not isinstance(pairing_key, (bytes, bytearray)) or len(pairing_key) != 32:
            raise ValueError("The local bridge key must contain exactly 32 bytes.")
        if isinstance(request_timeout, bool) or not isinstance(request_timeout, (int, float)) or not 0.1 <= request_timeout <= 30:
            raise ValueError("The local bridge deadline must be between 0.1 and 30 seconds.")
        if type(max_workers) is not int or not 1 <= max_workers <= MAX_WORKERS:
            raise ValueError("The local bridge worker limit is invalid.")

        self.pipe_id = pipe_id
        self.pipe_path = rf"\\.\pipe\{pipe_id}"
        self._key = bytearray(pairing_key)
        self._get_status = get_status
        self._get_vault = get_vault
        self._persist_candidate = persist_candidate
        self._authorize_release = authorize_release
        self._request_new_item = request_new_item
        self._request_timeout = float(request_timeout)
        self._max_workers = max_workers
        self._stop = threading.Event()
        self._start_lock = threading.Lock()
        self._consume_lock = threading.Lock()
        self._workers_lock = threading.Lock()
        self._workers: set[threading.Thread] = set()
        self._worker_slots = threading.BoundedSemaphore(max_workers)
        self._seen_nonces: OrderedDict[str, float] = OrderedDict()
        self._replay_lock = threading.Lock()
        self._replay_limit = 4096
        self._replay_ttl = 600.0
        self._started = False
        self._closed = False
        self._ready = threading.Event()
        self._startup_failed = False
        self._cleaned = False
        self._accept_thread: threading.Thread | None = None
        self._accept_handle = None
        self._active_handles: set[int] = set()
        self._active_handles_lock = threading.Lock()
        self._win: _Win32 | None = None
        self._security_descriptor = None
        self._security_attributes = None

    def start(self) -> "VaultBridgeServer":
        with self._start_lock:
            if self._closed:
                raise VaultBridgeError("The local bridge is closed.")
            if self._started:
                return self
            self._win = _Win32()
            self._security_attributes, self._security_descriptor = self._win.create_security_attributes(
                self._win.current_logon_sid_sddl()
            )
            self._accept_thread = threading.Thread(target=self._accept_loop, name="HexiKeysVaultPipe", daemon=True)
            self._started = True
            self._accept_thread.start()
        if not self._ready.wait(2.0) or self._startup_failed:
            self.stop()
            self.wait_closed(2.0)
            raise VaultBridgeError("Windows could not start the secured local bridge pipe.")
        return self

    @property
    def running(self) -> bool:
        return self._started and not self._closed and not self._stop.is_set()

    def stop(self) -> None:
        """Nonblocking stop for UI-thread hosts; cancels pipe I/O immediately."""
        with self._start_lock:
            self._closed = True
            self._stop.set()
            win = self._win
            with self._active_handles_lock:
                if win is not None:
                    if self._accept_handle:
                        win.k32.CancelIoEx(self._accept_handle, None)
                    for handle in list(self._active_handles):
                        win.k32.CancelIoEx(handle, None)

    def wait_closed(self, timeout: float = 6.0) -> bool:
        """Wait for accept/client workers to drain. Safe to poll with timeout 0.

        Returns False when an injected callback did not drain before timeout.
        The caller must not replace/swap its backing vault state until True.
        No response is released after stop begins, even if a callback finishes.
        """
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)) or timeout < 0 or timeout > 60:
            raise ValueError("The drain timeout is invalid.")
        deadline = time.monotonic() + timeout
        accept_thread = self._accept_thread
        if accept_thread and accept_thread is not threading.current_thread():
            accept_thread.join(max(0.0, deadline - time.monotonic()))
        with self._workers_lock:
            workers = list(self._workers)
        for worker in workers:
            if worker is not threading.current_thread():
                worker.join(max(0.0, deadline - time.monotonic()))
        drained = (accept_thread is None or not accept_thread.is_alive()) and all(not worker.is_alive() for worker in workers)

        win = self._win
        if drained and not self._cleaned:
            if win is not None and self._security_descriptor:
                win.k32.LocalFree(self._security_descriptor)
                self._security_descriptor = None
                self._security_attributes = None
            for index in range(len(self._key)):
                self._key[index] = 0
            self._cleaned = True
        return drained

    def close(self, timeout: float = 6.0) -> bool:
        """Stop and wait. For Tk, use stop() plus wait_closed(0) polling."""
        self.stop()
        return self.wait_closed(timeout)

    def _accept_loop(self) -> None:
        win = self._win
        assert win is not None
        first_instance = True
        max_instances = min(255, self._max_workers + 1)
        while not self._stop.is_set():
            self._prune_workers()
            handle = None
            try:
                handle = win.create_pipe(self.pipe_path, self._security_attributes, max_instances, first_instance=first_instance)
                first_instance = False
                self._ready.set()
                with self._active_handles_lock:
                    self._accept_handle = handle
                connected = self._connect_pipe(handle)
                with self._active_handles_lock:
                    self._accept_handle = None
                if not connected or self._stop.is_set():
                    self._close_pipe(handle)
                    if not self._stop.is_set():
                        # Do not reopen a pipe name without first-instance
                        # protection after an unexpected connect failure.
                        self._stop.set()
                    continue
                if not self._worker_slots.acquire(blocking=False):
                    self._close_pipe(handle)
                    continue
                worker = threading.Thread(target=self._serve_client, args=(handle,), name="HexiKeysVaultClient", daemon=True)
                with self._workers_lock:
                    if self._stop.is_set():
                        self._worker_slots.release()
                        self._close_pipe(handle)
                        continue
                    self._workers.add(worker)
                with self._active_handles_lock:
                    self._active_handles.add(self._handle_value(handle))
                try:
                    worker.start()
                except Exception:
                    with self._workers_lock:
                        self._workers.discard(worker)
                    with self._active_handles_lock:
                        self._active_handles.discard(self._handle_value(handle))
                    self._worker_slots.release()
                    self._close_pipe(handle)
                    handle = None
                    raise
            except Exception:
                if handle:
                    self._close_pipe(handle)
                if not self._ready.is_set():
                    self._startup_failed = True
                    self._ready.set()
                if not self._stop.is_set():
                    self._stop.set()
                break
        with self._active_handles_lock:
            self._accept_handle = None

    def _prune_workers(self) -> None:
        with self._workers_lock:
            self._workers = {worker for worker in self._workers if worker.is_alive()}

    def _connect_pipe(self, handle) -> bool:
        win = self._win
        assert win is not None
        event = win.create_event()
        overlapped = win.OVERLAPPED()
        overlapped.hEvent = event
        try:
            connected = bool(win.k32.ConnectNamedPipe(handle, ctypes.byref(overlapped)))
            error = ctypes.get_last_error() if not connected else 0
            if connected or error == 535:  # ERROR_PIPE_CONNECTED
                return True
            if error != 997:  # ERROR_IO_PENDING
                return False
            while not self._stop.is_set():
                result = win.k32.WaitForSingleObject(event, 100)
                if result == 0:
                    transferred = win.DWORD(0)
                    if win.k32.GetOverlappedResult(handle, ctypes.byref(overlapped), ctypes.byref(transferred), False):
                        return True
                    return ctypes.get_last_error() == 535
                if result != 0x00000102:  # WAIT_TIMEOUT
                    return False
            win.k32.CancelIoEx(handle, ctypes.byref(overlapped))
            win.k32.WaitForSingleObject(event, 1000)
            return False
        finally:
            win.k32.CloseHandle(event)

    @staticmethod
    def _handle_value(handle) -> int:
        return int(ctypes.cast(handle, ctypes.c_void_p).value or 0)

    def _close_pipe(self, handle) -> None:
        win = self._win
        if win is None or not handle:
            return
        try:
            win.k32.DisconnectNamedPipe(handle)
        except Exception:
            pass
        try:
            win.k32.CloseHandle(handle)
        except Exception:
            pass

    def _serve_client(self, handle) -> None:
        win = self._win
        handle_value = self._handle_value(handle)
        deadline = time.monotonic() + self._request_timeout
        try:
            header = self._read_exact(handle, 4, deadline)
            if header is None:
                return
            frame_size = struct.unpack(">I", header)[0]
            if not 1 <= frame_size <= MAX_FRAME_BYTES:
                return
            raw = self._read_exact(handle, frame_size, deadline)
            if raw is None:
                return
            response, release_guard = self._dispatch(raw)
            if response is None or self._stop.is_set():
                return
            if len(response) > MAX_FRAME_BYTES:
                return
            if release_guard is not None and not self._release_still_authorized(*release_guard):
                return
            if self._stop.is_set():
                return
            if self._write_all(handle, struct.pack(">I", len(response)) + response, deadline):
                # Let the client finish reading before disconnecting the pipe;
                # Windows can otherwise discard buffered response bytes.
                self._read_exact(handle, 1, deadline)
        except Exception:
            # Intentionally do not log exception content: callbacks can carry
            # private vault values in their exception chains.
            return
        finally:
            with self._active_handles_lock:
                self._active_handles.discard(handle_value)
                if win is not None:
                    self._close_pipe(handle)
            self._worker_slots.release()

    def _read_exact(self, handle, count: int, deadline: float) -> bytes | None:
        chunks = bytearray()
        while len(chunks) < count:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or self._stop.is_set():
                return None
            buffer = ctypes.create_string_buffer(count - len(chunks))
            transferred = self._pipe_io(handle, buffer, count - len(chunks), read=True, deadline=deadline)
            if transferred <= 0:
                return None
            chunks.extend(buffer.raw[:transferred])
        return bytes(chunks)

    def _write_all(self, handle, data: bytes, deadline: float) -> bool:
        offset = 0
        while offset < len(data):
            if self._stop.is_set() or deadline <= time.monotonic():
                return False
            buffer = ctypes.create_string_buffer(data[offset:])
            written = self._pipe_io(handle, buffer, len(data) - offset, read=False, deadline=deadline)
            if written <= 0:
                return False
            offset += written
        return True

    def _pipe_io(self, handle, buffer, count: int, *, read: bool, deadline: float) -> int:
        win = self._win
        assert win is not None
        event = win.create_event()
        overlapped = win.OVERLAPPED()
        overlapped.hEvent = event
        transferred = win.DWORD(0)
        try:
            if read:
                ok = win.k32.ReadFile(handle, buffer, count, ctypes.byref(transferred), ctypes.byref(overlapped))
            else:
                ok = win.k32.WriteFile(handle, buffer, count, ctypes.byref(transferred), ctypes.byref(overlapped))
            error = ctypes.get_last_error() if not ok else 0
            if ok:
                return int(transferred.value)
            if error != 997:  # ERROR_IO_PENDING
                return 0
            while not self._stop.is_set():
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    win.k32.CancelIoEx(handle, ctypes.byref(overlapped))
                    win.k32.WaitForSingleObject(event, 1000)
                    return 0
                wait_ms = max(1, min(100, int(remaining * 1000)))
                result = win.k32.WaitForSingleObject(event, wait_ms)
                if result == 0:
                    if win.k32.GetOverlappedResult(handle, ctypes.byref(overlapped), ctypes.byref(transferred), False):
                        return int(transferred.value)
                    return 0
                if result != 0x00000102:
                    return 0
            win.k32.CancelIoEx(handle, ctypes.byref(overlapped))
            win.k32.WaitForSingleObject(event, 1000)
            return 0
        finally:
            win.k32.CloseHandle(event)

    def _dispatch(self, raw: bytes) -> tuple[bytes | None, tuple[dict, dict] | None]:
        try:
            envelope = json.loads(raw.decode("utf-8"))
        except (UnicodeError, json.JSONDecodeError):
            return None, None
        if not isinstance(envelope, dict) or set(envelope) != {"v", "nonce", "payload", "mac"}:
            return None, None
        nonce = envelope.get("nonce")
        payload_b64 = envelope.get("payload")
        signature = envelope.get("mac")
        if type(envelope.get("v")) is not int or envelope["v"] != 1:
            return None, None
        if not isinstance(nonce, str) or not NONCE_RE.fullmatch(nonce):
            return None, None
        if not isinstance(payload_b64, str) or not isinstance(signature, str) or not MAC_RE.fullmatch(signature):
            return None, None
        expected = hmac.new(bytes(self._key), _mac_input(b"req", nonce, payload_b64), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, signature):
            return None, None

        release_guard = None
        try:
            payload = _decode_payload(payload_b64)
            self._reserve_nonce(nonce)
            request = _validate_request_payload(payload)
            result = self._execute(request)
            if request["op"] == "consume":
                release_guard = (request, result["receipt"])
            response_payload = {"ok": True, **result}
        except _Replay:
            response_payload = {"ok": False, "error": "denied"}
        except _Locked:
            response_payload = {"ok": False, "error": "locked"}
        except _StorageUnavailable:
            response_payload = {"ok": False, "error": "storage"}
        except _Denied:
            response_payload = {"ok": False, "error": "denied"}
        except _Unavailable:
            response_payload = {"ok": False, "error": "unavailable"}
        except Exception:
            response_payload = {"ok": False, "error": "unavailable"}
        if self._stop.is_set():
            return None, None
        try:
            return _envelope(bytes(self._key), b"res", nonce, response_payload), release_guard
        except Exception:
            return None, None

    def _reserve_nonce(self, nonce: str) -> None:
        now = time.monotonic()
        with self._replay_lock:
            expired_before = now - self._replay_ttl
            while self._seen_nonces:
                _old_nonce, created = next(iter(self._seen_nonces.items()))
                if created > expired_before:
                    break
                self._seen_nonces.popitem(last=False)
            if nonce in self._seen_nonces:
                raise _Replay()
            if len(self._seen_nonces) >= self._replay_limit:
                raise _Unavailable()
            self._seen_nonces[nonce] = now

    def _safe_status(self) -> dict:
        if self._get_status is None:
            return {"available": False, "unlocked": False}
        try:
            value = self._get_status()
            if not isinstance(value, dict):
                raise ValueError()
            return {
                "available": value.get("available") is True,
                "unlocked": value.get("unlocked") is True,
            }
        except Exception:
            return {"available": False, "unlocked": False}

    def _execute(self, request: dict) -> dict:
        if request["op"] == "status":
            return self._status_result(request)
        if request["op"] == "request-new-item":
            status = self._safe_status()
            if not status["available"] or not status["unlocked"]:
                raise _Locked()
            if self._request_new_item is None or self._stop.is_set():
                raise _Unavailable()
            try:
                opened = self._request_new_item(request)
            except Exception:
                raise _Unavailable() from None
            if type(opened) is not dict or opened != {"opened": True}:
                raise _Unavailable()
            return {"opened": True}
        status = self._safe_status()
        if not status["available"] or not status["unlocked"]:
            raise _Locked()
        if self._get_vault is None or self._persist_candidate is None or self._authorize_release is None:
            raise _Unavailable()

        with self._consume_lock:
            if self._stop.is_set():
                raise _Unavailable()
            status = self._safe_status()
            if not status["available"] or not status["unlocked"]:
                raise _Locked()
            try:
                vault = self._get_vault()
            except Exception:
                raise _Unavailable() from None
            if not isinstance(vault, dict):
                raise _Locked()
            if self._stop.is_set():
                raise _Unavailable()
            try:
                from vault_references import (
                    ReferenceAuthorizationError,
                    ReferencePersistenceError,
                    consume_reference_grant,
                )
                secret, receipt = consume_reference_grant(
                    vault,
                    {key: request[key] for key in _REQUEST_FIELDS},
                    persist_candidate=self._persist_candidate,
                )
            except ReferencePersistenceError:
                raise _StorageUnavailable() from None
            except ReferenceAuthorizationError:
                raise _Denied() from None
            except Exception:
                raise _Unavailable() from None
            if not isinstance(secret, str) or not secret or len(secret.encode("utf-8")) > MAX_SECRET_BYTES or not isinstance(receipt, dict):
                raise _Unavailable()
            if not self._release_still_authorized(request, receipt):
                raise _Unavailable()
            return {"value": secret, "receipt": receipt}

    def _status_result(self, request: dict) -> dict:
        status = self._safe_status()
        if not status["available"] or not status["unlocked"] or self._get_vault is None:
            return {"unlocked": False, "grants": [], "total": 0, "nextOffset": None}
        try:
            vault = self._get_vault()
            if not isinstance(vault, dict):
                return {"unlocked": False, "grants": [], "total": 0, "nextOffset": None}
            from vault_references import public_reference_grants
            grants = public_reference_grants(vault)
            if not isinstance(grants, list) or len(grants) > 1000:
                raise ValueError()
            safe = [self._safe_public_grant(item) for item in grants]
            offset = request["offset"]
            limit = request["limit"]
            # Metadata contains untrusted Unicode labels and scopes. Bound the
            # encoded envelope as well as the number of grants in each page.
            page = []
            for grant in safe[offset:offset + limit]:
                candidate_page = [*page, grant]
                candidate_end = offset + len(candidate_page)
                candidate = {
                    "ok": True, "unlocked": True, "grants": candidate_page,
                    "total": len(safe),
                    "nextOffset": candidate_end if candidate_end < len(safe) else None,
                }
                if len(_envelope(bytes(self._key), b"res", "0" * 64, candidate)) > MAX_FRAME_BYTES:
                    break
                page = candidate_page
            next_offset = offset + len(page) if offset + len(page) < len(safe) else None
            return {"unlocked": True, "grants": page, "total": len(safe), "nextOffset": next_offset}
        except Exception:
            return {"unlocked": False, "grants": [], "total": 0, "nextOffset": None}

    @staticmethod
    def _safe_public_grant(grant: object) -> dict:
        if not isinstance(grant, dict):
            raise ValueError("invalid")

        def safe_string(key: str, limit: int, default: str = "Unavailable") -> str:
            value = grant.get(key)
            if not isinstance(value, str):
                return default
            return value[:limit]

        methods = grant.get("methods")
        if not isinstance(methods, list) or len(methods) > 5 or any(
            not isinstance(method, str) or len(method) > 12 for method in methods
        ):
            methods = []
        def safe_int(key: str):
            value = grant.get(key)
            return value if type(value) is int and 0 <= value <= 2**53 - 1 else None

        prefix = grant.get("prefix")
        if (not isinstance(prefix, str) or len(prefix) > 64
                or any(ord(char) < 0x20 or 0x7F <= ord(char) <= 0x9F for char in prefix)):
            raise ValueError("invalid")

        return {
            "id": safe_string("id", 32, ""),
            "itemName": safe_string("itemName", 128),
            "fieldLabel": safe_string("fieldLabel", 128),
            "connectorId": safe_string("connectorId", 63, ""),
            "capabilityId": safe_string("capabilityId", 63, ""),
            "taskId": safe_string("taskId", 128, ""),
            "origin": safe_string("origin", 300, ""),
            "pathPrefix": safe_string("pathPrefix", 500, ""),
            "methods": methods,
            "header": safe_string("header", 88, ""),
            "prefix": prefix,
            "expiresAt": safe_int("expiresAt"),
            "maxUses": safe_int("maxUses"),
            "uses": safe_int("uses"),
            "revoked": grant.get("revoked") is True,
        }

    def _release_still_authorized(self, request: dict, receipt: dict) -> bool:
        if self._stop.is_set() or self._authorize_release is None:
            return False
        try:
            return self._authorize_release(request, receipt) is True
        except Exception:
            return False


class _Replay(Exception):
    pass
