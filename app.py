import json
import os
import ctypes
import copy
import hashlib
import queue
import secrets
import string
import subprocess
import re
import threading
from difflib import SequenceMatcher
import time
import tkinter as tk
import tempfile
from datetime import datetime
from pathlib import Path
from ctypes import wintypes
from tkinter import filedialog, messagebox, simpledialog, ttk
from vault_crypto import VaultAuthenticationError
from vault_store import create_encrypted_backup, copy_encrypted_vault, load_vault, save_vault
from vault_bridge import NEW_ITEM_CATEGORIES, VaultBridgeServer, validate_new_item_request
from vault_pairing import create_pairing_material, pairing_descriptor_path, remove_pairing_descriptor, restore_pairing_descriptor
from vault_grant_ui import show_grant_dialog, show_grants_dialog


APP_NAME = "HexiKeys"
LEGACY_DATA_NAME = "SimpleVault"
APP_DATA_ROOT = Path(os.environ.get("APPDATA") or Path.home())
MAX_JSON_IMPORT_BYTES = 16 * 1024 * 1024
MAX_TEXT_IMPORT_BYTES = 8 * 1024 * 1024
MAX_SCREENSHOT_IMPORT_BYTES = 32 * 1024 * 1024
MAX_SCREENSHOT_PIXELS = 40_000_000
MAX_SCREENSHOT_OCR_CHARS = 1_000_000
IDLE_LOCK_SECONDS = 10 * 60
IDLE_LOCK_CHECK_MS = 15_000
BRIDGE_CALLBACK_QUEUE_SIZE = 32
BRIDGE_CALLBACK_TIMEOUT_SECONDS = 4.0
BRIDGE_PUMP_INTERVAL_MS = 20
BRIDGE_PIPE_ID_RE = re.compile(r"hexikeys-[0-9a-f]{32}\Z")
BRIDGE_KEY_RE = re.compile(r"[0-9a-f]{64}\Z")
PAIRING_DATA_DIR = Path(os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA") or Path.home()) / "HexiKeys"


def hexigrid_pairing_record(vault):
    """Return only a structurally valid encrypted-vault pairing record."""
    if not isinstance(vault, dict):
        return None
    integrations = vault.get("integrations")
    grid = integrations.get("hexigrid") if isinstance(integrations, dict) else None
    pairing = grid.get("pairing") if isinstance(grid, dict) else None
    if not isinstance(pairing, dict) or set(pairing) != {"version", "pipeId", "hmacKey"}:
        return None
    if type(pairing.get("version")) is not int or pairing["version"] != 1:
        return None
    if not isinstance(pairing.get("pipeId"), str) or not BRIDGE_PIPE_ID_RE.fullmatch(pairing["pipeId"]):
        return None
    if not isinstance(pairing.get("hmacKey"), str) or not BRIDGE_KEY_RE.fullmatch(pairing["hmacKey"]):
        return None
    return pairing


def generate_secure_password(length=20, include_symbols=True):
    """Generate a uniformly shuffled password with guaranteed character classes."""
    if type(length) is not int or not 12 <= length <= 128:
        raise ValueError("Password length must be between 12 and 128 characters")
    groups = [string.ascii_lowercase, string.ascii_uppercase, string.digits]
    if include_symbols:
        groups.append("!@#$%^&*()-_=+[]{}:,.?")
    alphabet = "".join(groups)
    characters = [secrets.choice(group) for group in groups]
    characters.extend(secrets.choice(alphabet) for _ in range(length - len(characters)))
    secrets.SystemRandom().shuffle(characters)
    return "".join(characters)


def create_vault_field(label, value="", secret=False):
    """Create an opaque, stable field identity for future narrowly scoped references."""
    return {"id": secrets.token_hex(16), "label": str(label), "value": str(value), "secret": bool(secret)}


def valid_field_id(value):
    return isinstance(value, str) and len(value) == 32 and all(char in "0123456789abcdef" for char in value)


def entry_search_text(entry):
    """Build a search index from labels and non-secret values, never secrets."""
    if not isinstance(entry, dict):
        return ""
    parts = [entry.get("title"), entry.get("category"), entry.get("purpose")]
    fields = entry.get("fields", [])
    if isinstance(fields, list):
        for field in fields:
            if not isinstance(field, dict):
                continue
            parts.append(field.get("label"))
            if field.get("secret") is not True:
                parts.append(field.get("value"))
    return " ".join(part for part in parts if isinstance(part, str)).casefold()


# Keep the existing SimpleVault directory in place while transparently rebranding the app.
LEGACY_DATA_DIR = APP_DATA_ROOT / LEGACY_DATA_NAME
DATA_DIR = LEGACY_DATA_DIR if (LEGACY_DATA_DIR / "vault.dat").exists() else APP_DATA_ROOT / APP_NAME
VAULT_FILE = DATA_DIR / "vault.dat"


class HexiMark(tk.Canvas):
    """Approved hexi + key wordmark; never accesses vault contents."""

    def __init__(self, master, background, size=58):
        width = 276 if size == 76 else 204
        super().__init__(master, width=width, height=size, bg=background, highlightthickness=0, bd=0)
        asset_root = Path(__file__).resolve().parent / "assets"
        try:
            self._brand_image = tk.PhotoImage(file=str(asset_root / f"hexikeys-wordmark-{size}.png"))
            self.create_image(width / 2, size / 2, image=self._brand_image)
        except tk.TclError:
            self.create_text(width/2, size/2, text="HexiKeys", fill="#c9edff", font=("Segoe UI", 20, "bold"))


class ScrollableFrame(tk.Frame):
    """A vertically scrollable content area for entries with many dynamic fields."""

    def __init__(self, master, background="white"):
        super().__init__(master, bg=background)
        self.canvas = tk.Canvas(self, bg=background, highlightthickness=0, bd=0)
        self.scrollbar = ttk.Scrollbar(self, orient="vertical", command=self.canvas.yview)
        self.canvas.configure(yscrollcommand=self.scrollbar.set)
        self.scrollbar.pack(side="right", fill="y")
        self.canvas.pack(side="left", fill="both", expand=True)
        self.body = tk.Frame(self.canvas, bg=background)
        self._window = self.canvas.create_window((0, 0), window=self.body, anchor="nw")
        self.body.bind("<Configure>", self._update_scrollregion)
        self.canvas.bind("<Configure>", self._resize_body)
        self._mousewheel_binding = self.bind_all("<MouseWheel>", self._scroll_mousewheel, add="+")
        self.canvas.bind("<Destroy>", self._on_destroy)

    def _update_scrollregion(self, _event=None):
        self.canvas.configure(scrollregion=self.canvas.bbox("all"))

    def _resize_body(self, event):
        self.canvas.itemconfigure(self._window, width=event.width)

    def _scroll_mousewheel(self, event):
        widget = self.winfo_containing(event.x_root, event.y_root)
        if not widget or not (widget == str(self) or widget.startswith(str(self) + ".")):
            return None
        if event.delta:
            self.canvas.yview_scroll(-int(event.delta / 120), "units")
            return "break"

    def _on_destroy(self, event):
        if event.widget is self.canvas and self._mousewheel_binding:
            self._root()._unbind(("bind", "all", "<MouseWheel>"), self._mousewheel_binding)


class _InstanceAlreadyRunning(Exception):
    pass


class HexiKeysApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("HexiKeys")
        try:
            self._window_icon = tk.PhotoImage(file=str(Path(__file__).resolve().parent / "assets" / "hexikeys-76.png"))
            self.iconphoto(True, self._window_icon)
        except tk.TclError:
            pass
        self.geometry("1080x700")
        self.minsize(900, 560)
        self.configure(bg="#f5f7fb")
        self.style = ttk.Style(self)
        self.style.theme_use("clam")
        self.style.configure("TButton", padding=(12, 8), font=("Segoe UI", 10))
        self.style.configure("Accent.TButton", background="#315efb", foreground="white", padding=(14, 9), font=("Segoe UI", 10, "bold"))
        self.style.map("Accent.TButton", background=[("active", "#2449d8")])
        self.style.configure("Treeview", rowheight=34, font=("Segoe UI", 10), fieldbackground="white", background="white")
        self.style.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"))
        self.password = None
        self.vault = {"entries": []}
        self.field_rows = []
        self._clipboard_value = None
        self._clipboard_after_id = None
        self._idle_lock_after_id = None
        self._login_focus_after_id = None
        self._last_activity_at = None
        self._editing_entry_id = None
        self._editor_active = False
        self._capture_request = None
        self._instance_mutex_handle = None
        self._startup_ok = False
        self._ui_thread_id = threading.get_ident()
        self._bridge_callback_queue = queue.Queue(maxsize=BRIDGE_CALLBACK_QUEUE_SIZE)
        self._bridge_generation = 0
        self._vault_generation = 0
        self._draft_generation = 0
        self._bridge_worker_tokens = {}
        self._bridge_server = None
        self._bridge_callbacks_open = False
        self._bridge_pump_after_id = None
        self._bridge_stop_pending = None
        self._closing_session = False
        self._allow_destroy_after_bridge = False
        self._bridge_button = None
        self._form_trace_ids = []
        try:
            self._acquire_instance_mutex()
        except _InstanceAlreadyRunning:
            messagebox.showwarning("HexiKeys is already open", "This vault is already open in another HexiKeys window. Switch to that window to avoid conflicting changes.", parent=self)
            self.destroy()
            return
        except Exception as exc:
            messagebox.showerror("HexiKeys could not start safely", f"HexiKeys could not confirm exclusive access to its vault, so it did not open it.\n\n{exc}", parent=self)
            self.destroy()
            return
        self._startup_ok = True
        self.bind_all("<KeyPress>", self._record_activity, add="+")
        self.bind_all("<ButtonPress>", self._record_activity, add="+")
        self.bind_all("<MouseWheel>", self._record_activity, add="+")
        self.bind_all("<Motion>", self._record_activity, add="+")
        self.protocol("WM_DELETE_WINDOW", self.close)
        self.build_login()

    def _acquire_instance_mutex(self):
        """Keep a named Windows mutex alive to prevent concurrent vault writers."""
        if os.name != "nt":
            return
        vault_identity = os.path.normcase(str(VAULT_FILE.resolve())).encode("utf-8")
        mutex_name = "Local\\HexiKeys-" + hashlib.sha256(vault_identity).hexdigest()
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        kernel32.CreateMutexW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
        kernel32.CreateMutexW.restype = wintypes.HANDLE
        kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
        kernel32.CloseHandle.restype = wintypes.BOOL
        ctypes.set_last_error(0)
        handle = kernel32.CreateMutexW(None, False, mutex_name)
        last_error = ctypes.get_last_error()
        if not handle:
            raise ctypes.WinError(last_error)
        if last_error == 183:  # ERROR_ALREADY_EXISTS
            kernel32.CloseHandle(handle)
            raise _InstanceAlreadyRunning()
        self._instance_mutex_handle = (kernel32, handle)

    def _release_instance_mutex(self):
        mutex = self._instance_mutex_handle
        self._instance_mutex_handle = None
        if not mutex:
            return
        kernel32, handle = mutex
        try:
            kernel32.CloseHandle(handle)
        except (OSError, AttributeError):
            pass

    def clear(self):
        self.clear_container(self)

    def _wipe_widget_values(self, widget):
        try:
            if not widget.winfo_exists():
                return
        except tk.TclError:
            return
        if isinstance(widget, tk.Text):
            try: widget.delete("1.0", tk.END)
            except tk.TclError: pass
        elif isinstance(widget, (tk.Entry, ttk.Entry, ttk.Combobox)):
            try: widget.delete(0, tk.END)
            except tk.TclError: pass
        for child in widget.winfo_children():
            self._wipe_widget_values(child)

    def clear_container(self, container):
        if container is self:
            self._cancel_login_focus()
        if container is self or container is getattr(self, "detail", None):
            self._detach_form_traces()
            self._advance_draft_generation()
        for child in container.winfo_children():
            self._wipe_widget_values(child)
            child.destroy()
        if container is self or container is getattr(self, "detail", None):
            for name in ("title_var", "purpose_var"):
                variable = getattr(self, name, None)
                if variable is not None:
                    try: variable.set("")
                    except tk.TclError: pass
            self.field_rows = []

    def build_login(self):
        self.clear()
        self.configure(menu="")
        if hasattr(self, "app_menu"):
            self.app_menu.destroy()
            del self.app_menu
        frame = tk.Frame(self, bg="#080b16", highlightthickness=1, highlightbackground="#252b42")
        frame.place(relx=.5, rely=.5, anchor="center", width=460, height=430)
        exists = VAULT_FILE.exists()
        brand = tk.Frame(frame, bg="#080b16"); brand.pack(pady=(24, 8))
        HexiMark(brand, "#080b16", 76).pack(side="left", padx=(0, 10))
        tk.Label(frame, text="Your encrypted home for passwords, keys, tokens, and recovery codes", font=("Segoe UI", 10), fg="#a9b5d0", bg="#080b16", wraplength=390).pack(pady=(0, 22))
        tk.Label(frame, text="Master password", anchor="w", bg="#080b16", fg="#e4e9f7", font=("Segoe UI", 10, "bold")).pack(fill="x", padx=38)
        self.login_password = ttk.Entry(frame, show="•", font=("Segoe UI", 12))
        self.login_password.pack(fill="x", padx=38, pady=(6, 12), ipady=5)
        self.confirm_password = None
        if not exists:
            tk.Label(frame, text="Confirm master password", anchor="w", bg="#080b16", fg="#e4e9f7", font=("Segoe UI", 10, "bold")).pack(fill="x", padx=38)
            self.confirm_password = ttk.Entry(frame, show="•", font=("Segoe UI", 12))
            self.confirm_password.pack(fill="x", padx=38, pady=(6, 14), ipady=5)
            self.confirm_password.bind("<Return>", lambda e: self.unlock())
        self.login_password.bind("<Return>", lambda e: self.unlock())
        action = "Unlock vault" if exists else "Create vault"
        ttk.Button(frame, text=action, style="Accent.TButton", command=self.unlock).pack(fill="x", padx=38)
        hint = "Enter your master password to unlock." if exists else "Use at least 12 characters. Your old encrypted vault will be kept as a backup during its one-time upgrade."
        tk.Label(frame, text=hint, wraplength=380, justify="center", fg="#a9b5d0", bg="#080b16", font=("Segoe UI", 9)).pack(pady=16)
        if exists:
            ttk.Button(frame, text="Quit", command=self.destroy).pack(pady=(0, 12))
        self._login_focus_after_id = self.after(100, self._focus_login_password)

    def _focus_login_password(self):
        self._login_focus_after_id = None
        if getattr(self, "login_password", None) is not None and self.login_password.winfo_exists():
            self.login_password.focus_set()

    def _cancel_login_focus(self):
        if self._login_focus_after_id is not None:
            try: self.after_cancel(self._login_focus_after_id)
            except tk.TclError: pass
            self._login_focus_after_id = None

    def unlock(self):
        password = self.login_password.get()
        exists = VAULT_FILE.exists()
        minimum_length = 8 if exists else 12
        if len(password) < minimum_length:
            messagebox.showwarning("Password needed", f"Use at least {minimum_length} characters for your master password.")
            return
        if not exists and self.confirm_password.get() != password:
            messagebox.showwarning("Passwords do not match", "Enter the same master password in both boxes.")
            return
        migrated = False
        backup_path = None
        if exists:
            try:
                self.vault, version = load_vault(VAULT_FILE, password)
                if version == 1:
                    backup_path = self.save_vault(password)
                    migrated = True
            except (OSError, ValueError, MemoryError) as exc:
                messagebox.showerror("Could not unlock", str(exc) if isinstance(exc, ValueError) else "The vault could not be opened. The original file has not been changed.")
                return
        else:
            self.vault = {"entries": []}
            try:
                self.save_vault(password)
            except (OSError, ValueError, MemoryError) as exc:
                messagebox.showerror("Vault could not be created", f"The encrypted vault could not be saved: {exc}")
                return
        self.password = password
        self._closing_session = False
        self._advance_vault_generation()
        self.build_main()
        self._start_paired_bridge(show_error=True)
        self._last_activity_at = time.monotonic()
        self._schedule_idle_lock()
        if migrated:
            messagebox.showinfo("HexiKeys security upgrade", f"Your existing vault has been re-encrypted with the current format. An encrypted copy of the original was preserved at:\n\n{backup_path}")

    def save_vault(self, password=None):
        password = password or self.password
        return save_vault(VAULT_FILE, self.vault, password)

    def commit_vault(self, candidate):
        """Persist a proposed vault before publishing it to the live UI state."""
        try:
            save_vault(VAULT_FILE, candidate, self.password)
        except (OSError, ValueError, MemoryError) as exc:
            return exc
        self.vault = candidate
        self._advance_vault_generation()
        return None

    def commit_error(self, exc):
        messagebox.showerror("Vault could not be saved", f"Your changes were not saved. The current vault remains unchanged.\n\n{exc}")

    def _advance_vault_generation(self):
        self._vault_generation += 1
        self._bridge_worker_tokens.clear()

    def _advance_draft_generation(self):
        self._draft_generation += 1

    def _note_vault_draft_edit(self, *_args):
        self._advance_draft_generation()

    def _watch_form_variable(self, variable, callback=None):
        try:
            trace_id = variable.trace_add("write", callback or self._note_vault_draft_edit)
            self._form_trace_ids.append((variable, trace_id))
        except tk.TclError:
            pass

    def _detach_form_traces(self):
        for variable, trace_id in self._form_trace_ids:
            try:
                variable.trace_remove("write", trace_id)
            except tk.TclError:
                pass
        self._form_trace_ids = []

    def _bridge_call(self, generation, kind, *, worker_id=None, request=None, receipt=None, candidate=None):
        if threading.get_ident() == self._ui_thread_id:
            job = {"generation": generation, "kind": kind, "worker_id": worker_id,
                   "request": request, "receipt": receipt, "candidate": candidate,
                   "draft_generation": self._draft_generation,
                   "done": threading.Event(), "cancelled": False}
            self._run_bridge_ui_call(job)
        else:
            if not self._bridge_callbacks_open or generation != self._bridge_generation:
                raise RuntimeError("The local bridge is unavailable.")
            job = {"generation": generation, "kind": kind, "worker_id": worker_id,
                   "request": request, "receipt": receipt, "candidate": candidate,
                   "draft_generation": self._draft_generation,
                   "done": threading.Event(), "cancelled": False}
            try:
                self._bridge_callback_queue.put_nowait(job)
            except queue.Full:
                raise RuntimeError("The local bridge is busy.") from None
            if not job["done"].wait(BRIDGE_CALLBACK_TIMEOUT_SECONDS):
                if job["done"].is_set():
                    pass
                else:
                    job["cancelled"] = True
                    job["candidate"] = None
                    job["request"] = None
                    job["receipt"] = None
                    raise RuntimeError("The local bridge callback timed out.") from None
        if job.get("error") is not None:
            raise RuntimeError(job["error"]) from None
        return job.get("result")

    def _run_bridge_ui_call(self, job):
        if threading.get_ident() != self._ui_thread_id:
            job["error"] = "The local bridge callback was unavailable."
            job["candidate"] = None
            job["request"] = None
            job["receipt"] = None
            job["done"].set()
            return
        if job.get("cancelled"):
            job["error"] = "The local bridge callback was cancelled."
            job["candidate"] = None
            job["request"] = None
            job["receipt"] = None
            job["done"].set()
            return
        if (job.get("generation") != self._bridge_generation or not self._bridge_callbacks_open
                or self.password is None or self._closing_session):
            job["error"] = "The local bridge is unavailable."
            job["candidate"] = None
            job["request"] = None
            job["receipt"] = None
            job["done"].set()
            return
        try:
            kind = job.get("kind")
            if kind == "status":
                job["result"] = {"available": True, "unlocked": True}
            elif kind == "vault":
                worker_id = job.get("worker_id")
                if type(worker_id) is not int:
                    raise RuntimeError
                self._prune_bridge_worker_tokens()
                self._bridge_worker_tokens[worker_id] = {
                    "bridge_generation": self._bridge_generation,
                    "vault_generation": self._vault_generation,
                    "draft_generation": self._draft_generation,
                    "vault": self.vault,
                    "committed": False,
                    "expires_at": time.monotonic() + 30.0,
                }
                while len(self._bridge_worker_tokens) > 8:
                    oldest = next(iter(self._bridge_worker_tokens))
                    self._bridge_worker_tokens.pop(oldest, None)
                job["result"] = self.vault
            elif kind == "persist":
                job["result"] = self._persist_bridge_candidate_on_ui(job.get("worker_id"), job.get("candidate"), job["generation"])
            elif kind == "authorize":
                job["result"] = self._authorize_bridge_release_on_ui(
                    job.get("worker_id"), job.get("request"), job.get("receipt"), job["generation"]
                )
            elif kind == "request_new_item":
                if job.get("draft_generation") != self._draft_generation:
                    raise RuntimeError
                job["result"] = self._request_new_item_on_ui(job.get("request"), job["generation"])
            else:
                raise RuntimeError
        except Exception:
            # Callback exceptions never carry vault data back to the pipe worker.
            job["error"] = "The local bridge callback was denied."
        finally:
            job["candidate"] = None
            job["request"] = None
            job["receipt"] = None
            job["done"].set()

    def _request_new_item_on_ui(self, request, generation):
        try:
            intent = validate_new_item_request(request)
        except (TypeError, ValueError):
            raise RuntimeError("The local bridge request was denied.") from None
        if (generation != self._bridge_generation or not self._bridge_callbacks_open
                or self.password is None or self._closing_session
                or self._editor_active or self._editing_entry_id is not None
                or self._capture_request is not None):
            raise RuntimeError("The local bridge request was denied.")

        self._capture_request = {
            "requestId": intent["requestId"],
            "expiresAt": intent["expiresAt"],
            "bridge_generation": generation,
        }
        entry = {
            "title": intent["title"].strip(),
            "category": intent["category"],
            "purpose": "",
            "fields": [create_vault_field(intent["fieldLabel"].strip(), secret=True)],
        }
        try:
            self.edit_entry(entry, creating=True, request_context=intent["requestedBy"])
        except Exception:
            self._capture_request = None
            raise
        return {"opened": True}

    def _prune_bridge_worker_tokens(self):
        now = time.monotonic()
        for worker_id, token in list(self._bridge_worker_tokens.items()):
            if token.get("expires_at", 0) <= now or token.get("bridge_generation") != self._bridge_generation:
                self._bridge_worker_tokens.pop(worker_id, None)

    def _bridge_snapshot_matches(self, worker_id, generation):
        token = self._bridge_worker_tokens.get(worker_id)
        return bool(
            token and token.get("bridge_generation") == generation == self._bridge_generation
            and token.get("vault_generation") == self._vault_generation
            and token.get("draft_generation") == self._draft_generation
            and token.get("expires_at", 0) > time.monotonic()
            and token.get("vault") is self.vault
            and self.password is not None and not self._closing_session
            and self._bridge_callbacks_open
        )

    def _persist_bridge_candidate_on_ui(self, worker_id, candidate, generation):
        if not self._bridge_snapshot_matches(worker_id, generation) or not isinstance(candidate, dict):
            raise RuntimeError("The vault changed during the credential request.")
        current_pairing = hexigrid_pairing_record(self.vault)
        candidate_pairing = hexigrid_pairing_record(candidate)
        if current_pairing is None or candidate_pairing != current_pairing:
            raise RuntimeError("The local pairing changed during the credential request.")
        token = self._bridge_worker_tokens[worker_id]
        persisted = copy.deepcopy(candidate)
        try:
            # Durably encrypt the consumed-use candidate before publishing it in memory.
            save_vault(VAULT_FILE, persisted, self.password)
        except Exception:
            raise RuntimeError("The credential use could not be saved.") from None
        if not self._bridge_snapshot_matches(worker_id, generation):
            # Tk callbacks are serialized; reaching this branch means an unexpected
            # reentrant state change, so do not publish a stale in-memory candidate.
            raise RuntimeError("The vault changed during the credential request.")
        self.vault = persisted
        self._advance_vault_generation()
        self._bridge_worker_tokens[worker_id] = {
            **token,
            "vault_generation": self._vault_generation,
            "vault": self.vault,
            "committed": True,
            "expires_at": time.monotonic() + 30.0,
            "authorized_request": None,
        }
        return None

    def _authorize_bridge_release_on_ui(self, worker_id, request, receipt, generation):
        if (not self._bridge_snapshot_matches(worker_id, generation) or not isinstance(request, dict)
                or not isinstance(receipt, dict)):
            return False
        token = self._bridge_worker_tokens.get(worker_id)
        if not token or token.get("committed") is not True:
            return False
        expected = token.get("authorized_request")
        request_key = (request.get("grantId"), request.get("requestId"))
        if expected is not None and expected != request_key:
            return False
        grid = self.vault.get("integrations", {}).get("hexigrid", {})
        grants = grid.get("grants", []) if isinstance(grid, dict) else []
        matches = [grant for grant in grants if isinstance(grant, dict) and grant.get("id") == request_key[0]] if isinstance(grants, list) else []
        if len(matches) != 1:
            return False
        grant = matches[0]
        used_ids = grant.get("usedRequestIds")
        if (grant.get("revokedAt") is not None or type(grant.get("expiresAt")) is not int
                or grant["expiresAt"] <= int(time.time()) or type(grant.get("uses")) is not int
                or type(grant.get("maxUses")) is not int or grant["uses"] < 1
                or grant["uses"] > grant["maxUses"] or not isinstance(used_ids, list)
                or request_key[1] not in used_ids):
            return False
        try:
            from vault_references import _path_is_allowed
            request_matches = (
                request.get("connectorId") == grant.get("connectorId")
                and request.get("capabilityId") == grant.get("capabilityId")
                and request.get("taskId") == grant.get("taskId")
                and request.get("origin") == grant.get("origin")
                and request.get("method", "").upper() in grant.get("methods", [])
                and _path_is_allowed(grant.get("pathPrefix"), request.get("path"))
                and request.get("header", "").casefold() == grant.get("header")
                and request.get("prefix") == grant.get("prefix")
            )
        except Exception:
            return False
        receipt_matches = (
            receipt.get("status") == "authorized"
            and receipt.get("grantId") == grant.get("id")
            and receipt.get("requestId") == request_key[1]
            and receipt.get("connectorId") == grant.get("connectorId")
            and receipt.get("capabilityId") == grant.get("capabilityId")
            and receipt.get("taskId") == grant.get("taskId")
            and receipt.get("origin") == grant.get("origin")
            and receipt.get("method") == request.get("method", "").upper()
        )
        if not request_matches or not receipt_matches:
            return False
        if expected is None:
            token["authorized_request"] = request_key
        return True

    def _bridge_callback_pump(self):
        self._bridge_pump_after_id = None
        if threading.get_ident() != self._ui_thread_id:
            return
        for _ in range(BRIDGE_CALLBACK_QUEUE_SIZE):
            try:
                job = self._bridge_callback_queue.get_nowait()
            except queue.Empty:
                break
            self._run_bridge_ui_call(job)
        self._poll_bridge_stop()
        if self._bridge_callbacks_open or self._bridge_stop_pending is not None or not self._bridge_callback_queue.empty():
            try:
                self._bridge_pump_after_id = self.after(BRIDGE_PUMP_INTERVAL_MS, self._bridge_callback_pump)
            except tk.TclError:
                self._bridge_pump_after_id = None

    def _schedule_bridge_callback_pump(self):
        if self._bridge_pump_after_id is None and (self._bridge_callbacks_open or self._bridge_stop_pending is not None):
            try:
                self._bridge_pump_after_id = self.after(BRIDGE_PUMP_INTERVAL_MS, self._bridge_callback_pump)
            except tk.TclError:
                self._bridge_pump_after_id = None

    def _reject_queued_bridge_calls(self):
        while True:
            try:
                job = self._bridge_callback_queue.get_nowait()
            except queue.Empty:
                break
            job["cancelled"] = True
            job["candidate"] = None
            job["request"] = None
            job["receipt"] = None
            job["error"] = "The local bridge is unavailable."
            job["done"].set()

    def _bridge_callbacks(self, generation):
        return {
            "get_status": lambda: self._bridge_call(generation, "status"),
            "get_vault": lambda: self._bridge_call(generation, "vault", worker_id=threading.get_ident()),
            "persist_candidate": lambda candidate: self._bridge_call(
                generation, "persist", worker_id=threading.get_ident(), candidate=candidate
            ),
            "authorize_release": lambda request, receipt: self._bridge_call(
                generation, "authorize", worker_id=threading.get_ident(), request=request, receipt=receipt
            ),
            "request_new_item": lambda request: self._bridge_call(
                generation, "request_new_item", request=request
            ),
        }

    def _start_paired_bridge(self, *, show_error=False):
        if self.password is None or self._closing_session or self._bridge_server is not None:
            return False
        pairing = hexigrid_pairing_record(self.vault)
        if pairing is None:
            self._refresh_bridge_controls()
            return False
        key_material = bytearray.fromhex(pairing["hmacKey"])
        server = None
        self._bridge_generation += 1
        generation = self._bridge_generation
        try:
            restore_pairing_descriptor(PAIRING_DATA_DIR, pipe_id=pairing["pipeId"], hmac_key=key_material)
            callbacks = self._bridge_callbacks(generation)
            server = VaultBridgeServer(pairing["pipeId"], key_material, **callbacks)
            self._bridge_callbacks_open = True
            server.start()
            self._bridge_server = server
            self._schedule_bridge_callback_pump()
            self._refresh_bridge_controls()
            return True
        except Exception:
            self._bridge_callbacks_open = False
            self._bridge_generation += 1
            self._bridge_worker_tokens.clear()
            if server is not None:
                # Keep even a partially started server attached until it affirms
                # its workers drained. A stop failure must not orphan a worker
                # holding decrypted vault state when the owner locks or closes.
                self._bridge_server = server
                self._begin_bridge_stop(lambda: None)
            self._refresh_bridge_controls()
            if show_error:
                messagebox.showerror("HexiGrid connection unavailable", "HexiKeys could not start the secured local connection. Your vault remains unlocked and unchanged.")
            return False
        finally:
            for index in range(len(key_material)):
                key_material[index] = 0

    def _persist_pairing_material(self, material, base_vault, base_generation):
        if (self.password is None or self._closing_session or self.vault is not base_vault
                or self._vault_generation != base_generation or not isinstance(material, dict)
                or set(material) != {"version", "pipeId", "hmacKey"}
                or type(material.get("version")) is not int or material["version"] != 1
                or not isinstance(material.get("pipeId"), str) or not BRIDGE_PIPE_ID_RE.fullmatch(material["pipeId"])):
            raise RuntimeError("The vault changed before pairing could be saved.")
        key = material.get("hmacKey")
        if not isinstance(key, (bytes, bytearray, memoryview)) or len(key) != 32:
            raise RuntimeError("Pairing material is invalid.")
        if hexigrid_pairing_record(self.vault) is not None:
            raise RuntimeError("This vault is already paired.")
        candidate = copy.deepcopy(self.vault)
        integrations = candidate.setdefault("integrations", {})
        if not isinstance(integrations, dict):
            raise RuntimeError("Vault integration data is invalid.")
        grid = integrations.setdefault("hexigrid", {"grants": []})
        if not isinstance(grid, dict):
            raise RuntimeError("Vault integration data is invalid.")
        grid["pairing"] = {"version": 1, "pipeId": material["pipeId"], "hmacKey": bytes(key).hex()}
        try:
            save_vault(VAULT_FILE, candidate, self.password)
        except Exception:
            raise RuntimeError("Pairing could not be saved to the encrypted vault.") from None
        previous = self.vault
        previous_generation = self._vault_generation
        self.vault = candidate
        self._advance_vault_generation()
        return {"previous_vault": previous, "previous_generation": previous_generation,
                "candidate_vault": candidate, "committed_generation": self._vault_generation,
                "password": self.password}

    def _rollback_pairing_material(self, token):
        if not isinstance(token, dict) or self.password is None or self._closing_session:
            raise RuntimeError("Pairing rollback could not be confirmed.")
        if (self.vault is not token.get("candidate_vault")
                or self._vault_generation != token.get("committed_generation")
                or self.password != token.get("password")):
            raise RuntimeError("Pairing rollback could not be confirmed.")
        try:
            save_vault(VAULT_FILE, token["previous_vault"], self.password)
        except Exception:
            raise RuntimeError("Pairing rollback could not be confirmed.") from None
        self.vault = token["previous_vault"]
        self._advance_vault_generation()

    def connect_hexigrid(self):
        if self.password is None or self._closing_session or self._bridge_stop_pending is not None:
            return False
        if self._bridge_server is not None:
            return self.disconnect_hexigrid()
        pairing = hexigrid_pairing_record(self.vault)
        if pairing is None:
            if not messagebox.askyesno(
                "Connect HexiKeys to HexiGrid?",
                "This creates a local, current-Windows-user pairing so HexiGrid can use only fields you separately authorize. The encrypted vault stays in HexiKeys. Disconnecting here does not remove references imported into HexiGrid; unlink those in HexiGrid separately.",
                parent=self,
            ):
                return False
            base_vault = self.vault
            base_generation = self._vault_generation
            try:
                create_pairing_material(
                    PAIRING_DATA_DIR,
                    persist=lambda material: self._persist_pairing_material(material, base_vault, base_generation),
                    rollback=self._rollback_pairing_material,
                )
            except Exception:
                messagebox.showerror("HexiGrid pairing unavailable", "HexiKeys could not complete the protected local pairing. The vault was left unchanged unless the encrypted save completed; no connection was started.", parent=self)
                self._refresh_bridge_controls()
                return False
        return self._start_paired_bridge(show_error=True)

    def disconnect_hexigrid(self):
        if self._bridge_stop_pending is not None:
            return False
        if not messagebox.askyesno(
            "Disconnect HexiGrid?",
            "Stop the local connection and remove this computer's pairing material after active pipe work drains? Existing references imported into HexiGrid must be unlinked there separately.",
            parent=self,
        ):
            return False
        self._begin_bridge_stop(self._finish_unpair)
        return True

    def create_hexigrid_reference(self):
        if self.password is None or self._closing_session:
            messagebox.showinfo("HexiGrid reference", "Unlock the vault before sharing a field.", parent=self)
            return None
        return show_grant_dialog(
            self,
            get_vault=lambda: self.vault if self.password is not None and not self._closing_session else None,
            commit_vault=lambda candidate: self.commit_vault(candidate)
            if self.password is not None and not self._closing_session
            else RuntimeError("The vault is no longer available."),
        )

    def manage_hexigrid_references(self):
        if self.password is None or self._closing_session:
            messagebox.showinfo("HexiGrid references", "Unlock the vault to manage references.", parent=self)
            return None
        return show_grants_dialog(
            self,
            get_vault=lambda: self.vault if self.password is not None and not self._closing_session else None,
            commit_vault=lambda candidate: self.commit_vault(candidate)
            if self.password is not None and not self._closing_session
            else RuntimeError("The vault is no longer available."),
        )

    def _finish_unpair(self):
        if self.password is None or self._closing_session:
            return
        pairing = hexigrid_pairing_record(self.vault)
        if pairing is None:
            self._refresh_bridge_controls()
            return
        candidate = copy.deepcopy(self.vault)
        try:
            grid = candidate.get("integrations", {}).get("hexigrid", {})
            if isinstance(grid, dict):
                grid.pop("pairing", None)
            save_vault(VAULT_FILE, candidate, self.password)
        except Exception:
            messagebox.showerror("HexiGrid disconnect incomplete", "The encrypted vault could not save the local disconnect. The saved pairing remains available for a later reconnect.", parent=self)
            self._refresh_bridge_controls()
            return
        self.vault = candidate
        self._advance_vault_generation()
        try:
            remove_pairing_descriptor(PAIRING_DATA_DIR)
        except OSError:
            messagebox.showerror("HexiGrid disconnect incomplete", "The encrypted pairing was removed and the bridge is stopped, but the protected local descriptor could not be removed. HexiGrid-side references still require separate unlinking.", parent=self)
        self._refresh_bridge_controls()

    def _refresh_bridge_controls(self):
        button = self._bridge_button
        if button is None:
            return
        try:
            if not button.winfo_exists():
                self._bridge_button = None
                return
            if self._bridge_stop_pending is not None:
                button.configure(text="Disconnecting…", state="disabled")
            elif self._bridge_server is not None and getattr(self._bridge_server, "running", True):
                button.configure(text="Disconnect HexiGrid", state="normal")
            else:
                button.configure(text="Connect HexiGrid", state="normal")
        except tk.TclError:
            self._bridge_button = None

    def _begin_bridge_stop(self, finalize, *, ending_session=False):
        if self._capture_request is not None:
            self.show_welcome()
        self._bridge_callbacks_open = False
        self._bridge_generation += 1
        self._bridge_worker_tokens.clear()
        self._reject_queued_bridge_calls()
        if ending_session:
            self._closing_session = True
        if self._bridge_stop_pending is not None:
            self._bridge_stop_pending["finalizers"].append(finalize)
            self._schedule_bridge_callback_pump()
            self._refresh_bridge_controls()
            return
        server = self._bridge_server
        if server is None:
            finalize()
            self._refresh_bridge_controls()
            return
        self._bridge_stop_pending = {"server": server, "finalizers": [finalize]}
        try:
            server.stop()
        except Exception:
            # Continue polling: the server must affirm its workers have drained
            # before the decrypted vault can be cleared or replaced.
            pass
        self._schedule_bridge_callback_pump()
        self._refresh_bridge_controls()

    def _poll_bridge_stop(self):
        pending = self._bridge_stop_pending
        if pending is None:
            return
        server = pending["server"]
        try:
            drained = server.wait_closed(0)
        except Exception:
            drained = False
        if not drained:
            return
        self._bridge_stop_pending = None
        if self._bridge_server is server:
            self._bridge_server = None
        self._bridge_worker_tokens.clear()
        finalizers = pending["finalizers"]
        for finalize in finalizers:
            finalize()
        self._refresh_bridge_controls()

    def build_main(self):
        self.clear()
        self.build_menu()
        header = tk.Frame(self, bg="#080b16", height=76); header.pack(fill="x"); header.pack_propagate(False)
        HexiMark(header, "#080b16", 58).pack(side="left", padx=(22, 8), pady=8)
        ttk.Button(header, text="Import JSON", command=self.import_json).pack(side="right", padx=(8, 20), pady=16)
        ttk.Button(header, text="Import screenshot", command=self.import_screenshots).pack(side="right", padx=8, pady=16)
        ttk.Button(header, text="Import TXT", command=self.import_text_files).pack(side="right", padx=8, pady=16)
        tk.Label(header, text="Auto-locks after 10 min without HexiKeys activity", bg="#080b16", fg="#a9b5d0", font=("Segoe UI", 8)).pack(side="right", padx=4)
        self._bridge_button = ttk.Button(header, text="Connect HexiGrid", command=self.connect_hexigrid)
        self._bridge_button.pack(side="right", padx=(8, 4), pady=16)
        self._refresh_bridge_controls()
        ttk.Button(header, text="Lock", command=self.lock).pack(side="right", padx=20, pady=16)
        body = tk.Frame(self, bg="#f5f7fb"); body.pack(fill="both", expand=True, padx=24, pady=22)
        left = tk.Frame(body, bg="#f5f7fb", width=360); left.pack(side="left", fill="y", padx=(0, 20)); left.pack_propagate(False)
        tk.Label(left, text="Your items", bg="#f5f7fb", fg="#17213d", font=("Segoe UI", 17, "bold")).pack(anchor="w")
        tk.Label(left, text="Everything in one easy-to-find place", bg="#f5f7fb", fg="#667085", font=("Segoe UI", 9)).pack(anchor="w", pady=(2, 14))
        bar = tk.Frame(left, bg="white", highlightthickness=1, highlightbackground="#d0d5dd"); bar.pack(fill="x", pady=(0, 12))
        self.search = ttk.Entry(bar); self.search.pack(fill="x", padx=8, pady=7); self.search.bind("<KeyRelease>", lambda e: self.refresh_list())
        self.tree = ttk.Treeview(left, columns=("type",), show="tree headings", selectmode="browse"); self.tree.heading("#0", text="Name"); self.tree.heading("type", text="Type"); self.tree.column("#0", width=220); self.tree.column("type", width=100); self.tree.pack(fill="both", expand=True)
        self.tree.bind("<<TreeviewSelect>>", lambda e: self.show_selected())
        ttk.Button(left, text="＋  New item", style="Accent.TButton", command=self.new_entry).pack(fill="x", pady=(14, 0))
        ttk.Button(left, text="⇧  Import JSON", command=self.import_json).pack(fill="x", pady=(8, 0))
        ttk.Button(left, text="▣  Import screenshots", command=self.import_screenshots).pack(fill="x", pady=(8, 0))
        ttk.Button(left, text="▤  Import TXT backup", command=self.import_text_files).pack(fill="x", pady=(8, 0))
        ttk.Button(left, text="Share one field with HexiGrid", command=self.create_hexigrid_reference).pack(fill="x", pady=(18, 0))
        ttk.Button(left, text="Manage HexiGrid references", command=self.manage_hexigrid_references).pack(fill="x", pady=(8, 0))
        right = tk.Frame(body, bg="white", highlightthickness=1, highlightbackground="#e4e7ec"); right.pack(side="left", fill="both", expand=True)
        self.detail = right
        self.show_welcome()
        self.refresh_list()

    def build_menu(self):
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Save encrypted backup…", command=self.backup_vault)
        file_menu.add_command(label="Restore encrypted backup…", command=self.restore_vault_backup)
        file_menu.add_separator()
        file_menu.add_command(label="Quit", command=self.close)
        menu.add_cascade(label="File", menu=file_menu)
        security_menu = tk.Menu(menu, tearoff=False)
        security_menu.add_command(label="Change master password…", command=self.change_master_password)
        security_menu.add_command(label="Generate password…", command=self.generate_password_dialog)
        menu.add_cascade(label="Security", menu=security_menu)
        self.configure(menu=menu)
        self.app_menu = menu

    def backup_vault(self):
        destination = filedialog.asksaveasfilename(
            title="Save encrypted HexiKeys backup",
            defaultextension=".hexikeys",
            filetypes=[("HexiKeys encrypted vault", "*.hexikeys"), ("Vault files", "*.dat"), ("All files", "*.*")],
        )
        if not destination:
            return
        if Path(destination).exists() and not messagebox.askyesno(
            "Replace backup?", "A file already exists at that location. Replace it with this encrypted vault backup?"
        ):
            return
        try:
            copy_encrypted_vault(VAULT_FILE, destination, self.password)
        except (OSError, ValueError, MemoryError) as exc:
            messagebox.showerror("Backup failed", f"The encrypted backup could not be saved. Your vault was not changed.\n\n{exc}")
            return
        messagebox.showinfo("Encrypted backup saved", f"A copy of your encrypted vault was saved to:\n\n{destination}\n\nKeep this file somewhere safe. It requires the master password in use when the backup was made; changing your password does not change older backups.")

    def restore_vault_backup(self):
        source = filedialog.askopenfilename(
            title="Choose an encrypted HexiKeys backup",
            filetypes=[("HexiKeys encrypted vault", "*.hexikeys;*.dat;*.bak"), ("All files", "*.*")],
        )
        if not source:
            return
        try:
            if Path(source).resolve() == VAULT_FILE.resolve():
                raise ValueError("Choose a backup file, not the currently open vault")
            restored_vault, _version = load_vault(source, self.password)
        except VaultAuthenticationError:
            backup_password = simpledialog.askstring(
                "Backup master password",
                "This backup was created with a different master password. Enter the password that protected this backup:",
                show="•", parent=self,
            )
            if backup_password is None:
                return
            try:
                restored_vault, _version = load_vault(source, backup_password)
            except (OSError, ValueError, MemoryError) as exc:
                messagebox.showerror("Backup could not be opened", f"The backup could not be opened with the supplied master password. Your vault was not changed.\n\n{exc}")
                return
        except (OSError, ValueError, MemoryError) as exc:
            messagebox.showerror("Backup could not be opened", f"The selected backup could not be opened. Your vault was not changed.\n\n{exc}")
            return
        if not messagebox.askyesno(
            "Restore encrypted backup?",
            "Replace the current vault with this backup? HexiKeys will first keep an encrypted safety copy of the current vault.",
        ):
            return
        try:
            safety_copy = create_encrypted_backup(VAULT_FILE, self.password, label="before-restore")
        except (OSError, ValueError, MemoryError) as exc:
            messagebox.showerror("Restore failed", f"The restore did not complete. The current vault has been preserved.\n\n{exc}")
            return

        def finish_restore():
            try:
                save_vault(VAULT_FILE, restored_vault, self.password)
            except (OSError, ValueError, MemoryError) as exc:
                messagebox.showerror("Restore failed", f"The restore did not complete. The current vault has been preserved.\n\n{exc}")
                self._start_paired_bridge(show_error=False)
                return
            self.vault = restored_vault
            self._advance_vault_generation()
            self.refresh_list()
            self.show_welcome()
            self._start_paired_bridge(show_error=False)
            messagebox.showinfo("Vault restored", f"The encrypted backup was restored. A safety copy of the previous vault is at:\n\n{safety_copy}")

        if self._bridge_server is not None:
            self._begin_bridge_stop(finish_restore)
        else:
            finish_restore()

    def change_master_password(self):
        new_password = simpledialog.askstring("Change master password", "Enter a new master password (at least 12 characters):", show="•", parent=self)
        if new_password is None:
            return
        if len(new_password) < 12:
            messagebox.showwarning("Password too short", "Use at least 12 characters for the new master password.")
            return
        confirmation = simpledialog.askstring("Confirm new master password", "Enter the new master password again:", show="•", parent=self)
        if confirmation is None:
            return
        if confirmation != new_password:
            messagebox.showwarning("Passwords do not match", "The new passwords did not match. Your vault was not changed.")
            return
        if new_password == self.password:
            messagebox.showwarning("No change made", "Choose a different master password.")
            return
        try:
            safety_copy = create_encrypted_backup(VAULT_FILE, self.password, label="before-password-change")
            save_vault(VAULT_FILE, self.vault, new_password)
        except (OSError, ValueError, MemoryError) as exc:
            messagebox.showerror("Password change failed", f"Your existing master password and vault remain unchanged.\n\n{exc}")
            return
        self.password = new_password
        self._advance_vault_generation()
        messagebox.showinfo("Master password changed", f"Your vault was re-encrypted with the new master password. The old password will no longer unlock the current vault. An encrypted safety copy protected by the old password is at:\n\n{safety_copy}")

    def generate_password_dialog(self):
        length = simpledialog.askinteger(
            "Generate a password", "Password length (12–128 characters):", initialvalue=20,
            minvalue=12, maxvalue=128, parent=self,
        )
        if length is None:
            return
        password = generate_secure_password(length)
        dialog = tk.Toplevel(self)
        dialog.title("Generated password")
        dialog.transient(self)
        dialog.resizable(False, False)
        frame = ttk.Frame(dialog, padding=18)
        frame.pack(fill="both", expand=True)
        ttk.Label(frame, text=f"Random password · {length} characters", font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(0, 8))
        value = tk.StringVar(master=self, value=password)
        field = ttk.Entry(frame, textvariable=value, width=min(length + 4, 72), font=("Consolas", 11))
        field.pack(fill="x", pady=(0, 12))
        field.selection_range(0, "end")
        actions = ttk.Frame(frame)
        actions.pack(fill="x")
        ttk.Button(actions, text="Regenerate", command=lambda: value.set(generate_secure_password(length))).pack(side="left")

        def copy_generated():
            if not self.copy(value.get()):
                field.focus_set()
                return
            dialog.destroy()
            messagebox.showinfo("Password copied", "The generated password is on your clipboard. HexiKeys will clear it after 30 seconds unless you copy something else first.")

        ttk.Button(actions, text="Copy password", command=copy_generated).pack(side="right")
        field.focus_set()

    def show_welcome(self):
        self._editing_entry_id = None
        self._editor_active = False
        self._capture_request = None
        self.clear_container(self.detail)
        tk.Label(self.detail, text="Select an item", bg="white", fg="#17213d", font=("Segoe UI", 20, "bold")).pack(pady=(160, 8))
        tk.Label(self.detail, text="Or create a new one. You can add any fields you need.", bg="white", fg="#667085", font=("Segoe UI", 10)).pack()

    def refresh_list(self):
        if not hasattr(self, "tree"): return
        previously_selected = self.tree.selection()
        for item in self.tree.get_children(): self.tree.delete(item)
        query = self.search.get().strip().casefold() if hasattr(self, "search") else ""
        for entry in sorted(self.vault["entries"], key=lambda e: e.get("title", "").lower()):
            if not query or query in entry_search_text(entry): self.tree.insert("", "end", iid=entry["id"], text=entry.get("title", "Untitled"), values=(entry.get("category", "Other"),))
        if previously_selected:
            selected_id = previously_selected[0]
            if self.tree.exists(selected_id):
                self.tree.selection_set(selected_id)
            elif self._editing_entry_id != selected_id:
                self.show_welcome()

    def show_selected(self):
        selected = self.tree.selection()
        if selected: self.show_entry(next((e for e in self.vault["entries"] if e["id"] == selected[0]), None))

    def show_entry(self, entry):
        self._editing_entry_id = None
        self._editor_active = False
        self._capture_request = None
        self.clear_container(self.detail)
        if not entry: return
        top = tk.Frame(self.detail, bg="white"); top.pack(fill="x", padx=28, pady=24)
        tk.Label(top, text=entry.get("title", "Untitled"), bg="white", fg="#17213d", font=("Segoe UI", 20, "bold")).pack(side="left")
        ttk.Button(top, text="Edit", command=lambda: self.edit_entry(entry)).pack(side="right", padx=(8,0)); ttk.Button(top, text="Delete", command=lambda: self.delete_entry(entry)).pack(side="right")
        tk.Label(self.detail, text="For: " + entry.get("purpose", "Not specified"), bg="white", fg="#667085", font=("Segoe UI", 10)).pack(anchor="w", padx=28)
        fields_scroll = ScrollableFrame(self.detail, background="white"); fields_scroll.pack(fill="both", expand=True, padx=28, pady=24)
        fields = fields_scroll.body
        for i, field in enumerate(entry.get("fields", [])):
            row = tk.Frame(fields, bg="#f8f9fc"); row.pack(fill="x", pady=5)
            tk.Label(row, text=field.get("label", "Field"), bg="#f8f9fc", fg="#475467", font=("Segoe UI", 9, "bold"), width=18, anchor="w").pack(side="left", padx=12, pady=11)
            value = tk.StringVar(master=self, value=field.get("value", "")); ent = ttk.Entry(row, textvariable=value, show="•" if field.get("secret") else ""); ent.pack(side="left", fill="x", expand=True, padx=5, pady=7)
            if field.get("secret"):
                ttk.Button(row, text="Show", command=lambda e=ent: e.configure(show="" if e.cget("show") else "•")).pack(side="right", padx=4)
            ttk.Button(row, text="Copy", command=lambda v=value: self.copy(v.get())).pack(side="right", padx=8)

    def new_entry(self): self.edit_entry({"id": secrets.token_hex(8), "title": "", "category": "Password", "purpose": "", "fields": [create_vault_field("Username", secret=False), create_vault_field("Password", secret=True)]}, True)

    def edit_entry(self, entry, creating=False, request_context=None):
        if request_context is None:
            self._capture_request = None
        self._editing_entry_id = entry.get("id")
        self._editor_active = True
        self.clear_container(self.detail)
        self._advance_draft_generation()
        self.field_rows = []
        top = tk.Frame(self.detail, bg="white"); top.pack(fill="x", padx=28, pady=20)
        tk.Label(top, text="New item" if creating else "Edit item", bg="white", fg="#17213d", font=("Segoe UI", 20, "bold")).pack(side="left")
        form_scroll = ScrollableFrame(self.detail, background="white"); form_scroll.pack(fill="both", expand=True, padx=28)
        form = form_scroll.body
        self.capture_requester_label = None
        if request_context is not None:
            self.capture_requester_label = tk.Label(
                form,
                text=f"Requested by {request_context}. Enter the private value yourself; Save stores it only in this vault.",
                bg="#eef4ff", fg="#344054", justify="left", anchor="w", wraplength=880,
                padx=12, pady=10,
            )
            self.capture_requester_label.pack(fill="x", pady=(0, 12))
        self.title_var = tk.StringVar(master=self, value=entry.get("title", "")); self.category_var = tk.StringVar(master=self, value=entry.get("category", "Other")); self.purpose_var = tk.StringVar(master=self, value=entry.get("purpose", ""))
        for variable in (self.title_var, self.category_var, self.purpose_var):
            self._watch_form_variable(variable)
        self.form_field(form, "Name", self.title_var)
        tk.Label(form, text="Type", bg="white", fg="#475467", font=("Segoe UI", 9, "bold")).pack(anchor="w")
        ttk.Combobox(form, textvariable=self.category_var, values=NEW_ITEM_CATEGORIES, state="readonly").pack(fill="x", pady=(4, 10))
        self.form_field(form, "What is it for?", self.purpose_var)
        tk.Label(form, text="Optional details", bg="white", fg="#475467", font=("Segoe UI",11,"bold")).pack(anchor="w", pady=(12,5))
        self.fields_box = tk.Frame(form, bg="white"); self.fields_box.pack(fill="x")
        for f in entry.get("fields", []): self.add_field(f)
        actions = tk.Frame(form, bg="white"); actions.pack(fill="x", pady=16); ttk.Button(actions, text="＋ Add detail", command=lambda: self.add_field()).pack(side="left"); ttk.Button(actions, text="Cancel", command=self.show_welcome).pack(side="right", padx=(8,0)); ttk.Button(actions, text="Save item", style="Accent.TButton", command=lambda: self.save_entry(entry, creating)).pack(side="right")

    def form_field(self, parent, label, var):
        tk.Label(parent, text=label, bg="white", fg="#475467", font=("Segoe UI",9,"bold")).pack(anchor="w"); ttk.Entry(parent, textvariable=var).pack(fill="x", pady=(4,10))

    def add_field(self, field=None):
        field = field or {}
        field_id = field.get("id")
        existing_ids = {getattr(item[0], "field_id", None) for item in self.field_rows}
        if not valid_field_id(field_id) or field_id in existing_ids:
            field_id = secrets.token_hex(16)
        row = tk.Frame(self.fields_box, bg="#f8f9fc"); row.pack(fill="x", pady=3)
        row.field_id = field_id
        label_var = tk.StringVar(master=self, value=field.get("label", ""))
        label = ttk.Entry(row, width=18, textvariable=label_var); label.pack(side="left", padx=6, pady=6)
        row.original_value = str(field.get("value", ""))
        value_var = tk.StringVar(master=self, value=row.original_value)
        secret = tk.BooleanVar(master=self, value=field.get("secret", False))
        value = ttk.Entry(row, textvariable=value_var, show="•" if secret.get() else "")
        value.pack(side="left", fill="x", expand=True, padx=6, pady=6)
        row.value_entry = value

        def toggle_reveal():
            if not secret.get():
                return
            revealed = value.cget("show") == "•"
            value.configure(show="" if revealed else "•")
            reveal_button.configure(text="Hide" if revealed else "Show")

        reveal_button = ttk.Button(row, text="Show", command=toggle_reveal)
        reveal_button.pack(side="left", padx=4)
        row.reveal_button = reveal_button

        def update_secret_visibility(*_args):
            is_private = secret.get()
            value.configure(show="•" if is_private else "")
            reveal_button.configure(state="normal" if is_private else "disabled", text="Show")

        private_toggle = ttk.Checkbutton(row, text="Private", variable=secret)
        private_toggle.pack(side="left", padx=5)
        row.private_toggle = private_toggle
        ttk.Button(row, text="Remove", command=lambda: self.remove_field(row, label, value, secret)).pack(side="right", padx=6)
        for variable in (label_var, value_var, secret):
            self._watch_form_variable(variable)
        self._watch_form_variable(secret, update_secret_visibility)
        update_secret_visibility()
        self._advance_draft_generation()
        self.field_rows.append((row, label, value, secret))

    def remove_field(self, row, label, value, secret):
        self._advance_draft_generation()
        try: label.delete(0, tk.END); value.delete(0, tk.END)
        except tk.TclError: pass
        try: secret.set(False)
        except tk.TclError: pass
        self.field_rows = [item for item in self.field_rows if item[0] is not row]
        row.destroy()

    def save_entry(self, entry, creating):
        capture = self._capture_request
        if capture is not None and (
            capture.get("bridge_generation") != self._bridge_generation
            or not self._bridge_callbacks_open
            or self.password is None
            or self._closing_session
        ):
            self.show_welcome()
            return
        title = self.title_var.get().strip()
        if not title: messagebox.showwarning("Name needed", "Give this item a name so it is easy to find."); return
        fields = [{"id": row.field_id if v.get() == row.original_value else secrets.token_hex(16), "label": l.get().strip() or "Detail", "value": v.get(), "secret": s.get()} for row, l, v, s in self.field_rows if l.get().strip() or v.get()]
        updated = dict(entry)
        updated.update(title=title, category=self.category_var.get(), purpose=self.purpose_var.get().strip(), fields=fields, updated=datetime.now().isoformat(timespec="seconds"))
        if not isinstance(updated.get("id"), str) or not updated["id"]:
            updated["id"] = secrets.token_hex(8)
        entries = list(self.vault["entries"])
        index = next((i for i, existing in enumerate(entries) if existing.get("id") == updated["id"]), None)
        if index is None:
            existing_ids = {existing.get("id") for existing in entries}
            while updated["id"] in existing_ids: updated["id"] = secrets.token_hex(8)
            entries.append(updated)
        else:
            entries[index] = updated
        candidate = dict(self.vault); candidate["entries"] = entries
        error = self.commit_vault(candidate)
        if error: self.commit_error(error); return
        if hasattr(self, "search"): self.search.delete(0, tk.END)
        self._editing_entry_id = None
        self._editor_active = False
        self._capture_request = None
        self.refresh_list(); self.tree.selection_set(updated["id"]); self.show_entry(updated)

    def import_json(self):
        paths = filedialog.askopenfilenames(title="Import JSON files", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not paths: return
        imported = []
        errors = []
        for path in paths:
            try:
                payload = json.loads(self.read_bounded_text(path, MAX_JSON_IMPORT_BYTES))
                imported.extend(self.normalize_json_payload(payload, Path(path).stem))
            except Exception as exc:
                errors.append(f"{Path(path).name}: {exc}")
        if imported:
            existing_ids = {e.get("id") for e in self.vault["entries"]}
            entries = list(self.vault["entries"])
            for entry in imported:
                while entry["id"] in existing_ids: entry["id"] = secrets.token_hex(8)
                existing_ids.add(entry["id"]); entries.append(entry)
            candidate = dict(self.vault); candidate["entries"] = entries
            error = self.commit_vault(candidate)
            if error: self.commit_error(error)
            else: self.refresh_list()
        else:
            error = None
        imported_count = 0 if error else len(imported)
        summary = f"Imported {imported_count} item{'s' if imported_count != 1 else ''}."
        if error: summary += "\n\nThe imported items were not added because the vault could not be saved."
        if errors: summary += "\n\nSkipped:\n" + "\n".join(errors)
        messagebox.showinfo("JSON import", summary)

    def ocr_image(self, path):
        # Use Windows' built-in OCR engine locally; image contents never leave this computer.
        image_path = Path(path)
        if not image_path.is_file(): raise ValueError("The selected image could not be found")
        if image_path.stat().st_size > MAX_SCREENSHOT_IMPORT_BYTES: raise ValueError("Screenshot exceeds the 32 MiB import limit")
        script = r'''
$ErrorActionPreference = "Stop"
Add-Type -AssemblyName System.Runtime.WindowsRuntime
function Await($operation, $resultType) {
    $asTaskMethod = [System.WindowsRuntimeSystemExtensions].GetMethods() | Where-Object { $_.Name -eq "AsTask" -and $_.IsGenericMethod -and $_.GetGenericArguments().Count -eq 1 -and $_.GetParameters().Count -eq 1 } | Select-Object -First 1
    $task = $asTaskMethod.MakeGenericMethod($resultType).Invoke($null, [object[]]@($operation))
    return $task.GetAwaiter().GetResult()
}
$storageFileType = [Windows.Storage.StorageFile, Windows, ContentType=WindowsRuntime]
$fileAccessModeType = [Windows.Storage.FileAccessMode, Windows, ContentType=WindowsRuntime]
$bitmapDecoderType = [Windows.Graphics.Imaging.BitmapDecoder, Windows, ContentType=WindowsRuntime]
$softwareBitmapType = [Windows.Graphics.Imaging.SoftwareBitmap, Windows, ContentType=WindowsRuntime]
$bitmapPixelFormatType = [Windows.Graphics.Imaging.BitmapPixelFormat, Windows, ContentType=WindowsRuntime]
$bitmapAlphaModeType = [Windows.Graphics.Imaging.BitmapAlphaMode, Windows, ContentType=WindowsRuntime]
$ocrEngineType = [Windows.Media.Ocr.OcrEngine, Windows, ContentType=WindowsRuntime]
$file = Await ($storageFileType::GetFileFromPathAsync($env:SV_OCR_IMAGE)) $storageFileType
$streamType = [Windows.Storage.Streams.IRandomAccessStream, Windows, ContentType=WindowsRuntime]
$stream = Await ($file.OpenAsync($fileAccessModeType::Read)) $streamType
$decoder = Await ($bitmapDecoderType::CreateAsync($stream)) $bitmapDecoderType
if ([long]$decoder.PixelWidth -le 0 -or [long]$decoder.PixelHeight -le 0 -or ([long]$decoder.PixelWidth * [long]$decoder.PixelHeight) -gt __MAX_SCREENSHOT_PIXELS__) { throw "Screenshot dimensions exceed the 40 megapixel processing limit." }
$bitmap = Await ($decoder.GetSoftwareBitmapAsync()) $softwareBitmapType
$bitmap = $softwareBitmapType::Convert($bitmap, $bitmapPixelFormatType::Bgra8, $bitmapAlphaModeType::Premultiplied)
$engine = $ocrEngineType::TryCreateFromUserProfileLanguages()
if ($null -eq $engine) { throw "Windows OCR is not available for the current language." }
$ocrResultType = [Windows.Media.Ocr.OcrResult, Windows, ContentType=WindowsRuntime]
$result = Await ($engine.RecognizeAsync($bitmap)) $ocrResultType
if ($result.Text.Length -gt __MAX_SCREENSHOT_OCR_CHARS__) { throw "OCR output exceeds the 1 MiB text limit." }
if ($result.Lines.Count -gt 0) {
    [Console]::Out.Write(($result.Lines | ForEach-Object { $_.Text }) -join [Environment]::NewLine)
} else {
    [Console]::Out.Write($result.Text)
}
'''
        script = script.replace("__MAX_SCREENSHOT_PIXELS__", str(MAX_SCREENSHOT_PIXELS)).replace("__MAX_SCREENSHOT_OCR_CHARS__", str(MAX_SCREENSHOT_OCR_CHARS))
        environment = os.environ.copy(); environment["SV_OCR_IMAGE"] = str(Path(path).resolve())
        completed = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script], env=environment, capture_output=True, text=True, timeout=45)
        if completed.returncode != 0: raise RuntimeError(completed.stderr.strip() or "Windows OCR could not read this image")
        return completed.stdout.strip()

    def import_screenshots(self):
        paths = filedialog.askopenfilenames(title="Import screenshots", filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.gif;*.tif;*.tiff"), ("All files", "*.*")])
        if not paths: return
        imported = []; errors = []; empty = []
        for path in paths:
            try:
                text = self.ocr_image(path)
                if not text: empty.append(Path(path).name); continue
                title, category, fields = self.parse_ocr_text(text, Path(path).stem)
                imported.append({"id": secrets.token_hex(8), "title": title, "category": category, "purpose": f"Text extracted from {Path(path).name}", "fields": fields, "updated": datetime.now().isoformat(timespec="seconds")})
            except Exception as exc:
                errors.append(f"{Path(path).name}: {exc}")
        if imported:
            existing_ids = {e.get("id") for e in self.vault["entries"]}
            for entry in imported:
                while entry["id"] in existing_ids: entry["id"] = secrets.token_hex(8)
                existing_ids.add(entry["id"])
            candidate = dict(self.vault); candidate["entries"] = list(self.vault["entries"]) + imported
            error = self.commit_vault(candidate)
            if error: self.commit_error(error)
            else: self.refresh_list()
        else:
            error = None
        imported_count = 0 if error else len(imported)
        summary = f"Imported {imported_count} screenshot{'s' if imported_count != 1 else ''}."
        if error: summary += "\n\nThe extracted items were not added because the vault could not be saved."
        if empty: summary += "\n\nNo text found in:\n" + "\n".join(empty)
        if errors: summary += "\n\nSkipped:\n" + "\n".join(errors)
        messagebox.showinfo("Screenshot import", summary)

    def import_text_files(self):
        paths = filedialog.askopenfilenames(title="Import text backup files", filetypes=[("Text files", "*.txt;*.text;*.log"), ("All files", "*.*")])
        if not paths: return
        imported, errors = [], []
        for path in paths:
            try:
                text = self.read_bounded_text(path, MAX_TEXT_IMPORT_BYTES)
                if not text.strip(): raise ValueError("File is empty")
                imported.append(self.parse_text_backup(text, Path(path).stem))
            except Exception as exc:
                errors.append(f"{Path(path).name}: {exc}")
        if imported:
            existing_ids = {e.get("id") for e in self.vault["entries"]}
            entries = list(self.vault["entries"])
            for entry in imported:
                while entry["id"] in existing_ids: entry["id"] = secrets.token_hex(8)
                existing_ids.add(entry["id"]); entries.append(entry)
            candidate = dict(self.vault); candidate["entries"] = entries
            error = self.commit_vault(candidate)
            if error: self.commit_error(error)
            else: self.refresh_list()
        else:
            error = None
        imported_count = 0 if error else len(imported)
        summary = f"Imported {imported_count} text backup{'s' if imported_count != 1 else ''}."
        if error: summary += "\n\nThe imported items were not added because the vault could not be saved."
        if errors: summary += "\n\nSkipped:\n" + "\n".join(errors)
        messagebox.showinfo("Text import", summary)

    def parse_text_backup(self, text, fallback):
        if not text.strip(): raise ValueError("Text backup is empty")
        title = re.sub(r"[_-]+", " ", fallback).strip().title() or "Imported text backup"
        lines = [re.sub(r"^\s*(?:[-*•●▪]\s*)?", "", line).strip() for line in text.splitlines() if line.strip()]
        code_lines = []
        for line in lines:
            normalized = line.replace(" ", "")
            # Backup codes are usually short numeric/alphanumeric groups, often split by a hyphen.
            if re.fullmatch(r"[A-Za-z0-9]{3,12}(?:[-_][A-Za-z0-9]{3,12})?", normalized) and not re.search(r"(?i)(backup|code|recovery|stripe|generated|date|account|save|use|warning)", line):
                code_lines.append(line)
        looks_like_codes = len(code_lines) >= 2 or any(re.search(r"(?i)(backup|recovery)\s+codes?", line) for line in lines[:3])
        if looks_like_codes and code_lines:
            fields = [create_vault_field(f"Backup code {i}", code, True) for i, code in enumerate(code_lines, 1)]
            return {"id": secrets.token_hex(8), "title": title, "category": "Backup codes", "purpose": "Imported from a text backup file", "fields": fields, "updated": datetime.now().isoformat(timespec="seconds")}
        parsed = self.parse_ocr_text(text, fallback)
        return {"id": secrets.token_hex(8), "title": parsed[0], "category": parsed[1], "purpose": "Imported from a text file", "fields": parsed[2], "updated": datetime.now().isoformat(timespec="seconds")}

    def infer_category(self, text, fields=None):
        haystack = (text + " " + " ".join(f.get("label", "") for f in (fields or []))).lower()
        if any(word in haystack for word in ("recovery phrase", "seed phrase", "mnemonic", "private key")): return "Recovery phrase"
        if any(word in haystack for word in ("api key", "api token", "access token", "access key id", "secret access key", "client secret", "secret key")): return "API key"
        if any(word in haystack for word in ("license key", "product key", "serial number")): return "License key"
        if any(word in haystack for word in ("token", "bearer", "oauth", "refresh token")): return "Token"
        if any(word in haystack for word in ("password", "passcode", "username", "login", "email")): return "Password"
        if fields and len(fields) > 2: return "Secure note"
        return "Other"

    def infer_title(self, text, fallback):
        fallback = self.smart_title(re.sub(r"[_-]+", " ", fallback).strip()) or "Imported item"
        heading = re.match(r"^(.{2,50}?)\s+(created|generated|added|saved)\b", text.strip(), flags=re.I)
        if heading: return self.smart_title(heading.group(1).strip())
        lines = [re.sub(r"^[•●▪*-]\s*", "", line).strip() for line in text.splitlines() if line.strip()]
        for line in lines:
            if re.match(r"(?i)^(https?://)?([\w-]+\.)+[a-z]{2,}([/:].*)?$", line):
                domain = re.sub(r"^https?://", "", line, flags=re.I).split("/")[0]
                return self.smart_title(domain.removeprefix("www.").split(".")[0])
            match = re.match(r"^([^:=]{2,50})\s*[:=]\s*(.+)$", line)
            if match and not any(word in match.group(1).lower() for word in ("username", "email", "password", "token", "key", "secret", "phrase")):
                return self.smart_title(match.group(1).strip())
            if len(line) <= 50 and ":" not in line and not re.search(r"(?i)(password|username|email|token|key|secret|phrase)\s", line):
                title = re.sub(r"\s+(created|generated|added|saved)$", "", line.strip(), flags=re.I)
                return self.smart_title(title)
        for line in lines:
            match = re.match(r"^([^:=]{2,50})\s*[:=]\s*.+$", line)
            if match: return self.smart_title(match.group(1).strip())
        return fallback

    def smart_title(self, value):
        title = value.title()
        for acronym, replacement in (("oauth", "OAuth"), ("api", "API"), ("aws", "AWS"), ("ssh", "SSH"), ("url", "URL"), ("otp", "OTP"), ("mfa", "MFA"), ("2fa", "2FA")):
            title = re.sub(rf"\b{re.escape(acronym.title())}\b", replacement, title, flags=re.I)
        return title

    def match_ocr_label(self, label, known_labels):
        normalized = re.sub(r"[^a-z0-9]+", " ", str(label).casefold()).strip()
        normalized_known = {
            re.sub(r"[^a-z0-9]+", " ", candidate.casefold()).strip(): candidate
            for candidate in known_labels
        }
        if normalized in normalized_known:
            return normalized_known[normalized]
        if len(normalized) < 5:
            return None
        closest, score = max(
            ((candidate, SequenceMatcher(None, normalized, candidate).ratio()) for candidate in normalized_known),
            key=lambda item: item[1],
        )
        if score >= 0.86 and abs(len(normalized) - len(closest)) <= 3:
            return normalized_known[closest]
        return None

    def parse_flat_ocr_text(self, text):
        clean = re.sub(r"\s+", " ", text).strip()
        for pattern in (r"The client ID can always.+?Platform\.\s*", r"OAuth access is restricted.+?consent screen\s*", r"You will no longer.+?stored it\.\s*", r"Make sure you have.+?stored it\.\s*"):
            clean = re.sub(pattern, " ", clean, flags=re.I)
        fields = []
        client_id = re.search(r"client id\s+(.+?)(?=\s+client secret|\s+creation date|\s+status|\s+download json|$)", clean, flags=re.I)
        if client_id:
            value = re.sub(r"\s+", "", client_id.group(1)).strip(".,")
            if value: fields.append(create_vault_field("Client ID", value, False))
        secret = re.search(r"download json\s+([A-Za-z0-9_-]{16,})", clean, flags=re.I)
        if not secret:
            candidates = re.findall(r"(?:GOCSPX[-_])?[A-Za-z0-9_-]{20,}", clean)
            secret = type("Match", (), {"group": lambda self, n: candidates[-1]})() if candidates else None
        if secret:
            secret_value = secret.group(1)
            if re.search(r"oauth\s+client", clean, flags=re.I) and not secret_value.upper().startswith("GOCSPX-"):
                secret_value = "GOCSPX-" + secret_value
            fields.append(create_vault_field("Client secret", secret_value, True))
        created = re.search(r"([A-Z][a-z]+\s+\d{1,2},\s+\d{4},\s+[^.]+?GMT[-+]?\d+)", clean)
        if created: fields.append(create_vault_field("Creation date", created.group(1).strip(), False))
        if re.search(r"\benabled\b", clean, flags=re.I): fields.append(create_vault_field("Status", "Enabled", False))
        return fields

    def parse_ocr_text(self, text, fallback):
        fields = []
        inferred_title = self.infer_title(text, fallback)
        if len(text.splitlines()) <= 1 or (re.search(r"client\s+id", text, flags=re.I) and re.search(r"client\s+secret", text, flags=re.I) and re.search(r"creation\s+date", text, flags=re.I)):
            flat_fields = self.parse_flat_ocr_text(text)
            if flat_fields: return inferred_title, self.infer_category(text, flat_fields), flat_fields
        known = ("username", "user name", "email", "e-mail", "password", "passcode", "api key", "api token", "access token", "access key id", "secret access key", "client id", "client secret", "token", "refresh token", "bearer token", "secret", "private key", "public key", "recovery phrase", "seed phrase", "mnemonic", "url", "website", "endpoint", "host", "port", "region", "address", "account", "account id", "organization", "organization id", "project id", "subscription id", "creation date", "status", "owner", "name", "notes", "note", "description")
        noise = ("client id can always", "oauth access is restricted", "test users", "oauth consent screen", "you will no longer", "once you close this dialog", "make sure you have", "copied or downloaded", "securely stored", "save this code", "each code can only be used", "if you do not save", "if you don't save")
        current_label, current_value = None, []

        def save_current():
            if current_label and current_value:
                value = " ".join(current_value).strip()
                if value and value.casefold() != current_label.casefold():
                    fields.append(create_vault_field(current_label.title(), value, self.is_sensitive_label(current_label)))

        for raw_line in text.splitlines():
            line = re.sub(r"^[•●▪*-]\s*", "", raw_line).strip()
            if not line: continue
            lower = line.casefold()
            if lower in ("ok", "close", "cancel", "download json") or any(fragment in lower for fragment in noise):
                save_current(); current_label, current_value = None, []; continue
            match = re.match(r"^([^:=]{2,50})\s*[:=]\s*(.+)$", line)
            exact_label = self.match_ocr_label(line, known)
            raw_label = match.group(1).strip() if match else ""
            label = self.match_ocr_label(raw_label, known) or raw_label.casefold() if match else exact_label
            if label and label not in known:
                custom_label = match.group(1).strip() if match else ""
                instructional_label = bool(re.search(r"\b(warning|important|save|remember|do not|don't|click|close|download|copy|instructions)\b", custom_label, flags=re.I))
                if match and re.fullmatch(r"[A-Za-z][A-Za-z0-9 _./()#-]{1,49}", custom_label) and not instructional_label and not any(fragment in lower for fragment in noise):
                    save_current()
                    fields.append(create_vault_field(self.smart_title(custom_label), match.group(2).strip(), self.is_sensitive_label(custom_label)))
                    current_label, current_value = None, []
                    continue
                label = None
            if not label and not match:
                label = next((candidate for candidate in sorted(known, key=len, reverse=True) if lower.startswith(candidate + " ")), None)
                value = line[len(label):].strip() if label else None
            else:
                value = match.group(2).strip() if match else None
            if label:
                save_current(); current_label, current_value = label, ([value] if value else [])
            elif current_label:
                current_value.append(line)
        save_current()
        if not fields: fields = [create_vault_field("Extracted text", text.strip(), True)]
        return inferred_title, self.infer_category(text, fields), fields

    def read_bounded_text(self, path, max_bytes):
        with open(path, "rb") as stream:
            raw = stream.read(max_bytes + 1)
        if len(raw) > max_bytes:
            raise ValueError(f"File exceeds the {max_bytes // (1024 * 1024)} MiB import limit")
        try:
            return raw.decode("utf-8-sig")
        except UnicodeError as exc:
            raise ValueError("File is not valid UTF-8 text") from exc

    def flatten_json_fields(self, value, prefix=""):
        fields = []
        if isinstance(value, dict):
            for key, child in value.items(): fields.extend(self.flatten_json_fields(child, f"{prefix} {key}".strip()))
        elif isinstance(value, list):
            fields.append(create_vault_field(prefix or "Details", json.dumps(value, ensure_ascii=False), self.is_sensitive_label(prefix)))
        else:
            fields.append(create_vault_field(prefix or "Detail", str(value), self.is_sensitive_label(prefix)))
        return fields

    def is_sensitive_label(self, label):
        normalized = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1 \2", str(label))
        normalized = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", normalized).casefold()
        normalized = re.sub(r"[_\-.]+", " ", normalized)
        normalized = re.sub(r"\bpublic\s*key\b", "", normalized)
        pattern = r"\b(password|passwd|passphrase|passcode|secret|token|bearer|auth(?:entication|orization)?|private\s*key|api\s*key|access\s*key|recovery\s*phrase|seed\s*phrase|mnemonic|backup\s*codes?|recovery\s*codes?|otp|jwt|session|cookie|connection\s*string|dsn|key)\b"
        return normalized.strip() in ("credential", "credentials") or bool(re.search(pattern, normalized))

    def normalize_json_payload(self, payload, fallback_title):
        if isinstance(payload, dict) and isinstance(payload.get("entries"), list):
            values = payload["entries"]
        elif isinstance(payload, list):
            values = payload
        elif isinstance(payload, dict):
            values = [payload]
        else:
            raise ValueError("JSON must contain an object or array")
        result = []
        for index, raw in enumerate(values, 1):
            if not isinstance(raw, dict):
                raise ValueError(f"item {index} is not an object")
            title = str(raw.get("title") or raw.get("name") or raw.get("label") or raw.get("service") or raw.get("website") or raw.get("domain") or "")
            purpose = str(raw.get("purpose") or raw.get("description") or "")
            if isinstance(raw.get("fields"), list):
                fields = []
                for field in raw["fields"]:
                    if isinstance(field, dict):
                        label = str(field.get("label") or field.get("name") or "Detail")
                        fields.append(create_vault_field(label, str(field.get("value", "")), bool(field.get("secret", self.is_sensitive_label(label)))))
            else:
                reserved = {"id", "title", "name", "label", "category", "type", "purpose", "description", "created", "updated"}
                fields = []
                for key, value in raw.items():
                    if key not in reserved: fields.extend(self.flatten_json_fields(value, str(key)))
            source_text = " ".join(f"{f.get('label', '')}: {f.get('value', '')}" for f in fields)
            title = title.strip() or self.infer_title(source_text, f"{fallback_title} {index}")
            category = str(raw.get("category") or raw.get("type") or self.infer_category(source_text, fields))
            result.append({"id": str(raw.get("id") or secrets.token_hex(8)), "title": title, "category": category, "purpose": purpose, "fields": fields, "updated": datetime.now().isoformat(timespec="seconds")})
        return result

    def delete_entry(self, entry):
        if messagebox.askyesno("Delete item?", f"Delete '{entry.get('title')}' permanently?"):
            candidate = dict(self.vault); candidate["entries"] = [e for e in self.vault["entries"] if e["id"] != entry["id"]]
            error = self.commit_vault(candidate)
            if error: self.commit_error(error); return
            self.refresh_list(); self.show_welcome()

    def copy(self, value):
        if self._clipboard_after_id is not None:
            try: self.after_cancel(self._clipboard_after_id)
            except tk.TclError: pass
        self._clipboard_after_id = None
        try:
            self.clipboard_clear()
            self.clipboard_append(value)
        except tk.TclError:
            self._clipboard_value = None
            messagebox.showerror("Clipboard unavailable", "HexiKeys could not copy this value. Your vault is unchanged.")
            return False
        self._clipboard_value = value
        try:
            self._clipboard_after_id = self.after(30000, self.clear_clipboard)
        except tk.TclError:
            self.clear_clipboard()
            messagebox.showerror("Clipboard cleanup unavailable", "HexiKeys could not schedule automatic cleanup, so it removed the copied value. Try copying again after restarting the app.")
            return False
        return True

    def clear_clipboard(self):
        after_id = self._clipboard_after_id
        self._clipboard_after_id = None
        if after_id is not None:
            try: self.after_cancel(after_id)
            except tk.TclError: pass
        try:
            if self._clipboard_value is not None and self.clipboard_get() == self._clipboard_value:
                self.clipboard_clear()
        except tk.TclError: pass
        self._clipboard_value = None

    def _record_activity(self, _event=None):
        if self.password is not None:
            self._last_activity_at = time.monotonic()

    def _schedule_idle_lock(self):
        if self.password is not None and self._idle_lock_after_id is None:
            self._idle_lock_after_id = self.after(IDLE_LOCK_CHECK_MS, self._check_idle_lock)

    def _check_idle_lock(self):
        self._idle_lock_after_id = None
        if self.password is None:
            return
        if self._last_activity_at is not None and time.monotonic() - self._last_activity_at >= IDLE_LOCK_SECONDS:
            self.lock(automatic=True)
            return
        self._schedule_idle_lock()

    def _cancel_idle_lock(self):
        if self._idle_lock_after_id is not None:
            try: self.after_cancel(self._idle_lock_after_id)
            except tk.TclError: pass
            self._idle_lock_after_id = None

    def lock(self, automatic=False):
        self._cancel_idle_lock()
        self.clear_clipboard()
        if self._closing_session:
            return
        self._begin_bridge_stop(lambda: self._finish_lock(automatic), ending_session=True)

    def _finish_lock(self, automatic=False):
        self.password = None
        self.vault = {"entries": []}
        self._capture_request = None
        self._editor_active = False
        self._advance_vault_generation()
        self._advance_draft_generation()
        self._closing_session = False
        self.build_login()
        if automatic:
            messagebox.showinfo("Vault locked", "HexiKeys locked after 10 minutes without activity in the app.")

    def close(self):
        self._cancel_idle_lock()
        self.clear_clipboard()
        if self._closing_session and self._bridge_stop_pending is None:
            return
        self._closing_session = True
        if self._bridge_stop_pending is not None:
            self._bridge_stop_pending["finalizers"].append(self._finish_close)
            self._refresh_bridge_controls()
            return
        self._begin_bridge_stop(self._finish_close, ending_session=True)

    def _finish_close(self):
        self.password = None
        self.vault = {"entries": []}
        self._capture_request = None
        self._editor_active = False
        self._advance_vault_generation()
        self._advance_draft_generation()
        self.clear()
        self._allow_destroy_after_bridge = True
        self.destroy()

    def destroy(self):
        if (getattr(self, "_bridge_server", None) is not None
                and not getattr(self, "_allow_destroy_after_bridge", False)) or (
                    getattr(self, "password", None) is not None
                    and not getattr(self, "_allow_destroy_after_bridge", False)
                ):
            self.close()
            return
        self._cancel_idle_lock()
        self._cancel_login_focus()
        self._detach_form_traces()
        if self._bridge_pump_after_id is not None:
            try: self.after_cancel(self._bridge_pump_after_id)
            except tk.TclError: pass
            self._bridge_pump_after_id = None
        self._release_instance_mutex()
        super().destroy()


def run_self_check():
    """Exercise the packaged crypto and storage modules using disposable data."""
    payload = {
        "entries": [{
            "id": "self-check-item",
            "title": "Synthetic self-check entry",
            "category": "Secure note",
            "purpose": "Packaged runtime verification",
            "fields": [{"label": "Synthetic value", "value": "not a real credential", "secret": True}],
        }]
    }
    password = "synthetic HexiKeys self-check password"
    try:
        with tempfile.TemporaryDirectory(prefix="hexikeys-self-check-") as directory:
            path = Path(directory) / "vault.dat"
            save_vault(path, payload, password)
            restored, version = load_vault(path, password)
            if restored != payload or version != 2:
                return 1
            try:
                load_vault(path, password + "-wrong")
            except ValueError:
                pass
            else:
                return 2
    except Exception:
        return 3
    return 0


def run_ui_self_check():
    """Verify packaged Tk and branding without accessing a user's vault."""
    global DATA_DIR, VAULT_FILE, PAIRING_DATA_DIR
    with tempfile.TemporaryDirectory(prefix="hexikeys-ui-check-") as directory:
        DATA_DIR = Path(directory)
        VAULT_FILE = DATA_DIR / "vault.dat"
        PAIRING_DATA_DIR = DATA_DIR / "pairing"
        application = HexiKeysApp()
        try:
            application.withdraw()
            application.update_idletasks()
            if not application._startup_ok:
                return 1
            mark = HexiMark(application, background="#f5f7fb", size=58)
            if not getattr(mark, "_brand_image", None):
                return 2
            mark.destroy()
            return 0
        finally:
            application.destroy()


if __name__ == "__main__":
    if "--self-check" in os.sys.argv:
        raise SystemExit(run_self_check())
    if "--ui-self-check" in os.sys.argv:
        raise SystemExit(run_ui_self_check())
    application = HexiKeysApp()
    if application._startup_ok:
        application.mainloop()
