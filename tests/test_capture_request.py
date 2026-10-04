import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest.mock import patch, Mock

import app
import vault_bridge


SYNTHETIC_PASSWORD = "Synthetic capture request test password 2047"
CATEGORIES = (
    "Password", "API key", "Token", "Recovery phrase", "Backup codes",
    "License key", "Secure note", "Screenshot OCR", "Other",
)


def capture_payload(**updates):
    payload = {
        "op": "request-new-item",
        "requestId": "a" * 32,
        "title": "Synthetic service account",
        "category": "API key",
        "fieldLabel": "API key",
        "requestedBy": "Synthetic local agent",
        "expiresAt": int(time.time()) + 30,
    }
    payload.update(updates)
    return payload


class CaptureRequestValidationTests(unittest.TestCase):
    def test_exact_request_schema_categories_and_short_expiry(self):
        for category in CATEGORIES:
            request = capture_payload(category=category)
            self.assertEqual(vault_bridge._validate_request_payload(request), request)

        for invalid in (
            capture_payload(extra="ignored"),
            capture_payload(value="must never cross the pipe"),
            capture_payload(requestId="A" * 32),
            capture_payload(category="not a category"),
            capture_payload(title=""),
            capture_payload(title="x" * 121),
            capture_payload(fieldLabel="x" * 81),
            capture_payload(requestedBy="x" * 121),
            capture_payload(title="bad\nlabel"),
            capture_payload(requestedBy="bad\x85caller"),
        ):
            with self.subTest(invalid=invalid):
                with self.assertRaises(vault_bridge._Denied):
                    vault_bridge._validate_request_payload(invalid)

    def test_expiry_must_be_an_integer_inside_sixty_seconds(self):
        for expires_at in (999, 1000, 1061, True, "1030"):
            with self.subTest(expires_at=expires_at), patch.object(vault_bridge.time, "time", return_value=1000):
                with self.assertRaises(vault_bridge._Denied):
                    vault_bridge._validate_request_payload(capture_payload(expiresAt=expires_at))
        with patch.object(vault_bridge.time, "time", return_value=1000):
            self.assertEqual(
                vault_bridge._validate_request_payload(capture_payload(expiresAt=1060))["expiresAt"],
                1060,
            )

    def test_request_operation_returns_only_opened_standing(self):
        received = []
        server = vault_bridge.VaultBridgeServer(
            "hexikeys-" + "1" * 32,
            b"k" * 32,
            get_status=lambda: {"available": True, "unlocked": True},
            request_new_item=lambda request: received.append(dict(request)) or {"opened": True},
        )
        request = vault_bridge._validate_request_payload(capture_payload())
        self.assertEqual(server._execute(request), {"opened": True})
        self.assertEqual(received, [request])

    def test_public_grant_projection_preserves_valid_prefix_and_rejects_invalid(self):
        grant = {"prefix": "Bearer ", "id": "synthetic-grant"}
        self.assertEqual(vault_bridge.VaultBridgeServer._safe_public_grant(grant)["prefix"], "Bearer ")
        for prefix in ("x" * 65, "bad\nvalue", "bad\x85value", None):
            with self.subTest(prefix=prefix):
                with self.assertRaises(ValueError):
                    vault_bridge.VaultBridgeServer._safe_public_grant({"prefix": prefix})


class CaptureRequestAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="hexikeys-capture-test-")
        self.data_dir = Path(self.temp_dir.name)
        self.patches = [
            patch.object(app, "DATA_DIR", self.data_dir),
            patch.object(app, "VAULT_FILE", self.data_dir / "vault.dat"),
        ]
        for item in self.patches:
            item.start()
        try:
            self.root = app.HexiKeysApp()
            self.root.withdraw()
        except app.tk.TclError as exc:
            self.tearDown()
            self.skipTest(f"Tk display is unavailable: {exc}")
        self.root.password = SYNTHETIC_PASSWORD
        self.root.vault = {"entries": []}
        self.root.detail = app.tk.Frame(self.root)
        self.root.detail.pack(fill="both", expand=True)
        self.root._bridge_generation = 7
        self.root._bridge_callbacks_open = True

    def tearDown(self):
        root = getattr(self, "root", None)
        if root is not None:
            try:
                root._bridge_callbacks_open = False
                root._bridge_server = None
                root._bridge_stop_pending = None
                root.password = None
                root._allow_destroy_after_bridge = True
                root.destroy()
            except app.tk.TclError:
                pass
        for item in reversed(getattr(self, "patches", [])):
            item.stop()
        if hasattr(self, "temp_dir"):
            self.temp_dir.cleanup()

    def request(self, payload=None):
        callback = self.root._bridge_callbacks(7)["request_new_item"]
        return callback(payload or capture_payload())

    def test_request_opens_existing_editor_with_one_empty_masked_private_field(self):
        payload = capture_payload()
        self.assertEqual(self.request(payload), {"opened": True})

        self.assertTrue(self.root._editor_active)
        self.assertIsNone(self.root._editing_entry_id)
        self.assertEqual(self.root.title_var.get(), "Synthetic service account")
        self.assertEqual(self.root.category_var.get(), "API key")
        self.assertEqual(len(self.root.field_rows), 1)
        row, label, value, private = self.root.field_rows[0]
        self.assertEqual(label.get(), "API key")
        self.assertEqual(value.get(), "")
        self.assertTrue(private.get())
        self.assertEqual(value.cget("show"), "•")
        self.assertIn("Requested by Synthetic local agent", self.root.capture_requester_label.cget("text"))
        self.assertNotIn("value", self.root._capture_request)
        self.assertEqual(self.root.vault["entries"], [])

    def test_duplicate_active_capture_and_existing_owner_draft_are_denied(self):
        payload = capture_payload()
        self.request(payload)
        with self.assertRaisesRegex(RuntimeError, "denied"):
            self.request(payload)
        self.assertTrue(self.root._editor_active)
        self.assertEqual(self.root.title_var.get(), "Synthetic service account")

        self.root.show_welcome()
        owner_entry = {
            "id": "synthetic-owner-draft",
            "title": "Owner draft",
            "category": "Secure note",
            "purpose": "test",
            "fields": [app.create_vault_field("Private note", "synthetic-only", True)],
        }
        self.root.edit_entry(owner_entry)
        with self.assertRaisesRegex(RuntimeError, "denied"):
            self.request(capture_payload(requestId="b" * 32))
        self.assertEqual(self.root.title_var.get(), "Owner draft")
        self.assertEqual(self.root.field_rows[0][2].get(), "synthetic-only")

    def test_owner_save_uses_encrypted_commit_and_cancel_creates_nothing(self):
        self.request()
        self.root.show_welcome()
        self.assertEqual(self.root.vault["entries"], [])
        self.assertIsNone(self.root._capture_request)
        self.request(capture_payload(requestId="d" * 32))
        secret = "SYNTHETIC-ONLY-owner-entered-capture-secret"
        self.root.field_rows[0][2].insert(0, secret)
        self.root.tree = Mock()
        with patch.object(self.root, "refresh_list"), patch.object(self.root, "show_entry"):
            self.root.save_entry({}, True)
        from vault_store import load_vault
        saved, _version = load_vault(app.VAULT_FILE, SYNTHETIC_PASSWORD)
        self.assertEqual(saved["entries"][0]["fields"][0]["value"], secret)
        self.assertTrue(saved["entries"][0]["fields"][0]["secret"])
        self.assertNotIn(secret.encode(), app.VAULT_FILE.read_bytes())
        self.assertIsNone(self.root._capture_request)
        self.assertFalse(self.root._editor_active)

    def test_stale_queued_draft_generation_is_denied(self):
        original_generation = self.root._draft_generation
        self.root._advance_draft_generation()
        job = {
            "generation": 7,
            "kind": "request_new_item",
            "request": capture_payload(requestId="c" * 32),
            "draft_generation": original_generation,
            "done": threading.Event(),
            "cancelled": False,
        }
        self.root._run_bridge_ui_call(job)
        self.assertTrue(job["done"].is_set())
        self.assertEqual(job.get("error"), "The local bridge callback was denied.")
        self.assertIsNone(self.root._capture_request)
        self.assertFalse(self.root._editor_active)

    def test_queued_request_cancellation_and_lock_clear_only_capture_form(self):
        result = {}

        def invoke_from_worker():
            try:
                result["value"] = self.request()
            except Exception as exc:
                result["error"] = exc

        worker = threading.Thread(target=invoke_from_worker)
        worker.start()
        deadline = time.monotonic() + 2
        while self.root._bridge_callback_queue.empty() and time.monotonic() < deadline:
            time.sleep(0.001)
        self.assertFalse(self.root._bridge_callback_queue.empty())
        self.root._reject_queued_bridge_calls()
        worker.join(timeout=1)
        self.assertFalse(worker.is_alive())
        self.assertIn("error", result)
        self.assertIsNone(self.root._capture_request)
        self.assertFalse(self.root._editor_active)

        self.request()
        self.assertIsNotNone(self.root._capture_request)
        self.root.lock()
        self.assertIsNone(self.root.password)
        self.assertIsNone(self.root._capture_request)
        self.assertFalse(self.root._editor_active)


if __name__ == "__main__":
    unittest.main()
