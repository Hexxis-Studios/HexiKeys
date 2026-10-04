import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import app


class SecretFieldEditorTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="hexikeys-field-editor-")
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
        self.root.detail = app.tk.Frame(self.root)
        self.root.detail.pack(fill="both", expand=True)

    def tearDown(self):
        root = getattr(self, "root", None)
        if root is not None:
            try:
                root._allow_destroy_after_bridge = True
                root.destroy()
            except app.tk.TclError:
                pass
        for item in reversed(getattr(self, "patches", [])):
            item.stop()
        if hasattr(self, "temp_dir"):
            self.temp_dir.cleanup()

    def edit_fields(self, fields):
        entry = {
            "id": "synthetic-field-editor-entry",
            "title": "Synthetic field editor item",
            "category": "Secure note",
            "purpose": "UI behavior test",
            "fields": fields,
        }
        self.root.edit_entry(entry)
        return self.root.field_rows

    def test_private_field_is_masked_by_default_and_reveal_is_per_field(self):
        rows = self.edit_fields([
            app.create_vault_field("Account", "synthetic-account", False),
            app.create_vault_field("API key", "SYNTHETIC-ONLY-key-value", True),
        ])
        public_row, _, public_value, _ = rows[0]
        private_row, _, private_value, _ = rows[1]

        self.assertEqual(public_value.cget("show"), "")
        self.assertEqual(private_value.cget("show"), "•")
        self.assertEqual(str(public_row.reveal_button.cget("state")), "disabled")
        self.assertEqual(str(private_row.reveal_button.cget("state")), "normal")
        self.assertEqual(private_row.reveal_button.cget("text"), "Show")

        private_row.reveal_button.invoke()
        self.assertEqual(private_value.cget("show"), "")
        self.assertEqual(private_row.reveal_button.cget("text"), "Hide")
        self.assertEqual(public_value.cget("show"), "")

        private_row.reveal_button.invoke()
        self.assertEqual(private_value.cget("show"), "•")
        self.assertEqual(private_row.reveal_button.cget("text"), "Show")

    def test_private_toggle_masks_immediately_and_remasks_after_reveal(self):
        row, _, value, secret = self.edit_fields([
            app.create_vault_field("Token", "SYNTHETIC-ONLY-token-value", False),
        ])[0]

        self.assertEqual(value.cget("show"), "")
        row.private_toggle.invoke()
        self.assertTrue(secret.get())
        self.assertEqual(value.cget("show"), "•")
        self.assertEqual(row.reveal_button.cget("text"), "Show")

        row.reveal_button.invoke()
        self.assertEqual(value.cget("show"), "")
        row.private_toggle.invoke()
        self.assertFalse(secret.get())
        self.assertEqual(value.cget("show"), "")
        self.assertEqual(str(row.reveal_button.cget("state")), "disabled")

        row.private_toggle.invoke()
        self.assertTrue(secret.get())
        self.assertEqual(value.cget("show"), "•")
        self.assertEqual(row.reveal_button.cget("text"), "Show")

    def test_label_value_and_private_edits_still_invalidate_the_draft(self):
        row, label, value, secret = self.edit_fields([
            app.create_vault_field("Client secret", "SYNTHETIC-ONLY-secret-value", True),
        ])[0]

        before_label = self.root._draft_generation
        label.delete(0, app.tk.END)
        label.insert(0, "Renamed secret")
        self.assertGreater(self.root._draft_generation, before_label)

        before_value = self.root._draft_generation
        value.delete(0, app.tk.END)
        value.insert(0, "SYNTHETIC-ONLY-updated-value")
        self.assertGreater(self.root._draft_generation, before_value)

        before_private = self.root._draft_generation
        row.private_toggle.invoke()
        self.assertGreater(self.root._draft_generation, before_private)


if __name__ == "__main__":
    unittest.main()
