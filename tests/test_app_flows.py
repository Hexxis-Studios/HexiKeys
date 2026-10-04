import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

import app
from test_vault_crypto import PASSWORD, PAYLOAD, make_legacy_v1
from vault_store import load_vault, save_vault


class AppFlowTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="hexikeys-account-test-")
        self.data_dir = Path(self.temp_dir.name)
        self.vault_path = self.data_dir / "vault.dat"
        self.patches = [patch.object(app, "DATA_DIR", self.data_dir), patch.object(app, "VAULT_FILE", self.vault_path)]
        for item in self.patches: item.start()

    def tearDown(self):
        for item in reversed(self.patches): item.stop()
        self.temp_dir.cleanup()

    @unittest.skipUnless(os.name == "nt", "Windows named mutex is a Windows-only feature")
    def test_second_window_for_same_vault_is_rejected_then_reopens_after_close(self):
        first = app.HexiKeysApp()
        first.withdraw()
        reopened = None
        try:
            self.assertTrue(first._startup_ok)
            vault_identity = os.path.normcase(str(self.vault_path.resolve())).encode("utf-8")
            mutex_name = "Local\\HexiKeys-" + app.hashlib.sha256(vault_identity).hexdigest()
            probe = r'''import ctypes, sys
from ctypes import wintypes
kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
kernel32.CreateMutexW.argtypes = (wintypes.LPVOID, wintypes.BOOL, wintypes.LPCWSTR)
kernel32.CreateMutexW.restype = wintypes.HANDLE
kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
ctypes.set_last_error(0)
handle = kernel32.CreateMutexW(None, False, sys.argv[1])
error = ctypes.get_last_error()
if handle:
    kernel32.CloseHandle(handle)
print(error)
raise SystemExit(0 if handle and error == 183 else 1)
'''
            child = subprocess.run(
                [sys.executable, "-c", probe, mutex_name],
                check=True,
                capture_output=True,
                text=True,
                timeout=10,
            )
            self.assertEqual(child.stdout.strip(), "183")
            with patch.object(app.messagebox, "showwarning") as warning:
                second = app.HexiKeysApp()
            self.assertFalse(second._startup_ok)
            warning.assert_called_once()
            first.destroy()
            first = None
            reopened = app.HexiKeysApp()
            self.assertTrue(reopened._startup_ok)
        finally:
            if first is not None:
                first.destroy()
            if reopened is not None:
                reopened.destroy()

    def test_app_fails_closed_if_exclusive_access_cannot_be_confirmed(self):
        with patch.object(app.HexiKeysApp, "_acquire_instance_mutex", side_effect=OSError("synthetic mutex error")), \
             patch.object(app.messagebox, "showerror") as show_error:
            root = app.HexiKeysApp()
        self.assertFalse(root._startup_ok)
        show_error.assert_called_once()

    def test_password_generator_obeys_length_and_character_classes(self):
        password = app.generate_secure_password(32)
        self.assertEqual(len(password), 32)
        self.assertTrue(any(char.islower() for char in password))
        self.assertTrue(any(char.isupper() for char in password))
        self.assertTrue(any(char.isdigit() for char in password))
        self.assertTrue(any(char in "!@#$%^&*()-_=+[]{}:,.?" for char in password))
        plain = app.generate_secure_password(12, include_symbols=False)
        self.assertEqual(len(plain), 12)
        self.assertTrue(all(char.isalnum() for char in plain))
        for invalid in (0, 11, 129, True, 20.5):
            with self.subTest(length=invalid), self.assertRaises(ValueError):
                app.generate_secure_password(invalid)

    def test_entry_search_matches_context_and_public_fields_but_not_secrets(self):
        entry = {
            "title": "Synthetic OAuth client",
            "category": "API key",
            "purpose": "Staging dashboard",
            "fields": [
                {"label": "Account email", "value": "owner@example.invalid", "secret": False},
                {"label": "Client secret", "value": "SYNTHETIC-ONLY-secret-12345", "secret": True},
            ],
        }
        index = app.entry_search_text(entry)
        for expected in ("synthetic oauth client", "api key", "staging dashboard", "account email", "owner@example.invalid", "client secret"):
            with self.subTest(expected=expected):
                self.assertIn(expected, index)
        self.assertNotIn("SYNTHETIC-ONLY-secret-12345".casefold(), index)
        self.assertEqual(app.entry_search_text({"fields": [None, {"label": 3, "value": object()}]}), "")

    def test_json_import_ignores_external_field_ids_and_assigns_unique_references(self):
        root = app.HexiKeysApp()
        root.withdraw()
        try:
            imported = root.normalize_json_payload({"title": "Synthetic imported app", "fields": [
                {"id": "attacker-chosen-id", "label": "Client ID", "value": "synthetic-client-id"},
                {"id": "attacker-chosen-id", "label": "Client secret", "value": "SYNTHETIC-ONLY-value", "secret": True},
            ]}, "synthetic")
            fields = imported[0]["fields"]
            field_ids = [field["id"] for field in fields]
            self.assertEqual(len(set(field_ids)), 2)
            self.assertTrue(all(app.valid_field_id(field_id) for field_id in field_ids))
            self.assertNotIn("attacker-chosen-id", field_ids)
            self.assertEqual([field["label"] for field in fields], ["Client ID", "Client secret"])
        finally:
            root.destroy()

    def test_edit_assigns_opaque_ids_to_legacy_fields_and_preserves_them(self):
        root = app.HexiKeysApp()
        root.withdraw()
        root.detail = app.tk.Frame(root)
        root.detail.pack(fill="both", expand=True)
        root.tree = app.ttk.Treeview(root)
        entry = {"id": "synthetic-legacy-entry", "title": "Legacy synthetic item", "category": "Secure note", "purpose": "", "fields": [
            {"label": "Account", "value": "synthetic-account", "secret": False},
            {"label": "Key", "value": "SYNTHETIC-ONLY-key", "secret": True},
        ]}
        root.tree.insert("", "end", iid=entry["id"], text=entry["title"])
        try:
            root.edit_entry(entry)
            generated_ids = [field_row[0].field_id for field_row in root.field_rows]
            self.assertEqual(len(set(generated_ids)), 2)
            self.assertTrue(all(app.valid_field_id(field_id) for field_id in generated_ids))
            root.title_var.set(entry["title"])
            with patch.object(root, "commit_vault", return_value=None) as commit, \
                 patch.object(root, "refresh_list"), patch.object(root, "show_entry"):
                root.save_entry(entry, creating=False)
            saved = commit.call_args.args[0]["entries"][0]
            self.assertEqual([field["id"] for field in saved["fields"]], generated_ids)
            root.edit_entry(saved)
            self.assertEqual([field_row[0].field_id for field_row in root.field_rows], generated_ids)
        finally:
            root.destroy()

    def test_editing_a_field_value_rotates_its_reference_id(self):
        root = app.HexiKeysApp()
        root.withdraw()
        root.detail = app.tk.Frame(root)
        root.detail.pack(fill="both", expand=True)
        root.tree = app.ttk.Treeview(root)
        entry = {"id": "synthetic-rotating-entry", "title": "Rotating synthetic item", "category": "API key", "purpose": "", "fields": [
            app.create_vault_field("API key", "SYNTHETIC-ONLY-old", True),
        ]}
        root.tree.insert("", "end", iid=entry["id"], text=entry["title"])
        try:
            root.edit_entry(entry)
            old_id = root.field_rows[0][0].field_id
            root.field_rows[0][2].delete(0, app.tk.END)
            root.field_rows[0][2].insert(0, "SYNTHETIC-ONLY-rotated")
            with patch.object(root, "commit_vault", return_value=None) as commit, \
                 patch.object(root, "refresh_list"), patch.object(root, "show_entry"):
                root.save_entry(entry, creating=False)
            saved_field = commit.call_args.args[0]["entries"][0]["fields"][0]
            self.assertNotEqual(saved_field["id"], old_id)
            self.assertTrue(app.valid_field_id(saved_field["id"]))
            self.assertEqual(saved_field["value"], "SYNTHETIC-ONLY-rotated")
        finally:
            root.destroy()

    def test_search_interaction_finds_context_without_matching_secret_value(self):
        root = app.HexiKeysApp()
        root.withdraw()
        root.vault = {"entries": [{
            "id": "synthetic-search-entry", "title": "Cloud OAuth", "category": "API key",
            "purpose": "Deploy preview", "fields": [
                {"label": "Account", "value": "owner@example.invalid", "secret": False},
                {"label": "Client secret", "value": "SYNTHETIC-ONLY-secret-12345", "secret": True},
            ],
        }]}
        root.search = app.ttk.Entry(root)
        root.tree = app.ttk.Treeview(root, columns=("type",), show="tree headings")
        try:
            root.search.insert(0, "  OWNER@EXAMPLE.INVALID  ")
            root.refresh_list()
            self.assertEqual(root.tree.get_children(), ("synthetic-search-entry",))
            root.search.delete(0, app.tk.END)
            root.search.insert(0, "SYNTHETIC-ONLY-secret-12345")
            root.refresh_list()
            self.assertEqual(root.tree.get_children(), ())
        finally:
            root.destroy()

    def test_filtering_out_selected_entry_clears_its_details(self):
        root = app.HexiKeysApp()
        root.withdraw()
        entry = {"id": "synthetic-filtered-entry", "title": "Cloud OAuth", "category": "API key", "purpose": "Deploy", "fields": [
            {"label": "Client secret", "value": "SYNTHETIC-ONLY-secret-12345", "secret": True},
        ]}
        root.vault = {"entries": [entry]}
        root.search = app.ttk.Entry(root)
        root.tree = app.ttk.Treeview(root, columns=("type",), show="tree headings")
        root.detail = app.tk.Frame(root, bg="white")
        root.tree.insert("", "end", iid=entry["id"], text=entry["title"])
        root.tree.selection_set(entry["id"])
        try:
            root.show_entry(entry)
            root.search.insert(0, "no matching entry")
            root.refresh_list()
            self.assertEqual(root.tree.get_children(), ())
            visible_text = [widget.cget("text") for widget in root.detail.winfo_children() if isinstance(widget, app.tk.Label)]
            self.assertIn("Select an item", visible_text)
            self.assertNotIn(entry["title"], visible_text)
            self.assertIsNone(root._editing_entry_id)
        finally:
            root.destroy()

    def test_saving_new_entry_clears_filter_and_selects_saved_item(self):
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = {"entries": []}
        try:
            root.build_main()
            root.search.insert(0, "does not match the new item")
            root.refresh_list()
            root.new_entry()
            root.title_var.set("Synthetic filtered save")
            entry_id = root._editing_entry_id
            root.save_entry({"id": entry_id, "title": "", "category": "Password", "purpose": "", "fields": []}, creating=True)
            self.assertEqual(root.search.get(), "")
            self.assertEqual(root.tree.selection(), (entry_id,))
            self.assertEqual(root.tree.item(entry_id, "text"), "Synthetic filtered save")
            saved, _version = load_vault(self.vault_path, PASSWORD)
            self.assertEqual(saved["entries"][0]["title"], "Synthetic filtered save")
        finally:
            root.destroy()

    def test_scrollable_fields_keep_large_dynamic_entries_reachable(self):
        root = app.HexiKeysApp()
        root.withdraw()
        frame = app.ScrollableFrame(root)
        frame.pack(fill="both", expand=True)
        try:
            for index in range(40):
                app.ttk.Label(frame.body, text=f"Synthetic field {index}").pack(anchor="w", pady=8)
            root.update_idletasks()
            _left, top, _right, bottom = frame.canvas.bbox("all")
            self.assertGreater(bottom - top, frame.canvas.winfo_height())
            self.assertEqual(frame.scrollbar.winfo_manager(), "pack")
        finally:
            root.destroy()

    def test_scrollable_frame_unbinds_only_its_mousewheel_handler(self):
        root = app.HexiKeysApp()
        root.withdraw()
        frame = app.ScrollableFrame(root)
        try:
            binding = frame._mousewheel_binding
            with patch.object(root, "_unbind") as unbind:
                frame._on_destroy(SimpleNamespace(widget=frame.canvas))
            unbind.assert_called_once_with(("bind", "all", "<MouseWheel>"), binding)
        finally:
            root.destroy()

    def test_removed_dynamic_field_is_not_read_during_save(self):
        root = app.HexiKeysApp()
        root.withdraw()
        root.detail = app.tk.Frame(root)
        root.detail.pack(fill="both", expand=True)
        entry = {"id": "synthetic-edit-item", "title": "", "category": "Secure note", "purpose": "", "fields": [
            {"label": "Keep", "value": "synthetic retained", "secret": False},
            {"label": "Remove", "value": "synthetic removed", "secret": True},
        ]}
        try:
            root.edit_entry(entry, creating=True)
            root.title_var.set("Synthetic test item")
            removed_row, removed_label, removed_value, removed_secret = root.field_rows[1]
            root.remove_field(removed_row, removed_label, removed_value, removed_secret)
            root.tree = app.ttk.Treeview(root)
            root.tree.insert("", "end", iid=entry["id"], text="Synthetic test item")
            with patch.object(root, "commit_vault", return_value=None) as commit, \
                 patch.object(root, "refresh_list"), patch.object(root, "show_entry"):
                root.save_entry(entry, creating=True)
            saved_fields = commit.call_args.args[0]["entries"][0]["fields"]
            self.assertEqual(len(saved_fields), 1)
            self.assertEqual({key: saved_fields[0][key] for key in ("label", "value", "secret")}, {"label": "Keep", "value": "synthetic retained", "secret": False})
            self.assertTrue(app.valid_field_id(saved_fields[0]["id"]))
            self.assertNotIn((removed_row, removed_label, removed_value, removed_secret), root.field_rows)
        finally:
            root.destroy()

    def test_view_cleanup_wipes_secret_entry_variables_and_dynamic_field_references(self):
        root = app.HexiKeysApp()
        root.withdraw()
        container = app.tk.Frame(root)
        container.pack()
        secret_value = app.tk.StringVar(value="synthetic secret that must be cleared")
        secret_widget = app.ttk.Entry(container, textvariable=secret_value)
        secret_widget.pack()
        root.title_var = app.tk.StringVar(value="synthetic private title")
        root.purpose_var = app.tk.StringVar(value="synthetic private purpose")
        root.field_rows = [(container, secret_widget, secret_widget, app.tk.BooleanVar(value=True))]
        try:
            root.clear_container(root)
            self.assertEqual(secret_value.get(), "")
            self.assertEqual(root.title_var.get(), "")
            self.assertEqual(root.purpose_var.get(), "")
            self.assertEqual(root.field_rows, [])
        finally:
            root.destroy()

    def test_new_test_account_creation_writes_encrypted_v2(self):
        root = app.HexiKeysApp()
        root.withdraw()
        try:
            phrase = "synthetic test phrase 2041!"
            root.login_password.insert(0, phrase)
            root.confirm_password.insert(0, phrase)
            root.unlock()
            payload, version = load_vault(self.vault_path, phrase)
            self.assertEqual(payload, {"entries": []})
            self.assertEqual(version, 2)
            self.assertEqual(root.title(), "HexiKeys")
        finally:
            root.destroy()

    def test_existing_test_account_upgrades_with_encrypted_backup(self):
        self.vault_path.write_text(json.dumps(make_legacy_v1(PAYLOAD, PASSWORD)), encoding="utf-8")
        root = app.HexiKeysApp()
        root.withdraw()
        try:
            root.login_password.insert(0, PASSWORD)
            with patch.object(app.messagebox, "showinfo"):
                root.unlock()
            payload, version = load_vault(self.vault_path, PASSWORD)
            self.assertEqual(payload, PAYLOAD)
            self.assertEqual(version, 2)
            backups = list(self.data_dir.glob("*.legacy-v1-*.bak"))
            self.assertEqual(len(backups), 1)
            self.assertEqual(load_vault(backups[0], PASSWORD)[0], PAYLOAD)
        finally:
            root.destroy()

    def test_wrong_password_does_not_rewrite_legacy_test_vault(self):
        original = json.dumps(make_legacy_v1(PAYLOAD, PASSWORD)).encode("utf-8")
        self.vault_path.write_bytes(original)
        root = app.HexiKeysApp()
        root.withdraw()
        try:
            root.login_password.insert(0, "synthetic wrong test phrase")
            with patch.object(app.messagebox, "showerror"):
                root.unlock()
            self.assertIsNone(root.password)
            self.assertEqual(self.vault_path.read_bytes(), original)
            self.assertEqual(list(self.data_dir.glob("*.bak")), [])
        finally:
            root.destroy()

    def test_idle_lock_clears_session_secrets_and_replaces_login_view(self):
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = "synthetic session password"
        root.vault = {"entries": [{"id": "synthetic", "title": "Temporary", "fields": []}]}
        try:
            with patch.object(root, "build_login") as build_login, \
                 patch.object(root, "clear_clipboard") as clear_clipboard, \
                 patch.object(app.messagebox, "showinfo") as show_info:
                root.lock(automatic=True)
            self.assertIsNone(root.password)
            self.assertEqual(root.vault, {"entries": []})
            build_login.assert_called_once()
            clear_clipboard.assert_called_once()
            show_info.assert_called_once()
        finally:
            root.destroy()

    def test_idle_timer_reschedules_for_active_session_and_locks_expired_session(self):
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = "synthetic session password"
        try:
            root._last_activity_at = 100
            with patch("app.time.monotonic", return_value=110), patch.object(root, "after", return_value="synthetic-timer") as schedule:
                root._check_idle_lock()
            self.assertEqual(root._idle_lock_after_id, "synthetic-timer")
            schedule.assert_called_once_with(app.IDLE_LOCK_CHECK_MS, root._check_idle_lock)
            root._idle_lock_after_id = None
            root._last_activity_at = 100
            with patch("app.time.monotonic", return_value=100 + app.IDLE_LOCK_SECONDS + 1), patch.object(root, "lock") as lock:
                root._check_idle_lock()
            lock.assert_called_once_with(automatic=True)
        finally:
            root.destroy()

    def test_clipboard_cleanup_preserves_replacement_and_cancels_timer(self):
        root = app.HexiKeysApp()
        root.withdraw()
        root._clipboard_value = "synthetic credential"
        root._clipboard_after_id = "synthetic-timer"
        try:
            with patch.object(root, "after_cancel") as cancel, \
                 patch.object(root, "clipboard_get", return_value="user copied something else"), \
                 patch.object(root, "clipboard_clear") as clear:
                root.clear_clipboard()
            cancel.assert_called_once_with("synthetic-timer")
            clear.assert_not_called()
            self.assertIsNone(root._clipboard_value)
            self.assertIsNone(root._clipboard_after_id)
        finally:
            root.destroy()

    def test_copy_sets_a_clear_timer_without_touching_the_real_clipboard_in_test(self):
        root = app.HexiKeysApp()
        root.withdraw()
        try:
            with patch.object(root, "clipboard_clear") as clear, \
                 patch.object(root, "clipboard_append") as append, \
                 patch.object(root, "after", return_value="synthetic-clear-timer") as schedule:
                result = root.copy("synthetic test-only secret")
            self.assertTrue(result)
            clear.assert_called_once_with()
            append.assert_called_once_with("synthetic test-only secret")
            schedule.assert_called_once_with(30000, root.clear_clipboard)
            self.assertEqual(root._clipboard_value, "synthetic test-only secret")
            self.assertEqual(root._clipboard_after_id, "synthetic-clear-timer")
        finally:
            root.destroy()

    def test_copy_clipboard_failure_is_handled_without_exposing_value(self):
        root = app.HexiKeysApp()
        root.withdraw()
        try:
            with patch.object(root, "clipboard_clear", side_effect=app.tk.TclError("synthetic clipboard busy")), \
                 patch.object(root, "clipboard_append") as append, \
                 patch.object(app.messagebox, "showerror") as show_error:
                result = root.copy("synthetic test-only secret")
            self.assertFalse(result)
            append.assert_not_called()
            self.assertIsNone(root._clipboard_value)
            show_error.assert_called_once()
            self.assertNotIn("synthetic test-only secret", show_error.call_args.args[1])
        finally:
            root.destroy()

    def test_copy_removes_secret_if_clipboard_cleanup_cannot_be_scheduled(self):
        root = app.HexiKeysApp()
        root.withdraw()
        try:
            with patch.object(root, "clipboard_clear") as clear, \
                 patch.object(root, "clipboard_append") as append, \
                 patch.object(root, "clipboard_get", return_value="synthetic test-only secret"), \
                 patch.object(root, "after", side_effect=app.tk.TclError("synthetic shutdown")), \
                 patch.object(app.messagebox, "showerror") as show_error:
                result = root.copy("synthetic test-only secret")
            self.assertFalse(result)
            self.assertEqual(clear.call_count, 2)
            append.assert_called_once_with("synthetic test-only secret")
            self.assertIsNone(root._clipboard_value)
            self.assertIsNone(root._clipboard_after_id)
            show_error.assert_called_once()
            self.assertNotIn("synthetic test-only secret", show_error.call_args.args[1])
        finally:
            root.destroy()

    def test_restore_reencrypts_backup_and_preserves_previous_vault(self):
        previous = {"entries": [{"id": "old-test-entry", "title": "Old synthetic item", "fields": []}]}
        replacement = {"entries": [{"id": "new-test-entry", "title": "Restored synthetic item", "fields": []}]}
        save_vault(self.vault_path, previous, PASSWORD)
        backup_path = self.data_dir / "portable.hexikeys"
        save_vault(backup_path, replacement, PASSWORD)
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = previous
        try:
            with patch.object(app.filedialog, "askopenfilename", return_value=str(backup_path)), \
                 patch.object(app.messagebox, "askyesno", return_value=True), \
                 patch.object(root, "refresh_list"), \
                 patch.object(root, "show_welcome"), \
                 patch.object(app.messagebox, "showinfo"):
                root.restore_vault_backup()
            restored, version = load_vault(self.vault_path, PASSWORD)
            self.assertEqual(restored, replacement)
            self.assertEqual(version, 2)
            self.assertEqual(root.vault, replacement)
            safety_copies = list(self.data_dir.glob("vault.before-restore-*.bak"))
            self.assertEqual(len(safety_copies), 1)
            self.assertEqual(load_vault(safety_copies[0], PASSWORD)[0], previous)
        finally:
            root.destroy()

    def test_cancelled_restore_leaves_current_vault_and_backup_directory_unchanged(self):
        previous = {"entries": [{"id": "old-test-entry", "title": "Old synthetic item", "fields": []}]}
        replacement = {"entries": [{"id": "new-test-entry", "title": "Restored synthetic item", "fields": []}]}
        save_vault(self.vault_path, previous, PASSWORD)
        backup_path = self.data_dir / "portable.hexikeys"
        save_vault(backup_path, replacement, PASSWORD)
        original_bytes = self.vault_path.read_bytes()
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = previous
        try:
            with patch.object(app.filedialog, "askopenfilename", return_value=str(backup_path)), \
                 patch.object(app.messagebox, "askyesno", return_value=False), \
                 patch.object(root, "refresh_list") as refresh:
                root.restore_vault_backup()
            self.assertEqual(self.vault_path.read_bytes(), original_bytes)
            self.assertEqual(root.vault, previous)
            self.assertEqual(list(self.data_dir.glob("vault.before-restore-*.bak")), [])
            refresh.assert_not_called()
        finally:
            root.destroy()

    def test_restore_write_failure_keeps_current_vault_and_encrypted_safety_copy(self):
        previous = {"entries": [{"id": "old-test-entry", "title": "Old synthetic item", "fields": []}]}
        replacement = {"entries": [{"id": "new-test-entry", "title": "Restored synthetic item", "fields": []}]}
        save_vault(self.vault_path, previous, PASSWORD)
        backup_path = self.data_dir / "portable.hexikeys"
        save_vault(backup_path, replacement, PASSWORD)
        original_bytes = self.vault_path.read_bytes()
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = previous
        try:
            with patch.object(app.filedialog, "askopenfilename", return_value=str(backup_path)), \
                 patch.object(app.messagebox, "askyesno", return_value=True), \
                 patch("app.save_vault", side_effect=OSError("synthetic disk full")), \
                 patch.object(app.messagebox, "showerror") as show_error:
                root.restore_vault_backup()
            self.assertEqual(self.vault_path.read_bytes(), original_bytes)
            self.assertEqual(root.vault, previous)
            safety_copies = list(self.data_dir.glob("vault.before-restore-*.bak"))
            self.assertEqual(len(safety_copies), 1)
            self.assertEqual(load_vault(safety_copies[0], PASSWORD)[0], previous)
            show_error.assert_called_once()
        finally:
            root.destroy()

    def test_encrypted_backup_menu_action_exports_decryptable_identical_vault(self):
        save_vault(self.vault_path, PAYLOAD, PASSWORD)
        destination = self.data_dir / "exported.hexikeys"
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        try:
            with patch.object(app.filedialog, "asksaveasfilename", return_value=str(destination)), \
                 patch.object(app.messagebox, "showinfo") as show_info:
                root.backup_vault()
            self.assertTrue(destination.exists())
            self.assertEqual(destination.read_bytes(), self.vault_path.read_bytes())
            self.assertEqual(load_vault(destination, PASSWORD)[0], PAYLOAD)
            show_info.assert_called_once()
        finally:
            root.destroy()

    def test_restore_with_wrong_password_does_not_change_current_vault(self):
        previous = {"entries": [{"id": "old-test-entry", "title": "Old synthetic item", "fields": []}]}
        replacement = {"entries": [{"id": "new-test-entry", "title": "Restored synthetic item", "fields": []}]}
        save_vault(self.vault_path, previous, PASSWORD)
        backup_path = self.data_dir / "wrong-password.hexikeys"
        save_vault(backup_path, replacement, "different synthetic password")
        original_bytes = self.vault_path.read_bytes()
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = previous
        try:
            with patch.object(app.filedialog, "askopenfilename", return_value=str(backup_path)), \
                 patch.object(app.simpledialog, "askstring", return_value="synthetic incorrect password") as ask_password, \
                 patch.object(app.messagebox, "showerror") as show_error, \
                 patch.object(app.messagebox, "askyesno") as confirm:
                root.restore_vault_backup()
            self.assertEqual(self.vault_path.read_bytes(), original_bytes)
            self.assertEqual(root.vault, previous)
            ask_password.assert_called_once()
            show_error.assert_called_once()
            confirm.assert_not_called()
            self.assertEqual(list(self.data_dir.glob("vault.before-restore-*.bak")), [])
        finally:
            root.destroy()

    def test_restore_backup_after_password_rotation_reencrypts_under_current_password(self):
        previous = {"entries": [{"id": "current-test-entry", "title": "Current synthetic item", "fields": []}]}
        replacement = {"entries": [{"id": "old-test-entry", "title": "Old backup synthetic item", "fields": []}]}
        old_password = "synthetic old backup password"
        save_vault(self.vault_path, previous, PASSWORD)
        backup_path = self.data_dir / "old-password.hexikeys"
        save_vault(backup_path, replacement, old_password)
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = previous
        try:
            with patch.object(app.filedialog, "askopenfilename", return_value=str(backup_path)), \
                 patch.object(app.simpledialog, "askstring", return_value=old_password) as ask_password, \
                 patch.object(app.messagebox, "askyesno", return_value=True), \
                 patch.object(root, "refresh_list"), patch.object(root, "show_welcome"), \
                 patch.object(app.messagebox, "showinfo"):
                root.restore_vault_backup()
            ask_password.assert_called_once()
            restored, version = load_vault(self.vault_path, PASSWORD)
            self.assertEqual(restored, replacement)
            self.assertEqual(version, 2)
            self.assertEqual(root.vault, replacement)
            with self.assertRaises(ValueError):
                load_vault(self.vault_path, old_password)
            safety_copies = list(self.data_dir.glob("vault.before-restore-*.bak"))
            self.assertEqual(len(safety_copies), 1)
            self.assertEqual(load_vault(safety_copies[0], PASSWORD)[0], previous)
        finally:
            root.destroy()

    def test_cancel_old_backup_password_prompt_leaves_vault_unchanged(self):
        previous = {"entries": [{"id": "current-test-entry", "title": "Current synthetic item", "fields": []}]}
        replacement = {"entries": [{"id": "old-test-entry", "title": "Old backup synthetic item", "fields": []}]}
        save_vault(self.vault_path, previous, PASSWORD)
        backup_path = self.data_dir / "old-password.hexikeys"
        save_vault(backup_path, replacement, "synthetic old backup password")
        original_bytes = self.vault_path.read_bytes()
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = previous
        try:
            with patch.object(app.filedialog, "askopenfilename", return_value=str(backup_path)), \
                 patch.object(app.simpledialog, "askstring", return_value=None), \
                 patch.object(app.messagebox, "showerror") as show_error, \
                 patch.object(app.messagebox, "askyesno") as confirm:
                root.restore_vault_backup()
            self.assertEqual(self.vault_path.read_bytes(), original_bytes)
            self.assertEqual(root.vault, previous)
            show_error.assert_not_called()
            confirm.assert_not_called()
            self.assertEqual(list(self.data_dir.glob("vault.before-restore-*.bak")), [])
        finally:
            root.destroy()

    def test_restore_of_legacy_encrypted_backup_upgrades_it_and_retains_safety_copy(self):
        previous = {"entries": [{"id": "old-test-entry", "title": "Old synthetic item", "fields": []}]}
        replacement = {"entries": [{"id": "legacy-test-entry", "title": "Legacy synthetic item", "fields": []}]}
        save_vault(self.vault_path, previous, PASSWORD)
        backup_path = self.data_dir / "legacy.hexikeys"
        backup_path.write_text(json.dumps(make_legacy_v1(replacement, PASSWORD)), encoding="utf-8")
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        try:
            with patch.object(app.filedialog, "askopenfilename", return_value=str(backup_path)), \
                 patch.object(app.messagebox, "askyesno", return_value=True), \
                 patch.object(root, "refresh_list"), patch.object(root, "show_welcome"), \
                 patch.object(app.messagebox, "showinfo"):
                root.restore_vault_backup()
            payload, version = load_vault(self.vault_path, PASSWORD)
            self.assertEqual(payload, replacement)
            self.assertEqual(version, 2)
            safety_copies = list(self.data_dir.glob("vault.before-restore-*.bak"))
            self.assertEqual(len(safety_copies), 1)
            self.assertEqual(load_vault(safety_copies[0], PASSWORD)[0], previous)
        finally:
            root.destroy()

    def test_master_password_rotation_reencrypts_without_changing_entries(self):
        save_vault(self.vault_path, PAYLOAD, PASSWORD)
        new_password = "synthetic replacement master phrase 2047"
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = PAYLOAD
        try:
            with patch.object(app.simpledialog, "askstring", side_effect=[new_password, new_password]), \
                 patch.object(app.messagebox, "showinfo"):
                root.change_master_password()
            self.assertEqual(root.password, new_password)
            self.assertEqual(load_vault(self.vault_path, new_password)[0], PAYLOAD)
            with self.assertRaises(ValueError):
                load_vault(self.vault_path, PASSWORD)
            safety_copies = list(self.data_dir.glob("vault.before-password-change-*.bak"))
            self.assertEqual(len(safety_copies), 1)
            self.assertEqual(load_vault(safety_copies[0], PASSWORD)[0], PAYLOAD)
            with self.assertRaises(ValueError):
                load_vault(safety_copies[0], new_password)
        finally:
            root.destroy()

    def test_failed_master_password_rotation_keeps_session_and_disk_key(self):
        save_vault(self.vault_path, PAYLOAD, PASSWORD)
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = PAYLOAD
        original_bytes = self.vault_path.read_bytes()
        try:
            with patch.object(app.simpledialog, "askstring", side_effect=["synthetic new master phrase", "synthetic new master phrase"]), \
                 patch("app.save_vault", side_effect=OSError("synthetic disk full")), \
                 patch.object(app.messagebox, "showerror") as show_error:
                root.change_master_password()
            self.assertEqual(root.password, PASSWORD)
            self.assertEqual(self.vault_path.read_bytes(), original_bytes)
            self.assertEqual(load_vault(self.vault_path, PASSWORD)[0], PAYLOAD)
            safety_copies = list(self.data_dir.glob("vault.before-password-change-*.bak"))
            self.assertEqual(len(safety_copies), 1)
            self.assertEqual(load_vault(safety_copies[0], PASSWORD)[0], PAYLOAD)
            show_error.assert_called_once()
        finally:
            root.destroy()

    def test_password_rotation_stops_if_safety_backup_cannot_be_created(self):
        save_vault(self.vault_path, PAYLOAD, PASSWORD)
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = PAYLOAD
        original_bytes = self.vault_path.read_bytes()
        new_password = "synthetic replacement master phrase 2047"
        try:
            with patch.object(app.simpledialog, "askstring", side_effect=[new_password, new_password]), \
                 patch("app.create_encrypted_backup", side_effect=OSError("synthetic backup disk full")), \
                 patch("app.save_vault") as save, \
                 patch.object(app.messagebox, "showerror") as show_error:
                root.change_master_password()
            self.assertEqual(root.password, PASSWORD)
            self.assertEqual(self.vault_path.read_bytes(), original_bytes)
            self.assertEqual(load_vault(self.vault_path, PASSWORD)[0], PAYLOAD)
            save.assert_not_called()
            show_error.assert_called_once()
        finally:
            root.destroy()

    def test_master_password_mismatch_leaves_disk_and_session_unchanged(self):
        save_vault(self.vault_path, PAYLOAD, PASSWORD)
        original_bytes = self.vault_path.read_bytes()
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = PAYLOAD
        try:
            with patch.object(app.simpledialog, "askstring", side_effect=["synthetic replacement phrase", "different synthetic phrase"]), \
                 patch.object(app.messagebox, "showwarning") as show_warning:
                root.change_master_password()
            self.assertEqual(root.password, PASSWORD)
            self.assertEqual(self.vault_path.read_bytes(), original_bytes)
            show_warning.assert_called_once()
        finally:
            root.destroy()

    def test_oauth_screenshot_extracts_fields_and_ignores_warning_copy(self):
        root = app.HexiKeysApp()
        root.withdraw()
        try:
            text = """OAuth client created
The client ID can always be accessed from Clients tab under Google Auth Platform.
OAuth access is restricted to the test users listed on your OAuth consent screen.
Client ID
123456789012-abcde12345.apps.googleusercontent.com
You will no longer be able to view or download the client secret once you close this dialog. Make sure you have copied or downloaded the information below and securely stored it.
Client secret
GOCSPX-TESTonly_NotARealSecret_123456789
Creation date
September 16, 2026, 9:49:16 PM GMT-6
Status
Enabled
OK"""
            title, category, fields = root.parse_ocr_text(text, "screenshot-2026-09-16")
            by_label = {field["label"]: field for field in fields}
            self.assertEqual(title, "OAuth Client")
            self.assertEqual(category, "API key")
            self.assertEqual(by_label["Client ID"]["value"], "123456789012-abcde12345.apps.googleusercontent.com")
            self.assertEqual(by_label["Client secret"]["value"], "GOCSPX-TESTonly_NotARealSecret_123456789")
            self.assertTrue(by_label["Client secret"]["secret"])
            self.assertEqual(by_label["Status"]["value"], "Enabled")
            combined = " ".join(field["value"] for field in fields).casefold()
            self.assertNotIn("you will no longer", combined)
            self.assertNotIn("consent screen", combined)
            self.assertNotIn("securely stored", combined)
        finally:
            root.destroy()

    def test_screenshot_parser_adds_unknown_labeled_fields_but_skips_instructions(self):
        root = app.HexiKeysApp()
        root.withdraw()
        try:
            text = """OAuth client created
Client ID: synthetic-client-id
Client secret: SYNTHETIC-ONLY-secret-12345
Project Region: west-central
Signing secret: synthetic-signing-secret
Make sure you save this secret: instructional-placeholder
"""
            _, _, fields = root.parse_ocr_text(text, "sample")
            by_label = {field["label"]: field for field in fields}
            self.assertEqual(by_label["Project Region"]["value"], "west-central")
            self.assertEqual(by_label["Signing Secret"]["value"], "synthetic-signing-secret")
            self.assertTrue(by_label["Signing Secret"]["secret"])
            self.assertNotIn("Make Sure You Save This Secret", by_label)
        finally:
            root.destroy()

    def test_screenshot_parser_corrects_close_known_label_ocr_typos(self):
        root = app.HexiKeysApp()
        root.withdraw()
        try:
            text = """OAuth client created
Client 'D: synthetic-client.apps.example.invalid
Client Secret: SYNTHETIC-ONLY-secret-12345
"""
            _, _, fields = root.parse_ocr_text(text, "sample")
            by_label = {field["label"]: field for field in fields}
            self.assertEqual(by_label["Client Id"]["value"], "synthetic-client.apps.example.invalid")
            self.assertTrue(by_label["Client Secret"]["secret"])
        finally:
            root.destroy()

    def test_json_import_preserves_nested_dynamic_fields(self):
        root = app.HexiKeysApp()
        root.withdraw()
        try:
            entries = root.normalize_json_payload({
                "name": "Synthetic Cloud App",
                "credentials": {
                    "client": {"id": "synthetic-client-id", "secret": "synthetic-secret"},
                    "redirect_uris": ["https://example.invalid/callback"],
                },
            }, "sample")
            self.assertEqual(len(entries), 1)
            fields = {field["label"]: field for field in entries[0]["fields"]}
            self.assertEqual(entries[0]["title"], "Synthetic Cloud App")
            self.assertEqual(fields["credentials client id"]["value"], "synthetic-client-id")
            self.assertFalse(fields["credentials client id"]["secret"])
            self.assertEqual(fields["credentials client secret"]["value"], "synthetic-secret")
            self.assertTrue(fields["credentials client secret"]["secret"])
            self.assertIn("credentials redirect_uris", fields)
            self.assertTrue(all(app.valid_field_id(field["id"]) for field in entries[0]["fields"]))
            explicit = root.normalize_json_payload({"title": "Synthetic explicit fields", "fields": [
                {"label": "API key", "value": "synthetic-api-key"},
                {"label": "Recovery code", "value": "synthetic-recovery-code"},
                {"label": "Public key", "value": "synthetic-public-key"},
            ]}, "sample")[0]
            explicit_fields = {field["label"]: field for field in explicit["fields"]}
            self.assertTrue(explicit_fields["API key"]["secret"])
            self.assertTrue(explicit_fields["Recovery code"]["secret"])
            self.assertFalse(explicit_fields["Public key"]["secret"])
            camel_case = root.normalize_json_payload({"title": "Synthetic OAuth client", "clientSecret": "synthetic-secret", "accessToken": "synthetic-token", "privateKey": "synthetic-private-key", "publicKey": "synthetic-public-key"}, "sample")[0]
            camel_fields = {field["label"]: field for field in camel_case["fields"]}
            self.assertTrue(camel_fields["clientSecret"]["secret"])
            self.assertTrue(camel_fields["accessToken"]["secret"])
            self.assertTrue(camel_fields["privateKey"]["secret"])
            self.assertFalse(camel_fields["publicKey"]["secret"])
        finally:
            root.destroy()

    def test_text_backup_import_recognizes_recovery_codes_and_skips_guidance(self):
        root = app.HexiKeysApp()
        root.withdraw()
        try:
            entry = root.parse_text_backup("""Stripe backup codes
Save these codes somewhere safe. Each code can only be used once.
AB12-CD34
EF56-GH78
JK90-LM12
""", "stripe_backup_codes")
            self.assertEqual(entry["title"], "Stripe Backup Codes")
            self.assertEqual(entry["category"], "Backup codes")
            self.assertEqual([field["value"] for field in entry["fields"]], ["AB12-CD34", "EF56-GH78", "JK90-LM12"])
            self.assertTrue(all(field["secret"] for field in entry["fields"]))
            self.assertTrue(all(app.valid_field_id(field["id"]) for field in entry["fields"]))
        finally:
            root.destroy()

    def test_import_text_size_guard_and_empty_backup_validation(self):
        root = app.HexiKeysApp()
        root.withdraw()
        try:
            path = self.data_dir / "synthetic-text.txt"
            path.write_bytes(b"synthetic data")
            with self.assertRaisesRegex(ValueError, "import limit"):
                root.read_bounded_text(path, 8)
            with self.assertRaisesRegex(ValueError, "empty"):
                root.parse_text_backup("  \n", "empty-backup")
        finally:
            root.destroy()

    def test_json_import_interaction_saves_dynamic_sensitive_fields(self):
        path = self.data_dir / "synthetic-json-import.json"
        path.write_text(json.dumps({"name": "Synthetic OAuth App", "clientSecret": "not-a-real-secret", "region": "test-region"}), encoding="utf-8")
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = {"entries": []}
        try:
            with patch.object(app.filedialog, "askopenfilenames", return_value=[str(path)]), \
                 patch.object(app.messagebox, "showinfo") as show_info:
                root.import_json()
            saved, version = load_vault(self.vault_path, PASSWORD)
            self.assertEqual(version, 2)
            self.assertEqual(len(saved["entries"]), 1)
            imported = saved["entries"][0]
            self.assertEqual(imported["title"], "Synthetic OAuth App")
            fields = {field["label"]: field for field in imported["fields"]}
            self.assertTrue(all(app.valid_field_id(field["id"]) for field in imported["fields"]))
            self.assertTrue(fields["clientSecret"]["secret"])
            self.assertEqual(fields["region"]["value"], "test-region")
            self.assertIn("Imported 1 item", show_info.call_args.args[1])
        finally:
            root.destroy()

    def test_screenshot_import_interaction_parses_and_saves_ocr_fields(self):
        screenshot = self.data_dir / "synthetic-oauth-screenshot.png"
        screenshot.write_bytes(b"synthetic image placeholder")
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = {"entries": []}
        ocr_text = """OAuth client created
Client ID: synthetic-client-id.apps.example.invalid
Client secret: SYNTHETIC-ONLY-secret-12345
Project Region: test-region
Make sure you store this safely.
"""
        try:
            with patch.object(app.filedialog, "askopenfilenames", return_value=[str(screenshot)]), \
                 patch.object(root, "ocr_image", return_value=ocr_text) as ocr, \
                 patch.object(app.messagebox, "showinfo") as show_info:
                root.import_screenshots()
            ocr.assert_called_once_with(str(screenshot))
            saved, version = load_vault(self.vault_path, PASSWORD)
            self.assertEqual(version, 2)
            self.assertEqual(len(saved["entries"]), 1)
            imported = saved["entries"][0]
            self.assertEqual(imported["title"], "OAuth Client")
            fields = {field["label"]: field for field in imported["fields"]}
            self.assertTrue(all(app.valid_field_id(field["id"]) for field in imported["fields"]))
            self.assertTrue(fields["Client Secret"]["secret"])
            self.assertEqual(fields["Project Region"]["value"], "test-region")
            self.assertNotIn("Make sure", " ".join(field["value"] for field in imported["fields"]))
            self.assertIn("Imported 1 screenshot", show_info.call_args.args[1])
        finally:
            root.destroy()

    def test_text_import_interaction_stores_recovery_codes_as_private_fields(self):
        path = self.data_dir / "stripe_backup_codes.txt"
        path.write_text("Stripe backup codes\nEach code can only be used once.\nAB12-CD34\nEF56-GH78\n", encoding="utf-8")
        root = app.HexiKeysApp()
        root.withdraw()
        root.password = PASSWORD
        root.vault = {"entries": []}
        try:
            with patch.object(app.filedialog, "askopenfilenames", return_value=[str(path)]), \
                 patch.object(app.messagebox, "showinfo") as show_info:
                root.import_text_files()
            saved, version = load_vault(self.vault_path, PASSWORD)
            self.assertEqual(version, 2)
            self.assertEqual(len(saved["entries"]), 1)
            imported = saved["entries"][0]
            self.assertEqual(imported["title"], "Stripe Backup Codes")
            self.assertEqual(imported["category"], "Backup codes")
            self.assertEqual([field["value"] for field in imported["fields"]], ["AB12-CD34", "EF56-GH78"])
            self.assertTrue(all(field["secret"] for field in imported["fields"]))
            self.assertTrue(all(app.valid_field_id(field["id"]) for field in imported["fields"]))
            self.assertIn("Imported 1 text backup", show_info.call_args.args[1])
        finally:
            root.destroy()

    def test_failed_json_import_leaves_live_and_saved_vault_unchanged(self):
        original = {"entries": [{"id": "existing-test-item", "title": "Existing synthetic item", "fields": []}]}
        self.vault_path.write_text("synthetic original file", encoding="utf-8")
        import_path = self.data_dir / "synthetic-import.json"
        import_path.write_text(json.dumps({"title": "Synthetic import", "api_key": "not-a-real-key"}), encoding="utf-8")
        root = app.HexiKeysApp()
        root.withdraw()
        root.vault = original
        root.password = PASSWORD
        try:
            with patch.object(app.filedialog, "askopenfilenames", return_value=[str(import_path)]), \
                 patch("app.save_vault", side_effect=OSError("synthetic disk full")), \
                 patch.object(app.messagebox, "showerror") as show_error, \
                 patch.object(app.messagebox, "showinfo") as show_info:
                root.import_json()
            self.assertEqual(root.vault, original)
            self.assertEqual(self.vault_path.read_text(encoding="utf-8"), "synthetic original file")
            show_error.assert_called_once()
            self.assertIn("Imported 0 items", show_info.call_args.args[1])
            self.assertIn("were not added", show_info.call_args.args[1])
        finally:
            root.destroy()


if __name__ == "__main__":
    unittest.main()
