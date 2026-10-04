import copy
import json
import tkinter as tk
from tkinter import ttk
import unittest
from unittest.mock import patch

import vault_grant_ui as grant_ui
import vault_references as references


SYNTHETIC_VALUE = "SYNTHETIC-ONLY-never-render-this"
RECIPE = {
    "version": 1,
    "connectorId": "hexikeys",
    "capabilityId": "api-request",
    "taskId": "task-synthetic-01",
    "origin": "https://api.example.invalid",
    "pathPrefix": "/v1/items",
    "methods": ["GET"],
    "header": "Authorization",
    "prefix": "Bearer ",
}


def synthetic_vault():
    return {"entries": [{
        "id": "entry-synthetic",
        "title": "Synthetic service",
        "fields": [{"id": "a" * 32, "label": "API token", "value": SYNTHETIC_VALUE, "secret": True}],
    }]}


def descendants(widget):
    for child in widget.winfo_children():
        yield child
        yield from descendants(child)


class VaultGrantDialogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        try:
            cls.root = tk.Tk()
            cls.root.withdraw()
        except tk.TclError as exc:
            raise unittest.SkipTest(f"Tk display is unavailable: {exc}")

    @classmethod
    def tearDownClass(cls):
        try:
            cls.root.destroy()
        except tk.TclError:
            pass

    def test_recipe_requires_exact_nonsecret_fields_and_rejects_duplicate_keys(self):
        self.assertEqual(grant_ui._parse_scope_recipe(json.dumps(RECIPE)), RECIPE)
        with self.assertRaises(ValueError):
            grant_ui._parse_scope_recipe(json.dumps({**RECIPE, "credential": SYNTHETIC_VALUE}))
        duplicate = json.dumps(RECIPE)[:-1] + ',"version":1}'
        with self.assertRaisesRegex(ValueError, "duplicate"):
            grant_ui._parse_scope_recipe(duplicate)
        for unsafe in ("http://api.example.invalid", "https://api.example.invalid/path", "https://user:pass@api.example.invalid"):
            with self.subTest(origin=unsafe):
                with self.assertRaises(ValueError):
                    references.create_reference_grant(
                        synthetic_vault(), entry_id="entry-synthetic", field_index=0,
                        connector_id="hexikeys", capability_id="api-request", task_id="task-synthetic-01",
                        origin=unsafe, path_prefix="/v1/items", methods=["GET"], header="Authorization",
                    )

    def test_grant_dialog_saves_reviewed_scope_without_rendering_field_value(self):
        live_vault = synthetic_vault()
        committed = []
        captured = {}
        original_create = references.create_reference_grant

        def capture_create(vault, **kwargs):
            captured["field_value"] = vault["entries"][0]["fields"][0]["value"]
            captured["kwargs"] = kwargs
            return original_create(vault, **kwargs)

        def drive_dialog():
            dialog = next(w for w in self.root.winfo_children() if isinstance(w, tk.Toplevel))
            widgets = list(descendants(dialog))
            combos = [w for w in widgets if isinstance(w, ttk.Combobox)]
            texts = [w for w in widgets if isinstance(w, tk.Text)]
            buttons = [w for w in widgets if isinstance(w, ttk.Button)]
            self.assertEqual(len(combos), 2)
            self.assertEqual(combos[1].get(), "API token")
            self.assertEqual(len(texts), 1)
            texts[0].insert("1.0", json.dumps(RECIPE))
            next(button for button in buttons if button.cget("text") == "Review and create").invoke()

        self.root.after(30, drive_dialog)
        with patch.object(references, "create_reference_grant", side_effect=capture_create), \
             patch.object(grant_ui.messagebox, "askyesno", return_value=True), \
             patch.object(grant_ui, "_show_copyable_grant_id") as copied:
            grant_id = grant_ui.show_grant_dialog(
                self.root,
                get_vault=lambda: live_vault,
                commit_vault=lambda candidate: committed.append(candidate),
                entry_id="entry-synthetic",
                field_index=0,
            )
        self.assertRegex(grant_id, r"^[0-9a-f]{32}$")
        self.assertEqual(captured["field_value"], SYNTHETIC_VALUE)
        self.assertEqual(captured["kwargs"]["max_uses"], 1)
        self.assertEqual(captured["kwargs"]["expires_at"] - captured["kwargs"]["now"], grant_ui.DEFAULT_TTL_SECONDS)
        self.assertEqual(len(committed), 1)
        self.assertEqual(committed[0]["integrations"]["hexigrid"]["grants"][0]["capabilityId"], "api-request")
        copied.assert_called_once_with(self.root, grant_id)
        self.assertNotIn(SYNTHETIC_VALUE, repr(captured["kwargs"]))

    def test_stale_snapshot_and_failed_save_do_not_show_grant_id(self):
        original = synthetic_vault()
        current = {"entries": []}
        errors = []
        grant_id = "b" * 32
        reads = {"count": 0}

        def get_vault():
            reads["count"] += 1
            return original if reads["count"] == 1 else current

        def drive_dialog():
            dialog = next(w for w in self.root.winfo_children() if isinstance(w, tk.Toplevel))
            widgets = list(descendants(dialog))
            [w for w in widgets if isinstance(w, tk.Text)][0].insert("1.0", json.dumps(RECIPE))
            next(w for w in widgets if isinstance(w, ttk.Button) and w.cget("text") == "Review and create").invoke()
            self.root.after(20, dialog.destroy)

        self.root.after(30, drive_dialog)
        with patch.object(references, "create_reference_grant", return_value=(copy.deepcopy(original), grant_id)), \
             patch.object(grant_ui.messagebox, "askyesno", return_value=True), \
             patch.object(grant_ui.messagebox, "showerror", side_effect=lambda *a, **k: errors.append(a[1])), \
             patch.object(grant_ui, "_show_copyable_grant_id") as copied:
            result = grant_ui.show_grant_dialog(
                self.root, get_vault=get_vault, commit_vault=lambda _candidate: None,
                entry_id="entry-synthetic", field_index=0,
            )
        self.assertIsNone(result)
        self.assertTrue(any("vault changed" in text.lower() for text in errors), repr(errors))
        copied.assert_not_called()

    def test_grant_list_displays_metadata_and_revoke_persists_before_completion(self):
        vault, _grant_id = references.create_reference_grant(
            synthetic_vault(), entry_id="entry-synthetic", field_index=0,
            connector_id=RECIPE["connectorId"], capability_id=RECIPE["capabilityId"], task_id=RECIPE["taskId"],
            origin=RECIPE["origin"], path_prefix=RECIPE["pathPrefix"], methods=RECIPE["methods"],
            header=RECIPE["header"], prefix=RECIPE["prefix"], max_uses=2,
        )
        committed = []
        def drive_revoke():
            dialog = next(w for w in self.root.winfo_children() if isinstance(w, tk.Toplevel))
            widgets = list(descendants(dialog))
            tree = next(w for w in widgets if isinstance(w, ttk.Treeview))
            row = tree.get_children()[0]
            tree.selection_set(row)
            values = tree.item(row, "values")
            rendered = " ".join(str(value) for value in values)
            self.assertNotIn(SYNTHETIC_VALUE, rendered)
            self.assertNotIn("a" * 32, rendered)
            next(w for w in widgets if isinstance(w, ttk.Button) and w.cget("text") == "Revoke selected").invoke()
            dialog.destroy()

        self.root.after(30, drive_revoke)
        with patch.object(grant_ui.messagebox, "askyesno", return_value=True), \
             patch.object(grant_ui.messagebox, "showinfo"):
            grant_ui.show_grants_dialog(
                self.root,
                get_vault=lambda: vault,
                commit_vault=lambda candidate: committed.append(candidate),
            )
        self.assertEqual(len(committed), 1)
        self.assertIsNotNone(committed[0]["integrations"]["hexigrid"]["grants"][0]["revokedAt"])


if __name__ == "__main__":
    unittest.main()
