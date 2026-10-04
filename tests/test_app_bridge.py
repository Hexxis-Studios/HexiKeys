import copy
import os
import tempfile
import threading
import time
import unittest
import tkinter as tk
from unittest.mock import patch
from pathlib import Path

import app


PASSWORD = "Synthetic bridge test password 2047"
PAIRING = {
    "version": 1,
    "pipeId": "hexikeys-" + "1" * 32,
    "hmacKey": "a" * 64,
}


class FakeBridgeServer:
    def __init__(self):
        self.drained = False
        self.stop_called = False

    def stop(self):
        self.stop_called = True

    def wait_closed(self, timeout):
        if timeout != 0:
            raise AssertionError("Bridge shutdown polling must not block the Tk thread.")
        return self.drained


class HexiKeysBridgeAppTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="hexikeys-bridge-test-")
        self.data_dir = Path(self.temp_dir.name)
        self.vault_path = self.data_dir / "vault.dat"
        self.patches = [patch.object(app, "DATA_DIR", self.data_dir), patch.object(app, "VAULT_FILE", self.vault_path)]
        for item in self.patches:
            item.start()
        try:
            self.root = app.HexiKeysApp()
            self.root.withdraw()
        except tk.TclError as exc:
            self.tearDown()
            self.skipTest(f"Tk display is unavailable: {exc}")
        self.root.password = PASSWORD
        self.root.vault = {"entries": [], "integrations": {"hexigrid": {"pairing": dict(PAIRING), "grants": []}}}

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
            except tk.TclError:
                pass
        for item in reversed(getattr(self, "patches", [])):
            item.stop()
        if hasattr(self, "temp_dir"):
            self.temp_dir.cleanup()

    def open_bridge_callbacks(self):
        self.root._bridge_generation = 7
        self.root._bridge_callbacks_open = True
        return self.root._bridge_callbacks(7)

    def worker_call(self, callback):
        result = {}

        def run():
            result["worker_id"] = threading.get_ident()
            try:
                result["value"] = callback()
            except Exception as exc:
                result["error"] = exc

        self.root._schedule_bridge_callback_pump()
        worker = threading.Thread(target=run)
        worker.start()
        deadline = time.monotonic() + 3
        while worker.is_alive() and time.monotonic() < deadline:
            self.root.update()
            time.sleep(0.002)
        worker.join(timeout=0.1)
        self.assertFalse(worker.is_alive(), "The bridge callback worker did not finish.")
        if "error" in result:
            raise result["error"]
        return result["worker_id"], result.get("value")

    def test_consumed_candidate_is_saved_before_live_vault_publish(self):
        original = self.root.vault
        callbacks = self.open_bridge_callbacks()
        candidate_holder = {}
        order = []

        def save_before_publish(path, value, password):
            order.append("save")
            self.assertEqual(threading.get_ident(), self.root._ui_thread_id)
            self.assertEqual(path, self.vault_path)
            self.assertEqual(password, PASSWORD)
            self.assertIs(self.root.vault, original)
            self.assertEqual(value, candidate_holder["candidate"])

        def read_then_persist():
            worker_vault = callbacks["get_vault"]()
            candidate = copy.deepcopy(worker_vault)
            candidate["entries"].append({"id": "synthetic", "title": "synthetic"})
            candidate_holder["candidate"] = candidate
            callbacks["persist_candidate"](candidate)
            return candidate

        with patch.object(app, "save_vault", side_effect=save_before_publish):
            worker_id, candidate = self.worker_call(read_then_persist)
        order.append("published")
        self.assertEqual(order, ["save", "published"])
        self.assertIsNot(self.root.vault, original)
        self.assertEqual(self.root.vault, candidate)
        self.assertTrue(self.root._bridge_worker_tokens[worker_id]["committed"])

    def test_uncommitted_form_edit_invalidates_worker_snapshot(self):
        callbacks = self.open_bridge_callbacks()
        callbacks["get_vault"]()
        before = self.root._draft_generation
        draft = tk.StringVar(master=self.root, value="synthetic before")
        self.root._watch_form_variable(draft)
        draft.set("synthetic after")
        self.assertGreater(self.root._draft_generation, before)
        candidate = copy.deepcopy(self.root.vault)
        candidate["entries"].append({"id": "synthetic-edit", "title": "not saved"})
        with patch.object(app, "save_vault") as save:
            with self.assertRaisesRegex(RuntimeError, "vault changed"):
                self.root._persist_bridge_candidate_on_ui(threading.get_ident(), candidate, 7)
        save.assert_not_called()
        self.assertFalse(self.root.vault["entries"])

    def test_lock_starts_nonblocking_stop_and_clears_only_after_drain(self):
        server = FakeBridgeServer()
        self.root._bridge_server = server
        self.root._bridge_callbacks_open = True
        self.root._bridge_worker_tokens[123] = {"bridge_generation": 7}
        self.root._bridge_generation = 7

        self.root.lock()
        self.assertTrue(server.stop_called)
        self.assertTrue(self.root._closing_session)
        self.assertEqual(self.root.password, PASSWORD)
        self.assertFalse(self.root._bridge_callbacks_open)
        self.assertFalse(self.root._bridge_worker_tokens)

        self.root._poll_bridge_stop()
        self.assertEqual(self.root.password, PASSWORD)
        self.assertIsNotNone(self.root._bridge_stop_pending)

        server.drained = True
        self.root._poll_bridge_stop()
        self.assertIsNone(self.root.password)
        self.assertIsNone(self.root._bridge_stop_pending)
        self.assertIsNone(self.root._bridge_server)

    def test_old_bridge_generation_is_rejected_after_stop_begins(self):
        callbacks = self.open_bridge_callbacks()
        self.root._bridge_worker_tokens[threading.get_ident()] = {"bridge_generation": 7}
        self.root._begin_bridge_stop(lambda: None)
        job = {"generation": 7, "kind": "status", "done": threading.Event(), "cancelled": False}
        self.root._run_bridge_ui_call(job)
        self.assertEqual(job.get("error"), "The local bridge is unavailable.")
        self.assertTrue(job["done"].is_set())
        self.assertNotIn(threading.get_ident(), self.root._bridge_worker_tokens)

    def test_reference_commands_supply_unlocked_only_snapshot_and_commit_callback(self):
        captured = {}

        def open_grant(_parent, *, get_vault, commit_vault, **kwargs):
            captured["vault"] = get_vault()
            captured["get_vault"] = get_vault
            captured["commit"] = commit_vault
            captured["kwargs"] = kwargs
            return None

        with patch.object(app, "show_grant_dialog", side_effect=open_grant):
            self.root.create_hexigrid_reference()
        self.assertIs(captured["vault"], self.root.vault)
        self.assertEqual(captured["kwargs"], {})
        with patch.object(app, "save_vault") as save:
            replacement = {"entries": [], "integrations": {"hexigrid": {"pairing": dict(PAIRING), "grants": []}}}
            captured["commit"](replacement)
        save.assert_called_once()
        self.assertIs(self.root.vault, replacement)
        self.root.password = None
        self.assertIsNone(captured["get_vault"]())
        self.assertIsInstance(captured["commit"]({"entries": []}), RuntimeError)


if __name__ == "__main__":
    unittest.main()
