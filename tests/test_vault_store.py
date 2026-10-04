import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import vault_store
from test_vault_crypto import PASSWORD, PAYLOAD, make_legacy_v1
from vault_crypto import decrypt_vault, encrypt_vault
from vault_store import copy_encrypted_vault, create_encrypted_backup


class VaultStoreTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory(prefix="hexikeys-vault-test-")
        self.path = Path(self.temp_dir.name) / "vault.dat"

    def tearDown(self):
        self.temp_dir.cleanup()

    def test_save_load_round_trip_uses_version_2(self):
        self.assertIsNone(vault_store.save_vault(self.path, PAYLOAD, PASSWORD))
        payload, version = vault_store.load_vault(self.path, PASSWORD)
        self.assertEqual(payload, PAYLOAD)
        self.assertEqual(version, 2)

    def test_legacy_upgrade_preserves_exact_encrypted_copy(self):
        legacy_blob = make_legacy_v1(PAYLOAD, PASSWORD)
        original_bytes = json.dumps(legacy_blob).encode("utf-8")
        self.path.write_bytes(original_bytes)
        backup = vault_store.save_vault(self.path, PAYLOAD, PASSWORD)
        self.assertIsNotNone(backup)
        self.assertEqual(backup.read_bytes(), original_bytes)
        self.assertEqual(decrypt_vault(json.loads(backup.read_text(encoding="utf-8")), PASSWORD), PAYLOAD)
        upgraded, version = vault_store.load_vault(self.path, PASSWORD)
        self.assertEqual(upgraded, PAYLOAD)
        self.assertEqual(version, 2)

    def test_existing_v2_does_not_create_legacy_backup(self):
        self.path.write_text(json.dumps(encrypt_vault(PAYLOAD, PASSWORD)), encoding="utf-8")
        self.assertIsNone(vault_store.save_vault(self.path, PAYLOAD, PASSWORD))
        self.assertEqual(len(list(self.path.parent.glob("*.bak"))), 0)

    def test_encryption_failure_keeps_existing_file(self):
        original = json.dumps(encrypt_vault(PAYLOAD, PASSWORD)).encode("utf-8")
        self.path.write_bytes(original)
        with patch("vault_store.encrypt_vault", side_effect=RuntimeError("test failure")):
            with self.assertRaises(RuntimeError):
                vault_store.save_vault(self.path, PAYLOAD, PASSWORD)
        self.assertEqual(self.path.read_bytes(), original)
        self.assertEqual(list(self.path.parent.glob("*.tmp")), [])

    def test_encrypted_backup_is_exact_and_loadable_without_plaintext_copy(self):
        vault_store.save_vault(self.path, PAYLOAD, PASSWORD)
        backup = create_encrypted_backup(self.path, PASSWORD, label="test-safety")
        self.assertNotEqual(backup, self.path)
        self.assertEqual(backup.read_bytes(), self.path.read_bytes())
        restored, version = vault_store.load_vault(backup, PASSWORD)
        self.assertEqual(restored, PAYLOAD)
        self.assertEqual(version, 2)

    def test_copy_encrypted_vault_rejects_same_path_and_corrupt_source(self):
        vault_store.save_vault(self.path, PAYLOAD, PASSWORD)
        with self.assertRaisesRegex(ValueError, "different file"):
            copy_encrypted_vault(self.path, self.path, PASSWORD)
        corrupt = self.path.with_name("corrupt.dat")
        corrupt.write_text("not encrypted json", encoding="utf-8")
        with self.assertRaises(ValueError):
            copy_encrypted_vault(corrupt, self.path.with_name("copy.hexikeys"), PASSWORD)
        self.assertFalse(self.path.with_name("copy.hexikeys").exists())

    def test_copy_with_wrong_password_preserves_existing_destination(self):
        vault_store.save_vault(self.path, PAYLOAD, PASSWORD)
        destination = self.path.with_name("existing-backup.hexikeys")
        destination.write_bytes(b"pre-existing destination")
        with self.assertRaises(ValueError):
            copy_encrypted_vault(self.path, destination, "synthetic wrong password")
        self.assertEqual(destination.read_bytes(), b"pre-existing destination")
        copy_encrypted_vault(self.path, destination, PASSWORD)
        self.assertEqual(vault_store.load_vault(destination, PASSWORD)[0], PAYLOAD)

    def test_oversized_or_malformed_files_are_rejected(self):
        self.path.write_bytes(b"x" * (vault_store.MAX_VAULT_FILE_BYTES + 1))
        with self.assertRaises(ValueError):
            vault_store.read_encrypted_blob(self.path)
        self.path.write_text("not json", encoding="utf-8")
        with self.assertRaises(ValueError):
            vault_store.read_encrypted_blob(self.path)


if __name__ == "__main__":
    unittest.main()
