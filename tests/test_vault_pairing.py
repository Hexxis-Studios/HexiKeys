import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import vault_pairing as pairing


PIPE_ID = "hexikeys-0123456789abcdef0123456789abcdef"
HMAC_KEY = "a1" * 32


def protect_for_test(plaintext):
    return b"synthetic-dpapi:" + plaintext[::-1]


class PairingDescriptorTests(unittest.TestCase):
    def test_descriptor_is_bounded_protected_atomic_and_returns_metadata_only(self):
        with tempfile.TemporaryDirectory() as directory:
            restricted = []
            result = pairing.create_pairing_descriptor(
                directory,
                protect=protect_for_test,
                restrict_acl=restricted.append,
                pipe_id_factory=lambda: PIPE_ID,
                key_factory=lambda: HMAC_KEY,
            )
            target = pairing.pairing_descriptor_path(directory)
            stored = target.read_bytes()
            self.assertEqual(result, PIPE_ID)
            self.assertEqual(len(restricted), 1)
            self.assertEqual(restricted[0].parent, target.parent)
            self.assertTrue(restricted[0].name.endswith(".pending"))
            self.assertLessEqual(len(stored), pairing.MAX_DESCRIPTOR_BYTES)
            self.assertTrue(stored.startswith(b"synthetic-dpapi:"))
            self.assertNotIn(PIPE_ID.encode(), stored)
            self.assertNotIn(HMAC_KEY.encode(), stored)
            payload = json.loads(stored[len(b"synthetic-dpapi:"):][::-1])
            self.assertEqual(payload, {"version": 1, "pipeId": PIPE_ID, "hmacKey": HMAC_KEY})
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_invalid_generated_identity_or_key_never_publishes(self):
        for pipe_id, key in [("not-a-pipe", HMAC_KEY), (PIPE_ID, "too-short")]:
            with self.subTest(pipe_id=pipe_id, key_length=len(key)), tempfile.TemporaryDirectory() as directory:
                with self.assertRaises(ValueError):
                    pairing.create_pairing_descriptor(
                        directory,
                        protect=protect_for_test,
                        restrict_acl=lambda _path: None,
                        pipe_id_factory=lambda: pipe_id,
                        key_factory=lambda: key,
                    )
                self.assertEqual(list(Path(directory).iterdir()), [])

    def test_protection_acl_and_publication_failures_preserve_previous_file(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pairing.pairing_descriptor_path(directory)
            target.write_bytes(b"previous-protected-descriptor")

            def unavailable(_plaintext):
                raise RuntimeError("synthetic protection unavailable")

            cases = [
                {"protect": unavailable, "restrict_acl": lambda _path: None},
                {"protect": protect_for_test, "restrict_acl": lambda _path: (_ for _ in ()).throw(RuntimeError("synthetic ACL failure"))},
                {"protect": protect_for_test, "restrict_acl": lambda _path: None, "replace": lambda *_args: (_ for _ in ()).throw(OSError("synthetic publish failure"))},
            ]
            for options in cases:
                with self.subTest(options=tuple(options)):
                    with self.assertRaises((RuntimeError, OSError)):
                        pairing.create_pairing_descriptor(
                            directory,
                            pipe_id_factory=lambda: PIPE_ID,
                            key_factory=lambda: HMAC_KEY,
                            **options,
                        )
                    self.assertEqual(target.read_bytes(), b"previous-protected-descriptor")
                    self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_cleanup_removes_only_the_fixed_descriptor(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pairing.pairing_descriptor_path(directory)
            other = Path(directory) / "keep.txt"
            target.write_bytes(b"protected")
            other.write_text("keep", encoding="utf-8")
            pairing.remove_pairing_descriptor(directory)
            pairing.remove_pairing_descriptor(directory)
            self.assertFalse(target.exists())
            self.assertEqual(other.read_text(encoding="utf-8"), "keep")

    def test_encrypted_vault_commit_precedes_descriptor_publish_and_rolls_back_on_publish_failure(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pairing.pairing_descriptor_path(directory)
            target.write_bytes(b"previous-protected-descriptor")
            vault_state = {"value": "previous-encrypted-vault-state"}
            persisted = []

            def persist(material):
                self.assertEqual(material["version"], 1)
                self.assertEqual(material["pipeId"], PIPE_ID)
                self.assertEqual(material["hmacKey"], bytes.fromhex(HMAC_KEY))
                vault_state["value"] = {"pipeId": material["pipeId"], "hmacKey": material["hmacKey"].hex()}
                persisted.append("committed")
                return "opaque-exact-rollback-token"

            def rollback(token):
                self.assertEqual(token, "opaque-exact-rollback-token")
                vault_state["value"] = "previous-encrypted-vault-state"

            def fail_publication(_source, _destination):
                self.assertEqual(persisted, ["committed"])
                raise OSError("synthetic descriptor publication failure")

            with self.assertRaisesRegex(OSError, "publication"):
                pairing.create_pairing_material(
                    directory,
                    persist=persist,
                    rollback=rollback,
                    protect=protect_for_test,
                    restrict_acl=lambda _path: None,
                    pipe_id_factory=lambda: PIPE_ID,
                    key_factory=lambda: HMAC_KEY,
                    replace=fail_publication,
                )
            self.assertEqual(vault_state["value"], "previous-encrypted-vault-state")
            self.assertEqual(target.read_bytes(), b"previous-protected-descriptor")
            self.assertEqual(list(Path(directory).iterdir()), [target])

    def test_paired_material_commits_once_and_restore_reseals_the_same_key(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pairing.pairing_descriptor_path(directory)
            vault_state = {}

            def persist(material):
                vault_state["pairing"] = (material["pipeId"], material["hmacKey"].hex())
                return None

            result = pairing.create_pairing_material(
                directory,
                persist=persist,
                rollback=lambda _token: vault_state.pop("pairing", None),
                protect=protect_for_test,
                restrict_acl=lambda _path: None,
                pipe_id_factory=lambda: PIPE_ID,
                key_factory=lambda: HMAC_KEY,
            )
            self.assertEqual(result, PIPE_ID)
            self.assertEqual(vault_state["pairing"], (PIPE_ID, HMAC_KEY))
            protected_before = target.read_bytes()
            self.assertNotIn(HMAC_KEY.encode(), protected_before)
            target.unlink()
            self.assertEqual(
                pairing.restore_pairing_descriptor(
                    directory,
                    pipe_id=PIPE_ID,
                    hmac_key=bytes.fromhex(HMAC_KEY),
                    protect=protect_for_test,
                    unprotect=lambda ciphertext: ciphertext[len(b"synthetic-dpapi:"):][::-1],
                    restrict_acl=lambda _path: None,
                ),
                PIPE_ID,
            )
            restored = target.read_bytes()
            self.assertEqual(restored, protected_before)
            self.assertEqual(
                pairing.restore_pairing_descriptor(
                    directory,
                    pipe_id=PIPE_ID,
                    hmac_key=bytes.fromhex(HMAC_KEY),
                    protect=lambda _plaintext: self.fail("restore must not rotate/reprotect an existing descriptor"),
                    unprotect=lambda ciphertext: ciphertext[len(b"synthetic-dpapi:"):][::-1],
                    restrict_acl=lambda _path: None,
                ),
                PIPE_ID,
            )
            self.assertEqual(target.read_bytes(), restored)

    def test_restore_refuses_to_replace_a_different_existing_pairing(self):
        with tempfile.TemporaryDirectory() as directory:
            target = pairing.pairing_descriptor_path(directory)
            original = protect_for_test(pairing._descriptor_payload(PIPE_ID, "b2" * 32))
            target.write_bytes(original)
            with self.assertRaisesRegex(ValueError, "different pairing"):
                pairing.restore_pairing_descriptor(
                    directory,
                    pipe_id=PIPE_ID,
                    hmac_key=bytes.fromhex(HMAC_KEY),
                    protect=protect_for_test,
                    unprotect=lambda ciphertext: ciphertext[len(b"synthetic-dpapi:"):][::-1],
                    restrict_acl=lambda _path: None,
                )
            self.assertEqual(target.read_bytes(), original)

    @unittest.skipUnless(__import__("os").name == "nt", "Windows DPAPI is required")
    def test_windows_dpapi_protects_random_descriptor_bytes(self):
        with tempfile.TemporaryDirectory() as directory:
            pipe_id = pairing.create_pairing_descriptor(
                directory,
                pipe_id_factory=lambda: PIPE_ID,
                key_factory=lambda: HMAC_KEY,
            )
            stored = pairing.pairing_descriptor_path(directory).read_bytes()
            self.assertEqual(pipe_id, PIPE_ID)
            self.assertLessEqual(len(stored), pairing.MAX_DESCRIPTOR_BYTES)
            self.assertNotIn(pipe_id.encode(), stored)
            self.assertNotIn(HMAC_KEY.encode(), stored)

    def test_dpapi_unavailable_fails_closed_without_plaintext_fallback(self):
        with patch.object(pairing.os, "name", "posix"):
            with self.assertRaisesRegex(RuntimeError, "DPAPI is unavailable"):
                pairing.protect_current_user(b"synthetic descriptor")


if __name__ == "__main__":
    unittest.main()
