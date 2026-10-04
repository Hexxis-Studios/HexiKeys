import base64
import hashlib
import hmac
import json
import unittest

import vault_crypto


PASSWORD = "demo test phrase 2041!"
PAYLOAD = {
    "entries": [
        {
            "id": "test-entry-1",
            "title": "Example service",
            "category": "API key",
            "purpose": "Synthetic test data only",
            "fields": [
                {"label": "API key", "value": "not-a-real-key", "secret": True},
                {"label": "Region", "value": "test-region", "secret": False},
            ],
        }
    ]
}


def b64(value):
    return base64.b64encode(value).decode("ascii")


def make_legacy_v1(payload, password):
    salt = bytes(range(16))
    nonce = bytes(range(16, 32))
    key = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 240_000, 32)
    plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    stream = bytearray()
    counter = 0
    while len(stream) < len(plaintext):
        stream.extend(hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest())
        counter += 1
    ciphertext = bytes(a ^ b for a, b in zip(plaintext, stream))
    tag = hmac.new(key, nonce + ciphertext, hashlib.sha256).digest()
    return {"version": 1, "salt": b64(salt), "nonce": b64(nonce), "data": b64(ciphertext), "tag": b64(tag)}


class VaultCryptoTests(unittest.TestCase):
    def test_v2_round_trip(self):
        blob = vault_crypto.encrypt_vault(PAYLOAD, PASSWORD)
        self.assertEqual(blob["version"], 2)
        self.assertEqual(vault_crypto.decrypt_vault(blob, PASSWORD), PAYLOAD)

    def test_v1_legacy_is_readable(self):
        blob = make_legacy_v1(PAYLOAD, PASSWORD)
        self.assertEqual(vault_crypto.decrypt_vault(blob, PASSWORD), PAYLOAD)

    def test_wrong_password_is_rejected_for_both_formats(self):
        for blob in (vault_crypto.encrypt_vault(PAYLOAD, PASSWORD), make_legacy_v1(PAYLOAD, PASSWORD)):
            with self.subTest(version=blob["version"]):
                with self.assertRaises(vault_crypto.VaultAuthenticationError):
                    vault_crypto.decrypt_vault(blob, "wrong test password")

    def test_v2_tampering_is_rejected(self):
        blob = vault_crypto.encrypt_vault(PAYLOAD, PASSWORD)
        ciphertext = bytearray(base64.b64decode(blob["data"]))
        ciphertext[0] ^= 1
        blob["data"] = b64(bytes(ciphertext))
        with self.assertRaises(ValueError):
            vault_crypto.decrypt_vault(blob, PASSWORD)

    def test_unknown_format_and_bad_base64_are_rejected(self):
        with self.assertRaises(ValueError):
            vault_crypto.decrypt_vault({"version": 99}, PASSWORD)
        blob = vault_crypto.encrypt_vault(PAYLOAD, PASSWORD)
        blob["salt"] = "!invalid!"
        with self.assertRaises(ValueError):
            vault_crypto.decrypt_vault(blob, PASSWORD)

    def test_invalid_payload_is_not_written(self):
        with self.assertRaises(ValueError):
            vault_crypto.encrypt_vault({"items": []}, PASSWORD)

    def test_unrecognized_legacy_field_metadata_remains_compatible(self):
        payload = json.loads(json.dumps(PAYLOAD))
        payload["entries"][0]["fields"][0]["id"] = "legacy-external-field-id"
        blob = vault_crypto.encrypt_vault(payload, PASSWORD)
        self.assertEqual(vault_crypto.decrypt_vault(blob, PASSWORD), payload)

    def test_size_limits_are_enforced(self):
        with self.assertRaises(ValueError):
            vault_crypto.encrypt_vault({"entries": [], "padding": "x" * vault_crypto.MAX_VAULT_BYTES}, PASSWORD)


if __name__ == "__main__":
    unittest.main()
