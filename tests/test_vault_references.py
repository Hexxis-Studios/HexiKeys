import copy
import tempfile
import unittest
from pathlib import Path

import vault_references as refs
from test_vault_crypto import PASSWORD
from vault_store import load_vault, save_vault


NOW = 1_800_000_000
SECRET = "SYNTHETIC-ONLY-api-secret"


def payload(*, with_field_id=False):
    field = {"label": "API key", "value": SECRET, "secret": True}
    if with_field_id:
        field["id"] = "a" * 32
    return {"entries": [{"id": "synthetic-entry", "title": "Synthetic service", "fields": [field]}]}


def create_grant(vault=None, **overrides):
    options = {
        "entry_id": "synthetic-entry",
        "field_index": 0,
        "connector_id": "hexikeys",
        "capability_id": "api-request",
        "task_id": "task-synthetic-01",
        "origin": "https://API.Example.invalid:443/",
        "path_prefix": "/v1/records",
        "methods": ["GET", "POST"],
        "header": "Authorization",
        "prefix": "Bearer ",
        "expires_at": NOW + 600,
        "max_uses": 2,
        "now": NOW,
    }
    options.update(overrides)
    return refs.create_reference_grant(vault or payload(), **options)


def request(grant_id, **overrides):
    value = {
        "grantId": grant_id,
        "requestId": "b" * 32,
        "connectorId": "hexikeys",
        "capabilityId": "api-request",
        "taskId": "task-synthetic-01",
        "origin": "https://api.example.invalid",
        "path": "/v1/records/123",
        "method": "GET",
        "header": "authorization",
        "prefix": "Bearer ",
    }
    value.update(overrides)
    return value


def consume(vault, authorization_request, *, now):
    saved = {}
    secret, receipt = refs.consume_reference_grant(
        vault,
        authorization_request,
        persist_candidate=lambda candidate: saved.setdefault("vault", candidate),
        now=now,
    )
    return saved["vault"], secret, receipt


class VaultReferenceTests(unittest.TestCase):
    def test_read_only_grant_listing_handles_legacy_vault_without_metadata(self):
        self.assertEqual(refs.public_reference_grants(payload()), [])

    def test_grant_materializes_legacy_field_id_and_listing_redacts_value(self):
        original = payload()
        candidate, grant_id = create_grant(original)
        self.assertNotIn("id", original["entries"][0]["fields"][0])
        field = candidate["entries"][0]["fields"][0]
        self.assertRegex(field["id"], r"^[0-9a-f]{32}$")
        public = refs.public_reference_grants(candidate)
        self.assertEqual(len(public), 1)
        self.assertEqual(public[0]["id"], grant_id)
        self.assertEqual(public[0]["fieldLabel"], "API key")
        self.assertNotIn("fieldId", public[0])
        self.assertNotIn(SECRET, repr(public))

    def test_valid_use_returns_candidate_secret_and_redacted_receipt(self):
        vault, grant_id = create_grant()
        updated, secret, receipt = consume(vault, request(grant_id), now=NOW + 1)
        self.assertEqual(secret, SECRET)
        self.assertEqual(updated["integrations"]["hexigrid"]["grants"][0]["uses"], 1)
        self.assertEqual(vault["integrations"]["hexigrid"]["grants"][0]["uses"], 0)
        self.assertEqual(receipt["origin"], "https://api.example.invalid")
        self.assertNotIn(SECRET, repr(receipt))
        self.assertNotIn("path", receipt)

    def test_request_replay_and_use_limit_fail_closed(self):
        vault, grant_id = create_grant(max_uses=1)
        consumed, _secret, _receipt = consume(vault, request(grant_id), now=NOW + 1)
        with self.assertRaises(refs.ReferenceAuthorizationError):
            consume(consumed, request(grant_id), now=NOW + 1)
        with self.assertRaises(refs.ReferenceAuthorizationError):
            consume(consumed, request(grant_id, requestId="c" * 32), now=NOW + 1)

    def test_each_connector_task_destination_and_header_scope_is_exact(self):
        vault, grant_id = create_grant()
        invalid_requests = (
            {"connectorId": "other-plugin"},
            {"capabilityId": "other-capability"},
            {"taskId": "task-other"},
            {"origin": "https://other.example.invalid"},
            {"method": "DELETE"},
            {"path": "/v1/records-private/item"},
            {"path": "/v1/records2/item"},
            {"header": "x-api-key"},
            {"prefix": "Token "},
            {"method": "GETX"},
        )
        for change in invalid_requests:
            with self.subTest(change=change), self.assertRaises(refs.ReferenceAuthorizationError):
                consume(vault, request(grant_id, **change), now=NOW + 1)

    def test_path_scope_respects_segment_boundaries_and_decoding(self):
        self.assertTrue(refs._path_is_allowed("/v1/records", "/v1/records"))
        self.assertTrue(refs._path_is_allowed("/v1/records", "/v1/records/42"))
        self.assertTrue(refs._path_is_allowed("/v1/records", "/v1/rec%6Frds/42"))
        for path in (
            "/v1/records-other", "/v1/records2", "/v1/records/%2e%2e/admin",
            "/v1/records/%252e%252e/admin", "/v1//records/42", "/v1/records?x=1",
            "/v1/records\nsecret",
        ):
            with self.subTest(path=path):
                self.assertFalse(refs._path_is_allowed("/v1/records", path))

    def test_expiry_revocation_and_changed_field_identity_deny_use(self):
        vault, grant_id = create_grant()
        with self.assertRaises(refs.ReferenceAuthorizationError):
            consume(vault, request(grant_id), now=NOW + 600)
        revoked = refs.revoke_reference_grant(vault, grant_id, now=NOW + 2)
        with self.assertRaises(refs.ReferenceAuthorizationError):
            consume(revoked, request(grant_id), now=NOW + 3)
        changed = copy.deepcopy(vault)
        changed["entries"][0]["fields"][0]["id"] = "c" * 32
        with self.assertRaises(refs.ReferenceAuthorizationError):
            consume(changed, request(grant_id), now=NOW + 3)

    def test_grant_creation_rejects_overbroad_or_malformed_scopes(self):
        invalid = (
            {"origin": "http://api.example.invalid"},
            {"origin": "https://api.example.invalid/private"},
            {"path_prefix": "/v1/../admin"},
            {"methods": ["*"]},
            {"methods": ["TRACE"]},
            {"header": "cookie"},
            {"header": "x-key\r\nInjected"},
            {"max_uses": True},
            {"expires_at": NOW + refs.MAX_GRANT_TTL_SECONDS + 1},
            {"field_index": True},
        )
        for change in invalid:
            with self.subTest(change=change), self.assertRaises(ValueError):
                create_grant(**change)

    def test_origin_normalization_and_header_matching(self):
        self.assertEqual(refs.normalize_https_origin("HTTPS://API.Example.invalid:443/"), "https://api.example.invalid")
        with self.assertRaises(ValueError):
            refs.normalize_https_origin("https://user:pass@api.example.invalid")

    def test_malformed_persisted_replay_state_fails_closed(self):
        vault, grant_id = create_grant()
        vault["integrations"]["hexigrid"]["grants"][0]["usedRequestIds"] = "not-a-list"
        with self.assertRaises(refs.ReferenceAuthorizationError):
            consume(vault, request(grant_id), now=NOW + 1)

    def test_malformed_persisted_scope_fails_closed(self):
        for key, value in (("methods", "GET"), ("methods", ["GET,POST"]), ("pathPrefix", ""), ("prefix", "Bearer\n")):
            vault, grant_id = create_grant()
            vault["integrations"]["hexigrid"]["grants"][0][key] = value
            with self.subTest(key=key, value=value), self.assertRaises(refs.ReferenceAuthorizationError):
                consume(vault, request(grant_id), now=NOW + 1)

    def test_secret_is_not_returned_before_durable_save_succeeds(self):
        vault, grant_id = create_grant()
        saved = []

        def persist(candidate):
            saved.append(candidate)

        secret, receipt = refs.consume_reference_grant(vault, request(grant_id), persist_candidate=persist, now=NOW + 1)
        self.assertEqual(secret, SECRET)
        self.assertEqual(saved[0]["integrations"]["hexigrid"]["grants"][0]["uses"], 1)
        self.assertNotIn(SECRET, repr(receipt))

        with self.assertRaises(refs.ReferencePersistenceError) as raised:
            refs.consume_reference_grant(
                vault,
                request(grant_id, requestId="d" * 32),
                persist_candidate=lambda _candidate: (_ for _ in ()).throw(OSError(SECRET)),
                now=NOW + 1,
            )
        self.assertNotIn(SECRET, str(raised.exception))
        self.assertEqual(vault["integrations"]["hexigrid"]["grants"][0]["uses"], 0)

    def test_encrypted_use_count_is_committed_before_secret_release(self):
        vault, grant_id = create_grant()
        with tempfile.TemporaryDirectory(prefix="hexikeys-reference-test-") as directory:
            path = Path(directory) / "vault.dat"
            save_vault(path, vault, PASSWORD)

            def persist(candidate):
                save_vault(path, candidate, PASSWORD)

            secret, receipt = refs.consume_reference_grant(
                vault,
                request(grant_id),
                persist_candidate=persist,
                now=NOW + 1,
            )
            saved, _version = load_vault(path, PASSWORD)
            self.assertEqual(secret, SECRET)
            self.assertEqual(saved["integrations"]["hexigrid"]["grants"][0]["uses"], 1)
            self.assertNotIn(SECRET, repr(receipt))


if __name__ == "__main__":
    unittest.main()
