"""Least-privilege, one-field references for a future local HexiGrid broker.

Grant state lives inside the existing encrypted vault. This module deliberately
does not open a listener or expose a secret over IPC; callers must persist the
returned candidate vault before releasing a resolved secret to a local host.
"""

import copy
import re
import secrets
import time
from urllib.parse import unquote, urlsplit


MAX_GRANTS = 1_000
MAX_GRANT_TTL_SECONDS = 30 * 24 * 60 * 60
MAX_USES = 1_000
FIELD_ID_RE = re.compile(r"[0-9a-f]{32}\Z")
GRANT_ID_RE = FIELD_ID_RE
REQUEST_ID_RE = FIELD_ID_RE
IDENTIFIER_RE = re.compile(r"[a-z0-9][a-z0-9._-]{1,62}\Z")
TASK_ID_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{1,127}\Z")
HEADER_RE = re.compile(r"(?:authorization|x-[a-z0-9-]{1,80})\Z")
ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
REQUEST_KEYS = frozenset({
    "grantId", "requestId", "connectorId", "capabilityId", "taskId",
    "origin", "path", "method", "header", "prefix",
})


class ReferenceAuthorizationError(ValueError):
    """A live credential reference is missing, expired, replayed, or out of scope."""


class ReferencePersistenceError(ValueError):
    """An authorized use could not be durably recorded before releasing its value."""


def _require_identifier(value, label, pattern=IDENTIFIER_RE):
    if not isinstance(value, str) or not pattern.fullmatch(value):
        raise ValueError(f"Invalid {label}.")
    return value


def normalize_https_origin(value):
    if not isinstance(value, str) or len(value) > 300:
        raise ValueError("Use a valid HTTPS origin.")
    try:
        parsed = urlsplit(value)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Use a valid HTTPS origin.") from exc
    if (
        parsed.scheme.casefold() != "https" or not hostname or parsed.username or parsed.password
        or parsed.path not in ("", "/") or parsed.query or parsed.fragment
    ):
        raise ValueError("Use an HTTPS origin without a path, credentials, query, or fragment.")
    try:
        ascii_host = hostname.encode("idna").decode("ascii").casefold()
    except UnicodeError as exc:
        raise ValueError("Use a valid HTTPS host name.") from exc
    if not ascii_host or any(char.isspace() for char in ascii_host):
        raise ValueError("Use a valid HTTPS host name.")
    if ":" in ascii_host and not ascii_host.startswith("["):
        ascii_host = f"[{ascii_host}]"
    netloc = ascii_host if port in (None, 443) else f"{ascii_host}:{port}"
    return f"https://{netloc}"


def _validate_path_prefix(value):
    if not isinstance(value, str) or not value.startswith("/") or len(value) > 500:
        raise ValueError("Use an absolute path prefix.")
    if value.startswith("//") or any(char in value for char in "?#\\") or any(
        ord(char) < 0x21 or ord(char) == 0x7f for char in value
    ):
        raise ValueError("Path prefixes cannot contain an authority, query, or fragment.")
    if re.search(r"%(?![0-9a-fA-F]{2})", value):
        raise ValueError("Path prefixes must use valid percent-encoding.")
    decoded = unquote(value)
    if "%" in decoded or "\\" in decoded or any(ord(char) < 0x21 or ord(char) == 0x7f for char in decoded):
        raise ValueError("Path prefixes cannot use ambiguous or encoded control characters.")
    if "//" in decoded or any(segment in (".", "..") for segment in decoded.split("/")):
        raise ValueError("Path prefixes cannot traverse parent directories.")
    return value


def _path_is_allowed(prefix, path):
    if not isinstance(path, str) or len(path) > 2_048 or not path.startswith("/") or any(char in path for char in "?#\\"):
        return False
    if any(ord(char) < 0x21 or ord(char) == 0x7f for char in path):
        return False
    if re.search(r"%(?![0-9a-fA-F]{2})", path):
        return False
    decoded_prefix = unquote(prefix)
    decoded_path = unquote(path)
    if (
        "%" in decoded_path or "%" in decoded_prefix
        or "\\" in decoded_path or "\\" in decoded_prefix
        or "//" in decoded_path or "//" in decoded_prefix
        or any(ord(char) < 0x21 or ord(char) == 0x7f for char in decoded_path)
        or any(segment in (".", "..") for segment in decoded_path.split("/"))
    ):
        return False
    if decoded_prefix == "/":
        return True
    base = decoded_prefix.rstrip("/")
    return decoded_path == base or decoded_path.startswith(base + "/")


def _persisted_grant_is_valid(grant):
    if not isinstance(grant, dict):
        return False
    try:
        if not isinstance(grant.get("id"), str) or not GRANT_ID_RE.fullmatch(grant["id"]):
            return False
        if not isinstance(grant.get("entryId"), str) or not grant["entryId"] or len(grant["entryId"]) > 256:
            return False
        if not isinstance(grant.get("fieldId"), str) or not FIELD_ID_RE.fullmatch(grant["fieldId"]):
            return False
        _require_identifier(grant.get("connectorId"), "connector ID")
        _require_identifier(grant.get("capabilityId"), "capability ID")
        _require_identifier(grant.get("taskId"), "task ID", TASK_ID_RE)
        if normalize_https_origin(grant.get("origin")) != grant.get("origin"):
            return False
        if _validate_path_prefix(grant.get("pathPrefix")) != grant.get("pathPrefix"):
            return False
        methods = grant.get("methods")
        if not isinstance(methods, list) or not methods or len(methods) > len(ALLOWED_METHODS):
            return False
        if any(not isinstance(method, str) or method not in ALLOWED_METHODS for method in methods):
            return False
        if len(set(methods)) != len(methods):
            return False
        header = grant.get("header")
        if not isinstance(header, str) or not HEADER_RE.fullmatch(header) or header != header.casefold():
            return False
        prefix = grant.get("prefix")
        if not isinstance(prefix, str) or len(prefix) > 64 or any(ord(char) < 0x20 or ord(char) == 0x7f for char in prefix):
            return False
        for key in ("expiresAt", "createdAt", "uses", "maxUses"):
            if type(grant.get(key)) is not int:
                return False
        if grant["expiresAt"] <= grant["createdAt"]:
            return False
        if not 1 <= grant["maxUses"] <= MAX_USES or not 0 <= grant["uses"] <= grant["maxUses"]:
            return False
        if grant.get("revokedAt") is not None and type(grant.get("revokedAt")) is not int:
            return False
        used_ids = grant.get("usedRequestIds")
        if (
            not isinstance(used_ids, list) or len(used_ids) != grant["uses"]
            or len(used_ids) > MAX_USES
            or any(not isinstance(value, str) or not REQUEST_ID_RE.fullmatch(value) for value in used_ids)
            or len(set(used_ids)) != len(used_ids)
        ):
            return False
        if "lastUsedAt" in grant and type(grant["lastUsedAt"]) is not int:
            return False
    except (TypeError, ValueError):
        return False
    return True


def _bridge_state(vault, *, create=False):
    if not isinstance(vault, dict):
        raise ValueError("Vault contents have an unsupported format.")
    integrations = vault.get("integrations")
    if integrations is None:
        if not create:
            return {}, []
        integrations = {}
        vault["integrations"] = integrations
    if not isinstance(integrations, dict):
        raise ValueError("Vault integration metadata is invalid.")
    grid = integrations.get("hexigrid")
    if grid is None:
        if not create:
            return {}, []
        grid = {"grants": []}
        integrations["hexigrid"] = grid
    if not isinstance(grid, dict):
        raise ValueError("HexiGrid integration metadata is invalid.")
    grants = grid.get("grants")
    if grants is None and create:
        grants = []
        grid["grants"] = grants
    if not isinstance(grants, list) or len(grants) > MAX_GRANTS:
        raise ValueError("HexiGrid grant data is invalid.")
    return grid, grants


def _find_entry_and_field(vault, entry_id, field_id):
    entries = vault.get("entries")
    if not isinstance(entries, list):
        raise ReferenceAuthorizationError("Credential reference is unavailable.")
    matching_entries = [entry for entry in entries if isinstance(entry, dict) and entry.get("id") == entry_id]
    if len(matching_entries) != 1:
        raise ReferenceAuthorizationError("Credential reference is unavailable.")
    entry = matching_entries[0]
    fields = entry.get("fields")
    if not isinstance(fields, list):
        raise ReferenceAuthorizationError("Credential reference is unavailable.")
    matching_fields = [field for field in fields if isinstance(field, dict) and field.get("id") == field_id]
    if len(matching_fields) != 1:
        raise ReferenceAuthorizationError("Credential reference is unavailable.")
    return entry, matching_fields[0]


def create_reference_grant(
    vault, *, entry_id, field_index, connector_id, capability_id, task_id,
    origin, path_prefix, methods, header="authorization", prefix="",
    expires_at=None, max_uses=1, now=None,
):
    """Return (candidate_vault, opaque_grant_id) for an owner-confirmed field.

    `field_index` is only an in-process UI selection. It is replaced by a random
    field ID before any reference is issued, including for legacy entries.
    """
    connector_id = _require_identifier(connector_id, "connector ID")
    capability_id = _require_identifier(capability_id, "capability ID")
    task_id = _require_identifier(task_id, "task ID", TASK_ID_RE)
    origin = normalize_https_origin(origin)
    path_prefix = _validate_path_prefix(path_prefix)
    if type(field_index) is not int:
        raise ValueError("Select a valid field.")
    if not isinstance(methods, (list, tuple)) or not methods:
        raise ValueError("Choose at least one HTTP method.")
    normalized_methods = []
    for method in methods:
        if not isinstance(method, str):
            raise ValueError("Choose valid HTTP methods.")
        method = method.upper()
        if method not in ALLOWED_METHODS:
            raise ValueError("Choose only supported HTTP methods.")
        if method not in normalized_methods:
            normalized_methods.append(method)
    if not isinstance(header, str) or not HEADER_RE.fullmatch(header.casefold()):
        raise ValueError("Use Authorization or an X-prefixed credential header.")
    header = header.casefold()
    if not isinstance(prefix, str) or len(prefix) > 64 or any(ord(char) < 0x20 or ord(char) == 0x7f for char in prefix):
        raise ValueError("Credential header prefix is invalid.")
    if type(max_uses) is not int or not 1 <= max_uses <= MAX_USES:
        raise ValueError(f"Use limit must be between 1 and {MAX_USES}.")
    now = int(time.time()) if now is None else now
    if type(now) is not int:
        raise ValueError("Invalid current time.")
    if expires_at is None:
        expires_at = now + 24 * 60 * 60
    if type(expires_at) is not int or not now < expires_at <= now + MAX_GRANT_TTL_SECONDS:
        raise ValueError("Grant expiry must be within the next 30 days.")

    candidate = copy.deepcopy(vault)
    entries = candidate.get("entries")
    matching_entries = [entry for entry in entries or [] if isinstance(entry, dict) and entry.get("id") == entry_id]
    if len(matching_entries) != 1:
        raise ValueError("The selected vault item is unavailable.")
    entry = matching_entries[0]
    fields = entry.get("fields")
    if not isinstance(fields, list) or not 0 <= field_index < len(fields):
        raise ValueError("The selected vault field is unavailable.")
    field = fields[field_index]
    if not isinstance(field, dict) or not isinstance(field.get("value"), str) or not field["value"]:
        raise ValueError("The selected field has no value to share.")
    field_id = field.get("id")
    if not isinstance(field_id, str) or not FIELD_ID_RE.fullmatch(field_id) or sum(
        1 for existing in fields if isinstance(existing, dict) and existing.get("id") == field_id
    ) != 1:
        used_ids = {existing.get("id") for existing in fields if isinstance(existing, dict)}
        field_id = secrets.token_hex(16)
        while field_id in used_ids:
            field_id = secrets.token_hex(16)
        field["id"] = field_id

    grid, grants = _bridge_state(candidate, create=True)
    if len(grants) >= MAX_GRANTS:
        raise ValueError("HexiGrid grant limit reached.")
    grant_id = secrets.token_hex(16)
    while any(isinstance(grant, dict) and grant.get("id") == grant_id for grant in grants):
        grant_id = secrets.token_hex(16)
    grants.append({
        "id": grant_id,
        "entryId": entry_id,
        "fieldId": field_id,
        "connectorId": connector_id,
        "capabilityId": capability_id,
        "taskId": task_id,
        "origin": origin,
        "pathPrefix": path_prefix,
        "methods": normalized_methods,
        "header": header,
        "prefix": prefix,
        "expiresAt": expires_at,
        "maxUses": max_uses,
        "uses": 0,
        "usedRequestIds": [],
        "createdAt": now,
        "revokedAt": None,
    })
    return candidate, grant_id


def revoke_reference_grant(vault, grant_id, *, now=None):
    if not isinstance(grant_id, str) or not GRANT_ID_RE.fullmatch(grant_id):
        raise ValueError("Credential reference is unavailable.")
    now = int(time.time()) if now is None else now
    if type(now) is not int:
        raise ValueError("Invalid current time.")
    candidate = copy.deepcopy(vault)
    _grid, grants = _bridge_state(candidate)
    matching = [grant for grant in grants if isinstance(grant, dict) and grant.get("id") == grant_id]
    if len(matching) != 1:
        raise ValueError("Credential reference is unavailable.")
    matching[0]["revokedAt"] = now
    return candidate


def public_reference_grants(vault):
    """Return display-safe grant metadata, never credential values or field IDs."""
    _grid, grants = _bridge_state(vault)
    entries = vault.get("entries", [])
    entry_by_id = {
        entry.get("id"): entry for entry in entries
        if isinstance(entry, dict) and isinstance(entry.get("id"), str)
    }
    result = []
    for grant in grants:
        if not isinstance(grant, dict):
            continue
        entry = entry_by_id.get(grant.get("entryId"), {})
        fields = entry.get("fields", []) if isinstance(entry, dict) else []
        field = next((item for item in fields if isinstance(item, dict) and item.get("id") == grant.get("fieldId")), {}) if isinstance(fields, list) else {}
        result.append({
            "id": grant.get("id"),
            "itemName": entry.get("title", "Unavailable") if isinstance(entry, dict) else "Unavailable",
            "fieldLabel": field.get("label", "Unavailable") if isinstance(field, dict) else "Unavailable",
            "connectorId": grant.get("connectorId"),
            "capabilityId": grant.get("capabilityId"),
            "taskId": grant.get("taskId"),
            "origin": grant.get("origin"),
            "pathPrefix": grant.get("pathPrefix"),
            "methods": list(grant.get("methods", [])),
            "header": grant.get("header"),
            "prefix": grant.get("prefix"),
            "expiresAt": grant.get("expiresAt"),
            "maxUses": grant.get("maxUses"),
            "uses": grant.get("uses"),
            "revoked": bool(grant.get("revokedAt")),
        })
    return result


def consume_reference_grant(vault, request, *, persist_candidate, now=None):
    """Persist a use before returning (secret, redacted_receipt).

    `persist_candidate` must durably save the candidate encrypted vault and
    raise if it cannot. The candidate (which contains the full decrypted vault)
    is never returned to the broker caller. Request IDs are one-use to stop
    replays; a failed/ambiguous delivery consumes the use rather than risking
    replay.
    """
    if not callable(persist_candidate):
        raise ReferencePersistenceError("Credential use cannot proceed without durable encrypted storage.")
    if not isinstance(request, dict) or set(request) != REQUEST_KEYS:
        raise ReferenceAuthorizationError("Credential request is invalid or unavailable.")
    grant_id = request.get("grantId")
    request_id = request.get("requestId")
    if not isinstance(grant_id, str) or not GRANT_ID_RE.fullmatch(grant_id):
        raise ReferenceAuthorizationError("Credential request is invalid or unavailable.")
    if not isinstance(request_id, str) or not REQUEST_ID_RE.fullmatch(request_id):
        raise ReferenceAuthorizationError("Credential request is invalid or unavailable.")
    try:
        origin = normalize_https_origin(request.get("origin"))
    except ValueError as exc:
        raise ReferenceAuthorizationError("Credential request is invalid or unavailable.") from exc
    method = request.get("method")
    path = request.get("path")
    header = request.get("header")
    prefix = request.get("prefix")
    if not isinstance(method, str) or not isinstance(path, str) or not isinstance(header, str) or not isinstance(prefix, str) or len(prefix) > 64:
        raise ReferenceAuthorizationError("Credential request is invalid or unavailable.")
    method = method.upper()
    header = header.casefold()
    now = int(time.time()) if now is None else now
    if type(now) is not int:
        raise ReferenceAuthorizationError("Credential request is invalid or unavailable.")

    _grid, grants = _bridge_state(vault)
    matching = [grant for grant in grants if isinstance(grant, dict) and grant.get("id") == grant_id]
    if len(matching) != 1:
        raise ReferenceAuthorizationError("Credential request is invalid or unavailable.")
    grant = matching[0]
    if not _persisted_grant_is_valid(grant):
        raise ReferenceAuthorizationError("Credential request is invalid or unavailable.")
    used_request_ids = grant.get("usedRequestIds")
    if not isinstance(used_request_ids, list) or len(used_request_ids) > MAX_USES or any(
        not isinstance(used_id, str) or not REQUEST_ID_RE.fullmatch(used_id) for used_id in used_request_ids
    ):
        raise ReferenceAuthorizationError("Credential request is invalid or unavailable.")
    if (
        grant.get("revokedAt") is not None
        or type(grant.get("expiresAt")) is not int or grant["expiresAt"] <= now
        or type(grant.get("uses")) is not int or type(grant.get("maxUses")) is not int
        or not 0 <= grant["uses"] <= MAX_USES or not 1 <= grant["maxUses"] <= MAX_USES
        or grant["uses"] >= grant["maxUses"]
        or request_id in used_request_ids
        or request.get("connectorId") != grant.get("connectorId")
        or request.get("capabilityId") != grant.get("capabilityId")
        or request.get("taskId") != grant.get("taskId")
        or origin != grant.get("origin")
        or method not in ALLOWED_METHODS or method not in grant["methods"]
        or not _path_is_allowed(grant.get("pathPrefix", ""), path)
        or header != grant.get("header")
        or prefix != grant.get("prefix")
    ):
        raise ReferenceAuthorizationError("Credential request is invalid or unavailable.")
    try:
        entry, field = _find_entry_and_field(vault, grant.get("entryId"), grant.get("fieldId"))
    except ReferenceAuthorizationError:
        raise
    secret = field.get("value")
    if not isinstance(secret, str) or not secret:
        raise ReferenceAuthorizationError("Credential request is invalid or unavailable.")

    candidate = copy.deepcopy(vault)
    _candidate_grid, candidate_grants = _bridge_state(candidate)
    candidate_grant = next(item for item in candidate_grants if item.get("id") == grant_id)
    candidate_grant["uses"] += 1
    candidate_grant.setdefault("usedRequestIds", []).append(request_id)
    candidate_grant["lastUsedAt"] = now
    receipt = {
        "grantId": grant_id,
        "connectorId": grant["connectorId"],
        "capabilityId": grant["capabilityId"],
        "taskId": grant["taskId"],
        "origin": origin,
        "method": method,
        "requestId": request_id,
        "usedAt": now,
        "status": "authorized",
    }
    try:
        persist_candidate(candidate)
    except Exception:
        raise ReferencePersistenceError("Credential use was not released because its use could not be saved.") from None
    return secret, receipt
