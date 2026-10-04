import base64
import json
import hashlib
import os
import secrets
import shutil
import subprocess
import threading
import time
import unittest
import tempfile
from pathlib import Path

import vault_references as refs
from vault_bridge import MAX_FRAME_BYTES, VaultBridgeServer


SYNTHETIC_VALUE = "SYNTHETIC-ONLY-bridge-token-9f2a"
GRID_ROOT = next((candidate for parent in Path(__file__).resolve().parents for candidate in (Path(os.environ.get("HEXIGRID_ROOT", "__not_configured__")), parent, parent / "Ilands") if (candidate / "lib" / "hexikeys-bridge.mjs").is_file()), None)
GRID_CLIENT_URL = (GRID_ROOT / "lib" / "hexikeys-bridge.mjs").as_uri() if GRID_ROOT else ""
NODE = shutil.which("node")

NODE_CLIENT_SCRIPT = r"""
const { createHexiKeysBridgeClient } = await import(process.env.HEXIKEYS_BRIDGE_MODULE);
const key = Buffer.from(process.env.HEXIKEYS_TEST_KEY, 'base64');
const request = JSON.parse(process.env.HEXIKEYS_TEST_REQUEST || '{}');
const nonces = JSON.parse(process.env.HEXIKEYS_TEST_NONCES || '[]');
let nonceIndex = 0;
const nonceFactory = nonces.length ? () => nonces[nonceIndex++] : undefined;
const client = createHexiKeysBridgeClient({
  pipeId: process.env.HEXIKEYS_TEST_PIPE,
  key: process.env.HEXIKEYS_TEST_KEY_OVERRIDE
    ? Buffer.from(process.env.HEXIKEYS_TEST_KEY_OVERRIDE, 'base64')
    : key,
  timeoutMs: Number(process.env.HEXIKEYS_TEST_CLIENT_TIMEOUT || 3000),
  ...(nonceFactory ? { nonceFactory } : {}),
});
const action = process.env.HEXIKEYS_TEST_ACTION || 'status';
const errorCode = (error) => error?.code || 'error';
let result;
try {
  if (action === 'plugin-broker' || action === 'plugin-child') {
    const moduleUrl = new URL('.', process.env.HEXIKEYS_BRIDGE_MODULE);
    const { createHexiKeysAddon } = await import(new URL('hexikeys-addon.mjs', moduleUrl));
    const { createHexiKeysPluginBindings } = await import(new URL('hexikeys-plugin-bindings.mjs', moduleUrl));
    const { createCapabilityBroker, installPluginPackage, runPluginCapability } = await import(new URL('plugin-security.mjs', moduleUrl));
    const capability = { id: 'api-request', permissions: { files: { readRoots: [], writeRoots: [] }, network: [{ origin: 'https://api.example.invalid', pathPrefix: '/v1/records', methods: ['GET'], secretHeaders: [{ secret: 'api-key', header: 'authorization', prefix: 'Bearer ' }] }] }, limits: { timeoutMs: 3000, requestBytes: 32768, outputBytes: 32768, brokerRequests: 10 } };
    let plugin = { id: 'hexikeys', secrets: [{ id: 'api-key' }], capabilities: [capability] };
    let packageRoot;
    const fs = await import('node:fs/promises');
    const path = await import('node:path');
    if (action === 'plugin-child') {
      packageRoot = await fs.mkdtemp(path.join((await import('node:os')).tmpdir(), 'hexikeys-plugin-child-'));
      plugin = await installPluginPackage({ pluginRoot: packageRoot, trustMode: 'owner-local', manifest: { schemaVersion: 2, id: plugin.id, name: 'Synthetic vault child', version: '1.0.0', entry: 'plugin.mjs', secrets: [{ id: 'api-key', label: 'Synthetic key', required: true }], capabilities: [{ ...capability, label: 'Synthetic request', risk: 'high', inputSchema: { type: 'object', properties: {}, additionalProperties: false }, outputSchema: { type: 'object', properties: {}, additionalProperties: true } }] }, files: [{ path: 'plugin.mjs', content: "export async function run(){return await hexigrid.network.request({url:'https://api.example.invalid/v1/records/42',method:'GET'})}" }] });
    }
    const addon = createHexiKeysAddon({ withPairing: callback => callback({}), connect: async () => {}, disconnect: async () => {}, createClient: () => createHexiKeysBridgeClient({ pipeId: process.env.HEXIKEYS_TEST_PIPE, key }), authorize: async () => {} });
    const records = new Map();
    const bindings = createHexiKeysPluginBindings({ vault: { get: async id => records.get(id), set: async (id,value) => records.set(id,value), remove: async id => records.delete(id) }, consume: addon.consume, authorize: async () => {} });
    const identity = { plugin, capability: plugin.capabilities[0], secretId: 'api-key', actor: 'owner', context: {} };
    await bindings.set({ ...identity, grantId: request.grantId });
    let fetches = 0;
    const executionOptions = { capability: plugin.capabilities[0], workspaceRoot: '.', secretResolver: (secretId, context) => bindings.resolve({ ...identity, secretId, request: context }), fetchImpl: async (_url, options) => {
      fetches++;
      if (options.headers.authorization !== 'Bearer SYNTHETIC-ONLY-bridge-token-9f2a') throw new Error('Synthetic header mismatch');
      return { status: 204, get headers() { throw new Error('Destination content must not be read'); }, text() { throw new Error('Destination content must not be read'); } };
    } };
    const broker = createCapabilityBroker(executionOptions);
    const execute = async () => action === 'plugin-child'
      ? runPluginCapability({ ...executionOptions, plugin, pluginRoot: packageRoot, runnerPath: (await import('node:url')).fileURLToPath(new URL('plugin-runner.mjs', moduleUrl)) })
      : broker.dispatch('network.request', { url: 'https://api.example.invalid/v1/records/42', method: 'GET' });
    let outcome;
    let exhausted = false;
    try {
      outcome = await execute();
      try { await execute(); } catch { exhausted = true; }
    } finally { if (packageRoot) await fs.rm(packageRoot, { recursive: true, force: true }); }
    result = { outcome, fetches, exhausted, protectedBindingOnly: !JSON.stringify([...records]).includes('SYNTHETIC-ONLY') };
  } else if (action === 'consume') {
    result = { value: await client.consume(request) };
  } else if (action === 'consume-repeat') {
    const value = await client.consume(request);
    let duplicate;
    try { await client.consume(request); } catch (error) { duplicate = errorCode(error); }
    result = { value, duplicate };
  } else if (action === 'status-replay') {
    const statuses = [];
    for (let index = 0; index < nonces.length; index += 1) {
      try { statuses.push(await client.status()); } catch (error) { statuses.push({ error: errorCode(error) }); }
    }
    result = { statuses };
  } else if (action === 'locked-consume') {
    const status = await client.status();
    let consumeError;
    try { await client.consume(request); } catch (error) { consumeError = errorCode(error); }
    result = { status, consumeError };
  } else if (action === 'consume-once') {
    result = await client.consume(request);
  } else {
    result = await client.status();
  }
} catch (error) {
  result = { error: errorCode(error) };
} finally {
  await client.close();
}
console.log(JSON.stringify(result));
"""

NODE_RAW_PIPE_SCRIPT = r"""
import net from 'node:net';
const pipeId = process.env.HEXIKEYS_TEST_PIPE;
const pipePath = `\\\\.\\pipe\\${pipeId}`;
const kind = process.env.HEXIKEYS_TEST_ACTION;
const socket = net.createConnection(pipePath);
let done = false;
const finish = (value) => {
  if (done) return;
  done = true;
  socket.destroy();
  console.log(JSON.stringify({ result: value }));
};
socket.once('connect', () => {
  if (kind === 'oversize') {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(Number(process.env.HEXIKEYS_TEST_LENGTH), 0);
    socket.write(header);
  } else {
    const header = Buffer.alloc(4);
    header.writeUInt32BE(64, 0);
    socket.write(Buffer.concat([header, Buffer.from('{')]))
  }
});
socket.once('close', () => finish('closed'));
socket.once('error', () => finish('closed'));
setTimeout(() => finish('client-timeout'), 2500).unref();
"""


def fake_vault(max_uses=2, task_id="bridge-test-task-1"):
    vault = {
        "entries": [{
            "id": "synthetic-bridge-entry",
            "title": "Bridge fixture",
            "fields": [{"label": "Synthetic token", "value": SYNTHETIC_VALUE, "secret": True}],
        }]
    }
    now = int(time.time())
    candidate, grant_id = refs.create_reference_grant(
        vault,
        entry_id="synthetic-bridge-entry",
        field_index=0,
        connector_id="hexikeys",
        capability_id="api-request",
        task_id=task_id,
        origin="https://api.example.invalid",
        path_prefix="/v1/records",
        methods=["GET"],
        header="authorization",
        prefix="Bearer ",
        expires_at=now + 600,
        max_uses=max_uses,
        now=now,
    )
    request = {
        "grantId": grant_id,
        "requestId": "b" * 32,
        "connectorId": "hexikeys",
        "capabilityId": "api-request",
        "taskId": task_id,
        "origin": "https://api.example.invalid",
        "path": "/v1/records/42",
        "method": "GET",
        "header": "authorization",
        "prefix": "Bearer ",
    }
    return candidate, request


@unittest.skipUnless(os.name == "nt", "real Windows named-pipe integration")
@unittest.skipUnless(GRID_ROOT, "Optional HexiGrid checkout is not configured; set HEXIGRID_ROOT to run cross-project tests")
@unittest.skipUnless(NODE, "Node.js is required for the cross-language pipe test")
class VaultBridgeIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.key = bytes(range(32))
        self.pipe_id = "hexikeys-" + secrets.token_hex(16)
        self.state = {"available": True, "unlocked": True, "vault": None}
        self.persisted = 0
        self.status_calls = 0
        self.authorizations = []
        self.events = []

    def make_server(self, **overrides):
        if self.state["vault"] is None:
            self.state["vault"], self.request = fake_vault()

        def get_status():
            self.status_calls += 1
            return {"available": self.state["available"], "unlocked": self.state["unlocked"]}

        def get_vault():
            if not self.state["available"] or not self.state["unlocked"]:
                return None
            return self.state["vault"]

        def persist(candidate):
            self.events.append("persist")
            self.persisted += 1
            self.state["vault"] = candidate

        def authorize_release(request, receipt):
            self.events.append("authorize")
            self.authorizations.append((request["requestId"], receipt.get("requestId")))
            return (
                self.state["available"]
                and self.state["unlocked"]
                and receipt.get("taskId") == request.get("taskId")
            )

        kwargs = {
            "get_status": get_status,
            "get_vault": get_vault,
            "persist_candidate": persist,
            "authorize_release": authorize_release,
        }
        kwargs.update(overrides)
        server = VaultBridgeServer(self.pipe_id, self.key, **kwargs).start()
        self.addCleanup(server.close)
        return server

    def env(self, action="status", *, key=None, request=None, nonces=None, extra=None):
        env = os.environ.copy()
        env.update({
            "HEXIKEYS_BRIDGE_MODULE": GRID_CLIENT_URL,
            "HEXIKEYS_TEST_PIPE": self.pipe_id,
            "HEXIKEYS_TEST_KEY": base64.b64encode(self.key).decode("ascii"),
            "HEXIKEYS_TEST_ACTION": action,
            "HEXIKEYS_TEST_REQUEST": json.dumps(request if request is not None else getattr(self, "request", {})),
            "HEXIKEYS_TEST_NONCES": json.dumps(nonces or []),
        })
        if key is not None:
            env["HEXIKEYS_TEST_KEY_OVERRIDE"] = base64.b64encode(key).decode("ascii")
        if extra:
            env.update(extra)
        return env

    def node(self, action="status", **kwargs):
        completed = subprocess.run(
            [NODE, "--input-type=module", "-e", NODE_CLIENT_SCRIPT],
            env=self.env(action, **kwargs),
            capture_output=True,
            text=True,
            timeout=8,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, "Node bridge client did not exit cleanly.")
        lines = [line for line in completed.stdout.splitlines() if line.strip()]
        self.assertEqual(len(lines), 1, "Node bridge client returned unexpected output.")
        return json.loads(lines[0])

    def raw_node(self, action, **extra):
        values = {
            "HEXIKEYS_BRIDGE_MODULE": GRID_CLIENT_URL,
            "HEXIKEYS_TEST_PIPE": self.pipe_id,
            "HEXIKEYS_TEST_ACTION": action,
            **{key: str(value) for key, value in extra.items()},
        }
        env = os.environ.copy()
        env.update(values)
        completed = subprocess.run(
            [NODE, "--input-type=module", "-e", NODE_RAW_PIPE_SCRIPT],
            env=env,
            capture_output=True,
            text=True,
            timeout=5,
            check=False,
        )
        self.assertEqual(completed.returncode, 0, "Raw Node pipe client did not exit cleanly.")
        return json.loads(completed.stdout.strip())

    def test_plugin_binding_addon_real_pipe_and_broker_keep_value_out_of_results(self):
        digest = hashlib.sha256(json.dumps(["hexikeys", "api-request", "api-key", "owner"], separators=(",", ":")).encode()).hexdigest()
        self.state["vault"], self.request = fake_vault(max_uses=1, task_id="plugin-" + digest[:48])
        self.make_server()
        result = self.node("plugin-broker")
        self.assertEqual(result, {"outcome": {"status": 204, "ok": True, "headers": {}, "body": ""}, "fetches": 1, "exhausted": True, "protectedBindingOnly": True})
        self.assertEqual(self.persisted, 1)
        self.assertEqual(self.events, ["persist", "authorize", "authorize"])

    def test_installed_child_uses_real_pipe_and_encrypted_persistence(self):
        from vault_store import save_vault, load_vault
        digest = hashlib.sha256(json.dumps(["hexikeys", "api-request", "api-key", "owner"], separators=(",", ":")).encode()).hexdigest()
        self.state["vault"], self.request = fake_vault(max_uses=1, task_id="plugin-" + digest[:48])
        with tempfile.TemporaryDirectory(prefix="hexikeys-child-vault-") as directory:
            vault_file = Path(directory) / "synthetic-vault.dat"
            password = "synthetic-only-encrypted-fixture-password"
            save_vault(vault_file, self.state["vault"], password)
            def persist(candidate):
                save_vault(vault_file, candidate, password)
                self.state["vault"] = candidate
                self.persisted += 1
            self.make_server(persist_candidate=persist)
            result = self.node("plugin-child")
            self.assertNotIn("error", result)
            self.assertEqual(result["outcome"]["result"], {"status": 204, "ok": True, "headers": {}, "body": ""})
            self.assertEqual(result["fetches"], 1)
            self.assertTrue(result["exhausted"])
            self.assertTrue(result["protectedBindingOnly"])
            self.assertNotIn(SYNTHETIC_VALUE, json.dumps(result))
            saved, _version = load_vault(vault_file, password)
            self.assertEqual(refs.public_reference_grants(saved)[0]["uses"], 1)
            self.assertNotIn(SYNTHETIC_VALUE.encode(), vault_file.read_bytes())
            self.assertEqual(self.persisted, 1)

    def test_status_and_consume_use_authenticated_durable_local_flow(self):
        self.make_server()
        result = self.node("consume-repeat")

        self.assertEqual(result["value"]["value"], SYNTHETIC_VALUE)
        self.assertEqual(result["duplicate"], "denied")
        self.assertEqual(self.persisted, 1)
        self.assertEqual(self.events, ["persist", "authorize", "authorize"])
        self.assertEqual(self.authorizations, [
            (self.request["requestId"], self.request["requestId"]),
            (self.request["requestId"], self.request["requestId"]),
        ])
        self.assertEqual(self.state["vault"]["integrations"]["hexigrid"]["grants"][0]["uses"], 1)

    def test_status_is_metadata_only_and_page_is_bounded(self):
        self.make_server()
        status = self.node("status")
        self.assertTrue(status["unlocked"])
        self.assertEqual(status["total"], 1)
        self.assertIsNone(status["nextOffset"])
        self.assertNotIn("value", status["grants"][0])
        self.assertNotIn(SYNTHETIC_VALUE, json.dumps(status))

    def test_generation_change_between_post_persist_checks_withholds_value(self):
        release_checks = {"count": 0}

        def authorize_release(_request, _receipt):
            release_checks["count"] += 1
            if release_checks["count"] == 1:
                self.state["unlocked"] = False
                return True
            return False

        self.make_server(authorize_release=authorize_release)
        result = self.node("consume-once")
        self.assertEqual(result["error"], "transport")
        self.assertEqual(release_checks["count"], 2)
        self.assertEqual(self.persisted, 1)
        self.assertNotIn(SYNTHETIC_VALUE, json.dumps(result))
        self.assertEqual(self.state["vault"]["integrations"]["hexigrid"]["grants"][0]["uses"], 1)

    def test_locked_or_missing_callbacks_fail_closed(self):
        server = self.make_server()
        self.state["unlocked"] = False
        locked = self.node("locked-consume")
        self.assertFalse(locked["status"]["unlocked"])
        self.assertEqual(locked["consumeError"], "locked")
        self.assertEqual(self.persisted, 0)

        server.close()
        missing = VaultBridgeServer("hexikeys-" + secrets.token_hex(16), self.key).start()
        self.addCleanup(missing.close)
        self.pipe_id = missing.pipe_id
        unavailable = self.node("status")
        self.assertFalse(unavailable["unlocked"])
        self.assertEqual(unavailable["grants"], [])

    def test_wrong_key_is_rejected_before_callbacks(self):
        self.make_server()
        result = self.node("status", key=b"x" * 32)
        self.assertEqual(result["error"], "transport")
        self.assertEqual(self.status_calls, 0)
        self.assertEqual(self.persisted, 0)

    def test_persistence_error_is_redacted_and_does_not_release_value(self):
        def failed_persist(_candidate):
            raise OSError(SYNTHETIC_VALUE)

        self.make_server(persist_candidate=failed_persist)
        result = self.node("consume-once")
        self.assertEqual(result["error"], "storage")
        self.assertNotIn(SYNTHETIC_VALUE, json.dumps(result))
        self.assertEqual(self.authorizations, [])
        self.assertEqual(self.state["vault"]["integrations"]["hexigrid"]["grants"][0]["uses"], 0)

    def test_nonce_replay_is_denied_and_cache_stays_bounded(self):
        server = self.make_server()
        server._replay_limit = 2
        nonces = ["1" * 64, "1" * 64, "2" * 64, "3" * 64]
        result = self.node("status-replay", nonces=nonces)
        self.assertTrue(result["statuses"][0]["unlocked"])
        self.assertEqual(result["statuses"][1]["error"], "denied")
        self.assertTrue(result["statuses"][2]["unlocked"])
        self.assertEqual(result["statuses"][3]["error"], "unavailable")
        self.assertEqual(len(server._seen_nonces), 2)

    def test_oversized_and_partial_frames_close_within_deadline(self):
        self.make_server(request_timeout=0.2)
        self.assertEqual(self.raw_node("oversize", HEXIKEYS_TEST_LENGTH=MAX_FRAME_BYTES + 1)["result"], "closed")
        started = time.monotonic()
        self.assertEqual(self.raw_node("partial")["result"], "closed")
        self.assertLess(time.monotonic() - started, 1.5)

    def test_concurrency_limit_rejects_extra_clients_without_queue_growth(self):
        entered = threading.Event()
        release = threading.Event()
        concurrent = {"active": 0, "max": 0}
        base_get_vault = lambda: self.state["vault"]

        def slow_get_vault():
            concurrent["active"] += 1
            concurrent["max"] = max(concurrent["max"], concurrent["active"])
            entered.set()
            release.wait(3)
            concurrent["active"] -= 1
            return base_get_vault()

        self.make_server(get_vault=slow_get_vault, max_workers=1)
        first = subprocess.Popen(
            [NODE, "--input-type=module", "-e", NODE_CLIENT_SCRIPT],
            env=self.env("consume-once"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertTrue(entered.wait(2), "first consume did not reach the held fixture callback")
            extra = self.node("status")
            self.assertEqual(extra["error"], "transport")
        finally:
            release.set()
        stdout, _stderr = first.communicate(timeout=6)
        self.assertEqual(first.returncode, 0)
        self.assertEqual(json.loads(stdout.strip())["value"], SYNTHETIC_VALUE)
        self.assertEqual(concurrent["max"], 1)

    def test_stop_aborts_pipe_and_drains_before_any_late_consume(self):
        entered = threading.Event()
        release = threading.Event()

        def held_get_vault():
            entered.set()
            release.wait(3)
            return self.state["vault"]

        server = self.make_server(get_vault=held_get_vault)
        first = subprocess.Popen(
            [NODE, "--input-type=module", "-e", NODE_CLIENT_SCRIPT],
            env=self.env("consume-once"),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertTrue(entered.wait(2), "consume did not reach the held fixture callback")
            server.stop()
            self.assertFalse(server.wait_closed(0.05))
        finally:
            release.set()
        self.assertTrue(server.wait_closed(4))
        stdout, _stderr = first.communicate(timeout=5)
        self.assertEqual(first.returncode, 0)
        result = json.loads(stdout.strip())
        self.assertEqual(result.get("error"), "transport")
        self.assertEqual(self.persisted, 0)
        self.assertEqual(self.authorizations, [])


if __name__ == "__main__":
    unittest.main()
