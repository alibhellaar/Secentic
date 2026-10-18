# Python SDK

`secentic_sdk` (in `secentic_sdk/__init__.py`) is what an AI agent uses to talk to Secentic. It
holds the agent's key pair and signs every request according to the
[signing protocol](modules/m2-agent-identity.md#request-signing-protocol). It depends only on
`httpx` and `cryptography`.

For now the SDK lives in this repository rather than on PyPI. To import it from your own agent,
put the project root on `PYTHONPATH`, for example `PYTHONPATH=/path/to/Secentic python my_agent.py`.
(Modules started with `python -m` from the project root, like the demo agent, find it without that.)

## Quick example

```python
from secentic_sdk import AgentKey, SecenticClient

key = AgentKey.generate()
client = SecenticClient("http://localhost:8000", key)
client.register("billing-bot", environment="prod", owner="ali")
# ... an administrator approves the agent ...
print(client.whoami()["status"])      # "active"
```

A complete, runnable agent is in `examples/demo_agent.py` (walkthrough in the
[user guide](user-guide.md#walkthrough-your-first-agent)).

## `AgentKey`

An Ed25519 key pair. The private key stays inside the object; only the public key and key ID are
exposed.

| Member | Description |
|---|---|
| `AgentKey.generate()` | Create a new random key pair |
| `AgentKey.from_pem(pem: bytes)` | Load a private key saved with `to_pem()`; raises `TypeError` for non-Ed25519 keys |
| `key.to_pem() -> bytes` | The private key as unencrypted PKCS#8 PEM. Store it like a password (e.g. a file readable only by the agent, or a secrets manager) |
| `key.public_key: str` | Base64 of the raw 32-byte public key, the form Secentic expects |
| `key.key_id: str` | SHA-256 hex of the public key, the agent's key ID |
| `key.sign(message: bytes) -> str` | Base64 Ed25519 signature |

## `SecenticClient`

```python
SecenticClient(base_url: str, key: AgentKey, http: httpx.Client | None = None)
```

`http` lets you pass your own `httpx.Client` (timeouts, proxies, or a FastAPI `TestClient` in
tests). Otherwise one is created for `base_url`. `client.key` is the key used for signing and is
replaced by a successful rotation.

| Method | Description |
|---|---|
| `register(name, environment="development", owner=None) -> dict` | Register the agent with its public key (signed, `source=sdk`). Returns the Agent record. Raises `httpx.HTTPStatusError` on failure, e.g. 409 if the name is taken by another key |
| `whoami() -> dict` | The agent's own record. Raises on 401/403 (e.g. 403 while `pending_review`) |
| `ensure_allowed(tool, action, resource) -> dict` | Ask the gateway ([M5](modules/m5-runtime-gateway.md)) and raise `ActionNotAllowed` unless the decision is `allow`. Call it right before acting |
| `authorize(tool, action, resource) -> dict` | Ask the gateway and return the recorded decision, whatever it is. Raises `httpx.HTTPStatusError` if the gateway cannot decide (503): treat that as a denial |
| `tools() -> list[dict]` | The tools this agent may use ([M4](modules/m4-agent-tool-registry.md)) |
| `delegations() -> list[dict]` | The authority delegated to this agent that is in force now ([M3](modules/m3-delegated-authority.md)) |
| `rotate_key(new_key=None) -> AgentKey` | Switch to a new key, see below |
| `request(method, path, json_body=None, params=None, proof_key=None) -> httpx.Response` | Send any signed request and return the raw response without raising. `proof_key` adds an `X-Secentic-Proof` signature made with a second key |

## Asking before acting

The pattern every agent action should follow:

```python
from secentic_sdk import ActionNotAllowed

try:
    client.ensure_allowed("crm", "crm:update", "crm:accounts/42")
except ActionNotAllowed as refused:
    # refused.decision["decision"] is "deny" or "require_approval";
    # refused.decision["reasons"] says why. Do not perform the action.
    ...
else:
    update_the_record()
```

Anything other than an explicit `allow`, including the gateway being unreachable or answering 503,
must mean "do not act". `ensure_allowed` raises in all of those cases.

## Rotating keys safely

After a rotation the old key is dead, so the new key must never be lost. Save it **before** asking
the server to switch:

```python
from pathlib import Path
from secentic_sdk import AgentKey, RotationInterrupted

new_key = AgentKey.generate()
Path("agent.pem.new").write_bytes(new_key.to_pem())
try:
    client.rotate_key(new_key)                    # on success client.key is new_key
    Path("agent.pem.new").replace("agent.pem")
except RotationInterrupted as exc:
    # No definite answer (connection lost, or a 5xx): the server may or may not have
    # switched. Keep both keys; whichever one /identity/whoami accepts is current.
    ...
```

| Outcome | What `rotate_key` does |
|---|---|
| 200 | Switches `client.key` to the new key and returns it |
| 401 `Key has been rotated` | Raises `RotationInterrupted`: the current key was already rotated, typically by an earlier attempt whose answer was lost, so `exc.new_key` may be the active key |
| Other 4xx (e.g. 409) | Raises `httpx.HTTPStatusError`; the old key is still active |
| No response, or 5xx | Raises `RotationInterrupted`; `exc.new_key` is the key that may now be active |

If `new_key` is omitted, the SDK generates one; on `RotationInterrupted` it is available as
`exc.new_key`, so it is still not lost as long as you handle the exception.

## Lower-level functions

| Function | Description |
|---|---|
| `sign_request(key, method, path, query="", body=b"", timestamp=None, nonce=None)` | Returns `(headers, canonical_bytes)`: the four signature headers and the bytes that were signed. Defaults to the current time and a random nonce |
| `canonical_request(method, path, query, key_id, timestamp, nonce, body)` | Builds the canonical request bytes |

These are useful in tests, or to sign requests sent with another HTTP library. Pass `path` in the form
the server routes it: percent-decoded, without a trailing `/` (see the
[canonical request](modules/m2-agent-identity.md#canonical-request)); `SecenticClient.request` does
this for you.

## Writing an SDK in another language

Implement the [signing protocol](modules/m2-agent-identity.md#request-signing-protocol) and check
it against the [test vector](modules/m2-agent-identity.md#test-vector). Points that commonly go
wrong:

- Sign the exact body bytes you send; do not re-serialise the JSON after signing.
- Use the path and query string exactly as they appear on the wire.
- Hex digests are lowercase; base64 uses the standard alphabet with padding.
- Generate a fresh nonce for every request, including retries.
