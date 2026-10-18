"""Secentic Python SDK — gives an AI agent an Ed25519 identity and signs its requests.

    key = AgentKey.generate()                    # persist key.to_pem() somewhere safe
    client = SecenticClient("http://localhost:8000", key)
    client.register("billing-bot", environment="prod", owner="ali")
    # ...an administrator approves the agent...
    client.whoami()
    client.ensure_allowed("crm", "read", "crm:accounts/42")   # ask the gateway before acting
    new_key = AgentKey.generate()                # persist new_key.to_pem() first, then:
    client.rotate_key(new_key)

Each request is signed over the canonical string below (it must match app/crypto.py):

    SECENTIC-V1\\n<METHOD>\\n<path>\\n<query>\\n<key id>\\n<unix timestamp>\\n<nonce>\\n<sha256 hex of body>
"""
import base64
import hashlib
import json
import secrets
import time

import httpx
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SIGNATURE_VERSION = "SECENTIC-V1"


class AgentKey:
    """An agent's Ed25519 key pair. The private key never leaves the agent."""

    def __init__(self, private_key: Ed25519PrivateKey):
        self._private_key = private_key
        raw = private_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        self.public_key = base64.b64encode(raw).decode()
        self.key_id = hashlib.sha256(raw).hexdigest()

    @classmethod
    def generate(cls) -> "AgentKey":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_pem(cls, pem: bytes) -> "AgentKey":
        private_key = serialization.load_pem_private_key(pem, password=None)
        if not isinstance(private_key, Ed25519PrivateKey):
            raise TypeError("Secentic agent keys must be Ed25519")
        return cls(private_key)

    def to_pem(self) -> bytes:
        return self._private_key.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()
        )

    def sign(self, message: bytes) -> str:
        return base64.b64encode(self._private_key.sign(message)).decode()


def canonical_request(method: str, path: str, query: str, key_id: str, timestamp: str, nonce: str, body: bytes) -> bytes:
    return "\n".join([
        SIGNATURE_VERSION,
        method.upper(),
        path,
        query,
        key_id,
        timestamp,
        nonce,
        hashlib.sha256(body).hexdigest(),
    ]).encode()


def sign_request(
    key: AgentKey,
    method: str,
    path: str,
    query: str = "",
    body: bytes = b"",
    timestamp: int | None = None,
    nonce: str | None = None,
) -> tuple[dict[str, str], bytes]:
    """Returns the signature headers and the canonical message that was signed."""
    timestamp = str(int(time.time()) if timestamp is None else timestamp)
    nonce = nonce or secrets.token_urlsafe(24)
    message = canonical_request(method, path, query, key.key_id, timestamp, nonce, body)
    headers = {
        "X-Secentic-Key-Id": key.key_id,
        "X-Secentic-Timestamp": timestamp,
        "X-Secentic-Nonce": nonce,
        "X-Secentic-Signature": key.sign(message),
    }
    return headers, message


class RotationInterrupted(Exception):
    """A key rotation got no definite answer, so it may or may not have been applied."""

    def __init__(self, new_key: AgentKey):
        super().__init__("Key rotation outcome unknown; keep both keys until whoami shows which one is active")
        self.new_key = new_key


class ActionNotAllowed(Exception):
    """The gateway did not allow the action (deny or require_approval). `decision` has the reasons."""

    def __init__(self, decision: dict):
        super().__init__(f"{decision['decision']}: " + "; ".join(decision["reasons"]))
        self.decision = decision


def _detail(response: httpx.Response) -> str | None:
    try:
        return response.json().get("detail")
    except ValueError:
        return None


class SecenticClient:
    def __init__(self, base_url: str, key: AgentKey, http: httpx.Client | None = None):
        self.key = key
        self.http = http or httpx.Client(base_url=base_url)

    def request(
        self,
        method: str,
        path: str,
        json_body: dict | None = None,
        params: dict | None = None,
        proof_key: AgentKey | None = None,
    ) -> httpx.Response:
        """Send a signed request. `proof_key` additionally signs it with a second key."""
        body = b"" if json_body is None else json.dumps(json_body).encode()
        request = self.http.build_request(
            method,
            path,
            params=params,
            content=body or None,
            headers={"Content-Type": "application/json"} if body else None,
        )
        # Sign the path as the server routes it (percent-decoded, a trailing slash ignored) and the
        # query exactly as it goes over the wire.
        path = request.url.path
        if len(path) > 1 and path.endswith("/"):
            path = path[:-1]
        headers, message = sign_request(self.key, method, path, request.url.query.decode(), body)
        if proof_key is not None:
            headers["X-Secentic-Proof"] = proof_key.sign(message)
        request.headers.update(headers)
        return self.http.send(request)

    def register(self, name: str, environment: str = "development", owner: str | None = None) -> dict:
        body = {"name": name, "environment": environment, "owner": owner, "public_key": self.key.public_key}
        response = self.request("POST", "/agents/register", body, params={"source": "sdk"})
        response.raise_for_status()
        return response.json()

    def whoami(self) -> dict:
        response = self.request("GET", "/identity/whoami")
        response.raise_for_status()
        return response.json()

    def tools(self) -> list[dict]:
        """The tools this agent may use (M4)."""
        response = self.request("GET", "/identity/tools")
        response.raise_for_status()
        return response.json()

    def authorize(self, tool: str, action: str, resource: str) -> dict:
        """Ask the gateway (M5) whether this agent may use `tool` to perform `action` on `resource`.
        Returns the recorded decision. Raises httpx.HTTPStatusError if the gateway cannot decide
        (503): treat that as a denial."""
        response = self.request("POST", "/gateway/authorize", {"tool": tool, "action": action, "resource": resource})
        response.raise_for_status()
        return response.json()

    def ensure_allowed(self, tool: str, action: str, resource: str) -> dict:
        """Like authorize(), but raises ActionNotAllowed unless the decision is allow. Call it right
        before performing the action, and perform the action only if it returns."""
        decision = self.authorize(tool, action, resource)
        if decision["decision"] != "allow":
            raise ActionNotAllowed(decision)
        return decision

    def delegations(self) -> list[dict]:
        """The authority delegated to this agent that is in force now (M3)."""
        response = self.request("GET", "/identity/delegations")
        response.raise_for_status()
        return response.json()

    def rotate_key(self, new_key: AgentKey | None = None) -> AgentKey:
        """Enrol a new key and switch to it; the old key stops working.

        Safest is to generate and persist `new_key` yourself before calling. If no definite
        answer arrives (connection lost, 5xx), or the server says the current key was already
        rotated (a retry of a rotation whose answer was lost), RotationInterrupted carries the new
        key: the rotation may have been applied, so keep both keys until whoami shows which one works.
        """
        new_key = new_key or AgentKey.generate()
        try:
            response = self.request("POST", "/identity/rotate", {"public_key": new_key.public_key}, proof_key=new_key)
        except httpx.TransportError as exc:
            raise RotationInterrupted(new_key) from exc
        if response.status_code >= 500 or _detail(response) == "Key has been rotated":
            raise RotationInterrupted(new_key)
        response.raise_for_status()
        self.key = new_key
        return new_key

