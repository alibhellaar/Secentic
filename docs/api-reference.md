# API reference

Every HTTP endpoint Secentic exposes. The server also serves a live, interactive version of this
reference at `/docs` (Swagger UI) and the raw schema at `/openapi.json`.

The OpenAPI schema describes the API exactly: every validation rule below is expressed as a
pattern or limit, every error response is declared, and signed requests appear as four API-key
security schemes (`AgentSignatureKeyId`, `AgentSignatureTimestamp`, `AgentSignatureNonce`,
`AgentSignatureSignature`) that must all be present together. Two rules are checked by the server
only, because JSON Schema cannot compare values with each other or with the clock: the delegation
time window, and unique rule IDs within a policy. `tests/test_openapi.py` keeps the schema and the
validators in step.

## Conventions

**Base URL**: `http://localhost:8000` in development. Request and response bodies are JSON.

**Authentication**: each endpoint is marked with one of:

| Marker | Meaning |
|---|---|
| *public* | No authentication |
| *admin* | Header `Authorization: Bearer <SECENTIC_ADMIN_TOKEN>` |
| *agent (signed)* | Ed25519 signature headers, see [request signing](modules/m2-agent-identity.md#request-signing-protocol) |

Errors common to all *admin* endpoints:

| Status | `detail` | When |
|---|---|---|
| 401 | `Invalid admin token` | Header missing or token wrong |
| 503 | `Admin access is disabled: set SECENTIC_ADMIN_TOKEN to a random value of at least 16 characters` | Server has no usable token |

Any endpoint answers 503 `The database could not complete the request; try again later (agents must
treat this as a denial)` when the database is unreachable or fails, authentication included.

Errors common to all *agent (signed)* endpoints:

| Status | `detail` | When |
|---|---|---|
| 401 | `Missing signature headers (...)` | One of the four signature headers is absent |
| 401 | `Key ID must be 64 lowercase hexadecimal characters` | Malformed key ID header |
| 401 | `Signature must be 88 base64 characters (an Ed25519 signature)` | Malformed signature header |
| 401 | `Timestamp must be integer Unix seconds` | Malformed timestamp |
| 401 | `Request timestamp is outside the accepted window` | More than 300 s from server time |
| 401 | `Nonce must be 16-128 URL-safe characters` | Malformed nonce |
| 401 | `Invalid signature` | No key with that key ID, or the signature does not match the request (the same answer for both, so nothing about a key is revealed to someone who cannot sign) |
| 401 | `Key has been rotated` / `Key has been revoked` | Correctly signed, but with a key that is no longer active |
| 401 | `Nonce has already been used (replayed request)` | Replay |
| 403 | `Agent is pending_review` / `Agent is inactive` / `Agent is disabled` | Valid identity, but the agent is not active |

**Error format**: errors are `{"detail": "<message>"}`. Invalid input (422) uses FastAPI's
format, a list of problems: `{"detail": [{"loc": ["body", "name"], "msg": "...", ...}]}`. The
offending value is echoed back as `input` only when it is a single number, boolean or piece of valid
text: never an object or list, nor anything a JSON response cannot carry (raw bytes of a body that is
not UTF-8, `NaN`, `Infinity`, or a lone `\ud800` surrogate).

**Environments** are plain ASCII names: 1–64 letters, digits, `.`, `_` or `-`, starting with a
letter or digit (`prod`, `eu-west-1`). Policy rules select agents by environment, so a look-alike
such as `prоd` with a Cyrillic `о` is refused (422).

**Text fields**: `name`, `owner` and `delegator` are one line of at most 200
characters; `task` and revocation `reason` at most 500. They are stored exactly as sent: they may
not be blank, start or end with any kind of space (including a non-breaking one), or contain control
characters or invisible ones (422). Refused are every Unicode control, format, surrogate and
private-use character, line and paragraph separators, Unicode's default-ignorable characters
(zero-width characters, bidirectional controls, variation selectors, tag characters, Hangul fillers,
...) and blank-looking letters such as the Braille blank. Accented letters, other scripts and emoji
are fine. Lone surrogates (`\ud800`, valid as a JSON escape but not a character) are refused too;
the published `pattern` leaves them out because many JSON Schema engines cannot express them.

**IDs in paths**: agent and delegation IDs are lowercase UUIDs, key IDs 64 lowercase hex characters.
A path with anything else matches no endpoint and gets 404 `Not Found`; a well-formed ID that does
not exist gets 404 with a specific message such as `Agent not found`.

**Wrong method**: 405 `Method Not Allowed`, with an `Allow` header listing the methods the path
supports.

**Trailing slashes** are ignored: `/agents/` is `/agents`, `/tools/crm/` is `/tools/crm`, without a
redirect. Signed requests are checked against the path without the slash, so sign that one.

**Normalisation**: resources and actions are stored and compared in one canonical spelling. A
resource becomes its system name, one `:`, then a `/`-separated path (`crm:accounts:42` and
`crm/accounts/42` become `crm:accounts/42`; case is kept); actions, action patterns and tool
capabilities become lower case. Responses, including the decision log, show the normalised form.
See [M3](modules/m3-delegated-authority.md#resources-and-actions).

**Tool names in paths** (`tool_name`) are 1–64 lowercase letters, digits, `.`, `_` or `-`; policy
version numbers are positive integers. Anything else matches no endpoint (404).

**Unreadable body**: 400 `There was an error parsing the body`, for example when it is not UTF-8.

**Request size**: bodies larger than 64 KiB are refused with 413
`Request body too large (limit 65536 bytes)`, whether or not they declare a `Content-Length`. The
one exception is `PUT /policy` (a whole policy, up to 200 rules): up to 1 MiB
(`Request body too large (limit 1048576 bytes)` above that).

**Timestamps** are RFC 3339. Responses always give them in UTC with a `Z` suffix. Timestamps you
send (delegation windows, `at`) must be RFC 3339 strings with a timezone: the date, `T`, hours,
minutes and seconds, an optional fraction, then `Z` or an offset, e.g. `2026-10-13T09:00:00Z` or
`2026-10-13T14:00:00.5+05:00`. Anything else is refused (422
`must be an RFC 3339 timestamp with a timezone, ...`): times without a timezone, numbers and number
strings (which would otherwise be read as Unix times), and looser forms such as
`2026-10-13 09:00:00Z` or `2026-10-13T09:00Z`. The published schema gives the same pattern.

## Objects

### Agent

Returned by the inventory endpoints.

```json
{
  "id": "3983a5bd-c10c-4728-a4d4-99f08b977d6d",
  "name": "billing-bot",
  "owner": "ali",
  "environment": "prod",
  "status": "active",
  "registration_source": "sdk",
  "active_key_id": "79bf39c32cb57ae7341dcd639d4a8af20e52c83ea3318644512b449bd3f27d7a",
  "first_seen": "2026-10-06T02:52:35.963259Z",
  "last_seen": "2026-10-06T02:52:36.049286Z"
}
```

| Field | Meaning |
|---|---|
| `id` | UUID assigned by Secentic |
| `name`, `environment` | Together they identify the agent, compared ignoring case and Unicode spelling differences (NFKC with case folding; see [M1](modules/m1-agent-inventory.md#deduplication)) |
| `owner` | Person responsible. While `pending_review` it is only the agent's claim; afterwards an administrator confirmed it. May be `null` |
| `status` | `pending_review`, `active`, `inactive` or `disabled`; only `active` agents can authenticate |
| `registration_source` | `api` or `sdk` (self-registered), or `manual` (onboarded by an administrator) |
| `active_key_id` | Key ID of the agent's active key, or `null` if it has no cryptographic identity |
| `first_seen` | When the record was created |
| `last_seen` | Last verified sign of life: creation, a signed re-registration, or an authenticated request (refreshed at most once a minute) |

### AgentKey

```json
{
  "key_id": "79bf39c32cb57ae7341dcd639d4a8af20e52c83ea3318644512b449bd3f27d7a",
  "agent_id": "3983a5bd-c10c-4728-a4d4-99f08b977d6d",
  "algorithm": "ed25519",
  "public_key": "PBnoU6xC68f16zo9OITnyLT1Yne3s2o91oq/znA1TVQ=",
  "status": "active",
  "created_at": "2026-10-06T02:52:35.972807Z",
  "rotated_at": null,
  "revoked_at": null,
  "revocation_reason": null
}
```

| Field | Meaning |
|---|---|
| `key_id` | SHA-256 (hex) of the raw 32-byte public key |
| `public_key` | Base64 of the raw 32-byte Ed25519 public key |
| `status` | `active`, `rotated` (replaced by the agent) or `revoked` (withdrawn by an administrator) |
| `rotated_at`, `revoked_at`, `revocation_reason` | Set when the key leaves the `active` state |

### Delegation

```json
{
  "id": "149258e9-66fc-46cd-8dce-c01d7e950cdc",
  "agent_id": "b0ebe929-023d-4f79-9916-b8fca3d748be",
  "delegator": "ali",
  "task": "Prepare the monthly sales report",
  "actions": ["read"],
  "resources": ["crm:accounts/*", "crm:reports/2026-09"],
  "starts_at": "2026-10-06T05:17:58.000979Z",
  "expires_at": "2026-10-13T05:17:57Z",
  "state": "active",
  "created_at": "2026-10-06T05:17:58.004108Z",
  "revoked_at": null,
  "revocation_reason": null
}
```

| Field | Meaning |
|---|---|
| `delegator` | The human whose authority is delegated |
| `task` | What the authority is for |
| `actions` | Exact action names the agent may perform |
| `resources` | Resource identifiers, or prefix patterns ending in `/*` or `:*` ([rules](modules/m3-delegated-authority.md#resources-and-actions)) |
| `starts_at`, `expires_at` | The window in which the delegation is in force |
| `state` | `scheduled` (not started), `active`, `expired` or `revoked`, at the time of the response |
| `revoked_at`, `revocation_reason` | Set when an administrator revokes it |

### AuthorityCheck

```json
{
  "allowed": false,
  "reason": "'read' is delegated only on crm:accounts/*, crm:reports/2026-09, not on 'crm:invoices/7'",
  "delegation_id": null,
  "at": "2026-10-06T05:17:58.037625Z"
}
```

`delegation_id` names the delegation that allows the request, when `allowed` is true. `at` is the
moment the check was made for.

### Tool

```json
{
  "name": "crm",
  "kind": "tool",
  "provider": "internal",
  "endpoint": "https://crm.internal.example/api",
  "version": "2.1.0",
  "capabilities": ["read", "crm:update"],
  "resources": ["crm:*"],
  "description": "Customer records",
  "trust_state": "trusted",
  "trust_reason": "Reviewed by the security team",
  "definition_hash": "46fbb30cf97c2a95b17ea0255f74e3b676c04a9c5763427312a9616451d06d92",
  "trust_changed_at": "2026-10-06T06:47:18.480558Z",
  "created_at": "2026-10-06T06:47:18.462819Z",
  "updated_at": "2026-10-06T06:47:18.462819Z"
}
```

| Field | Meaning |
|---|---|
| `name` | Unique ID (see [M4](modules/m4-agent-tool-registry.md#tools)) |
| `kind` | `tool` or `mcp_server` |
| `provider`, `endpoint`, `version` | Where it comes from and which version was reviewed |
| `capabilities` | Action names the tool performs |
| `resources` | What the tool works on: resource identifiers or prefix patterns, as in [delegations](modules/m3-delegated-authority.md#resources-and-actions). The gateway refuses any other resource for this tool |
| `trust_state` | `trusted`, `unknown`, `suspicious` or `blocked` |
| `trust_reason`, `trust_changed_at` | The latest review, or the automatic reset after a definition change |
| `definition_hash` | SHA-256 of the reviewed fields (kind, provider, endpoint, version, capabilities, resources); send it as `reviewed_definition` when marking the tool trusted |

### Decision

```json
{
  "id": "01b65b70-c545-48d8-8984-2f32c4c132a5",
  "agent_id": "49ae8a50-40f6-4d5a-92a3-000da2be1ff3",
  "tool": "crm",
  "action": "crm:update",
  "resource": "crm:accounts/42",
  "decision": "require_approval",
  "reasons": [
    "Tool 'crm' (trusted) is assigned to the agent and provides 'crm:update' on 'crm:accounts/42'",
    "Allowed by delegation 8d611aea-9b9b-468a-965c-58c85a8780dd: task 'Prepare the monthly sales report', delegated by ali, valid until 2026-10-13T06:47:18Z",
    "Policy rule 'crm-updates-need-approval' (require_approval): Changes to customer records need a person's approval"
  ],
  "matched_rules": ["crm-updates-need-approval"],
  "delegation_id": "8d611aea-9b9b-468a-965c-58c85a8780dd",
  "policy_version": 1,
  "decided_at": "2026-10-06T06:47:18.652103Z"
}
```

| Field | Meaning |
|---|---|
| `id` | The recorded decision; `null` for simulations |
| `decision` | `allow`, `require_approval` or `deny` ([how it is reached](modules/m5-runtime-gateway.md#the-decision)) |
| `reasons` | Every check and rule behind it, in order |
| `matched_rules` | IDs of the policy rules that applied |
| `delegation_id` | The delegation that covers the action, when one does |
| `policy_version` | The policy version used (0: no policy saved) |

### PolicyVersion

```json
{
  "version": 1,
  "rules": [
    {"id": "crm-updates-need-approval", "description": "Changes to customer records need a person's approval",
     "effect": "require_approval", "when": {"actions": ["crm:update"]}},
    {"id": "no-external-email-in-prod", "description": "Agents in production do not send email",
     "effect": "deny", "when": {"environments": ["prod"], "actions": ["email.*"]}}
  ],
  "comment": "CRM updates need a person; nothing leaves by email",
  "created_at": "2026-10-06T06:47:18.578124Z"
}
```

Rules are described in [M6](modules/m6-policy-engine.md#rules). A rule's `when` lists only the
conditions it states.

## Health

### `GET /health`

*public*. Returns `{"status": "ok"}` when the server is up.

### `HEAD /health`

*public*. The same check for monitors that use `HEAD`: 200 with no body.

## Inventory (M1)

### `POST /agents/register`

*public*, but must be *signed with the key being enrolled* when `public_key` is sent.
Self-registration by an agent.

Query: `source` = `api` (default) or `sdk`. Any other value, including `manual`, is refused
(422); administrators onboard agents with `POST /agents` instead.

Body:

| Field | Type | Required | Meaning |
|---|---|---|---|
| `name` | string | yes | Agent name |
| `environment` | string | no, default `development` | e.g. `dev`, `staging`, `prod` |
| `owner` | string | no | Owner the agent *claims*; an administrator confirms or changes it on approval |
| `public_key` | string | no | Base64 Ed25519 public key to enrol. The request must then be signed with this key |

Behaviour:

- **New name + environment**: creates the agent in `pending_review`, binds `public_key` if given,
  returns 200 with the [Agent](#agent).
- **Existing agent, request signed with its active key** (with or without `public_key` in the
  body): refreshes `last_seen`, returns 200 with
  the Agent. Nothing else changes (a different `owner` in the body is ignored). If the agent is
  `inactive` or `disabled`, 403 instead: a switched-off agent is not refreshed as alive.
- **Existing agent, anything else**: 409 if the request is unsigned, or carries `public_key` for
  another key. The answer is the same in every case, so it reveals nothing about the agent.
- **Signed, without `public_key`, and not by the enrolled key of an existing agent** (another key, a
  replayed request, or a name nobody holds): 401 `A signed registration must include the public_key
  it was signed with; ...`. The answer is the same whether or not the name exists, so signed requests
  cannot be used to find out which names are taken (an unsigned registration of a free name creates
  a record, visible in the review queue).

Errors (besides the signing errors above, which apply when `public_key` is sent):

| Status | `detail` |
|---|---|
| 401 | `Request must be signed with the key being presented` |
| 401 | `Signature key ID does not match the key being presented` |
| 401 | `A signed registration must include the public_key it was signed with; only an existing agent's enrolled key can sign without it` (signature headers without a key to check them against, not made by an existing agent's enrolled key) |
| 403 | `Agent is inactive` / `Agent is disabled` (signed re-registration of a switched-off agent) |
| 409 | `Agent is already registered; re-registration must be signed with its enrolled key` |
| 409 | `This public key has already been used; generate a new key pair` |
| 422 | Invalid input, including `public_key` that is malformed or a weak (small-order) key |

### `POST /agents`

*admin*. Manual onboarding: creates an agent that is already approved (`active`,
`registration_source` `manual`). Bind its key afterwards with `POST /agents/{agent_id}/keys`.

Body: `name` (required), `owner` (required), `environment` (default `development`).

Returns 201 with the [Agent](#agent). Errors: 409 `Agent is already in the inventory`.

### `GET /agents`

*admin*. Lists all agents. Optional query `status` filters by status. Returns a list of
[Agent](#agent).

### `GET /agents/review-queue`

*admin*. Lists the agents in `pending_review`.

### `GET /agents/{agent_id}`

*admin*. One agent. Errors: 404 `Agent not found`.

### `DELETE /agents/{agent_id}`

*admin*. Rejects a pending registration: deletes the agent, which frees its name, and retires its
key for good (it can never be enrolled again, under any name). Returns 204 with no body.

| Status | `detail` |
|---|---|
| 404 | `Agent not found` |
| 409 | `Only pending registrations can be rejected; disable approved agents instead` |
| 409 | `The registration was approved or rejected while this rejection was in progress; nothing was changed` |
| 409 | `The registration was rejected concurrently; nothing was changed` |

### `POST /agents/{agent_id}/approve`

*admin*. Approves a pending agent: sets its owner and makes it `active`. Only while it is still
pending: if it was rejected meanwhile, 404; if approved meanwhile, 409.

Query: `owner` (required, not blank).

| Status | `detail` |
|---|---|
| 404 | `Agent not found` |
| 409 | `Only pending_review agents can be approved (agent is <status>)` |

### `PUT /agents/{agent_id}/owner`

*admin*. Changes the owner of an approved agent. Body: `{"owner": "<name>"}`.

| Status | `detail` |
|---|---|
| 404 | `Agent not found` |
| 409 | `Pending agents get their owner through /approve` |

### `POST /agents/{agent_id}/status`

*admin*. Moves an approved agent between `active`, `inactive` and `disabled`.
Body: `{"status": "<status>"}`, one of those three values; anything else, including
`pending_review`, is refused (422).

| Status | `detail` |
|---|---|
| 404 | `Agent not found` |
| 409 | `Pending agents must be approved via /approve first` |

## Identity (M2)

### `GET /agents/{agent_id}/keys`

*admin*. The agent's key history, oldest first, as a list of [AgentKey](#agentkey).
Errors: 404 `Agent not found`.

### `POST /agents/{agent_id}/keys`

*admin*. Binds a public key the agent's operator supplied out of band. Used for manually
onboarded agents, agents registered without a key, and recovery after a revocation.
Body: `{"public_key": "<base64>"}`. Returns 201 with the [AgentKey](#agentkey).

| Status | `detail` |
|---|---|
| 404 | `Agent not found` |
| 409 | `Agent already has an active key; revoke it first` |
| 409 | `This public key has already been used; generate a new key pair` |
| 409 | `The agent's keys changed concurrently; check them and retry` |
| 422 | Malformed or weak `public_key` |

### `POST /agents/{agent_id}/keys/{key_id}/revoke`

*admin*. Revokes the agent's **active** key. It stops working immediately and can never be bound
again. Optional body: `{"reason": "<text>"}`. Returns the [AgentKey](#agentkey).

A key that is no longer active is refused and the answer names the key actually in use: if a stolen
key was already rotated to the thief's own key, revoking the old one would cut nothing off.

| Status | `detail` |
|---|---|
| 404 | `Key not found` (no such key, or it belongs to another agent) |
| 409 | `Key is not active (rotated); the agent's active key is <key_id>. Revoke that key, or disable the agent` (also `(revoked)`, or `the agent has no active key`) |

### `GET /identity/whoami`

*agent (signed)*. Returns the calling agent's own [Agent](#agent) record. Useful to check that the
key works and whether the agent has been approved.

### `POST /identity/rotate`

*agent (signed)*, plus header `X-Secentic-Proof`: the **new** key's signature over the same
canonical request, in base64 (88 characters; see [rotation](modules/m2-agent-identity.md#key-rotation)).
Body: `{"public_key": "<new base64 public key>"}`.

Replaces the agent's key: the current key becomes `rotated` and stops working immediately; the new
key becomes `active`. Returns the new [AgentKey](#agentkey).

| Status | `detail` |
|---|---|
| 401 | `Missing or invalid proof of possession for the new key` |
| 409 | `This public key has already been used; generate a new key pair` |
| 409 | `The key was rotated by a concurrent request` |
| 409 | `The key was revoked or rotated while this rotation was in progress; nothing was changed` |
| 422 | Malformed or weak `public_key`, or a malformed `X-Secentic-Proof` |

## Delegated authority (M3)

### `POST /agents/{agent_id}/delegations`

*admin*. Records that a human delegates authority to the agent. Returns 201 with the
[Delegation](#delegation).

Body:

| Field | Type | Required | Rules |
|---|---|---|---|
| `delegator` | string | yes | The human whose authority this is |
| `task` | string | yes | What it is for (at most 500 characters) |
| `actions` | list of strings | yes | 1–50 exact names (letters, digits, `_ . : -`, starting with a letter); no wildcards |
| `resources` | list of strings | yes | 1–50 identifiers or prefix patterns of at most 256 characters; `*` only at the end, right after `/` or `:`, after a system name containing a letter or digit; no empty, `.` or `..` segments |
| `starts_at` | timestamp | no, default now | Must include a timezone, and convert to a valid UTC time; not in the past (5 minutes' tolerance) |
| `expires_at` | timestamp | yes | In the future, after `starts_at`, at most 30 days after it |

Duplicate entries in `actions` and `resources` are dropped.

| Status | `detail` |
|---|---|
| 404 | `Agent not found` |
| 409 | `Pending agents cannot receive authority; approve the agent first` |
| 422 | A rule above is broken; the message says which |

### `GET /agents/{agent_id}/delegations`

*admin*. The agent's delegations, oldest first. Optional query `state` (`scheduled`, `active`,
`expired` or `revoked`) filters them. Errors: 404 `Agent not found`.

### `GET /agents/{agent_id}/delegations/{delegation_id}`

*admin*. One [Delegation](#delegation). Errors: 404 `Delegation not found` (also when it belongs to
another agent).

### `POST /agents/{agent_id}/delegations/{delegation_id}/revoke`

*admin*. Withdraws the delegation; it stops granting authority immediately. Optional body:
`{"reason": "<text>"}`. Returns the [Delegation](#delegation).

| Status | `detail` |
|---|---|
| 404 | `Delegation not found` |
| 409 | `Delegation is already revoked` |

### `POST /agents/{agent_id}/check-authority`

*admin*. Dry run of the [authority check](modules/m3-delegated-authority.md#the-authority-check):
may the agent perform `action` on `resource`? Nothing is executed or recorded.

Body: `action` (required), `resource` (required, an identifier without wildcards), `at` (optional
timestamp with timezone; default now, so you can ask about the past or future).

Returns 200 with an [AuthorityCheck](#authoritycheck) whether the answer is yes or no. Errors:
404 `Agent not found`; 422 for a malformed action or resource.

### `GET /identity/delegations`

*agent (signed)*. The calling agent's delegations that are in force now, as a list of
[Delegation](#delegation).

## Tool registry (M4)

### `POST /tools`

*admin*. Registers a tool or MCP server; it starts as `unknown`. Returns 201 with the [Tool](#tool).

Body: `name` (required), `kind` (`tool` or `mcp_server`), `provider`, `endpoint` (at most 500
characters), `version`, `capabilities` (1–50 action names), `resources` (1–50 resource
identifiers or prefix patterns such as `crm:*`, with the same rules as delegation resources: no
blanket `*`), `description` (optional).

| Status | `detail` |
|---|---|
| 409 | `A tool with this name is already registered` |
| 422 | Malformed name, capability or resource pattern, or a missing field |

### `GET /tools`

*admin*. The registry, sorted by name. Optional query `trust_state` and `kind` filter it.

### `GET /tools/{tool_name}`

*admin*. One [Tool](#tool). Errors: 404 `Tool not found`.

### `PUT /tools/{tool_name}`

*admin*. Replaces the definition (every field of `POST /tools` except `name`). If the tool was
`trusted` and its kind, provider, endpoint, version, capabilities or resources change, its trust becomes
`unknown` with the reason `Definition changed (...); review it again`. Returns the [Tool](#tool).

| Status | `detail` |
|---|---|
| 404 | `Tool not found` |
| 409 | `The tool changed while it was being updated; reload it and try again` (a review or another update landed in between) |

### `POST /tools/{tool_name}/trust`

*admin*. Records a review. Body: `{"trust_state": "<state>", "reason": "<text>"}` (`reason` optional).
To mark the tool `trusted`, also send `"reviewed_definition": "<definition_hash>"`, the hash of the
definition that was reviewed (from `GET /tools/{tool_name}`): an approval applies only to that exact
definition. `unknown`, `suspicious` and `blocked` never need it. Returns the [Tool](#tool).

| Status | `detail` |
|---|---|
| 404 | `Tool not found` |
| 409 | `The tool's current definition is not the one you reviewed; review it and send its definition_hash` |
| 409 | `The tool changed while the review was being recorded; review it again` |
| 422 | `trusted` without `reviewed_definition`, or a malformed one |

### `GET /agents/{agent_id}/tools`

*admin*. The tools the agent may use, as a list of [Tool](#tool). Errors: 404 `Agent not found`.

### `PUT /agents/{agent_id}/tools/{tool_name}`

*admin*. Lets the agent use the tool; repeating it changes nothing. Returns
`{"agent_id": "...", "tool_name": "crm", "assigned_at": "..."}`.

| Status | `detail` |
|---|---|
| 404 | `Agent not found` / `Tool not found` |
| 409 | `Pending agents cannot be given tools; approve the agent first` |
| 409 | `Tool is blocked` |
| 409 | `The agent's tools changed concurrently; check them and retry` |

### `DELETE /agents/{agent_id}/tools/{tool_name}`

*admin*. Takes the tool away; the agent's next request for it is denied. Returns 204.
Errors: 404 `Agent not found` / `The agent is not assigned this tool`.

### `GET /identity/tools`

*agent (signed)*. The calling agent's tools, as a list of [Tool](#tool).

## Gateway (M5)

### `POST /gateway/authorize`

*agent (signed)*. Asks whether the calling agent may use `tool` to perform `action` on `resource`.
Body: `{"tool": "<tool name>", "action": "<action>", "resource": "<resource identifier>"}`.
Returns 200 with the recorded [Decision](#decision), whatever the decision is. The agent must
proceed only when `decision` is `allow`.

| Status | `detail` |
|---|---|
| 422 | Malformed tool name, action or resource |
| 503 | `The gateway could not reach a decision; failing closed (deny)`: treat as a denial |

### `POST /gateway/simulate`

*admin*. The [Decision](#decision) the gateway would make, without recording it. Body: `agent_id`,
`tool`, `action`, `resource`, and optionally `at` (a timestamp, to ask about another moment).
With `at`, the delegations and the policy version in force at that moment are used (the response's
`policy_version` says which); the agent's status, its tools and their trust are taken as they are
now, because they keep no history yet. `id` in the response is `null`. Errors: 404 `Agent not
found`; 503 as above.

### `GET /gateway/decisions`

*admin*. Recorded decisions, newest first. Optional query: `agent_id` (a UUID), `decision`
(`allow`, `require_approval` or `deny`), `limit` (1–500, default 50).

## Policy (M6)

### `GET /policy`

*admin*. The [PolicyVersion](#policyversion) in force. Before any policy is saved: version 0, no
rules, `created_at` `null`.

### `PUT /policy`

*admin*. Saves the whole rule set as a new version, in force immediately. Body:
`{"rules": [...], "comment": "<why>"}`, at most 200 rules with unique IDs
([rule format](modules/m6-policy-engine.md#rules)). Returns 201 with the new [PolicyVersion](#policyversion).

| Status | `detail` |
|---|---|
| 409 | `The policy was changed concurrently; reload it and try again` |
| 413 | `Request body too large (limit 1048576 bytes)`: this endpoint accepts up to 1 MiB, every other one 64 KiB |
| 422 | A malformed rule: unknown field or effect, duplicate ID, bad pattern, empty condition |

### `GET /policy/versions`

*admin*. Every version, newest first: `[{"version": 1, "comment": "...", "rule_count": 2, "created_at": "..."}]`.

### `GET /policy/versions/{version}`

*admin*. One [PolicyVersion](#policyversion). Errors: 404 `Policy version not found`; 422 for
version 0 or a number too large.

### `POST /policy/versions/{version}/restore`

*admin*. Saves that version's rules as a new version, in force immediately. Optional body:
`{"comment": "<text>"}` (default `Restored version N`). Returns 201 with the new
[PolicyVersion](#policyversion). Errors: 404 `Policy version not found`; 409 as for `PUT /policy`.

