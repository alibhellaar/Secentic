# Changelog

Notable changes to Secentic, newest first, grouped by module. How to maintain this file is
described in [docs/development.md](docs/development.md#changelog).

## Unreleased

### Action needed

- `.env` must set `DATABASE_URL` (the server no longer falls back to a local SQLite file) and a
  `SECENTIC_ADMIN_TOKEN` of at least 16 characters. Start from `.env.example`.
- Inventory endpoints (`GET /agents/...`, approve, status) now require the admin token.
- Install the new dependencies: `pip install -r requirements.txt` (`cryptography`, `psycopg`).
- API timestamps now always end in `Z` (UTC). On SQLite they previously had no timezone at all.
  Timestamps sent to the API (delegation windows) must include a timezone.
- Development databases from the first M1 version keep working: their fingerprints are updated
  at startup. If one holds the same agent twice, the server explains and stops; delete it.

### M1 — Agent Discovery & Asset Inventory

Changed:
- Agents are identified by name and environment only; the owner is no longer part of the
  fingerprint, so approving or changing the owner no longer produces duplicate records.
- Self-registration always waits in `pending_review`; a claimed owner no longer activates an agent.
- Once an agent exists, only a registration signed with its enrolled key is accepted (and refreshes
  `last_seen`). Every other repeat gets the same 409, revealing nothing.
- Approval works only on pending agents. Blank names, environments and owners are refused.

Added:
- Administrator authentication on all control-plane endpoints.
- Manual onboarding (`POST /agents/`), single-agent lookup (`GET /agents/{agent_id}`),
  rejection of pending registrations (`DELETE /agents/{agent_id}`), owner changes
  (`PUT /agents/{agent_id}/owner`) and status changes (`POST /agents/{agent_id}/status`).
- PostgreSQL support.

Fixed:
- `first_seen` and `last_seen` are set from the same instant on creation.
- Concurrent registrations of the same agent return 409 instead of a server error.

### M2 — Agent Identity & Non-Human Identity

Added:
- Ed25519 identity per agent; the private key stays with the agent.
- Signed requests with timestamp window and single-use nonces (replay protection).
- Key enrolment at registration (with proof of possession), administrator key binding, key
  rotation with proof of the new key, and revocation.
- Refusal of weak (small-order) Ed25519 keys.
- `authenticate_agent` dependency for other modules.
- Python SDK (`secentic_sdk`) and a demo agent (`examples/demo_agent.py`).

### M3 — Delegated Authority

Added:
- Delegations: a named human grants an agent exact actions on specific resources for a task,
  within a time window of at most 30 days; revocable at any time.
- Deny-by-default authority check (`check_authority`) with a human-readable reason, for the M5
  gateway, and an administrator dry run (`POST /agents/{agent_id}/check-authority`).
- Refusal of blanket grants, wildcard actions and path-traversal resource names.
- Agents can list their delegated authority (`GET /identity/delegations`, SDK `delegations()`).

### Fixed after the sixth code review

Changed (action needed for clients):
- Timestamps in requests must be RFC 3339 strings with a timezone (`2026-10-13T09:00:00Z`).
  Numbers and number strings, which were read as Unix times, and looser forms such as
  `2026-10-13 09:00:00Z` or `2026-10-13T09:00Z` are refused (422). The schema publishes the pattern.
- A signed registration without `public_key` is accepted only when an existing agent's enrolled key
  made it. Everything else, replays included, gets one 401 (`A signed registration must include the
  public_key it was signed with; ...`), whether or not the name exists. A replayed re-registration
  used to get 409.
- `PUT /policy` accepts bodies up to 1 MiB, so a full policy of 200 realistic rules fits; every
  other endpoint keeps the 64 KiB limit.
- SQLite now enforces foreign keys, as PostgreSQL always did.

Fixed:
- A body that is not UTF-8 (sent without a JSON content type), `NaN` or `Infinity` in a field made
  the open registration endpoint answer 500: the 422 tried to echo them back.
- A signed registration without a key revealed whether the name existed (409 or 401), without
  leaving a record.
- A failure after storing a gateway decision answered 503 (deny) for an action the log records as
  allowed.
- A key bound to a pending agent while it was being rejected could point at a deleted agent (SQLite).
- A rotation racing another enrolment of the same new key blamed a concurrent rotation.
- Replays made each request repeat the purge of expired nonces.

Improved:
- Re-registration refreshes `last_seen` in the same commit that spends the nonce; policy versions
  are counted by the database; policy evaluation computes the request's comparison forms once per
  decision; one helper (`update_one`) for every guarded update; the gateway uses the authority lookup
  directly instead of re-checking; the action alphabet and canonical pattern rule are shared.

### Found by the test campaign

Fixed:
- A request with a lone surrogate (`\ud800`) in a field answered 500 instead of 422: the value was
  refused correctly, but echoing it back in the error response failed.
- The OpenAPI `pattern` of every text field named the surrogate range, which JSON Schema engines in
  Rust, Go and other languages cannot compile, so they could not use the schema at all (Schemathesis
  dropped the pattern and fuzzed text fields blind). Surrogates are now left out of the published
  pattern; the server still refuses them.
- Four race-condition tests did not actually simulate their race (the stale record was not kept
  alive), so they would have passed without their fix; one signature test passed through a different
  check. They now fail without their fixes, and new tests cover a stale approval re-activating a
  disabled agent and the gateway's status check coming first.

### Fixed after the fifth code review

Changed (action needed for clients):
- Resources and actions are normalised to one spelling wherever they are accepted (delegations,
  tool definitions, policy rules, gateway requests, authority checks): a resource becomes its
  system name, one `:`, then a `/`-separated path (`crm:accounts:42` -> `crm:accounts/42`; case is
  kept), and actions become lower case. Responses and the decision log show the normalised form.
- A delegation's `starts_at` may not be in the past (5 minutes' tolerance).
- Revoking an already revoked delegation at the same moment as another administrator gets 409.
- A replayed re-registration of an existing agent gets 409 (was 401), like every other refusal.
- Policy rules may name any environment again (also free-text ones from older versions).
- Agent-facing endpoints declare 503 in OpenAPI.

Fixed:
- Each signed request held two database connections at once (a regression from the previous
  round), which could exhaust the pool and stall every agent under load.
- Questions about an earlier moment treated a revoked delegation as revoked before it was.
- Agents from older versions whose names had surrounding spaces did not match rules naming them.
- A key bound to a pending agent during its rejection could be deleted without being retired.
- A failed nonce insert rolled back the expired-nonce purge but still postponed the next one.
- Importing `app.schemas` scanned all of Unicode (about 0.25 s); the result is now a fixed table,
  checked against the running Python by a test.

Improved:
- One function for the policy version in force (`version_in_force`), one fetch-or-404 helper.
- `.schemathesis/` is git-ignored.

### Fixed after the fourth code review

Changed (action needed for clients):
- Environments must be plain ASCII names: 1–64 letters, digits, `.`, `_` or `-` (`prod`,
  `eu-west-1`); policy rules' `environments` too.
- Signed paths are the routed form: percent-decoded, without a trailing `/`. The SDK does this;
  other clients that signed `/x/` must sign `/x`.
- Database failures answer 503 (`The database could not complete the request; ...`) everywhere,
  authentication included, instead of 500.
- `POST /gateway/simulate` with `at` uses the policy version in force at that moment.
- `rotate_key` raises `RotationInterrupted` (with the new key) when the server says the current key
  was already rotated.

Fixed:
- `crm:accounts:secret` slipped past a policy rule on `crm:accounts/secret*`.
- The SDK could not sign requests to paths with a trailing slash.
- On older Starlette versions, a crafted `Host` header could make a signature verify for another
  endpoint; the signed path now comes from the routed request.
- A registration racing another for the same key got "Agent is already registered" instead of
  "This public key has already been used".
- A registration rejected while one of its requests was being authenticated crashed that request.
- Spending a nonce committed anything else pending in the request; it now has its own transaction.
- The demo agent could write its private key into an existing world-readable file.
- A blank line broke the user guide's troubleshooting table and the security threat table.
- OpenAPI descriptions now take their limits from the code's constants.

Improved:
- `tests/test_docs.py` now checks that every error message is documented in the API reference and
  the troubleshooting table, and that no table is broken by a blank line.

### Fixed after the third code review

Changed (action needed for clients):
- **Delete development databases** (`secentic.db`): tools have a new required `resources` column,
  and there are no migrations.
- Registering or updating a tool requires `resources`: the resource identifiers or prefix patterns
  it works on (`["crm:*"]`). They are part of the reviewed definition, so `definition_hash` values
  change. The gateway refuses a resource outside the tool's scope (`Tool 'x' does not work on 'r'`),
  and its "allowed" reason now names the resource.
- Policy rules match actions and resources ignoring case.
- More invisible characters are refused in names and other text (all Unicode format characters,
  default-ignorables, blank-looking letters).
- A signed registration of a new agent without `public_key` gets 401 instead of being accepted
  with the signature ignored.
- Malformed `X-Secentic-Key-Id` and `X-Secentic-Signature` headers get specific 401 messages.

Fixed:
- `crm:accounts/Secret` slipped past a policy rule on `crm:accounts/secret*`.
- Any assigned tool offering an action could be used on any delegated resource.
- Upgrading a database from the first M1 version left agents it had auto-activated on a claimed
  owner active; they now go back to review.
- A rejection could delete an agent another administrator had just approved; an approval racing a
  rejection returned 500.
- Several server processes starting on a fresh database could crash at startup.
- `POST /docs` and other FastAPI routes answered 405 with an empty `Allow` header.
- Agent listings ran one query per agent (a regression from the previous round); agent tool and
  delegation listings now filter in the database; an authenticated request no longer reads its agent
  and key twice; policy name comparisons are cached.

Improved:
- Shared router helpers moved to `app/routers/common.py`, with one `ADMIN` dependency constant.

### Fixed after the second code review

Changed (action needed for clients):
- `POST /agents/{agent_id}/keys/{key_id}/revoke` revokes only the active key; for a rotated or
  revoked key it returns 409 naming the agent's current key (was 200 for rotated keys).
- `PUT /tools/{tool_name}` can return 409 if a review or another update landed at the same moment.
- Agent names and environments are compared by NFKC with case folding (fingerprint format 3), in
  the inventory and in policy rules: `straße` and `strasse`, full-width and plain letters are one
  name. Databases are updated once at startup; one holding two such agents stops with an explanation.
- The documented paths are `/agents` and `/tools`; a trailing slash on any path is ignored.

Fixed:
- An update and an approval of a tool landing together could leave it trusted with the new,
  unreviewed definition.
- Revoking a key the agent had already rotated (e.g. a thief swapping a stolen key) reported success
  while the newer key kept working.
- A re-registration signed with the enrolled key but without `public_key` in the body got a
  misleading 409; it is now accepted.
- Rejecting a registration deleted its key, so the same key could be enrolled again; it is now
  retired (new `retired_keys` table).

Improved:
- Denials search only the agent's latest 100 delegations for an explanation.
- Removed an unreachable loop in `check_authority`, duplicated tool and delegation listings, and the
  duplicated trailing-slash routes; the agent's active key is no longer loaded on every request.

### Fixed after code review

Changed (action needed for clients):
- Marking a tool `trusted` now requires `"reviewed_definition"`: the tool's new `definition_hash`
  (shown with every tool) for the definition that was reviewed. If the tool changed since, 409.
- Resource identifiers may no longer contain empty segments (`crm:accounts//x`, a leading or
  trailing `/` or `:`).
- Text fields refuse every kind of leading or trailing space and invisible characters (C1 controls,
  Unicode line separators, zero-width characters, bidirectional overrides, soft hyphens).
- Agent requests with an unknown key now get `Invalid signature` (was `Unknown key`).
- The gateway answers `Agent 'a' is not allowed to use tool 'x'` for unregistered tools too (was
  `Tool 'x' is not registered`), and checks assignment before revealing that a tool is blocked.
- Signed re-registration of an inactive or disabled agent gets 403.
- `last_seen` is refreshed at most once a minute.

Fixed:
- A doubled separator let a request fall under a delegation yet slip past a policy rule on the same
  resource.
- A key rotation running while an administrator revoked the key could overwrite the revocation and
  enrol the rotating party's new key.
- A tool could be marked trusted for a definition that changed while it was being reviewed.
- Agents could learn which tools exist, and administrators' block reasons, for tools they were not given.
- Key existence and revocation could be learnt without being able to sign.
- `name|environment` fingerprints collided for values containing `|` (format 2 uses a JSON array;
  databases are updated once at startup).
- The rotation proof header is now bounded (base64, 88 characters).

Improved:
- Delegations in force are filtered in the database; the full history is read only to explain a denial.
- The startup fingerprint check is a single lookup unless the format changed (new `system_settings` table).
- One routers list, one ID pattern, one latest-policy query, one pattern-matching function.

### M4 — Agent & Tool Registry

Added:
- A registry of tools and MCP servers: kind, provider, endpoint, version, capabilities and a trust
  state (`trusted`, `unknown`, `suspicious`, `blocked`); new tools start `unknown`.
- Trust reviews with reasons, and an automatic reset to `unknown` when a trusted tool's definition
  changes (protection against MCP "rug pulls").
- Per-agent tool assignments; agents can list their own tools (`GET /identity/tools`, SDK `tools()`).

### M5 — Runtime Security Gateway (core)

Added:
- `POST /gateway/authorize`: agents ask before acting and get ALLOW, DENY or REQUIRE APPROVAL with
  every reason, from a fixed sequence of checks (agent, tool, assignment, capability, delegation,
  tool trust, policy).
- Every decision is recorded (`GET /gateway/decisions`); administrators can simulate decisions
  (`POST /gateway/simulate`).
- Fail closed: any internal error answers 503, never an ALLOW.
- SDK `authorize()`, `ensure_allowed()` and `ActionNotAllowed`; the demo agent now asks the gateway.

### M6 — Contextual Policy Engine (core)

Added:
- Deterministic policy rules (deny / require approval) on agent, environment, tool, tool trust,
  action and resource; the most restrictive outcome wins and every matching rule is explained.
- Policies can only restrict: there is no allow effect.
- Versioned policies (`PUT /policy`, `GET /policy/versions`, restore as a new version); every
  decision records the policy version it used.

### Fixed after fuzzing and edge-case testing

- NUL characters in any text field or ID caused server errors (500) on PostgreSQL. Text fields
  now refuse control characters and path IDs must be well formed (422).
- Timestamps near year 1 or 9999 with a timezone offset caused server errors (500); they are now
  refused (422), and `check_authority` denies instead of raising.
- `crm:../admin` passed the path-traversal check and was allowed under a `crm:*` grant; `:` now
  separates segments too.
- No size limits: request bodies are now capped at 64 KiB (413) and text fields at 200 characters
  (500 for tasks and reasons).
- Deeply nested JSON caused a server error while the 422 response echoed it back; nested input is
  no longer echoed.
- One test failed on Python 3.10 (`datetime.fromisoformat` accepts `Z` only from 3.11).

### API polish (schema, routing, demo)

Changed (action needed for clients):
- Text values are stored exactly as sent: a leading or trailing space is now refused (422) instead
  of trimmed.
- `source=manual` on registration and `"status": "pending_review"` on the status endpoint are now
  refused by validation (422 instead of 400).
- Malformed IDs in URLs now get 404 `Not Found` (no endpoint matches) instead of 422.
- Timestamps sent as numbers are refused; they must be ISO 8601 strings.
- A wildcard resource pattern needs a system name before its first `/` or `:` (`/crm/*` is
  refused), and patterns are at most 256 characters including the `*`.

Fixed:
- `/openapi.json` now describes the API exactly: every error response, every validation pattern,
  and the signature headers as security schemes. Schemathesis finds no mismatch except the
  delegation window rules, which JSON Schema cannot express.
- `GET /agents/register` and `DELETE /agents/review-queue` were read as "agent with ID register" (404);
  they now get 405. Every 405 lists all allowed methods in `Allow`.
- `/agents` without the trailing slash works directly instead of redirecting; `HEAD /health` works.
- The demo agent prints a clear message instead of a traceback when the server is down, a request
  is refused, or the key file cannot be read.

### Project

Added:
- Full documentation in `docs/`, kept in step with the code by `tests/test_docs.py`.
- Test isolation: every test uses its own database; `TEST_DATABASE_URL` runs the suite on PostgreSQL.
- GitHub Actions running the tests on SQLite and PostgreSQL, and a pull request template.

## 2026-10-03 — M1 first version

- Agent registration through the API, deduplication by fingerprint, review queue for agents
  without an owner, and approval.
