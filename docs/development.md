# Development guide

For team members (and anyone else) changing Secentic. Setup is in the
[user guide](user-guide.md#installation); how the code is organised is in
[architecture.md](architecture.md).

## Workflow

1. Create a branch per piece of work, e.g. `m3-delegated-authority` or `fix-rotation-race`.
2. Write the code **and** its tests **and** the documentation updates (see
   [below](#keeping-the-docs-up-to-date)) in the same branch.
3. Run `pytest`. If you touched the data model, also run it on PostgreSQL
   ([how](user-guide.md#running-the-tests)).
4. Open a pull request to `main`. The pull request template has a checklist, and GitHub Actions
   runs the tests on SQLite and PostgreSQL.

## Conventions

The rules every module follows (authentication, failing closed, error codes, transactions,
timestamps) are listed in [architecture.md](architecture.md#cross-cutting-conventions). In short:

- Control-plane endpoints use `dependencies=ADMIN` (from `app/routers/common.py`, with the other
  helpers every router shares); agent endpoints use `Depends(authenticate_agent)`. Never accept both on one endpoint.
- When unsure, refuse: missing configuration or state disables the feature.
- Security decisions must be deterministic and explainable. ML or LLM output is advisory only.
- Commits that can violate a unique constraint go through `commit_or_409`; updates that must not
  overwrite a concurrent change go through `update_one` (`app/routers/common.py`).
- Use `utcnow()` for timestamps, `UtcInput` for timestamps in requests, `NonBlankStr` /
  `Description` for text, and `{agent_id:uuid_id}` with `AgentId` (or `DelegationId`, `KeyId`) for
  IDs in paths, and `ResourceId` / `ResourcePattern` / `ActionName` for resources and actions (they
  normalise to one spelling; compare only normalised values). Never accept free-form `str` input: unbounded or control-character text has crashed
  requests before (see T28 and T29 in security.md).
- Declare every error a route can return with `responses=error_responses(...)`, and mark
  agent-facing routes with `openapi_extra=SIGNED_REQUEST`. A new validator needs an equivalent JSON
  Schema (`WithJsonSchema`) and a case in `tests/test_openapi.py`.
- Match the style of the surrounding code: short functions, comments that explain *why*.

## Adding a new module

Using M7 as an example:

- [ ] Router in `app/routers/risk.py`, included in `app/main.py` and added to `_ROUTERS` there
      (which builds the 405 `Allow` header).
- [ ] Models in `app/models.py`, request/response schemas in `app/schemas.py`.
- [ ] Agent-facing endpoints depend on `authenticate_agent`; admin endpoints declare `dependencies=ADMIN`.
- [ ] Tests in `tests/test_risk.py`, including the attacks the module must stop.
- [ ] Documentation, all in the same pull request:
  - [ ] Module page `docs/modules/m7-risk-engine.md`, from the
        [template](modules/README.md#template), linked from [docs/README.md](README.md) and
        [modules/README.md](modules/README.md)
  - [ ] Status row in [overview.md](overview.md#modules-and-status) set to *Implemented*, with a link
  - [ ] Endpoints in [api-reference.md](api-reference.md)
  - [ ] Code map, data model and "where future modules plug in" in [architecture.md](architecture.md)
  - [ ] New threats and their tests in [security.md](security.md)
  - [ ] New settings in the [user guide](user-guide.md#configuration) and `.env.example`
  - [ ] Status in the root `README.md`
  - [ ] An entry in [CHANGELOG.md](../CHANGELOG.md)

## Changing the data model

There are no migrations yet: `create_all` at startup creates missing tables but never alters
existing ones. When you add a table, nothing else is needed. When you change an existing table:

- note in [CHANGELOG.md](../CHANGELOG.md) that development databases must be deleted;
- update the ER diagram in [architecture.md](architecture.md#data-model);
- run the tests on PostgreSQL as well as SQLite (partial indexes and enums behave differently).

Adding Alembic is the planned fix once real data has to survive schema changes.

## Writing tests

Fixtures in `tests/conftest.py`:

| Fixture | Gives you |
|---|---|
| `session_factory` | SQLAlchemy sessions on a fresh database for this test (SQLite, or `TEST_DATABASE_URL`) |
| `client` | A FastAPI `TestClient` wired to that database, with an admin token configured |
| `admin` | The headers for administrator requests |
| `make_agent(name=..., environment=..., approve=True)` | A registered (and by default approved) agent; returns `(sdk_client, agent_record)` |
| `trust(name, reason=...)` | Marks a registered tool trusted, naming its current `definition_hash` as a reviewer would; returns the tool |

Write security tests as attack scenarios, named after what they prove
(`test_cannot_attach_a_key_to_someone_elses_pending_agent`), and add each to the threat table in
[security.md](security.md). A fix for a vulnerability is not done until a test fails without it.

## Fuzzing the API

[Schemathesis](https://schemathesis.readthedocs.io/) generates thousands of requests from
`/openapi.json` and reports server errors and any mismatch between the API and its schema. Run it
against a development server (with a throwaway database) after changing endpoints:

```bash
uvx schemathesis run http://localhost:8000/openapi.json \
  -H "Authorization: Bearer $SECENTIC_ADMIN_TOKEN" --phases examples,coverage,fuzzing
```

Expect exactly two findings, both "rejected schema-compliant request" for rules JSON Schema cannot
express: `POST /agents/{agent_id}/delegations` (the delegation time window) and `PUT /policy`
(unique rule IDs). Anything else is a bug. Run it against PostgreSQL as well: some inputs only fail
there.

## Keeping the docs up to date

The documentation describes the code **as it is now**. Any change to behaviour updates the docs in
the same pull request; a pull request that changes behaviour without updating the docs is not
finished.

| You changed... | Update |
|---|---|
| An endpoint (added, removed, renamed, new parameters, new errors) | [api-reference.md](api-reference.md) and the module page |
| A rule or behaviour of a module | The module page in `docs/modules/` |
| A new module | See [Adding a new module](#adding-a-new-module) |
| A setting or environment variable | [user-guide.md](user-guide.md#configuration) and `.env.example` |
| Setup, installation or run steps | [user-guide.md](user-guide.md) |
| A table, column or constraint | [architecture.md](architecture.md#data-model) |
| Files or folders | The code map in [architecture.md](architecture.md#code-map) |
| Anything security-relevant | [security.md](security.md) (threats, tests, residual risks) |
| The SDK | [sdk.md](sdk.md) |
| The signing protocol | [M2 page](modules/m2-agent-identity.md#request-signing-protocol) and the test vector |
| An error message | The [user guide troubleshooting](user-guide.md#troubleshooting) table and [api-reference.md](api-reference.md) |
| A new term | [glossary.md](glossary.md) |
| Anything a user or teammate would notice | [CHANGELOG.md](../CHANGELOG.md) under *Unreleased* |

`tests/test_docs.py` checks the parts that can be checked mechanically, and fails with a message
saying what to update:

- every API endpoint is documented in `api-reference.md`, and every documented endpoint exists;
- every environment variable the code reads is documented in the user guide (and in
  `.env.example`, for server settings);
- the signature headers and parameters in the M2 page match the code, and its test vector is correct;
- every test named in the docs exists;
- every page in `docs/` is linked from the documentation index;
- every relative link, including `#section` anchors, points somewhere that exists.

Everything else (explanations, diagrams, design decisions) relies on review: check the docs
section of the pull request checklist honestly.

## Changelog

[CHANGELOG.md](../CHANGELOG.md) lists notable changes, newest first. Add entries under
*Unreleased*, grouped by module, and call out anything that requires action from others (a new
setting, a deleted database, a changed endpoint) under *Action needed*. When a milestone is
demonstrated or submitted, rename *Unreleased* to the date and milestone.
