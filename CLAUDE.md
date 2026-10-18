# Secentic

FYP: a security control plane for AI agents (FastAPI + SQLAlchemy + Ed25519). Start with
`docs/README.md`; module status is in `docs/overview.md`.

## Commands

- Install: `pip install -r requirements.txt`
- Run: `uvicorn app.main:app --reload` (needs `.env`, from `.env.example`)
- Test: `pytest` (fresh SQLite database per test). PostgreSQL:
  `TEST_DATABASE_URL=postgresql+psycopg://... pytest`

## Documentation must be updated with every change

The docs describe the code as it is now. In the same change as any code change, update the
affected docs. The full mapping is in `docs/development.md` ("Keeping the docs up to date"):

- endpoints → `docs/api-reference.md` + the module page in `docs/modules/`
- module behaviour or rules → `docs/modules/mN-*.md`
- new module → page from the template in `docs/modules/README.md`, `docs/README.md` index,
  `docs/overview.md` status table, `docs/architecture.md`, root `README.md` status table
- settings → user guide configuration table + `.env.example`
- data model or files → `docs/architecture.md`
- security behaviour → `docs/security.md` threat table (with the test that proves it)
- SDK → `docs/sdk.md`; signing protocol → M2 page and its test vector
- error messages → user guide troubleshooting + `docs/api-reference.md`
- anything user-visible → `CHANGELOG.md` under "Unreleased"

`tests/test_docs.py` checks part of this mechanically. Run `pytest` before finishing.

## Conventions

- Control-plane endpoints: `dependencies=ADMIN` (shared helpers live in `app/routers/common.py`). Agent endpoints:
  `Depends(authenticate_agent)`. Never both on one endpoint.
- Fail closed. Security decisions are deterministic; ML/LLM output is advisory only.
- Unique-constraint commits go through `commit_or_409`; updates that must not overwrite a concurrent
  change go through `update_one`; timestamps use `utcnow()`.
- Request input uses the bounded types in `app/schemas.py` (`NonBlankStr`, `Description`,
  `UtcInput`, ...), never bare `str`/`datetime`. Path IDs: `{agent_id:uuid_id}` + `AgentId` (or
  `DelegationId`, `KeyId`). Resources and actions are normalised by their input types (`ResourceId`,
  `ResourcePattern`, `ActionName`, ...); store and compare only normalised values.
- Routes declare errors with `responses=error_responses(...)`; agent-facing routes add
  `openapi_extra=SIGNED_REQUEST`. Validators and their JSON Schemas must stay equivalent
  (`tests/test_openapi.py`).
- No migrations: a change to an existing table means deleting dev databases; say so in the changelog.
- Security fixes come with a test that fails without the fix.
