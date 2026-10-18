# Secentic — AI Agent Security Control Plane

AI agents now read data, call tools and take actions on their own, and their reasoning can be
manipulated, for example by instructions hidden in a web page or email they read (indirect prompt
injection). Secentic does not try to make an agent's reasoning safe. It **constrains what the
agent can do**: every agent has a verifiable identity, only the authority a human explicitly
delegated to it, and only the tools it was given; before each action, a gateway checks all of that
plus a deterministic policy and answers allow, deny or "needs a person's approval".

Final Year Project, FAST National University (Karachi), Fall 2026.

## Status

| Module | Status |
|---|---|
| M1 Agent Discovery & Asset Inventory | Implemented |
| M2 Agent Identity & Non-Human Identity | Implemented |
| M3 Delegated Authority | Implemented |
| M4 Agent & Tool Registry | Implemented |
| M5 Runtime Security Gateway (core) | Implemented |
| M6 Contextual Policy Engine (core) | Implemented |
| M7–M12 (risk, approvals, investigation, alerts, audit, dashboard) | Planned for FYP-II |

Details of every module: [docs/overview.md](docs/overview.md#modules-and-status).

## Quick start

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env     # then set SECENTIC_ADMIN_TOKEN, see the user guide
uvicorn app.main:app     # API docs at http://localhost:8000/docs
pytest
```

Then follow the ten-minute [walkthrough](docs/user-guide.md#walkthrough-your-first-agent): an agent
registers, you approve it, it proves its identity and rotates its key, you give it a tool and
narrowly scoped authority, and the gateway decides its actions.

## Documentation

Start at the [documentation index](docs/README.md).

- [Overview](docs/overview.md): the problem, the approach, the 12 modules
- [User guide](docs/user-guide.md): installation, configuration, usage, troubleshooting
- [API reference](docs/api-reference.md) and [Python SDK](docs/sdk.md)
- [Architecture](docs/architecture.md) and [security model](docs/security.md)
- [Development guide](docs/development.md): contributing and keeping the docs up to date
- [Changelog](CHANGELOG.md)

## Team

Syed Bakhtiar Ahmed (group leader), Syed Areeb Hussain, Ali Hyder Bhellar.
Supervisor: Sandesh Kumar.
