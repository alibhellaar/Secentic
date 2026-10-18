# Secentic documentation

Secentic is a security control plane for AI agents: it keeps an inventory of agents, gives each a
cryptographic identity, records exactly what authority humans delegate to each one and which
tools it may use, and decides, before each action an agent takes, whether it is allowed, needs a
person's approval, or is denied, against that authority and a deterministic policy.

## Where to start

| If you want to... | Read |
|---|---|
| Understand what the project is and why | [Project overview](overview.md) |
| Install and run it, or use it as an administrator | [User guide](user-guide.md) |
| Connect an AI agent to it | [User guide: connecting your own agent](user-guide.md#connecting-your-own-agent), then the [SDK](sdk.md) |
| Look up an endpoint | [API reference](api-reference.md) |
| Understand how the code fits together | [Architecture](architecture.md) |
| Understand a specific module | [Module pages](modules/README.md) |
| Assess its security | [Security model](security.md) |
| Change or extend the code | [Development guide](development.md) |
| Look up a term | [Glossary](glossary.md) |
| See what changed recently | [Changelog](../CHANGELOG.md) |

## All pages

- [overview.md](overview.md): problem, approach, architecture at a glance, the 12 modules and their status, research basis
- [user-guide.md](user-guide.md): requirements, installation, configuration, running, walkthrough, administrator tasks, connecting agents, troubleshooting
- [architecture.md](architecture.md): technology, code map, request lifecycles, data model, lifecycles, conventions, integration points
- [api-reference.md](api-reference.md): every endpoint, its authentication, inputs, behaviour and errors
- [sdk.md](sdk.md): the Python SDK for agents
- [security.md](security.md): principles, trust boundaries, threats with the tests that prove each defence, residual risks
- [development.md](development.md): workflow, conventions, adding a module, testing, keeping these docs up to date
- [glossary.md](glossary.md): terms used across the project
- [modules/README.md](modules/README.md): module page index and template
  - [modules/m1-agent-inventory.md](modules/m1-agent-inventory.md): M1 Agent Discovery & Asset Inventory
  - [modules/m2-agent-identity.md](modules/m2-agent-identity.md): M2 Agent Identity & Non-Human Identity
  - [modules/m3-delegated-authority.md](modules/m3-delegated-authority.md): M3 Delegated Authority
  - [modules/m4-agent-tool-registry.md](modules/m4-agent-tool-registry.md): M4 Agent & Tool Registry
  - [modules/m5-runtime-gateway.md](modules/m5-runtime-gateway.md): M5 Runtime Security Gateway
  - [modules/m6-policy-engine.md](modules/m6-policy-engine.md): M6 Contextual Policy Engine

These pages are kept in step with the code: every change updates them in the same pull request,
and `tests/test_docs.py` checks what can be checked automatically. See
[keeping the docs up to date](development.md#keeping-the-docs-up-to-date).
