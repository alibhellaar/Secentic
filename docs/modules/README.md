# Module pages

One page per implemented module. Planned modules are described in the
[overview](../overview.md#modules-and-status) until they are built.

| Module | Page |
|---|---|
| M1 Agent Discovery & Asset Inventory | [m1-agent-inventory.md](m1-agent-inventory.md) |
| M2 Agent Identity & Non-Human Identity | [m2-agent-identity.md](m2-agent-identity.md) |
| M3 Delegated Authority | [m3-delegated-authority.md](m3-delegated-authority.md) |
| M4 Agent & Tool Registry | [m4-agent-tool-registry.md](m4-agent-tool-registry.md) |
| M5 Runtime Security Gateway | [m5-runtime-gateway.md](m5-runtime-gateway.md) |
| M6 Contextual Policy Engine | [m6-policy-engine.md](m6-policy-engine.md) |

## Template

Copy this into `docs/modules/mN-short-name.md` when you start a module, fill it in as you build,
and add the page to the table above and to the [documentation index](../README.md). Keep sections
that do not apply, with "None yet", so every module page reads the same way.

```markdown
# MN — Module name

| | |
|---|---|
| Status | In progress / Implemented |
| Semester | FYP-I or FYP-II (weeks …) |
| Owner(s) | … |
| Code | files |
| Tests | files |

## Purpose
The problem this module solves, in plain words, and the proposal's description of it.

## How it works
Concepts, rules and flows. Diagrams (Mermaid) for anything with more than three steps.

## Endpoints
Table of endpoints with caller and purpose; details go in docs/api-reference.md.

## Using it from other modules
The functions or dependencies other modules should call, with a short code example.

## Design decisions
Table: decision and why.

## Limitations and future work
What it does not do yet.
```
