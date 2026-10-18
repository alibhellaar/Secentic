# M6 — Contextual Policy Engine

| | |
|---|---|
| Status | Implemented (core) |
| Semester | FYP-I (weeks 13–14) |
| Owners | Bakhtiar, Areeb (per proposal) |
| Code | `app/policy.py`, `app/routers/policy.py`, `PolicyVersion` in `app/models.py` |
| Tests | `tests/test_policy.py` |

## Purpose

Delegations (M3) say what a person allowed an agent to do. Organisations also need rules that hold
whoever delegated what: "nothing is deleted in production", "payments always need a person",
"agents in production do not send email", "nothing goes through a tool we have not reviewed". M6
evaluates such rules for every request, deterministically, and explains which rules decided.

From the proposal: *a deterministic policy evaluation engine that authorizes actions based on
agent, delegation, tool, resource, action, and environment, with basic policy versioning and
decision explanations.*

## Rules

```json
{
  "id": "crm-updates-need-approval",
  "description": "Changes to customer records need a person's approval",
  "effect": "require_approval",
  "when": {"actions": ["crm:update"]}
}
```

| Field | Meaning |
|---|---|
| `id` | Unique within the policy: 1–64 lowercase letters, digits or `-`. Named in every decision the rule affects. |
| `description` | Why the rule exists, shown in every decision it affects |
| `effect` | `deny` or `require_approval` |
| `when` | Conditions; the rule applies when **all** stated conditions match. With no conditions it applies to everything. |

| Condition | Matches when | Example |
|---|---|---|
| `agents` | the agent's name is listed, compared as the inventory compares names ([M1](m1-agent-inventory.md#deduplication)) | `["billing-bot"]` |
| `environments` | the agent's environment is listed, compared as the inventory compares them | `["prod"]` |
| `tools` | the tool is listed | `["crm", "mail"]` |
| `tool_trust` | the tool's trust state is listed | `["unknown", "suspicious"]` |
| `actions` | the action matches a pattern: exact, a prefix ending in `*`, or `*` for all | `["payments:*", "email.send"]` |
| `resources` | the resource matches a pattern: exact, a prefix ending in `*`, or `*` for all (ignoring case) | `["hr:*"]` |

Each condition lists 1–50 values. Unlike delegations, policy patterns may be broad (`*`,
`crm:acc*`): a rule only ever restricts, so a broad rule is a strict rule. Resource patterns still
refuse empty, `.` and `..` segments, and requests can only name resources in their normal form
(see [M3](m3-delegated-authority.md#resources-and-actions)), so a rule on `crm:accounts/secret*`
cannot be dodged with `crm:accounts//secret`. Delegations and policies use the same matching code.
Rules are saved in the same normalised form as everything else (see
[one spelling per resource](m3-delegated-authority.md#resources-and-actions)): action patterns in
lower case, resource patterns in the canonical spelling, so `crm:accounts:secret` cannot dodge a
rule on `crm:accounts/secret*`. One difference is deliberate: rules compare resources **ignoring
case**, so `crm:accounts/Secret` cannot dodge it either. A rule only restricts, so matching more
spellings makes it stricter; grants keep case because resource IDs are often case-sensitive.
Rules may name any environment (also free-text ones stored by older versions); agents' own
environments are plain ASCII names. Delegations and tool scopes, which grant, match exactly: there,
matching fewer spellings is the safe side.
Misspelt or unknown fields are refused (422), because a condition that
was silently ignored would make a rule apply to everything. A policy holds at most **200** rules,
and a `PUT /policy` request may be up to 1 MiB (every other request is limited to 64 KiB).

### Only restrictions

There is no `allow` effect. Delegations are the only thing that permits an action; policies can only
deny it or require approval. A mistake in a policy can therefore make the system stricter, never
more permissive, and "what may this agent do?" is always answered by its delegations.

## Evaluation

For a request (agent, environment, tool, tool trust, action, resource):

1. Find every rule whose conditions all match.
2. No match: the policy has nothing against it (`No rule in policy version 3 applies`).
3. Otherwise the most restrictive effect wins: **deny over require_approval**. Every matching rule
   is reported, in policy order, with its description.

Evaluation is pure and deterministic: the same request and the same policy version always give the
same answer, and nothing is learned or guessed.

## Versions

The policy is saved as a whole (`PUT /policy`, with a comment saying why). Each save creates a new
numbered version, in force immediately; earlier versions are never changed. Before the first save
the policy is version 0, with no rules. Every gateway decision records the version it used, so any
past decision can be explained with the exact rules that applied.

To go back, `POST /policy/versions/{version}/restore` saves an old version's rules as a **new**
version: history is never rewritten.

## Endpoints

Full details in the [API reference](../api-reference.md#policy-m6).

| Endpoint | Caller | Purpose |
|---|---|---|
| `GET /policy` | admin | the policy in force |
| `PUT /policy` | admin | save a new version |
| `GET /policy/versions` | admin | version history |
| `GET /policy/versions/{version}` | admin | one version |
| `POST /policy/versions/{version}/restore` | admin | bring an old version back, as a new version |

## Using M6 from other modules

```python
from app.policy import PolicyContext, evaluate_policy, version_in_force

saved = version_in_force(db)                  # or version_in_force(db, at) for another moment
version, rules = (saved.version, saved.rules) if saved else (0, [])
result = evaluate_policy(rules, version, PolicyContext(
    agent="billing-bot", environment="prod", tool="crm", tool_trust="trusted",
    action="crm:update", resource="crm:accounts/42"))
result.effect      # Decision.allow (nothing against it), Decision.require_approval or Decision.deny
result.reasons     # one line per matching rule
result.matched     # the matching rules
```

The gateway (M5) is the only caller today; the risk engine (M7) will add its own signals next to it.

## Design decisions

| Decision | Why |
|---|---|
| Rules restrict only | A policy error can never grant authority; delegations stay the single source of permission. |
| Deny over require_approval, every match reported | Deterministic, and the explanation shows everything that applied. |
| JSON rules, no code | Rules can be validated, stored, versioned and explained; nothing executes. |
| Unknown fields refused | A typo must not turn a narrow rule into one that applies to everything. |
| Whole-policy versions, append-only | Any decision can be traced to the exact rules in force; rollback keeps history. |

## Limitations and future work

- Conditions are positive matches; there is no "except" or "not" yet, and no conditions on time of
  day or data volume (the risk engine, M7, adds signals of that kind).
- Policy changes are made with the shared admin token; who changed what is recorded only by the
  comment until the audit log (M11).
