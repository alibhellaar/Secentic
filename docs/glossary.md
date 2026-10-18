# Glossary

| Term | Meaning |
|---|---|
| **Agent** | An AI program that acts on its own: reads data, calls tools and APIs, takes actions. |
| **Administrator** | A human who manages Secentic with the admin token: approves agents, binds and revokes keys. |
| **Approval (of an agent)** | An administrator confirming an agent's owner and making it `active`. Different from M8's approval of individual actions. |
| **Assignment** | Permission for an agent to use a tool (M4). |
| **Audit trail** | A tamper-evident record of who did what and what was decided (M11, planned). |
| **Canonical request** | The exact bytes an agent signs: method, path, query, key ID, timestamp, nonce and body hash. See [M2](modules/m2-agent-identity.md#canonical-request). |
| **Control plane** | The part of Secentic that manages configuration and state: inventory, identity, policy, approvals. |
| **Data plane** | The part that handles live traffic: the runtime gateway (M5) that checks each agent action. |
| **Decision** | The gateway's answer to one requested action: ALLOW, DENY or REQUIRE APPROVAL, with reasons (M5). |
| **Decision log** | The record of every decision the gateway made (`GET /gateway/decisions`). |
| **Action** | A named operation an agent performs, such as `read` or `email.send`. Delegations list exact actions. |
| **Authority check** | The decision whether an agent may perform an action on a resource at a moment, with a reason. See [M3](modules/m3-delegated-authority.md#the-authority-check). |
| **Definition hash** | SHA-256 of a tool's reviewed fields; approving a tool names the hash that was reviewed (M4). |
| **Tool resources** | The resources a tool works on (`crm:*`); the gateway refuses any other resource for that tool (M4, M5). |
| **Canonical form** | The one spelling every resource and action is normalised to before it is stored or compared: `crm:accounts/42` (system, `:`, `/`-separated path), actions in lower case (M3). |
| **Delegated authority** | Permissions a human explicitly grants an agent for a task, scoped and time-limited. See [M3](modules/m3-delegated-authority.md). |
| **Delegation** | One grant of delegated authority: delegator, task, actions, resources and a time window. |
| **Delegator** | The human whose authority a delegation passes on, and who is accountable for it. |
| **Ed25519** | The digital-signature algorithm agents use (RFC 8032). |
| **Enrolment** | Binding a public key to an agent so it can authenticate. |
| **Environment** | Where an agent runs, e.g. `development` or `prod`. Part of its identity in the inventory. |
| **Effect** | What a policy rule does when it matches: `deny` or `require_approval` (M6). |
| **Fail closed** | Refusing when something is missing or broken, rather than allowing by default. |
| **Gateway** | The runtime security gateway (M5): agents ask it before each action. |
| **Fingerprint** | SHA-256 of an agent's name and environment, compared ignoring case and Unicode spelling differences; makes each agent one inventory record. |
| **Indirect prompt injection** | Instructions hidden in content an agent reads (an email, a web page) that try to take over its behaviour. |
| **Key ID** | SHA-256 (hex) of an agent's raw public key; names the key in requests. |
| **Key rotation** | An agent replacing its key with a new one; the old key stops working. |
| **Key revocation** | An administrator permanently withdrawing a key, e.g. after a compromise. |
| **MCP (Model Context Protocol)** | A standard way to connect AI agents to external tools and data servers. |
| **Nonce** | A random value used once per request, so a copied request can be recognised as a replay. |
| **Non-human identity** | An identity for software (here, an agent) rather than a person. |
| **Owner** | The person responsible for an agent. Claimed at self-registration, confirmed by an administrator. |
| **Policy** | The organisation's rules on top of delegations; they can only restrict (M6). |
| **Policy version** | One saved rule set; the highest is in force, and every decision records which it used. |
| **Pending review** | The status of a self-registered agent until an administrator approves or rejects it. |
| **Proof of possession** | A signature showing the sender holds the private key for a public key. |
| **Require approval** | A decision meaning "not without a person's approval": the agent must not proceed. |
| **Replay** | Re-sending a captured valid request to make it take effect again. |
| **Resource identifier** | The name of something an action touches, written `system:path`, e.g. `crm:accounts/42`. |
| **Resource pattern** | A resource identifier, or a prefix ending in `/*` or `:*`, used in delegations. |
| **Rug pull** | A tool or MCP server that changes what it does after it was reviewed; M4 resets its trust. |
| **Shadow agent** | An agent running in an organisation without being known to its security team. |
| **Small-order key** | A degenerate Ed25519 public key for which signatures can be forged; Secentic refuses them. |
| **Tool** | Anything an agent acts through: an API, a service or an MCP server, registered in M4. |
| **Trust state** | How far a tool is trusted: `trusted`, `unknown`, `suspicious` or `blocked` (M4). |
| **SDK** | The Python library agents use to sign requests (`secentic_sdk`). See [sdk.md](sdk.md). |
| **TOFU (trust on first use)** | Trusting the first key presented for a name until proven otherwise; applies to self-registration until review. |
