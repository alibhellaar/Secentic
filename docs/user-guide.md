# User guide

How to install, configure and run Secentic, and how to use it as an administrator and from an
agent. If you want to know *what* Secentic is first, read [overview.md](overview.md).

## Contents

1. [Requirements](#requirements)
2. [Installation](#installation)
3. [Configuration](#configuration)
4. [Running the server](#running-the-server)
5. [Using PostgreSQL](#using-postgresql)
6. [Running the tests](#running-the-tests)
7. [Walkthrough: your first agent](#walkthrough-your-first-agent)
8. [Administrator tasks](#administrator-tasks)
9. [Connecting your own agent](#connecting-your-own-agent)
10. [Troubleshooting](#troubleshooting)

## Requirements

- Python 3.10 or newer, and `git`
- `curl` (or any HTTP client) for the administrator examples
- Optional: PostgreSQL 14 or newer. SQLite, which needs no setup, is fine for development.

The shell examples use bash. On Windows, run them in Git Bash or WSL.

## Installation

```bash
git clone https://github.com/SickTyphon/Secentic.git
cd Secentic
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -r requirements.txt
```

## Configuration

Settings are read from environment variables, or from a `.env` file in the project root (the
folder containing `requirements.txt`), wherever you start the server from. Variables already set
in the environment take precedence over `.env`. Start from the example:

```bash
cp .env.example .env               # Windows: copy .env.example .env
python -c "import secrets; print(secrets.token_urlsafe(32))"
```

Paste the printed value into `.env` as `SECENTIC_ADMIN_TOKEN`. Keep it secret: anyone holding it
can administer every agent.

| Variable | Required | If missing | Meaning |
|---|---|---|---|
| `DATABASE_URL` | yes | the server refuses to start | SQLAlchemy URL of the database: `sqlite:///./secentic.db`, or `postgresql+psycopg://user:password@host:5432/dbname` |
| `SECENTIC_ADMIN_TOKEN` | for admin endpoints | admin endpoints answer 503 | Bearer token for administrators; at least 16 characters, shorter values are refused |
| `TEST_DATABASE_URL` | no (tests only) | each test uses a temporary SQLite file | Run the test suite against another database, e.g. PostgreSQL. Its tables are dropped after every test, so never point it at real data. |

`.env` is read when the server starts; restart the server after editing it.

## Running the server

```bash
uvicorn app.main:app --reload      # add --host 0.0.0.0 to accept connections from other machines
```

- Health check: `curl http://localhost:8000/health` returns `{"status":"ok"}`.
- Interactive API documentation: <http://localhost:8000/docs>. Click **Authorize** and paste the
  admin token to try the administrator endpoints. Agent endpoints need signed requests, which the
  browser cannot produce; use the [SDK](sdk.md) for those.

On first start the tables are created automatically. With the example `DATABASE_URL`, the SQLite
file `secentic.db` is created in the directory the server is started from (normally the project
root). To start again from an empty development database, stop the server and delete that file.

> For anything beyond local development, run Secentic behind HTTPS. Signatures protect agent
> requests from tampering, but the admin token travels in a header and must not be sent in clear text.

## Using PostgreSQL

Create a database and user, for example:

```bash
sudo -u postgres createuser --pwprompt secentic
sudo -u postgres createdb --owner secentic secentic
```

or with Docker:

```bash
docker run --name secentic-db -e POSTGRES_USER=secentic -e POSTGRES_PASSWORD=secentic \
  -e POSTGRES_DB=secentic -p 5432:5432 -d postgres:16
```

Then set in `.env`:

```
DATABASE_URL=postgresql+psycopg://secentic:secentic@localhost:5432/secentic
```

The `postgresql+psycopg://` prefix selects the `psycopg` driver installed by `requirements.txt`.

## Running the tests

```bash
pytest                    # every test gets its own temporary SQLite database
pytest tests/test_identity.py -k rotation      # a subset
```

To run the same tests on PostgreSQL, create an empty database and:

```bash
TEST_DATABASE_URL=postgresql+psycopg://secentic:secentic@localhost:5432/secentic_test pytest
```

The tests never touch the database in `DATABASE_URL`. `tests/test_docs.py` also checks that this
documentation still matches the code; see [development.md](development.md#keeping-the-docs-up-to-date).

## Walkthrough: your first agent

This takes about fifteen minutes and shows M1 to M6 working together: an agent registers itself,
an administrator approves it, the agent proves its identity and rotates its key, receives narrowly
scoped authority and tools, and the gateway decides what it may do. You need three terminals, each
in the project directory with the virtual environment activated.

**Terminal 1: the server**

```bash
uvicorn app.main:app
```

**Terminal 2: the agent.** The demo agent creates a key pair (saved to `demo-agent.pem`),
registers, and waits for approval:

```bash
python -m examples.demo_agent --owner ali
```

```
Generated a new key and saved it to demo-agent.pem (key id 2a71af5264016631...)
Registered: agent id 0453f248-9520-4618-a7d1-5256c884d4a9, status pending_review

Waiting for approval. As an administrator, run in another terminal:
...
```

The agent is in the review queue: the owner it claimed is recorded, but nobody has confirmed it.

**Terminal 3: the administrator.** Load the admin token into the shell, look at the review queue,
then approve the agent (use the agent id the demo printed):

```bash
set -a; source .env; set +a
export ADMIN="Authorization: Bearer $SECENTIC_ADMIN_TOKEN"

curl -s -H "$ADMIN" http://localhost:8000/agents/review-queue | python -m json.tool
curl -s -X POST -H "$ADMIN" "http://localhost:8000/agents/<agent id>/approve?owner=ali" | python -m json.tool
```

Back in terminal 2 the agent notices it was approved and authenticates. It holds no authority yet,
so when it asks the gateway about two actions, both are denied. Then it rotates its key:

```
Approved. Authenticated as 'demo-agent' owned by 'ali', status active
Delegated authority: none yet
Gateway: DENY crm read crm:accounts/42
    - Agent 'demo-agent' is not allowed to use tool 'crm'
Gateway: DENY mail email.send mail:outbox/attacker@evil.example
    - Agent 'demo-agent' is not allowed to use tool 'mail'
Rotated key: 2a71af5264016631... -> a105afad263481ef... (saved to demo-agent.pem)
whoami with the new key: active key id a105afad263481ef...
```

Look at the agent's key history from terminal 3. There is one `rotated` key and one `active` key:

```bash
curl -s -H "$ADMIN" http://localhost:8000/agents/<agent id>/keys | python -m json.tool
```

Now give the agent some authority. In terminal 3, delegate read access to CRM accounts for one
week, on Ali's behalf, then ask Secentic what the agent may do:

```bash
EXPIRES=$(python -c "from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) + timedelta(days=7)).replace(microsecond=0).isoformat())")
curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" -d @- \
  http://localhost:8000/agents/<agent id>/delegations <<EOF | python -m json.tool
{"delegator": "ali", "task": "Prepare the monthly sales report",
 "actions": ["read"], "resources": ["crm:accounts/*"], "expires_at": "$EXPIRES"}
EOF

curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" \
  -d '{"action": "read", "resource": "crm:accounts/42"}' http://localhost:8000/agents/<agent id>/check-authority
curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" \
  -d '{"action": "write", "resource": "crm:accounts/42"}' http://localhost:8000/agents/<agent id>/check-authority
```

The first check is allowed and names the delegation, the task and Ali; the second is denied with
`No delegation in force grants the action 'write'`. Everything not delegated is denied.

Finally, register the tools the agent works with, mark the CRM as reviewed, and let the agent use
both. Each tool states the actions it performs and the resources it works on (`crm:*`): the
gateway never lets a tool act on another system's data, even if that data was delegated. Approving a tool names the exact definition that was reviewed (its `definition_hash`), so an
approval can never apply to a definition that changed in the meantime. The mail tool stays `unknown`:

```bash
HASH=$(curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" http://localhost:8000/tools \
  -d '{"name": "crm", "kind": "tool", "provider": "internal", "endpoint": "https://crm.internal.example/api", "version": "2.1.0", "capabilities": ["read", "crm:update"], "resources": ["crm:*"]}' \
  | python -c "import sys, json; print(json.load(sys.stdin)['definition_hash'])")
curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" http://localhost:8000/tools/crm/trust \
  -d "{\"trust_state\": \"trusted\", \"reviewed_definition\": \"$HASH\", \"reason\": \"Reviewed by the security team\"}"
curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" http://localhost:8000/tools \
  -d '{"name": "mail", "kind": "mcp_server", "provider": "acme", "endpoint": "stdio: npx @acme/mail-mcp", "version": "0.4.0", "capabilities": ["email.send"], "resources": ["mail:*"]}'
curl -s -X PUT -H "$ADMIN" http://localhost:8000/agents/<agent id>/tools/crm
curl -s -X PUT -H "$ADMIN" http://localhost:8000/agents/<agent id>/tools/mail
```

Run the demo again. It reuses `demo-agent.pem`, so the registration is accepted as the same agent
(signed with the enrolled key) and no approval is needed. This time the gateway allows reading the
CRM, and still denies the email: the agent has the mail tool, but nobody delegated sending email.
That is what stops an agent that was talked into mailing data away:

```
Delegated authority: read on crm:accounts/* for 'Prepare the monthly sales report' (from ali, until 2026-10-13T06:50:57Z)
Gateway: ALLOW crm read crm:accounts/42
    - Tool 'crm' (trusted) is assigned to the agent and provides 'read' on 'crm:accounts/42'
    - Allowed by delegation 824d754c-...: task 'Prepare the monthly sales report', delegated by ali, valid until 2026-10-13T06:50:57Z
    - No rule in policy version 0 applies
Gateway: DENY mail email.send mail:outbox/attacker@evil.example
    - No delegation in force grants the action 'email.send'
```

Every decision is in the log: `curl -s -H "$ADMIN" http://localhost:8000/gateway/decisions | python -m json.tool`.

## Administrator tasks

All administrator requests carry the token. The examples assume the shell setup from the
walkthrough (`$ADMIN`), with the server at `http://localhost:8000`. Full details of every
endpoint are in [api-reference.md](api-reference.md).

### See the inventory

```bash
curl -s -H "$ADMIN" http://localhost:8000/agents                        # every agent
curl -s -H "$ADMIN" "http://localhost:8000/agents?status=disabled"       # filter by status
curl -s -H "$ADMIN" http://localhost:8000/agents/review-queue             # waiting for review
curl -s -H "$ADMIN" http://localhost:8000/agents/<agent id>               # one agent
```

`active_key_id` shows whether an agent has a cryptographic identity, and which key it is.

### Review a self-registered agent

Before approving, confirm with the agent's operator, out of band, that the agent is theirs and
that its `active_key_id` matches their key. Then either approve it, confirming the owner:

```bash
curl -s -X POST -H "$ADMIN" "http://localhost:8000/agents/<agent id>/approve?owner=<owner>"
```

or reject the registration. This deletes the record and frees the name (its key can never be used
again), which is the
fix when someone registered under another team's agent name:

```bash
curl -s -X DELETE -H "$ADMIN" http://localhost:8000/agents/<agent id>
```

### Onboard an agent yourself

Create the agent already approved, then bind the public key its operator gives you:

```bash
curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" \
  -d '{"name": "ops-bot", "owner": "bakhtiar", "environment": "prod"}' http://localhost:8000/agents

curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" \
  -d '{"public_key": "<base64 public key>"}' http://localhost:8000/agents/<agent id>/keys
```

The operator can create a key file and print its public key with (where the SDK is importable, e.g.
in the project directory with the virtual environment active):

```bash
python -c "from secentic_sdk import AgentKey; k = AgentKey.generate(); open('ops-bot.pem', 'wb').write(k.to_pem()); print(k.public_key)"
chmod 600 ops-bot.pem
```

### Change an agent's owner

```bash
curl -s -X PUT -H "$ADMIN" -H "Content-Type: application/json" \
  -d '{"owner": "areeb"}' http://localhost:8000/agents/<agent id>/owner
```

### Disable, deactivate or re-enable an agent

`disabled` (for example, suspected misuse) and `inactive` (decommissioned) both stop the agent from
authenticating immediately; `active` restores it:

```bash
curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" \
  -d '{"status": "disabled"}' http://localhost:8000/agents/<agent id>/status
```

### Respond to a compromised key

Revoke the key. It stops working at once and can never be bound again:

```bash
curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" \
  -d '{"reason": "key leaked in CI logs"}' http://localhost:8000/agents/<agent id>/keys/<key id>/revoke
```

To bring the agent back, the operator generates a new key pair and you bind its public key with
`POST /agents/<agent id>/keys`, as in [Onboard an agent yourself](#onboard-an-agent-yourself).

### Delegate authority to an agent

An agent can do nothing until a person delegates authority to it for a task. Grant only what the
task needs: exact action names, the narrowest resources that work, and a short expiry (at most 30
days). The [M3 page](modules/m3-delegated-authority.md#resources-and-actions) explains resource
patterns such as `crm:accounts/*`.

```bash
EXPIRES=$(python -c "from datetime import datetime, timedelta, timezone; print((datetime.now(timezone.utc) + timedelta(days=7)).replace(microsecond=0).isoformat())")
curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" -d @- \
  http://localhost:8000/agents/<agent id>/delegations <<EOF
{"delegator": "ali", "task": "Prepare the monthly sales report",
 "actions": ["read"], "resources": ["crm:accounts/*", "crm:reports/2026-09"],
 "expires_at": "$EXPIRES"}
EOF
```

`delegator` is the person whose authority this is: they are accountable for what the agent does
with it. Add `"starts_at"` to make it begin later (never earlier: a delegation cannot be
backdated). The agent must be approved first. Resources and actions are stored in one spelling:
`crm:accounts:42` becomes `crm:accounts/42`, `READ` becomes `read`.

### Check what an agent may do

Ask whether an agent may perform an action on a resource. The answer always comes with a reason:

```bash
curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" \
  -d '{"action": "read", "resource": "crm:accounts/42"}' http://localhost:8000/agents/<agent id>/check-authority
```

Add `"at": "<timestamp>"` to ask about another moment, for example whether access will still be
allowed next week. Nothing is executed; the M5 gateway will make the same decision for real actions.

### Review and revoke delegations

```bash
curl -s -H "$ADMIN" http://localhost:8000/agents/<agent id>/delegations                 # all
curl -s -H "$ADMIN" "http://localhost:8000/agents/<agent id>/delegations?state=active"  # in force
curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" \
  -d '{"reason": "report delivered"}' http://localhost:8000/agents/<agent id>/delegations/<delegation id>/revoke
```

Revocation is immediate and permanent. To extend authority, create a new delegation, so each grant
keeps its own record.

### Register and review tools

Register every tool and MCP server agents may use. A new tool is `unknown`, and every use of it
needs a person's approval until someone reviews it ([M4](modules/m4-agent-tool-registry.md)).
Review the definition you get back, then approve exactly that definition by sending its
`definition_hash`; if the tool changed in the meantime, the approval is refused (409):

```bash
curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" http://localhost:8000/tools \
  -d '{"name": "github-mcp", "kind": "mcp_server", "provider": "github", "endpoint": "stdio: npx @modelcontextprotocol/server-github", "version": "1.0.0", "capabilities": ["github.read_repo", "github.create_issue"], "resources": ["github:*"]}'
HASH=$(curl -s -H "$ADMIN" http://localhost:8000/tools/github-mcp | python -c "import sys, json; print(json.load(sys.stdin)['definition_hash'])")
curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" http://localhost:8000/tools/github-mcp/trust \
  -d "{\"trust_state\": \"trusted\", \"reviewed_definition\": \"$HASH\", \"reason\": \"Reviewed by the security team\"}"
curl -s -H "$ADMIN" "http://localhost:8000/tools?trust_state=unknown"     # what still needs review
```

Use `suspicious` while investigating a tool (every use needs approval) and `blocked` to stop it
completely. Updating a trusted tool's version, endpoint, provider, kind, capabilities or resources with
`PUT /tools/<name>` sets it back to `unknown`, so review it again after every change.

### Give an agent tools

```bash
curl -s -X PUT -H "$ADMIN" http://localhost:8000/agents/<agent id>/tools/github-mcp     # allow
curl -s -X DELETE -H "$ADMIN" http://localhost:8000/agents/<agent id>/tools/github-mcp  # take away
curl -s -H "$ADMIN" http://localhost:8000/agents/<agent id>/tools                       # list
```

An agent also needs a delegation for the actions it performs with a tool: the tool says what is
*possible*, the delegation what is *permitted*.

### Set the policy

Policy rules apply to every agent's requests on top of delegations, and can only deny or require
approval ([M6](modules/m6-policy-engine.md)). The policy is replaced as a whole and every save is a
new version:

```bash
curl -s -X PUT -H "$ADMIN" -H "Content-Type: application/json" http://localhost:8000/policy -d @- <<EOF
{"comment": "CRM updates need a person; production agents send no email",
 "rules": [
  {"id": "crm-updates-need-approval", "description": "Changes to customer records need a person's approval",
   "effect": "require_approval", "when": {"actions": ["crm:update"]}},
  {"id": "no-email-in-prod", "description": "Agents in production do not send email",
   "effect": "deny", "when": {"environments": ["prod"], "actions": ["email.*"]}}
 ]}
EOF
curl -s -H "$ADMIN" http://localhost:8000/policy/versions                         # history
curl -s -X POST -H "$ADMIN" http://localhost:8000/policy/versions/1/restore       # go back to version 1
```

### Check decisions

See what the gateway decided, newest first, or ask what it *would* decide without recording anything:

```bash
curl -s -H "$ADMIN" "http://localhost:8000/gateway/decisions?decision=deny&limit=20" | python -m json.tool
curl -s -X POST -H "$ADMIN" -H "Content-Type: application/json" http://localhost:8000/gateway/simulate \
  -d '{"agent_id": "<agent id>", "tool": "crm", "action": "crm:update", "resource": "crm:accounts/42"}'
```

Every decision lists its reasons in order; the first one of a DENY is what stopped it.

## Connecting your own agent

Agents talk to Secentic through the Python SDK in `secentic_sdk/` (reference: [sdk.md](sdk.md)).
Put the project root on `PYTHONPATH` so your agent can import it, e.g.
`PYTHONPATH=/path/to/Secentic python my_agent.py`. Agents in other languages can implement the
signing protocol described in
[modules/m2-agent-identity.md](modules/m2-agent-identity.md#request-signing-protocol).

```python
from pathlib import Path
from secentic_sdk import AgentKey, RotationInterrupted, SecenticClient

key_file = Path("my-agent.pem")
if key_file.exists():
    key = AgentKey.from_pem(key_file.read_bytes())
else:
    key = AgentKey.generate()
    key_file.write_bytes(key.to_pem())          # keep this file private (chmod 600)

client = SecenticClient("http://localhost:8000", key)
client.register("my-agent", environment="prod", owner="ali")   # waits in pending_review

# Once an administrator has approved the agent (until then whoami raises an HTTP 403 error):
me = client.whoami()
authority = client.delegations()      # what humans have delegated to this agent, in force now
tools = client.tools()                # the tools it may use

# Before every consequential action, ask the gateway, and act only if it allows:
client.ensure_allowed("crm", "read", "crm:accounts/42")    # raises ActionNotAllowed otherwise
```

Rules an agent must follow:

- **Keep the private key secret and persistent.** It *is* the agent's identity. If it is lost,
  an administrator has to bind a new key.
- **Keep the clock in sync** (NTP). Requests whose timestamp is more than 5 minutes off are refused.
- **Rotate keys safely**: save the new key before rotating, and handle an interrupted rotation:

  ```python
  new_key = AgentKey.generate()
  Path("my-agent.pem.new").write_bytes(new_key.to_pem())
  try:
      client.rotate_key(new_key)
      Path("my-agent.pem.new").replace(key_file)
  except RotationInterrupted:
      pass   # outcome unknown: keep both files; whoami shows which key is active
  ```

- **Register once.** Re-registering is allowed only with the enrolled key (it refreshes
  `last_seen`); there is no need to do it on every start.
- **Ask before every consequential action** with `ensure_allowed`, and treat anything but `allow`
  (including a 503 from the gateway) as "do not act".

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Server exits with `RuntimeError: DATABASE_URL is not set` | No `.env` in the project root, or it lacks `DATABASE_URL` | Create `.env` from `.env.example` in the project root (a `.env` elsewhere is not read) |
| Server exits with `The inventory already holds duplicate agents ...` | A database from the first M1 version contains the same agent twice | Delete the duplicate rows, or the development database |
| `ModuleNotFoundError: No module named 'app'` (or `secentic_sdk`) | The project root is not on Python's import path | Run the server, tests and `python -m` commands from the project root; for your own agent scripts, set `PYTHONPATH` to the project root |
| 503 `Admin access is disabled: set SECENTIC_ADMIN_TOKEN ...` | Token unset or shorter than 16 characters | Set a long random token in `.env` and restart |
| 401 `Invalid admin token` | Missing or wrong `Authorization` header | Send `Authorization: Bearer <token>` with the exact value from `.env` |
| 401 `Missing signature headers (...)` | Agent endpoint called without signing | Use the SDK, or implement the signing protocol |
| 401 `Request timestamp is outside the accepted window` | Agent clock more than 5 minutes off | Synchronise the clock |
| 401 `Nonce has already been used (replayed request)` | The same signed request sent twice | Sign every request afresh (the SDK does this) |
| 401 `Invalid signature` | Path, query or body changed after signing (e.g. a proxy rewriting the path), the wrong key, or a key this server does not know (never bound, or the database was reset) | Sign exactly what is sent; check proxies; register, or ask an admin to bind the key |
| 401 `Key has been rotated` / `Key has been revoked` | Using an old or withdrawn key | Load the current key; after revocation, ask an admin to bind a new one |
| 403 `Agent is pending_review` | Not approved yet | An administrator approves it |
| 403 `Agent is disabled` / `Agent is inactive` | Switched off by an administrator | An administrator sets it back to `active` |
| 409 `Agent is already registered; ...` | That name and environment already exist | If it is your agent, register with its enrolled key; if someone else took the name, ask an admin to reject that registration |
| 409 `This public key has already been used; ...` | Reusing a key that was bound before | Generate a new key pair |
| 409 `Agent already has an active key; revoke it first` | Binding a second key | Revoke the current key first |
| 422 `... must be a base64-encoded 32-byte Ed25519 public key (...)` | Malformed or weak public key | Send the base64 of the raw 32-byte key (`AgentKey.public_key`) |
| 409 `Pending agents cannot receive authority; approve the agent first` | Delegating to an agent still in review | Approve the agent, then delegate |
| 422 `'*' is only allowed at the end, right after '/' or ':', following a system name ...` | Blanket or malformed resource pattern | Name the resources, or use a prefix such as `crm:accounts/*` |
| 422 `resource must not contain '.' or '..' path segments` | Path traversal in a resource | Use the resource's real path |
| 422 `resource must not contain empty segments (...)` | A doubled, leading or trailing `/` or `:` | Write the resource in its normal form, e.g. `crm:accounts/42` |
| 422 `action must be a name such as 'read' ...` | Wildcard or malformed action | List exact action names |
| 422 `must be an RFC 3339 timestamp with a timezone, ...` | A time without a timezone, a number (or number string), or a looser form such as `2026-10-13 09:00Z` | Send e.g. `2026-10-13T09:00:00Z`; Python's `datetime.isoformat()` on an aware datetime produces it |
| 422 `timestamp is out of range` | A time so close to year 1 or 9999 that it has no UTC equivalent | Use a realistic time |
| 422 `must not contain control or invisible formatting characters (...)` | A line break, tab, control character, or an invisible character (zero-width, bidirectional control, variation selector, filler, ...) in a name, owner, task or reason; often pasted in by accident | Retype the value; these fields are single-line, visible text |
| 422 `String should have at most 200 characters` (or 500) | Text longer than its limit | Shorten it; see the [API conventions](api-reference.md#conventions) |
| 404 `Not Found` (not `Agent not found`) | The ID in the URL is malformed, so no endpoint matches | Copy the ID exactly from an earlier response |
| 405 `Method Not Allowed` | Wrong HTTP method for that path | The `Allow` response header lists the right ones |
| 422 `must not start or end with a space` | A name, owner, task or reason with a leading or trailing space | Remove the spaces; values are stored exactly as sent |
| 413 `Request body too large (limit 65536 bytes)` | Request body over 64 KiB | Send less; no valid request comes close to the limit |
| 413 `Request body too large (limit 1048576 bytes)` | A policy over 1 MiB | Shorten descriptions or merge rules |
| 422 `starts_at must not be in the past: a delegation cannot be backdated` | A `starts_at` earlier than now | Leave it out (it defaults to now) or choose a later time |
| 422 `a delegation may last at most 30 days` / `expires_at must be after starts_at` | Window too long, or already over | Choose an expiry in the future, within 30 days of the start |
| 409 `Delegation is already revoked` | Revoking twice | Nothing to do; create a new delegation if authority is needed again |
| A check says `allowed: false` | Nothing in force grants it | Read `reason`: it says whether the action, the resource or the time window is the problem |
| Gateway DENY `Agent 'a' is not allowed to use tool 'x'` | The tool is not assigned to the agent, or not registered at all (agents get the same answer for both) | Register it if needed, and assign it with `PUT /agents/<id>/tools/<name>` |
| Gateway DENY `Tool 'x' does not provide the action 'y'` | The action is not in the tool's capabilities | Use the right tool, or update the tool's definition (which needs a new review) |
| Gateway DENY `Tool 'x' does not work on 'r'` | The resource is outside the tool's `resources` | Use the tool for that system, or add the resource to the tool's definition (which needs a new review) |
| 401 `Timestamp must be integer Unix seconds` / `Nonce must be 16-128 URL-safe characters` / `Key ID must be 64 lowercase hexadecimal characters` / `Signature must be 88 base64 characters (an Ed25519 signature)` | A malformed signature header (a client bug, or a proxy changing headers) | Send the headers exactly as the SDK produces them |
| 401 `Request must be signed with the key being presented` / `Signature key ID does not match the key being presented` | A registration with `public_key` that is unsigned, or signed with another key | Sign the registration with the key being enrolled (the SDK does) |
| 401 `A signed registration must include the public_key it was signed with; only an existing agent's enrolled key can sign without it` | A signed registration for a new name, without the key | Send `public_key` (the SDK does), or check the name and environment if you meant an existing agent |
| 401 `Missing or invalid proof of possession for the new key` | A rotation without a valid `X-Secentic-Proof` | Sign the request with the new key too (`rotate_key` does) |
| 404 `Key not found` / `Delegation not found` / `Tool not found` / `Policy version not found` | Wrong ID or name, or it belongs to another agent | Copy it from a listing |
| 404 `The agent is not assigned this tool` | Taking away a tool the agent does not have | Nothing to do |
| 409 `Agent is already in the inventory` | Onboarding a name and environment that already exist | Use the existing record |
| 409 `Only pending registrations can be rejected; disable approved agents instead` | Rejecting an approved agent | Set its status to `disabled` |
| 409 `Only pending_review agents can be approved (agent is ...)` | Approving an agent that is not pending | Change an owner with `PUT /agents/<id>/owner` |
| 409 `Pending agents get their owner through /approve` / `Pending agents must be approved via /approve first` | Changing the owner or status of an agent still in review | Approve it first |
| 409 `The agent's keys changed concurrently; ...` / `The agent's tools changed concurrently; ...` / `The key was rotated by a concurrent request` / `The policy was changed concurrently; ...` / `The registration was rejected concurrently; ...` / `The tool changed while the review was being recorded; ...` | Two requests changed the same thing at the same moment | Reload it and try again |
| 422 `environment must be 1-64 ASCII letters, ...` | An environment with spaces, other scripts or symbols | Use a plain name such as `prod` or `eu-west-1` |
| 503 `The database could not complete the request; ...` | The database is unreachable or failing | Check the database and the server log; agents must not act meanwhile |
| 409 `The registration was approved or rejected while this rejection was in progress; ...` | Two administrators acted on the same agent at once | Reload it; nothing was changed |
| Gateway REQUIRE APPROVAL `Tool 'x' is unknown: ...` | The tool was never reviewed, or its definition changed | Review it and record `trusted` with `POST /tools/<name>/trust` |
| Gateway REQUIRE APPROVAL or DENY naming a `Policy rule` | A policy rule applies | That is the policy working; change the policy if the rule is wrong |
| 503 `The gateway could not reach a decision; failing closed (deny)` | Internal error (database, corrupt policy) | Check the server log; the agent must not act meanwhile |
| 409 `A tool with this name is already registered` | Name taken | Pick another name, or update the existing tool |
| 409 `The tool's current definition is not the one you reviewed; ...` | The tool changed after you looked at it | Look at it again (`GET /tools/<name>`) and approve its current `definition_hash` |
| 422 when marking a tool trusted | `reviewed_definition` missing | Send the `definition_hash` of the definition you reviewed |
| 403 `Agent is disabled` on registration | The agent was switched off; re-registering does not bring it back | An administrator sets it back to `active` |
| 409 `Key is not active (rotated); the agent's active key is ...` when revoking | The key was rotated (by the agent, or by someone holding a stolen key) | Revoke the key it names, or disable the agent first |
| 409 `The tool changed while it was being updated; ...` | A review or another update landed at the same moment | Reload the tool and send the update again |
| 409 `This public key has already been used; ...` after a rejection | The key belonged to a rejected registration and is retired | Generate a new key pair |
| 409 `The key was revoked or rotated while this rotation was in progress; ...` | An administrator revoked the key during the rotation | Ask an administrator; if the key was revoked on purpose, a new key must be bound |
| 409 `Tool is blocked` / `Pending agents cannot be given tools; ...` | Assigning a blocked tool, or to a pending agent | Unblock after review, or approve the agent first |
| 422 `Extra inputs are not permitted` (in a policy rule) | A misspelt condition or field | Use only the documented conditions: agents, environments, tools, tool_trust, actions, resources |
| 422 `rule ids must be unique` | Two rules with the same `id` | Rename one |
