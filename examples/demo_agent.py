"""Demo agent: registers with Secentic, waits for an administrator to approve it, proves its
identity and rotates its key. Used by the walkthrough in docs/user-guide.md.

Run from the repository root while the server is running:

    python -m examples.demo_agent [--url http://localhost:8000] [--name demo-agent] [--environment development]

The private key is kept in demo-agent.pem (in the current directory) so the agent keeps its
identity across runs. Private keys must never be committed; *.pem is git-ignored.
"""
import argparse
import os
import time
from pathlib import Path

import httpx

from secentic_sdk import AgentKey, RotationInterrupted, SecenticClient


def save_key(path: Path, key: AgentKey) -> None:
    """Write the private key readable by the owner only, also when the file already existed with
    wider permissions (a mode given at creation would not apply to it)."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as file:
        os.chmod(path, 0o600)  # before writing: the file is still empty here
        file.write(key.to_pem())


def main() -> int:
    args = parse_args()
    try:
        return run(args)
    except httpx.HTTPStatusError as exc:
        print(f"Secentic refused a request ({exc.response.status_code}): {exc.response.text}")
    except httpx.RequestError as exc:
        print(f"Cannot reach Secentic at {args.url}: {exc}. Is the server running?")
    except KeyboardInterrupt:
        print("\nStopped.")
    return 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default="http://localhost:8000")
    parser.add_argument("--name", default="demo-agent")
    parser.add_argument("--environment", default="development")
    parser.add_argument("--owner", default=None, help="owner to claim (an admin confirms it)")
    parser.add_argument("--key-file", default="demo-agent.pem")
    return parser.parse_args()


def run(args: argparse.Namespace) -> int:
    key_path = Path(args.key_file)
    if key_path.exists():
        try:
            key = AgentKey.from_pem(key_path.read_bytes())
        except (ValueError, TypeError) as exc:
            print(f"Cannot load the private key in {key_path}: {exc}")
            return 1
        print(f"Loaded existing key from {key_path} (key id {key.key_id[:16]}...)")
    else:
        key = AgentKey.generate()
        save_key(key_path, key)
        print(f"Generated a new key and saved it to {key_path} (key id {key.key_id[:16]}...)")
    client = SecenticClient(args.url, key)

    # 1. Register (or, if this key is already enrolled, refresh last_seen).
    body = {"name": args.name, "environment": args.environment, "owner": args.owner, "public_key": key.public_key}
    response = client.request("POST", "/agents/register", body, params={"source": "sdk"})
    if response.status_code != 200:
        print(f"Registration refused ({response.status_code}): {response.json()['detail']}")
        return 1
    agent = response.json()
    print(f"Registered: agent id {agent['id']}, status {agent['status']}")

    # 2. Wait until an administrator approves the agent.
    told = False
    while True:
        response = client.request("GET", "/identity/whoami")
        if response.status_code == 200:
            break
        detail = response.json()["detail"]
        if response.status_code == 403 and detail == "Agent is pending_review":
            if not told:
                print("\nWaiting for approval. As an administrator, run in another terminal:\n")
                print(f'  curl -X POST -H "Authorization: Bearer $SECENTIC_ADMIN_TOKEN" \\\n'
                      f'       "{args.url}/agents/{agent["id"]}/approve?owner=<owner>"\n')
                told = True
            time.sleep(2)
            continue
        print(f"Cannot authenticate ({response.status_code}): {detail}")
        return 1
    me = response.json()
    print(f"Approved. Authenticated as '{me['name']}' owned by '{me['owner']}', status {me['status']}")

    # The agent holds only the authority humans delegated to it (M3).
    delegations = client.delegations()
    if not delegations:
        print("Delegated authority: none yet")
    for d in delegations:
        print(f"Delegated authority: {', '.join(d['actions'])} on {', '.join(d['resources'])} "
              f"for '{d['task']}' (from {d['delegator']}, until {d['expires_at']})")

    # Before acting, the agent asks the gateway (M5). Only "allow" means go ahead.
    for tool, action, resource in [("crm", "read", "crm:accounts/42"),
                                   ("mail", "email.send", "mail:outbox/attacker@evil.example")]:
        decision = client.authorize(tool, action, resource)
        print(f"Gateway: {decision['decision'].upper()} {tool} {action} {resource}")
        for reason in decision["reasons"]:
            print(f"    - {reason}")

    # 3. Rotate the key. The new key is saved before the request, so it cannot be lost.
    new_key = AgentKey.generate()
    new_path = key_path.with_name(key_path.name + ".new")
    save_key(new_path, new_key)
    try:
        client.rotate_key(new_key)
    except RotationInterrupted:
        print(f"Rotation outcome unknown. Both keys are kept ({key_path}, {new_path}); "
              "use whichever one /identity/whoami accepts.")
        return 1
    os.replace(new_path, key_path)
    print(f"Rotated key: {key.key_id[:16]}... -> {new_key.key_id[:16]}... (saved to {key_path})")
    print(f"whoami with the new key: active key id {client.whoami()['active_key_id'][:16]}...")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
