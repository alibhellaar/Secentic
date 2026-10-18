"""Keeps the documentation in step with the code.

A failure names the document to update. What to update for each kind of change is listed in
docs/development.md, "Keeping the docs up to date".
"""
import ast
import json
import os
import re
import stat
from pathlib import Path

import pytest

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app import crypto, delegation, identity, policy
from app.main import app
from secentic_sdk import AgentKey

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"
M2_PAGE = DOCS / "modules" / "m2-agent-identity.md"
M3_PAGE = DOCS / "modules" / "m3-delegated-authority.md"
M6_PAGE = DOCS / "modules" / "m6-policy-engine.md"
PAGES = [ROOT / "README.md", ROOT / "CHANGELOG.md", ROOT / "CLAUDE.md", *sorted(DOCS.rglob("*.md"))]

FENCED_BLOCK = re.compile(r"^```.*?^```", re.S | re.M)
LINK = re.compile(r"\[[^\]]*\]\(([^)\s]+)\)")
SETTING = re.compile(r"""os\.(?:getenv|environ\.get)\(\s*["']([A-Z][A-Z0-9_]*)""")


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def prose(path: Path) -> str:
    """The page without its fenced code blocks."""
    return FENCED_BLOCK.sub("", read(path))


def anchors(path: Path) -> set[str]:
    """GitHub's anchors for the page's headings."""
    headings = re.findall(r"^#{1,6} (.+)$", prose(path), re.M)
    return {re.sub(r"[^\w\- ]", "", h.strip().lower()).replace(" ", "-") for h in headings}


def documented_endpoints() -> set[str]:
    return set(re.findall(r"^### `([A-Z]+ /\S*)`$", read(DOCS / "api-reference.md"), re.M))


def app_endpoints() -> set[str]:
    # The OpenAPI schema lists every endpoint, however routers are nested.
    endpoints = {f"{method.upper()} {path}" for path, ops in app.openapi()["paths"].items() for method in ops}
    assert "GET /health" in endpoints and len(endpoints) > 1, "Could not list the app's endpoints"
    return endpoints


def settings_read_in(files) -> set[str]:
    return {name for f in files for name in SETTING.findall(read(f))}


def test_every_endpoint_is_documented():
    missing = app_endpoints() - documented_endpoints()
    assert not missing, f"Document these endpoints in docs/api-reference.md: {sorted(missing)}"


def test_every_documented_endpoint_exists():
    stale = documented_endpoints() - app_endpoints()
    assert not stale, f"docs/api-reference.md documents endpoints that no longer exist: {sorted(stale)}"


def test_every_setting_is_documented():
    server_files = list((ROOT / "app").rglob("*.py"))
    settings = settings_read_in(server_files + [ROOT / "tests" / "conftest.py"])
    assert settings, "No settings found; update SETTING in this test if settings are read differently now"

    guide = read(DOCS / "user-guide.md")
    undocumented = sorted(s for s in settings if f"| `{s}` |" not in guide)
    assert not undocumented, f"Add these settings to the configuration table in docs/user-guide.md: {undocumented}"

    example = read(ROOT / ".env.example")
    missing = sorted(s for s in settings_read_in(server_files) if f"\n{s}=" not in example)
    assert not missing, f"Add these settings to .env.example: {missing}"


def test_signing_parameters_match_the_m2_page():
    page = read(M2_PAGE)
    headers = [value for name, value in vars(identity).items() if name.startswith("HEADER_")]
    missing = [h for h in headers if f"`{h}`" not in page]
    assert not missing, f"Document these headers in {M2_PAGE.name}: {missing}"
    assert f"`{crypto.SIGNATURE_VERSION}`" in page, f"Update the protocol version in {M2_PAGE.name}"

    for name in ("MAX_CLOCK_SKEW", "NONCE_RETENTION", "NONCE_PURGE_INTERVAL"):
        value = getattr(identity, name)
        rows = [line for line in page.splitlines() if line.startswith("|") and f"`{name}`" in line]
        assert rows and f" {value} s" in rows[0], f"Set {name} to {value} s in the parameters table of {M2_PAGE.name}"


def test_delegation_limits_match_the_m3_page():
    days = delegation.MAX_DELEGATION_LIFETIME.days
    assert f"at most **{days} days** (`MAX_DELEGATION_LIFETIME`)" in read(M3_PAGE), (
        f"Set the maximum delegation lifetime to {days} days in {M3_PAGE.name} (and the user guide)"
    )


def test_policy_limits_match_the_m6_page():
    assert f"A policy holds at most **{policy.MAX_RULES}** rules" in read(M6_PAGE), (
        f"Set the maximum number of policy rules to {policy.MAX_RULES} in {M6_PAGE.name}"
    )


def test_m2_test_vector_matches_the_code():
    key = AgentKey(Ed25519PrivateKey.from_private_bytes(bytes(range(32))))
    body = json.dumps({"name": "vector-bot", "public_key": key.public_key}, separators=(",", ":")).encode()
    message = crypto.canonical_request(
        "POST", "/agents/register", "source=sdk", key.key_id, "1760000000", "test-vector-nonce-0001", body
    )
    signature = key.sign(message)
    assert crypto.verify_signature(key.public_key, signature, message)

    page = read(M2_PAGE)
    for label, value in (
        ("public key", key.public_key),
        ("key ID", key.key_id),
        ("body", body.decode()),
        ("canonical request", message.decode()),
        ("signature", signature),
    ):
        assert value in page, f"The {label} in the test vector of {M2_PAGE.name} no longer matches the code; regenerate it"


def test_tests_named_in_the_docs_exist():
    defined = {name for f in (ROOT / "tests").glob("test_*.py") for name in re.findall(r"^def (test_\w+)", read(f), re.M)}
    missing = sorted(
        f"{page.relative_to(ROOT)}: {name}"
        for page in PAGES
        for name in re.findall(r"`(test_\w+)`", read(page))
        if name not in defined
    )
    assert not missing, f"These tests are named in the docs but do not exist (renamed?): {missing}"


def test_every_page_is_in_the_index():
    index = read(DOCS / "README.md")
    missing = [
        page.relative_to(DOCS).as_posix()
        for page in DOCS.rglob("*.md")
        if page != DOCS / "README.md" and f"]({page.relative_to(DOCS).as_posix()})" not in index
    ]
    assert not missing, f"Link these pages from docs/README.md: {missing}"


def test_relative_links_resolve():
    broken = []
    for page in PAGES:
        for target in LINK.findall(prose(page)):
            if re.match(r"[a-z]+:", target):  # http:, https:, mailto:
                continue
            path, _, anchor = target.partition("#")
            destination = (page.parent / path).resolve() if path else page
            if not destination.exists():
                broken.append(f"{page.relative_to(ROOT)}: {target} (no such file)")
            elif anchor and destination.suffix == ".md" and anchor not in anchors(destination):
                broken.append(f"{page.relative_to(ROOT)}: {target} (no such section)")
    assert not broken, f"Broken links: {broken}"


@pytest.mark.skipif(os.name == "nt", reason="POSIX permissions")
def test_demo_saves_its_private_key_readable_by_the_owner_only(tmp_path):
    from examples.demo_agent import save_key
    path = tmp_path / "demo-agent.pem"
    path.write_bytes(b"")
    path.chmod(0o644)  # left over from somewhere, readable by everyone
    key = AgentKey.generate()
    save_key(path, key)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert AgentKey.from_pem(path.read_bytes()).key_id == key.key_id


def _error_messages() -> set[str]:
    """The fixed text of every error message the API returns: HTTPException details,
    _unauthorized(...), commit_or_409(...), get_or_404(...) and the module-level message constants
    they use."""
    messages, constants = set(), {}
    trees = [ast.parse(read(path)) for path in sorted((ROOT / "app").rglob("*.py"))]
    for tree in trees:
        for node in tree.body:
            if isinstance(node, ast.Assign) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
                for target in node.targets:
                    if isinstance(target, ast.Name) and target.id.isupper():
                        constants[target.id] = node.value.value

    def texts(node):
        for child in ast.walk(node):
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                yield child.value
            elif isinstance(child, ast.JoinedStr) and child.values and isinstance(child.values[0], ast.Constant):
                yield child.values[0].value
            elif isinstance(child, ast.Name) and child.id in constants and child.id.endswith(("REASON", "USED", "UNAVAILABLE")):
                yield constants[child.id]

    for tree in trees:
        for call in (n for n in ast.walk(tree) if isinstance(n, ast.Call)):
            name = getattr(call.func, "id", getattr(call.func, "attr", ""))
            if name == "HTTPException":
                args = [k.value for k in call.keywords if k.arg == "detail"]
            elif name == "_unauthorized":
                args = call.args[:1]
            elif name == "commit_or_409":
                args = call.args[1:2]
            elif name == "get_or_404":
                args = call.args[3:4] + [k.value for k in call.keywords if k.arg == "detail"]
            else:
                continue
            for arg in args:
                if isinstance(arg, ast.Name) and arg.id in constants:  # detail=SOME_MESSAGE
                    messages.add(constants[arg.id])
                    continue
                for text in texts(arg):
                    # In JoinedStr walks, inner constants are fragments; keep only real sentences.
                    if len(text) > 3 and text[0].isupper():
                        messages.add(text)
    return messages


def _head(message: str) -> str:
    """The part of a message the docs must quote: up to the first ';', '(' or ':' (docs may
    abbreviate what follows)."""
    return re.split(r"[;(:]", message)[0].strip()


def test_every_error_message_is_documented():
    reference, guide = read(DOCS / "api-reference.md"), read(DOCS / "user-guide.md")
    messages = _error_messages()
    assert len(messages) > 40  # the extraction works
    missing = {
        "docs/api-reference.md": sorted(m for m in messages if _head(m) not in reference),
        "docs/user-guide.md (troubleshooting)": sorted(m for m in messages if _head(m) not in guide),
    }
    assert missing == {page: [] for page in missing}, f"Document these error messages: {missing}"


def test_markdown_tables_are_not_broken_by_blank_lines():
    # A blank line inside a table ends it; every row after it renders as plain text. (Two tables in a
    # row are fine: the second starts with a header and a |---| separator.)
    separator = re.compile(r"^\|[\s:|-]+\|$")
    for path in PAGES:
        lines = prose(path).splitlines() + [""]
        for number, line in enumerate(lines[1:-2], start=2):
            if (not line.strip() and lines[number - 2].startswith("|") and lines[number].startswith("|")
                    and not separator.match(lines[number + 1])):
                raise AssertionError(f"{path.relative_to(ROOT)}: blank line inside a table near line {number}")
