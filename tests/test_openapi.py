"""The OpenAPI schema (/openapi.json) must describe the API exactly: clients and fuzzers rely on it.

Each pattern published in the schema is compared with the validator that enforces it, on targeted
edge cases and on thousands of random strings, so the two cannot drift apart.
"""
import random
import re

import pytest

from app.delegation import validate_action, validate_resource, validate_resource_pattern
from app.policy import validate_policy_action, validate_policy_resource, validate_rule_id
from app.tools import validate_tool_name
from app.main import app
from app.schemas import (
    AgentRegisterRequest, AuthorityCheckRequest, DelegationCreate, OwnerUpdate, PolicyRule, RevokeRequest, RuleConditions,
    ToolCreate, validate_environment,
)

SCHEMA = app.openapi()
COMPONENTS = SCHEMA["components"]["schemas"]
SIGNATURE_SCHEMES = {name for name in SCHEMA["components"]["securitySchemes"] if name.startswith("AgentSignature")}
OPERATIONS = [(path, method, op) for path, ops in SCHEMA["paths"].items() for method, op in ops.items()]


def field_schema(model, field):
    # Older FastAPI names a model used in both requests and responses "<Name>-Input" / "-Output".
    component = COMPONENTS.get(model.__name__) or COMPONENTS[f"{model.__name__}-Input"]
    schema = component["properties"][field]
    if "anyOf" in schema:  # optional fields: [the type, null]
        schema = next(s for s in schema["anyOf"] if s.get("type") != "null")
    if schema.get("type") == "array":
        schema = schema["items"]
    return schema


def schema_accepts(schema, value: str) -> bool:
    # JSON Schema patterns use ECMA-262 semantics, where "$" matches only at the very end;
    # fullmatch gives the same result for these anchored patterns.
    return (schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", 10**9)
            and re.fullmatch(schema["pattern"], value) is not None)


def validator_accepts(validate, value: str) -> bool:
    try:
        validate(value)
    except ValueError:
        return False
    return True


def model_accepts(model, field, value, **other_fields) -> bool:
    try:
        model.model_validate({field: value} | other_fields)
    except ValueError:  # pydantic.ValidationError is a ValueError
        return False
    return True


ALPHABET = ("abcXYZ019._~@+=,-/:*% \t\n\x00\x7fé\u00a0\u2028\u200b\u202e\x85\u00ad\u3000"
            "\u061c\u180e\U000e0041\u034f\ufe0f\u3164\u2800\U000f0000\ufdd0🚀サ")
EDGE_CASES_EXTRA = ["crm", "github-mcp", "a.b_c-d", "-crm", "Crm", "c" * 64, "c" * 65, "payments:*", "pay*", "**", "*x",
                    "crm:acc*", "hr:*", "x/*/y"]


def random_strings(seed: int, count: int, max_length: int):
    rng = random.Random(seed)
    for _ in range(count):
        length = rng.choice([0, 1, 2, 3, 5, 8, 20, max_length - 1, max_length, max_length + 1])
        yield "".join(rng.choice(ALPHABET) for _ in range(max(length, 0)))


EDGE_CASES = [
    "", " ", "a", " a", "a ", "a b", ".", "..", "...", ".a", "a.", "..a", "crm:accounts/42", "crm:../x",
    "crm:..", "crm:./x", "x//y", "a:/b", "crm:*", "crm:accounts/*", "*", "/*", ":*", "crm:acc*", "/crm/*",
    "crm:../*", "a.b:*", "-/*", "crm:*/x", "crm:%2e%2e", "read", "email.send", "crm:update", "1read",
    "re ad", "x" * 99, "x" * 100, "x" * 101, "y" * 255, "y" * 256, "y" * 257, "line\nbreak", "tab\t", "nul\x00",
]


@pytest.mark.parametrize("validate, model, field, max_length", [
    (validate_action, AuthorityCheckRequest, "action", 100),
    (validate_resource, AuthorityCheckRequest, "resource", 256),
    (validate_resource_pattern, DelegationCreate, "resources", 256),
    (validate_tool_name, ToolCreate, "name", 64),
    (validate_environment, AgentRegisterRequest, "environment", 64),
    (validate_rule_id, PolicyRule, "id", 64),
    (validate_policy_action, RuleConditions, "actions", 100),
    (validate_policy_resource, RuleConditions, "resources", 256),
])
def test_patterns_match_their_validators(validate, model, field, max_length):
    schema = field_schema(model, field)
    for value in EDGE_CASES + EDGE_CASES_EXTRA + list(random_strings(seed=len(field), count=20_000, max_length=max_length)):
        assert schema_accepts(schema, value) == validator_accepts(validate, value), repr(value)


@pytest.mark.parametrize("model, field, max_length, others", [
    (OwnerUpdate, "owner", 200, {}),
    (AgentRegisterRequest, "name", 200, {}),
    (RevokeRequest, "reason", 500, {}),
])
def test_text_patterns_match_their_validators(model, field, max_length, others):
    schema = field_schema(model, field)
    for value in EDGE_CASES + list(random_strings(seed=7, count=5_000, max_length=max_length)):
        assert schema_accepts(schema, value) == model_accepts(model, field, value, **others), repr(value)


def test_public_key_pattern_covers_what_the_validator_accepts():
    from secentic_sdk import AgentKey
    schema = field_schema(AgentRegisterRequest, "public_key")
    for _ in range(200):
        key = AgentKey.generate().public_key
        assert schema_accepts(schema, key) and model_accepts(AgentRegisterRequest, "public_key", key, name="bot")
    for bad in ["", "AAAA", "A" * 43, "A" * 44, "A" * 42 + "==", "-" * 43 + "="]:
        assert not schema_accepts(schema, bad) and not model_accepts(AgentRegisterRequest, "public_key", bad, name="bot")


# --- Every operation documents its security and its errors -------------------------------------

def test_admin_operations_declare_bearer_auth_and_its_errors():
    admin_ops = [(p, m, op) for p, m, op in OPERATIONS if {"HTTPBearer": []} in op.get("security", [])]
    assert len(admin_ops) >= 16
    for path, method, op in admin_ops:
        assert {"401", "503"} <= set(op["responses"]), f"{method.upper()} {path}"


def test_signed_operations_require_all_four_signature_headers_together():
    signed = {(p, m): op["security"] for p, m, op in OPERATIONS if any(SIGNATURE_SCHEMES & set(r) for r in op.get("security", []))}
    every_header = {name: [] for name in SIGNATURE_SCHEMES}
    assert len(SIGNATURE_SCHEMES) == 4
    assert signed == {
        ("/identity/whoami", "get"): [every_header],
        ("/identity/rotate", "post"): [every_header],
        ("/identity/delegations", "get"): [every_header],
        ("/identity/tools", "get"): [every_header],
        ("/gateway/authorize", "post"): [every_header],
        ("/agents/register", "post"): [{}, every_header],  # unsigned, or signed by the key being enrolled
    }
    for path, method in signed:
        assert "401" in SCHEMA["paths"][path][method]["responses"]


def test_operations_document_the_errors_they_can_return():
    for path, method, op in OPERATIONS:
        codes = set(op["responses"])
        where = f"{method.upper()} {path}"
        if "{" in path:
            assert "404" in codes, where   # malformed or unknown IDs
        if "requestBody" in op:
            assert {"400", "413"} <= codes, where   # unreadable body, body size limit
        for code in codes - {"200", "201", "204", "422"}:
            assert op["responses"][code]["content"]["application/json"]["schema"] == {"$ref": "#/components/schemas/ErrorMessage"}, where


def test_rotation_proof_header_is_described_by_pattern():
    proof = [p for p in SCHEMA["paths"]["/identity/rotate"]["post"]["parameters"] if p["name"] == "X-Secentic-Proof"]
    assert proof and proof[0]["schema"].get("pattern") or any(s.get("pattern") for s in proof[0]["schema"].get("anyOf", []))


def test_path_parameters_are_constrained():
    for path, method, op in OPERATIONS:
        for parameter in op.get("parameters", []):
            if parameter["in"] == "path":
                schema = parameter["schema"]
                constrained = schema.get("pattern") or (schema.get("type") == "integer" and "maximum" in schema)
                assert constrained, f"{method.upper()} {path} {parameter['name']}"


def test_documented_limits_come_from_the_constants():
    from app.identity import MAX_CLOCK_SKEW, NONCE_MAX_LENGTH, NONCE_MIN_LENGTH
    from app.request_guards import MAX_BODY_BYTES, MAX_POLICY_BODY_BYTES
    schema = app.openapi()
    schemes = schema["components"]["securitySchemes"]
    assert f"within {MAX_CLOCK_SKEW} s" in schemes["AgentSignatureTimestamp"]["description"]
    assert f"{NONCE_MIN_LENGTH}-{NONCE_MAX_LENGTH} characters" in schemes["AgentSignatureNonce"]["description"]
    assert schema["paths"]["/agents/register"]["post"]["responses"]["413"]["description"] == \
        f"Request body larger than {MAX_BODY_BYTES // 1024} KiB ({MAX_POLICY_BODY_BYTES // 1024 // 1024} MiB for PUT /policy)"


def test_every_route_that_uses_the_database_declares_503():
    # A database failure answers 503 anywhere (request_guards.database_error_handler).
    missing = [f"{method.upper()} {path}" for path, method, op in OPERATIONS if path != "/health" and "503" not in op["responses"]]
    assert missing == []


def test_published_patterns_name_only_real_characters():
    # Surrogates (U+D800-U+DFFF) are not characters: JSON Schema engines in Rust, Go and others
    # refuse to compile a pattern that names them, which made the whole schema unusable there.
    def patterns(node):
        if isinstance(node, dict):
            if isinstance(node.get("pattern"), str):
                yield node["pattern"]
            for value in node.values():
                yield from patterns(value)
        elif isinstance(node, list):
            for value in node:
                yield from patterns(value)

    found = list(patterns(SCHEMA))
    assert found
    surrogate_escape = re.compile(r"\\u[dD][89a-fA-F][0-9a-fA-F]{2}")
    offending = [p[:60] for p in found if surrogate_escape.search(p) or any(0xD800 <= ord(c) <= 0xDFFF for c in p)]
    assert offending == []


TIMESTAMPS = [
    "2026-10-13T09:00:00Z", "2026-10-13t09:00:00z", "2026-10-13T09:00:00.5+05:30", "2026-10-13T09:00:00.123456789-00:00",
    "0001-01-02T00:00:00Z", "9999-12-30T00:00:00Z", "2026-10-13T23:59:59+23:59",
    "2026-10-13T09:00:00+24:00", "2026-10-13T23:59:60Z", "0000-01-01T00:00:00Z", "2026-10-13T24:00:00Z", "2026-13-01T00:00:00Z",
    "2026-10-13T09:00:00+0530", "2026-10-13T09:00:00+05", "2026-10-13 09:00:00Z", "2026-10-13T09:00Z", "2026-10-13T09:00:00",
    "2026-10-13T09:00:00,5Z", "1791814203", "1791814203000", "", "2026-10-13", "09:00:00Z", "2026-10-13T09:00:00Z\n",
    "2026-10-13T09:00:00.Z", "+2026-10-13T09:00:00Z", "2026-1-13T09:00:00Z",
]


def test_timestamp_pattern_matches_its_validator():
    # Calendar rules (which days a month has, and times beyond the representable range) belong to the
    # "date-time" format, which is published alongside the pattern; these cases are all valid dates.
    schema = field_schema(AuthorityCheckRequest, "at")
    assert schema["format"] == "date-time"
    for value in TIMESTAMPS:
        accepted = model_accepts(AuthorityCheckRequest, "at", value, action="read", resource="crm:accounts/1")
        assert schema_accepts(schema, value) == accepted, repr(value)
