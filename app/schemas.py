import enum
import re
import unicodedata
from typing import Annotated, Literal

from pydantic import (
    AfterValidator, AwareDatetime, BaseModel, BeforeValidator, ConfigDict, Field, StringConstraints, WithJsonSchema,
    field_validator, model_validator,
)
from datetime import datetime
from .crypto import load_public_key
from .request_guards import MAX_BODY_BYTES, MAX_POLICY_BODY_BYTES
from .delegation import (
    ACTION_REGEX, MAX_BACKDATING, MAX_DELEGATION_LIFETIME, MAX_RESOURCE_LENGTH, MAX_ACTION_LENGTH,
    RESOURCE_PATTERN_REGEX, RESOURCE_REGEX, normalize_action, normalize_resource, normalize_resource_pattern,
)
from .models import AgentStatus, Decision, DelegationState, KeyStatus, RegistrationSource, ToolKind, TrustState, as_utc, utcnow
from .policy import (
    MAX_ACTION_PATTERN_LENGTH, MAX_RESOURCE_PATTERN_LENGTH, MAX_RULES, POLICY_ACTION_REGEX, POLICY_RESOURCE_REGEX,
    RULE_ID_REGEX, normalize_policy_action, normalize_policy_resource, validate_rule_id,
)
from .tools import TOOL_NAME_REGEX, validate_tool_name

# Each input type below is checked by a validator with a readable error message, and described in
# the OpenAPI schema by an equivalent JSON Schema. tests/test_openapi.py keeps the two in step.

# Never allowed in one-line text: characters that are invisible or break the line, with which two
# different names could look identical, or a name look blank. Derived from Unicode properties
# rather than listed one by one:
#  - every control (Cc, NUL included, which PostgreSQL rejects anyway), format (Cf: zero-width
#    characters, bidirectional controls, tag characters, ...), surrogate (Cs) and private-use (Co)
#    character, and the line and paragraph separators (Zl, Zp);
#  - Unicode's Default_Ignorable_Code_Point ranges (DerivedCoreProperties.txt; not in unicodedata),
#    e.g. variation selectors, the combining grapheme joiner and Hangul fillers;
#  - letters that render blank (Braille pattern blank, Khitan filler) and noncharacters.
_HIDDEN_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Zl", "Zp"}
_DEFAULT_IGNORABLE = (
    (0x00AD, 0x00AD), (0x034F, 0x034F), (0x061C, 0x061C), (0x115F, 0x1160), (0x17B4, 0x17B5), (0x180B, 0x180F),
    (0x200B, 0x200F), (0x202A, 0x202E), (0x2060, 0x206F), (0x3164, 0x3164), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF),
    (0xFFA0, 0xFFA0), (0xFFF0, 0xFFF8), (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0xE0000, 0xE0FFF),
)
_BLANK_LOOKING = ((0x2800, 0x2800), (0x16FE4, 0x16FE4))
_NONCHARACTERS = ((0xFDD0, 0xFDEF), *((plane + 0xFFFE, plane + 0xFFFF) for plane in range(0, 0x110000, 0x10000)))


def forbidden_code_points() -> set[int]:
    """Every code point the rules above forbid, from the running Python's Unicode database. Scanning
    all 1.1 million code points takes about a quarter of a second, so it is not done at import:
    FORBIDDEN_RANGES holds the result, and tests/test_input_safety.py checks that it still covers
    this scan (a newer Python may know new format characters)."""
    points = {c for c in range(0x110000) if unicodedata.category(chr(c)) in _HIDDEN_CATEGORIES}
    for first, last in (*_DEFAULT_IGNORABLE, *_BLANK_LOOKING, *_NONCHARACTERS):
        points.update(range(first, last + 1))
    return points


# forbidden_code_points() as ranges, generated with Unicode 16.0 (Python 3.14).
FORBIDDEN_RANGES = (
    (0x0000, 0x001F), (0x007F, 0x009F), (0x00AD, 0x00AD), (0x034F, 0x034F), (0x0600, 0x0605), (0x061C, 0x061C),
    (0x06DD, 0x06DD), (0x070F, 0x070F), (0x0890, 0x0891), (0x08E2, 0x08E2), (0x115F, 0x1160), (0x17B4, 0x17B5),
    (0x180B, 0x180F), (0x200B, 0x200F), (0x2028, 0x202E), (0x2060, 0x206F), (0x2800, 0x2800), (0x3164, 0x3164),
    (0xD800, 0xF8FF), (0xFDD0, 0xFDEF), (0xFE00, 0xFE0F), (0xFEFF, 0xFEFF), (0xFFA0, 0xFFA0), (0xFFF0, 0xFFFB),
    (0xFFFE, 0xFFFF), (0x110BD, 0x110BD), (0x110CD, 0x110CD), (0x13430, 0x1343F), (0x16FE4, 0x16FE4),
    (0x1BCA0, 0x1BCA3), (0x1D173, 0x1D17A), (0x1FFFE, 0x1FFFF), (0x2FFFE, 0x2FFFF), (0x3FFFE, 0x3FFFF),
    (0x4FFFE, 0x4FFFF), (0x5FFFE, 0x5FFFF), (0x6FFFE, 0x6FFFF), (0x7FFFE, 0x7FFFF), (0x8FFFE, 0x8FFFF),
    (0x9FFFE, 0x9FFFF), (0xAFFFE, 0xAFFFF), (0xBFFFE, 0xBFFFF), (0xCFFFE, 0xCFFFF), (0xDFFFE, 0xE0FFF),
    (0xEFFFE, 0x10FFFF),
)


def _character_class(ranges) -> str:
    """The body of a regex character class matching exactly `ranges`, valid both in Python and in
    JSON Schema (ECMA-262 in Unicode mode): BMP characters as \\uXXXX escapes, others literally."""
    def char(c: int) -> str:
        return f"\\u{c:04x}" if c <= 0xFFFF else chr(c)

    return "".join(char(a) if a == b else f"{char(a)}-{char(b)}" for a, b in ranges)


def _without_surrogates(ranges):
    """`ranges` minus U+D800-U+DFFF. Surrogates are not characters: JSON Schema engines that only
    handle real characters (Rust, Go, ...) cannot compile a pattern that names them, and the strings
    they validate never contain them anyway."""
    for first, last in ranges:
        if last < 0xD800 or first > 0xDFFF:
            yield first, last
            continue
        if first < 0xD800:
            yield first, 0xD7FF
        if last > 0xDFFF:
            yield 0xE000, last


_FORBIDDEN = _character_class(FORBIDDEN_RANGES)
# The published pattern leaves surrogates out (see above); the server still refuses them, and
# refuses them in the 422 too (request_guards.validation_error_handler).
_FORBIDDEN_IN_SCHEMA = _character_class(_without_surrogates(FORBIDDEN_RANGES))
# Spaces that may appear inside text but not at either end.
_EDGE_SPACES = r"\x20\xa0\u1680\u2000-\u200a\u202f\u205f\u3000"
ONE_LINE_REGEX = rf"^[^{_FORBIDDEN_IN_SCHEMA}{_EDGE_SPACES}](?:[^{_FORBIDDEN_IN_SCHEMA}]*[^{_FORBIDDEN_IN_SCHEMA}{_EDGE_SPACES}])?$"
_FORBIDDEN_CHARACTER = re.compile(f"[{_FORBIDDEN}]")
_EDGE_SPACE = re.compile(f"[{_EDGE_SPACES}]")

PUBLIC_KEY_REGEX = r"^[A-Za-z0-9+/]{43}=$"  # base64 of 32 bytes
SIGNATURE_REGEX = r"^[A-Za-z0-9+/]{86}==$"  # base64 of a 64-byte Ed25519 signature
DEFINITION_HASH_REGEX = r"^[0-9a-f]{64}$"
UUID_REGEX = "[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"
KEY_ID_REGEX = "[0-9a-f]{64}"
UUID_PATTERN = f"^{UUID_REGEX}$"


def _one_line(value: str) -> str:
    if _FORBIDDEN_CHARACTER.search(value):
        raise ValueError("must not contain control or invisible formatting characters "
                         "(such as line breaks, NUL or zero-width characters)")
    if _EDGE_SPACE.fullmatch(value[0]) or _EDGE_SPACE.fullmatch(value[-1]):
        raise ValueError("must not start or end with a space")
    return value


def _text(max_length: int):
    return Annotated[
        str,
        StringConstraints(min_length=1, max_length=max_length),
        AfterValidator(_one_line),
        WithJsonSchema({"type": "string", "minLength": 1, "maxLength": max_length, "pattern": ONE_LINE_REGEX}),
    ]


# RFC 3339 date-time with a timezone, which is what JSON Schema's "date-time" format means: the date,
# "T", hours, minutes and seconds, an optional fraction, then "Z" or an offset. The ranges are the
# ones the server can represent (no year 0000, no leap second, offsets up to 23:59); which days a
# month has is left to the "date-time" format. No lookaheads, so every regex engine can use it.
RFC3339_REGEX = (
    r"^(?:[1-9][0-9]{3}|0[1-9][0-9]{2}|00[1-9][0-9]|000[1-9])-(?:0[1-9]|1[0-2])-(?:0[1-9]|[12][0-9]|3[01])"
    r"[Tt](?:[01][0-9]|2[0-3]):[0-5][0-9]:[0-5][0-9](?:\.[0-9]+)?(?:[Zz]|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])$"
)
_RFC3339 = re.compile(RFC3339_REGEX)


def _timestamp_string(value):
    # Only RFC 3339 strings: pydantic would read numbers, and even number strings, as Unix times,
    # and accepts looser forms ("2026-10-13 09:00Z") that the published schema does not.
    if isinstance(value, datetime):  # built in code, not taken from a request
        return value
    if not isinstance(value, str) or not _RFC3339.fullmatch(value):
        raise ValueError("must be an RFC 3339 timestamp with a timezone, such as 2026-10-13T09:00:00Z")
    return value


def _to_utc(value: datetime) -> datetime:
    try:
        return as_utc(value)
    except OverflowError:  # e.g. year 1 at +14:00 is before the earliest representable time
        raise ValueError("timestamp is out of range") from None


def _public_key(value: str) -> str:
    try:
        load_public_key(value)
    except ValueError as exc:
        raise ValueError(f"must be a base64-encoded 32-byte Ed25519 public key ({exc})") from None
    return value


# Environments ("prod", "eu-west-1") are plain ASCII names: policy rules select agents by
# environment, and a look-alike such as "prоd" (Cyrillic о) would escape every rule on "prod".
ENVIRONMENT_REGEX = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
_ENVIRONMENT = re.compile(ENVIRONMENT_REGEX)


def validate_environment(value: str) -> str:
    if not _ENVIRONMENT.fullmatch(value):
        raise ValueError("environment must be 1-64 ASCII letters, digits, '.', '_' or '-', starting with a letter "
                         "or digit (e.g. 'prod')")
    return value


# One line of text, 1-200 characters (names, owners, delegators).
NonBlankStr = _text(200)
# A short description, 1-500 characters (tasks, reasons).
Description = _text(500)
# Timestamps in requests: RFC 3339 strings with a timezone, converted to UTC.
UtcInput = Annotated[AwareDatetime, BeforeValidator(_timestamp_string), AfterValidator(_to_utc), WithJsonSchema(
    {"type": "string", "format": "date-time", "pattern": RFC3339_REGEX})]
# Response timestamps always carry their UTC offset, whichever database stored them.
UtcDatetime = Annotated[datetime, AfterValidator(as_utc)]
# Actions and resources are validated, then normalised to their one canonical spelling (see
# delegation.canonical_form): everything stored and compared is in that form.
ActionName = Annotated[str, AfterValidator(normalize_action), WithJsonSchema(
    {"type": "string", "minLength": 1, "maxLength": MAX_ACTION_LENGTH, "pattern": ACTION_REGEX})]
ResourceId = Annotated[str, AfterValidator(normalize_resource), WithJsonSchema(
    {"type": "string", "minLength": 1, "maxLength": MAX_RESOURCE_LENGTH, "pattern": RESOURCE_REGEX})]
ResourcePattern = Annotated[str, AfterValidator(normalize_resource_pattern), WithJsonSchema(
    {"type": "string", "minLength": 1, "maxLength": MAX_RESOURCE_LENGTH, "pattern": RESOURCE_PATTERN_REGEX})]
EnvironmentName = Annotated[str, AfterValidator(validate_environment), WithJsonSchema(
    {"type": "string", "minLength": 1, "maxLength": 64, "pattern": ENVIRONMENT_REGEX})]
PublicKey = Annotated[str, AfterValidator(_public_key), WithJsonSchema(
    {"type": "string", "pattern": PUBLIC_KEY_REGEX, "description": "Base64 of a raw 32-byte Ed25519 public key"})]


class SelfRegistrationSource(str, enum.Enum):
    """How a self-registering agent reached Secentic. `manual` is reserved for administrators."""
    api = "api"
    sdk = "sdk"


class SettableStatus(str, enum.Enum):
    """Statuses an administrator can set; agents leave pending_review only through approval."""
    active = "active"
    inactive = "inactive"
    disabled = "disabled"


class ErrorMessage(BaseModel):
    detail: str


_ERROR_DESCRIPTIONS = {
    400: "Request body could not be read (for example, not UTF-8)",
    401: "Not authenticated: missing or invalid admin token, or invalid agent signature",
    403: "Authenticated, but the agent is not active",
    404: "Not found",
    409: "Conflicts with the current state",
    413: f"Request body larger than {MAX_BODY_BYTES // 1024} KiB ({MAX_POLICY_BODY_BYTES // 1024 // 1024} MiB for PUT /policy)",
    503: "Unavailable: admin access is not configured, the database failed, or the gateway cannot decide "
         "(agents must treat it as a denial)",
}


def error_responses(*codes: int) -> dict:
    """OpenAPI `responses` for the error status codes an endpoint can return."""
    return {code: {"model": ErrorMessage, "description": _ERROR_DESCRIPTIONS[code]} for code in codes}


class AgentRegisterRequest(BaseModel):
    name: NonBlankStr
    owner: NonBlankStr | None = None  # a claim only; an admin confirms the owner when approving
    environment: EnvironmentName = "development"
    # Optional Ed25519 identity. If present, the request must be signed with this key.
    public_key: PublicKey | None = None


class AgentOnboardRequest(BaseModel):
    name: NonBlankStr
    owner: NonBlankStr
    environment: EnvironmentName = "development"


class AgentStatusUpdate(BaseModel):
    status: SettableStatus


class OwnerUpdate(BaseModel):
    owner: NonBlankStr


class AgentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    owner: str | None
    environment: str
    status: AgentStatus
    registration_source: RegistrationSource
    active_key_id: str | None
    first_seen: UtcDatetime
    last_seen: UtcDatetime


class PublicKeyRequest(BaseModel):
    public_key: PublicKey


class RevokeRequest(BaseModel):
    reason: Description | None = None


class AgentKeyResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    key_id: str
    agent_id: str
    algorithm: str
    public_key: str
    status: KeyStatus
    created_at: UtcDatetime
    rotated_at: UtcDatetime | None
    revoked_at: UtcDatetime | None
    revocation_reason: str | None


def _unique(values: list) -> list:
    return list(dict.fromkeys(values))


class DelegationCreate(BaseModel):
    """`expires_at` must also be after `starts_at`, in the future, and at most 30 days after
    `starts_at`; `starts_at` must not be in the past (a few minutes' clock difference is allowed).
    JSON Schema cannot compare fields with each other or with the current time, so these rules are
    checked by the server only (422)."""

    delegator: NonBlankStr  # the human whose authority is delegated
    task: Description
    actions: list[ActionName] = Field(min_length=1, max_length=50)
    resources: list[ResourcePattern] = Field(min_length=1, max_length=50)
    starts_at: UtcInput | None = None  # default: now
    expires_at: UtcInput

    _unique_entries = field_validator("actions", "resources")(_unique)

    @model_validator(mode="after")
    def _check_window(self):
        now = utcnow()
        self.starts_at = self.starts_at or now
        if self.starts_at < now - MAX_BACKDATING:
            raise ValueError("starts_at must not be in the past: a delegation cannot be backdated")
        if self.expires_at <= self.starts_at:
            raise ValueError("expires_at must be after starts_at")
        if self.expires_at <= now:
            raise ValueError("expires_at must be in the future")
        if self.expires_at - self.starts_at > MAX_DELEGATION_LIFETIME:
            raise ValueError(f"a delegation may last at most {MAX_DELEGATION_LIFETIME.days} days")
        return self


class DelegationResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    agent_id: str
    delegator: str
    task: str
    actions: list[str]
    resources: list[str]
    starts_at: UtcDatetime
    expires_at: UtcDatetime
    state: DelegationState
    created_at: UtcDatetime
    revoked_at: UtcDatetime | None
    revocation_reason: str | None


class AuthorityCheckRequest(BaseModel):
    action: ActionName
    resource: ResourceId
    at: UtcInput | None = None  # default: now


class AuthorityCheckResponse(BaseModel):
    allowed: bool
    reason: str
    delegation_id: str | None
    at: UtcDatetime


# --- M4 tool registry ---------------------------------------------------------------------------

ToolName = Annotated[str, AfterValidator(validate_tool_name), WithJsonSchema(
    {"type": "string", "minLength": 1, "maxLength": 64, "pattern": TOOL_NAME_REGEX})]


class ToolDefinition(BaseModel):
    """What a reviewer approves when marking a tool trusted. Changing kind, provider, endpoint,
    version, capabilities or resources of a trusted tool resets its trust to unknown."""

    kind: ToolKind
    provider: NonBlankStr
    endpoint: Description  # a URL, or how the tool is reached (e.g. "stdio: npx @acme/mcp-server")
    version: NonBlankStr
    capabilities: list[ActionName] = Field(min_length=1, max_length=50)  # the actions the tool performs
    # What the tool works on, as delegations name it ("crm:*", "mail:outbox/*"): the gateway refuses
    # any other resource, so a tool cannot be used on another system's data.
    resources: list[ResourcePattern] = Field(min_length=1, max_length=50)
    description: Description | None = None

    _unique_entries = field_validator("capabilities", "resources")(_unique)


class ToolCreate(ToolDefinition):
    name: ToolName


class TrustApproval(BaseModel):
    """Marking a tool trusted must say which definition was reviewed: if the tool changed since,
    the review does not apply to it (409)."""

    trust_state: Literal["trusted"]
    reviewed_definition: Annotated[str, StringConstraints(pattern=DEFINITION_HASH_REGEX)]  # the definition_hash reviewed
    reason: Description | None = None


class TrustChange(BaseModel):
    """Any other review outcome; it never needs the definition, so blocking is never held up."""

    trust_state: Literal["unknown", "suspicious", "blocked"]
    reason: Description | None = None


TrustUpdate = Annotated[TrustApproval | TrustChange, Field(discriminator="trust_state")]


class ToolResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    name: str
    kind: ToolKind
    provider: str
    endpoint: str
    version: str
    capabilities: list[str]
    resources: list[str]
    description: str | None
    trust_state: TrustState
    trust_reason: str | None
    definition_hash: str  # SHA-256 of the reviewed fields; send it as reviewed_definition when trusting
    trust_changed_at: UtcDatetime
    created_at: UtcDatetime
    updated_at: UtcDatetime


class ToolAssignmentResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    agent_id: str
    tool_name: str
    assigned_at: UtcDatetime


# --- M6 policy ----------------------------------------------------------------------------------

RuleId = Annotated[str, AfterValidator(validate_rule_id), WithJsonSchema(
    {"type": "string", "minLength": 1, "maxLength": 64, "pattern": RULE_ID_REGEX})]
PolicyActionPattern = Annotated[str, AfterValidator(normalize_policy_action), WithJsonSchema(
    {"type": "string", "minLength": 1, "maxLength": MAX_ACTION_PATTERN_LENGTH, "pattern": POLICY_ACTION_REGEX})]
PolicyResourcePattern = Annotated[str, AfterValidator(normalize_policy_resource), WithJsonSchema(
    {"type": "string", "minLength": 1, "maxLength": MAX_RESOURCE_PATTERN_LENGTH, "pattern": POLICY_RESOURCE_REGEX})]


class RuleEffect(str, enum.Enum):
    """Policies only restrict: there is no allow effect."""
    deny = "deny"
    require_approval = "require_approval"


class RuleConditions(BaseModel):
    """A rule applies when every condition it states matches; omitted conditions match anything."""

    model_config = ConfigDict(extra="forbid")  # a misspelt condition must not silently match everything

    agents: list[NonBlankStr] | None = Field(default=None, min_length=1, max_length=50)  # agent names, any case
    # Any text, so rules can also name environments stored by older versions; matching an
    # environment never needs more, since a rule only restricts.
    environments: list[NonBlankStr] | None = Field(default=None, min_length=1, max_length=50)
    tools: list[ToolName] | None = Field(default=None, min_length=1, max_length=50)
    tool_trust: list[TrustState] | None = Field(default=None, min_length=1, max_length=4)
    actions: list[PolicyActionPattern] | None = Field(default=None, min_length=1, max_length=50)
    resources: list[PolicyResourcePattern] | None = Field(default=None, min_length=1, max_length=50)


class PolicyRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: RuleId
    description: Description  # shown in every decision the rule affects
    effect: RuleEffect
    when: RuleConditions = Field(default_factory=RuleConditions)


class PolicyUpdate(BaseModel):
    """Rule IDs must also be unique within the policy; JSON Schema cannot compare one field across
    list items, so this rule is checked by the server only (422)."""

    rules: list[PolicyRule] = Field(max_length=MAX_RULES)
    comment: Description  # why the policy changed

    @model_validator(mode="after")
    def _unique_rule_ids(self):
        ids = [rule.id for rule in self.rules]
        if len(ids) != len(set(ids)):
            raise ValueError("rule ids must be unique")
        return self


class PolicyRestore(BaseModel):
    comment: Description | None = None


class PolicyVersionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    version: int
    rules: list[PolicyRule]
    comment: str
    created_at: UtcDatetime | None  # None for version 0, the empty policy before any is saved


class PolicyVersionSummary(BaseModel):
    version: int
    comment: str
    rule_count: int
    created_at: UtcDatetime


# --- M5 gateway ---------------------------------------------------------------------------------

class ActionRequest(BaseModel):
    """An action an agent wants to take: use this tool to perform this action on this resource."""

    tool: ToolName
    action: ActionName
    resource: ResourceId


class SimulationRequest(ActionRequest):
    agent_id: Annotated[str, StringConstraints(pattern=UUID_PATTERN)]
    at: UtcInput | None = None  # default: now


class DecisionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str | None  # the recorded decision; None for simulations, which are not recorded
    agent_id: str
    tool: str
    action: str
    resource: str
    decision: Decision
    reasons: list[str]
    matched_rules: list[str]
    delegation_id: str | None
    policy_version: int
    decided_at: UtcDatetime
