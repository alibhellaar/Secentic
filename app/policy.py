"""M6 — Contextual policy engine.

Policies are guardrails on top of delegations: a delegation (M3) says what an agent may do, and
policy rules can only restrict it. Each rule matches a request by agent, environment, tool, tool
trust, action and resource, and has the effect `deny` or `require_approval`. There is no `allow`
effect, so no policy can widen what an agent was delegated.

Evaluation is deterministic: every matching rule is reported, and the most restrictive effect
wins (deny over require_approval). Rules are versioned: each change stores a new numbered
version, and the highest version is in force.
"""
import re
from dataclasses import dataclass, field
from datetime import datetime

from sqlalchemy.orm import Session

from .delegation import ACTION_CORE, IDENTIFIER_PATTERN, canonical_pattern, pattern_matches, validate_resource
from .models import Decision, PolicyVersion, as_utc
from .utils import comparable_name

MAX_RULES = 200
RULE_ID_REGEX = r"^[a-z0-9][a-z0-9-]{0,63}$"
# Policies restrict, so their patterns may be broad: "*" alone, an exact name, or any prefix + "*".
POLICY_ACTION_REGEX = rf"^(?:\*|{ACTION_CORE}\*?)$"
POLICY_RESOURCE_REGEX = rf"^(?:\*|{IDENTIFIER_PATTERN}(?:[/:]?\*)?)$"
MAX_ACTION_PATTERN_LENGTH = 100
MAX_RESOURCE_PATTERN_LENGTH = 256

_RULE_ID = re.compile(RULE_ID_REGEX)
_ACTION_PREFIX = re.compile(ACTION_CORE)


def validate_rule_id(rule_id: str) -> str:
    if not _RULE_ID.fullmatch(rule_id):
        raise ValueError("rule id must be 1-64 lowercase letters, digits or '-', starting with a letter or digit")
    return rule_id


def validate_policy_action(pattern: str) -> str:
    core = pattern[:-1] if pattern.endswith("*") else pattern
    if len(pattern) > MAX_ACTION_PATTERN_LENGTH or (pattern != "*" and not _ACTION_PREFIX.fullmatch(core)):
        raise ValueError("action pattern must be '*', an action name, or an action name prefix ending in '*' (at most 100 characters)")
    return pattern


def normalize_policy_action(pattern: str) -> str:
    """Validate `pattern` and return it in lower case, like every action name."""
    return validate_policy_action(pattern).lower()


def normalize_policy_resource(pattern: str) -> str:
    """Validate `pattern` and return its canonical spelling, as for delegation resources
    ('crm/accounts:secret*' -> 'crm:accounts/secret*')."""
    return canonical_pattern(validate_policy_resource(pattern))


def validate_policy_resource(pattern: str) -> str:
    if not 1 <= len(pattern) <= MAX_RESOURCE_PATTERN_LENGTH:
        raise ValueError(f"resource pattern must be 1-{MAX_RESOURCE_PATTERN_LENGTH} characters")
    if pattern == "*":  # every resource
        return pattern
    core = pattern
    if core.endswith("*"):
        core = core[:-1]
        if core[-1:] in ("/", ":"):  # "crm:*", "crm:accounts/*"
            core = core[:-1]
    validate_resource(core)
    return pattern


@dataclass
class PolicyContext:
    agent: str
    environment: str
    tool: str
    tool_trust: str
    action: str
    resource: str


@dataclass
class PolicyResult:
    version: int
    effect: Decision  # allow when no rule matches; otherwise deny or require_approval
    reasons: list[str]
    matched: list[dict] = field(default_factory=list)


def _comparable(context: PolicyContext) -> PolicyContext:
    """The request in the form rules are compared with, computed once per decision. Rules,
    requests, delegations and tool scopes all hold normalised values (one spelling per resource,
    actions in lower case; see delegation.canonical_form). Names are compared exactly as the
    inventory compares them, so a rule names an agent exactly when the inventory would consider it
    the same agent. One difference remains on purpose: rules compare resources ignoring case. A
    rule only restricts, so matching more spellings makes it stricter ('crm:accounts/Secret'
    cannot slip past a rule on 'crm:accounts/secret*'); grants keep case, because resource IDs are
    often case-sensitive."""
    return PolicyContext(comparable_name(context.agent), comparable_name(context.environment), context.tool,
                         context.tool_trust, context.action, context.resource.lower())


def _matches(when: dict, request: PolicyContext) -> bool:
    """A rule applies when every condition it states matches (conditions it omits match anything).
    `request` is the _comparable form; checks stop at the first condition that fails."""
    agents, environments = when.get("agents"), when.get("environments")
    tools, states, actions, resources = when.get("tools"), when.get("tool_trust"), when.get("actions"), when.get("resources")
    return ((not agents or any(comparable_name(name) == request.agent for name in agents))
            and (not environments or any(comparable_name(env) == request.environment for env in environments))
            and (not tools or request.tool in tools)
            and (not states or request.tool_trust in states)
            and (not actions or any(pattern_matches(p, request.action) for p in actions))
            and (not resources or any(pattern_matches(p.lower(), request.resource) for p in resources)))


def rule_matches(conditions: dict, context: PolicyContext) -> bool:
    """Whether one rule's conditions match the request (see _matches)."""
    return _matches(conditions, _comparable(context))


def evaluate_policy(rules: list[dict], version: int, context: PolicyContext) -> PolicyResult:
    request = _comparable(context)
    matched = [rule for rule in rules if _matches(rule.get("when", {}), request)]
    if not matched:
        return PolicyResult(version, Decision.allow, [f"No rule in policy version {version} applies"])
    effect = Decision.deny if any(rule["effect"] == Decision.deny.value for rule in matched) else Decision.require_approval
    reasons = [f"Policy rule '{rule['id']}' ({rule['effect']}): {rule['description']}" for rule in matched]
    return PolicyResult(version, effect, reasons, matched)


def version_in_force(db: Session, at: datetime | None = None) -> PolicyVersion | None:
    """The saved policy version in force at `at` (default: now), i.e. the highest one saved by then;
    None before any policy was saved (version 0, no rules)."""
    query = db.query(PolicyVersion)
    if at is not None:
        query = query.filter(PolicyVersion.created_at <= as_utc(at))
    return query.order_by(PolicyVersion.version.desc()).first()
