"""M5 — Runtime security gateway: the decision for one action an agent wants to take.

`decide` runs the checks in a fixed order and returns ALLOW, DENY or REQUIRE_APPROVAL with every
reason behind it:

  1. the agent is active
  2. the tool is assigned to the agent (an unregistered tool gets the same answer, so agents
     cannot probe the registry)                                      (M4)
  3. the tool is not blocked                                         (M4)
  4. the tool provides the requested action                          (M4)
  5. the tool works on the requested resource                        (M4)
  6. a delegation in force covers the action on the resource         (M3)
  7. the tool is trusted; unknown or suspicious tools need approval   (M4)
  8. no policy rule denies the request or requires approval          (M6)

Checks 1-6 stop at the first failure with DENY. Otherwise the most restrictive of 7 and 8 decides.
The gateway router records every decision and fails closed if anything here raises.
"""
from dataclasses import dataclass
from datetime import datetime

from sqlalchemy.orm import Session

from .delegation import authority_in_force, normalize_action, normalize_resource, pattern_matches
from .models import Agent, AgentStatus, AgentTool, Decision, Tool, TrustState, as_utc, utcnow
from .policy import PolicyContext, evaluate_policy, version_in_force

FAIL_CLOSED_REASON = "The gateway could not reach a decision; failing closed (deny)"

_RESTRICTIVENESS = {Decision.allow: 0, Decision.require_approval: 1, Decision.deny: 2}


@dataclass
class GatewayResult:
    decision: Decision
    reasons: list[str]
    matched_rules: list[str]
    delegation_id: str | None
    policy_version: int


def decide(db: Session, agent: Agent, tool_name: str, action: str, resource: str, at: datetime | None = None) -> GatewayResult:
    """The decision for this request. With `at`, delegations and the policy are taken as they were
    at that moment; the agent, its tools and their trust as they are now (they keep no history)."""
    saved = version_in_force(db, at)
    version, rules = (saved.version, saved.rules) if saved else (0, [])

    def deny(reason: str) -> GatewayResult:
        return GatewayResult(Decision.deny, [reason], [], None, version)

    if agent.status != AgentStatus.active:
        return deny(f"Agent is {agent.status.value}")
    try:  # API requests arrive normalised already; other callers get the same treatment
        action, resource = normalize_action(action), normalize_resource(resource)
        when = as_utc(at or utcnow())
    except ValueError as exc:
        return deny(f"Invalid request: {exc}")
    except OverflowError:
        return deny("Invalid request: time out of range")
    tool = db.get(Tool, tool_name)
    if tool is None or db.get(AgentTool, (agent.id, tool_name)) is None:
        return deny(f"Agent '{agent.name}' is not allowed to use tool '{tool_name}'")
    if tool.trust_state == TrustState.blocked:
        return deny(f"Tool '{tool_name}' is blocked" + (f": {tool.trust_reason}" if tool.trust_reason else ""))
    if action not in tool.capabilities:
        return deny(f"Tool '{tool_name}' does not provide the action '{action}'")
    if not any(pattern_matches(pattern, resource) for pattern in tool.resources):
        # A delegation for CRM records must not let the agent read them through, say, a web search tool.
        return deny(f"Tool '{tool_name}' does not work on '{resource}'")
    authority = authority_in_force(db, agent.id, action, resource, when)  # agent and request checked above
    if not authority.allowed:
        return deny(authority.reason)

    decision = Decision.allow
    reasons = [f"Tool '{tool_name}' ({tool.trust_state.value}) is assigned to the agent and provides '{action}' on '{resource}'",
               authority.reason]
    if tool.trust_state != TrustState.trusted:
        decision = Decision.require_approval
        reasons.append(f"Tool '{tool_name}' is {tool.trust_state.value}: a person must approve its use")

    context = PolicyContext(agent.name, agent.environment, tool_name, tool.trust_state.value, action, resource)
    policy = evaluate_policy(rules, version, context)
    reasons += policy.reasons
    decision = max(decision, policy.effect, key=_RESTRICTIVENESS.__getitem__)
    return GatewayResult(decision, reasons, [rule["id"] for rule in policy.matched], authority.delegation.id, version)
