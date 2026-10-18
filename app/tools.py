"""M4 — Agent & tool registry rules.

Tools and MCP servers are registered by administrators under a unique lowercase name, with the
actions they perform and the resources they work on. Each has a trust state; new tools start
`unknown`. When the definition of a trusted tool changes (endpoint, version, provider, kind,
capabilities or resources), its trust drops back to `unknown`: a tool approved once must not be
able to change what it does afterwards (the MCP "rug pull").
"""
import re

from sqlalchemy.orm import Session

from .models import AgentTool, Tool, TrustState, utcnow

TOOL_NAME_REGEX = r"^[a-z0-9][a-z0-9._-]{0,63}$"
_TOOL_NAME = re.compile(TOOL_NAME_REGEX)


def validate_tool_name(name: str) -> str:
    if not _TOOL_NAME.fullmatch(name):
        raise ValueError("tool name must be 1-64 lowercase letters, digits, '.', '_' or '-', starting with a letter or digit")
    return name


def definition_update(tool: Tool, definition: dict) -> dict:
    """The column values that apply `definition` to `tool`. If the tool is trusted and a reviewed
    field changes, the values also reset its trust to unknown. The caller applies them with an
    update guarded against concurrent changes (see routers/tools.py)."""
    now = utcnow()
    values = {getattr(Tool, field): value for field, value in definition.items()}
    values[Tool.updated_at] = now
    changed = [field for field in Tool.REVIEWED_FIELDS if getattr(tool, field) != definition[field]]
    if changed and tool.trust_state == TrustState.trusted:
        values[Tool.trust_state] = TrustState.unknown
        values[Tool.trust_reason] = f"Definition changed ({', '.join(changed)}); review it again"
        values[Tool.trust_changed_at] = now
    return values


def assigned_tools(db: Session, agent_id: str) -> list[Tool]:
    """The tools an agent may use, by name (one query)."""
    return (db.query(Tool).join(AgentTool, AgentTool.tool_name == Tool.name)
            .filter(AgentTool.agent_id == agent_id).order_by(Tool.name).all())
