from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.orm import Session
from starlette.convertors import register_url_convertor

from ..database import get_db
from ..identity import SIGNED_REQUEST, AgentPrincipal, authenticate_agent
from ..models import AgentStatus, AgentTool, Tool, ToolKind, TrustState, utcnow
from ..schemas import ToolAssignmentResponse, ToolCreate, ToolDefinition, ToolResponse, TrustUpdate, error_responses
from ..tools import TOOL_NAME_REGEX, assigned_tools, definition_update
from .common import ADMIN, ADMIN_ERRORS, AgentId, PathIdConvertor, commit_or_409, get_agent_or_404, get_or_404, update_one

register_url_convertor("tool_name", PathIdConvertor(TOOL_NAME_REGEX.strip("^$")))
ToolNamePath = Annotated[str, Path(pattern=TOOL_NAME_REGEX, description="Tool name")]

router = APIRouter(tags=["tools"])


# --- Control plane: the registry ------------------------------------------------------------

@router.post("/tools", response_model=ToolResponse, status_code=201, dependencies=ADMIN,
             responses=error_responses(*ADMIN_ERRORS, 409, 400, 413))
def register_tool(payload: ToolCreate, db: Session = Depends(get_db)):
    """Register a tool or MCP server. It starts as `unknown` until a reviewer trusts it."""
    if db.get(Tool, payload.name):
        raise HTTPException(status_code=409, detail="A tool with this name is already registered")
    now = utcnow()
    tool = Tool(**payload.model_dump(), trust_state=TrustState.unknown, trust_changed_at=now, created_at=now, updated_at=now)
    db.add(tool)
    commit_or_409(db, "A tool with this name is already registered")
    db.refresh(tool)
    return tool


@router.get("/tools", response_model=list[ToolResponse], dependencies=ADMIN, responses=error_responses(*ADMIN_ERRORS))
def list_tools(trust_state: TrustState | None = None, kind: ToolKind | None = None, db: Session = Depends(get_db)):
    query = db.query(Tool)
    if trust_state:
        query = query.filter(Tool.trust_state == trust_state)
    if kind:
        query = query.filter(Tool.kind == kind)
    return query.order_by(Tool.name).all()


@router.get("/tools/{tool_name:tool_name}", response_model=ToolResponse, dependencies=ADMIN,
            responses=error_responses(*ADMIN_ERRORS, 404))
def get_tool(tool_name: ToolNamePath, db: Session = Depends(get_db)):
    return get_or_404(db, Tool, tool_name, "Tool not found")


@router.put("/tools/{tool_name:tool_name}", response_model=ToolResponse, dependencies=ADMIN,
            responses=error_responses(*ADMIN_ERRORS, 404, 409, 400, 413))
def update_tool(tool_name: ToolNamePath, payload: ToolDefinition, db: Session = Depends(get_db)):
    """Replace a tool's definition. If the tool was trusted and anything a reviewer approved has
    changed, its trust drops back to `unknown` until someone reviews it again."""
    tool = get_or_404(db, Tool, tool_name, "Tool not found")
    # Applied only if neither the definition nor the trust changed since the tool was read: a
    # review recorded in between must not end up approving this new, unreviewed definition.
    unchanged = db.query(Tool).filter(Tool.name == tool.name, Tool.updated_at == tool.updated_at,
                                      Tool.trust_changed_at == tool.trust_changed_at)
    if not update_one(db, unchanged, definition_update(tool, payload.model_dump())):
        raise HTTPException(status_code=409, detail="The tool changed while it was being updated; reload it and try again")
    db.commit()
    db.refresh(tool)
    return tool


@router.post("/tools/{tool_name:tool_name}/trust", response_model=ToolResponse, dependencies=ADMIN,
             responses=error_responses(*ADMIN_ERRORS, 404, 409, 400, 413))
def set_trust(tool_name: ToolNamePath, payload: TrustUpdate, db: Session = Depends(get_db)):
    """Record a review: trusted, suspicious, blocked, or back to unknown. Marking a tool trusted
    must name the definition that was reviewed (`reviewed_definition`, the tool's definition_hash)."""
    tool = get_or_404(db, Tool, tool_name, "Tool not found")
    state = TrustState(payload.trust_state)
    update = db.query(Tool).filter(Tool.name == tool.name)
    if state == TrustState.trusted:
        if payload.reviewed_definition != tool.definition_hash:
            raise HTTPException(status_code=409, detail="The tool's current definition is not the one you reviewed; "
                                                        "review it and send its definition_hash")
        # Neither the definition nor the trust may change between that check and this update.
        update = update.filter(Tool.updated_at == tool.updated_at, Tool.trust_changed_at == tool.trust_changed_at)
    if not update_one(db, update, {Tool.trust_state: state, Tool.trust_reason: payload.reason, Tool.trust_changed_at: utcnow()}):
        raise HTTPException(status_code=409, detail="The tool changed while the review was being recorded; review it again")
    db.commit()
    db.refresh(tool)
    return tool


# --- Control plane: which agent may use which tool ------------------------------------------

@router.get("/agents/{agent_id:uuid_id}/tools", response_model=list[ToolResponse], dependencies=ADMIN,
            responses=error_responses(*ADMIN_ERRORS, 404))
def list_agent_tools(agent_id: AgentId, db: Session = Depends(get_db)):
    return assigned_tools(db, get_agent_or_404(db, agent_id).id)


@router.put("/agents/{agent_id:uuid_id}/tools/{tool_name:tool_name}", response_model=ToolAssignmentResponse,
            dependencies=ADMIN, responses=error_responses(*ADMIN_ERRORS, 404, 409))
def assign_tool(agent_id: AgentId, tool_name: ToolNamePath, db: Session = Depends(get_db)):
    """Allow the agent to use the tool. Assigning a tool twice is harmless."""
    agent = get_agent_or_404(db, agent_id)
    if agent.status == AgentStatus.pending_review:
        raise HTTPException(status_code=409, detail="Pending agents cannot be given tools; approve the agent first")
    tool = get_or_404(db, Tool, tool_name, "Tool not found")
    if tool.trust_state == TrustState.blocked:
        raise HTTPException(status_code=409, detail="Tool is blocked")
    assignment = db.get(AgentTool, (agent.id, tool.name))
    if assignment is None:
        assignment = AgentTool(agent_id=agent.id, tool_name=tool.name)
        db.add(assignment)
        commit_or_409(db, "The agent's tools changed concurrently; check them and retry")
        db.refresh(assignment)
    return assignment


@router.delete("/agents/{agent_id:uuid_id}/tools/{tool_name:tool_name}", status_code=204, dependencies=ADMIN,
               responses=error_responses(*ADMIN_ERRORS, 404))
def unassign_tool(agent_id: AgentId, tool_name: ToolNamePath, db: Session = Depends(get_db)):
    """Take the tool away from the agent. Its next request for the tool is denied."""
    get_agent_or_404(db, agent_id)
    assignment = db.get(AgentTool, (agent_id, tool_name))
    if assignment is None:
        raise HTTPException(status_code=404, detail="The agent is not assigned this tool")
    db.delete(assignment)
    db.commit()


# --- Agent-facing ---------------------------------------------------------------------------

@router.get("/identity/tools", response_model=list[ToolResponse], responses=error_responses(401, 403, 503),
            openapi_extra=SIGNED_REQUEST)
def my_tools(principal: AgentPrincipal = Depends(authenticate_agent), db: Session = Depends(get_db)):
    """The tools the calling agent may use."""
    return assigned_tools(db, principal.agent.id)
