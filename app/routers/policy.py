from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy import func
from sqlalchemy.orm import Session

from ..database import get_db
from ..models import PolicyVersion
from ..policy import version_in_force
from ..schemas import PolicyRestore, PolicyUpdate, PolicyVersionResponse, PolicyVersionSummary, error_responses
from .common import ADMIN, ADMIN_ERRORS, commit_or_409

# Policy responses leave out conditions a rule does not state (response_model_exclude_unset), so
# a saved rule reads back exactly as it was written.
router = APIRouter(prefix="/policy", tags=["policy"])
VersionNumber = Annotated[int, Path(ge=1, le=2_147_483_647, description="Policy version number")]


def _save_version(db: Session, rules: list[dict], comment: str) -> PolicyVersion:
    version = db.query(func.max(PolicyVersion.version)).scalar() or 0
    saved = PolicyVersion(version=version + 1, rules=rules, comment=comment)
    db.add(saved)
    commit_or_409(db, "The policy was changed concurrently; reload it and try again")
    db.refresh(saved)
    return saved


@router.get("", response_model=PolicyVersionResponse, response_model_exclude_unset=True, dependencies=ADMIN,
            responses=error_responses(*ADMIN_ERRORS))
def get_policy(db: Session = Depends(get_db)):
    """The policy in force: the highest version. Before any policy is saved, version 0 with no rules."""
    latest = version_in_force(db)
    if latest is None:
        return PolicyVersionResponse(version=0, rules=[], comment="No policy saved yet", created_at=None)
    return latest


@router.put("", response_model=PolicyVersionResponse, response_model_exclude_unset=True, status_code=201,
            dependencies=ADMIN, responses=error_responses(*ADMIN_ERRORS, 409, 400, 413))
def replace_policy(payload: PolicyUpdate, db: Session = Depends(get_db)):
    """Save the whole rule set as a new version. It is in force immediately; earlier versions are kept."""
    rules = [rule.model_dump(mode="json", exclude_none=True) for rule in payload.rules]
    return _save_version(db, rules, payload.comment)


@router.get("/versions", response_model=list[PolicyVersionSummary], dependencies=ADMIN, responses=error_responses(*ADMIN_ERRORS))
def list_versions(db: Session = Depends(get_db)):
    """Every saved version, newest first."""
    # The rules are counted by the database: each version's rule set is not loaded just to count it.
    rows = (db.query(PolicyVersion.version, PolicyVersion.comment, PolicyVersion.created_at,
                     func.json_array_length(PolicyVersion.rules))
            .order_by(PolicyVersion.version.desc()).all())
    return [PolicyVersionSummary(version=version, comment=comment, rule_count=count, created_at=created_at)
            for version, comment, created_at, count in rows]


@router.get("/versions/{version:int}", response_model=PolicyVersionResponse, response_model_exclude_unset=True,
            dependencies=ADMIN, responses=error_responses(*ADMIN_ERRORS, 404))
def get_version(version: VersionNumber, db: Session = Depends(get_db)):
    saved = db.get(PolicyVersion, version)
    if saved is None:
        raise HTTPException(status_code=404, detail="Policy version not found")
    return saved


@router.post("/versions/{version:int}/restore", response_model=PolicyVersionResponse, response_model_exclude_unset=True,
             status_code=201, dependencies=ADMIN, responses=error_responses(*ADMIN_ERRORS, 404, 409, 400, 413))
def restore_version(version: VersionNumber, payload: PolicyRestore | None = None, db: Session = Depends(get_db)):
    """Put an earlier version back in force by saving its rules as a new version (history is never rewritten)."""
    saved = db.get(PolicyVersion, version)
    if saved is None:
        raise HTTPException(status_code=404, detail="Policy version not found")
    comment = payload.comment if payload and payload.comment else f"Restored version {version}"
    return _save_version(db, saved.rules, comment)
