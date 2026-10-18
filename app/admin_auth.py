"""Control-plane (human administrator) authentication.

Admins authenticate with a bearer token. Agents never do: they prove who they are with
signed requests (see identity.py), so agent identity stays separate from human identity.
The static token is an MVP stand-in for SSO/OIDC, which is out of scope for the FYP.
"""
import hmac
import os

from fastapi import Depends, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

MIN_TOKEN_LENGTH = 16

bearer = HTTPBearer(auto_error=False)


def require_admin(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> None:
    expected = os.getenv("SECENTIC_ADMIN_TOKEN", "")
    if len(expected) < MIN_TOKEN_LENGTH:
        # Fail closed: a missing or guessable token (e.g. a copied placeholder) means no admin access.
        raise HTTPException(
            status_code=503,
            detail=f"Admin access is disabled: set SECENTIC_ADMIN_TOKEN to a random value of at least {MIN_TOKEN_LENGTH} characters",
        )
    if credentials is None or not hmac.compare_digest(credentials.credentials.encode(), expected.encode()):
        raise HTTPException(status_code=401, detail="Invalid admin token", headers={"WWW-Authenticate": "Bearer"})
