"""Protections and error responses applied to every request.

- Request bodies are capped at MAX_BODY_BYTES (413), so nobody can make the server read or
  store megabytes through the open registration endpoint.
- Validation errors (422) never echo nested input back: FastAPI's default handler did, and a
  deeply nested JSON body made it recurse until the request failed with a 500.
- 405 responses list every method the path supports in `Allow`.
- A trailing slash is ignored: /agents/ is /agents, without a redirect.
- Database errors anywhere, authentication included, answer 503 rather than a bare 500.
"""
import logging
import math

from fastapi import HTTPException, Request
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse

logger = logging.getLogger("secentic")
DATABASE_UNAVAILABLE = "The database could not complete the request; try again later (agents must treat this as a denial)"
# Request bodies are limited (413). Every request but a policy is small: the largest, a delegation
# or a tool definition at their limits, is about 20 KB. A whole policy (up to 200 rules) can be far
# larger, so PUT /policy, an administrator-only endpoint, may send up to 1 MiB.
MAX_BODY_BYTES = 64 * 1024
MAX_POLICY_BODY_BYTES = 1024 * 1024
BODY_LIMITS = {"/policy": MAX_POLICY_BODY_BYTES}  # by path, after a trailing slash is dropped


def _too_large_detail(limit: int) -> str:
    return f"Request body too large (limit {limit} bytes)"


class IgnoreTrailingSlash:
    """ASGI middleware serving /path/ as /path, so each route is declared once (no hidden twin
    routes that could miss a dependency) and clients need no redirect. Signed requests are checked
    against the path without the slash."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        path = scope.get("path", "")
        if scope["type"] == "http" and len(path) > 1 and path.endswith("/"):
            scope = dict(scope, path=path[:-1])
            raw_path = scope.get("raw_path")
            if raw_path and raw_path.endswith(b"/"):
                scope["raw_path"] = raw_path[:-1]
        await self.app(scope, receive, send)


class LimitBodySize:
    """ASGI middleware refusing request bodies larger than their path's limit with 413: `limits`
    by path, `max_bytes` everywhere else."""

    def __init__(self, app, max_bytes: int = MAX_BODY_BYTES, limits: dict[str, int] | None = None):
        self.app = app
        self.max_bytes = max_bytes
        self.limits = BODY_LIMITS if limits is None else limits

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        limit = self.limits.get(scope.get("path", ""), self.max_bytes)
        declared = dict(scope["headers"]).get(b"content-length", b"")
        if declared.isdigit() and int(declared) > limit:
            response = JSONResponse({"detail": _too_large_detail(limit)}, status_code=413)
            await response(scope, receive, send)
            return

        received = 0

        async def limited_receive():
            # Bodies sent without Content-Length (chunked) are counted as they arrive.
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > limit:
                    raise HTTPException(status_code=413, detail=_too_large_detail(limit))
            return message

        await self.app(scope, limited_receive, send)


def _echoable(value) -> bool:
    """Whether an invalid value can be shown back in a 422: a single number, boolean or null, or
    text that is valid UTF-8. Never an object or a list (deeply nested input made the encoder
    recurse until the request failed), and never what a JSON response cannot carry: raw bytes (a
    body that is not UTF-8), a lone surrogate such as "\\ud800", NaN or Infinity (which Python's JSON
    parser accepts). Echoing those made the error response itself fail with a 500."""
    if value is None or isinstance(value, (bool, int)):
        return True
    if isinstance(value, float):
        return math.isfinite(value)
    if isinstance(value, str):
        try:
            value.encode("utf-8")
        except UnicodeEncodeError:
            return False
        return True
    return False


async def validation_error_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    """FastAPI's 422 response, echoing an invalid value back only when that is safe (_echoable)."""
    errors = []
    for error in exc.errors():
        error = dict(error)
        if "input" in error and not _echoable(error["input"]):
            del error["input"]
        errors.append(error)
    return JSONResponse(status_code=422, content={"detail": jsonable_encoder(errors)})


def method_not_allowed_handler(routes):
    """Build the 405 handler. Starlette lists only the methods of the first route whose path
    matched, but FastAPI makes one route per method, so Allow would miss the others."""

    async def handler(request: Request, exc) -> JSONResponse:
        path = request.scope["path"]
        allowed = sorted({method for route in routes if route.path_regex.match(path) for method in route.methods or ()})
        return JSONResponse({"detail": "Method Not Allowed"}, status_code=405, headers={"Allow": ", ".join(allowed)})

    return handler


async def database_error_handler(request: Request, exc: Exception) -> JSONResponse:
    """Fail closed when the database fails (unreachable, deadlock, ...), wherever it happens."""
    logger.exception("Database error while handling %s %s", request.method, request.scope.get("path"), exc_info=exc)
    return JSONResponse({"detail": DATABASE_UNAVAILABLE}, status_code=503)
