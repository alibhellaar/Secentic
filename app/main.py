from contextlib import asynccontextmanager

from fastapi import FastAPI, Response
from fastapi.exceptions import RequestValidationError
from sqlalchemy.exc import SQLAlchemyError
from starlette.routing import Route
from .database import SessionLocal, create_tables, engine
from .identity import SIGNATURE_SECURITY_SCHEMES
from .request_guards import (
    IgnoreTrailingSlash, LimitBodySize, database_error_handler, method_not_allowed_handler, validation_error_handler,
)
from .routers import agents, delegation, gateway, identity, policy, tools
from .utils import ensure_current_fingerprints


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Runs at server start rather than import, so importing the app (e.g. in tests)
    # never touches the configured database.
    if engine is None:
        raise RuntimeError("DATABASE_URL is not set; copy .env.example to .env (see README)")
    create_tables(engine)
    with SessionLocal() as db:
        ensure_current_fingerprints(db)
    yield


app = FastAPI(title="Secentic — AI Agent Security Control Plane", lifespan=lifespan)
app.add_middleware(LimitBodySize)
app.add_middleware(IgnoreTrailingSlash)
app.add_exception_handler(RequestValidationError, validation_error_handler)
app.add_exception_handler(SQLAlchemyError, database_error_handler)
# The single list of routers: it registers them and gives the 405 handler their routes.
_ROUTERS = (agents.router, identity.router, delegation.router, tools.router, policy.router, gateway.router)
for _router in _ROUTERS:
    app.include_router(_router)


@app.get("/health")
def health():
    return {"status": "ok"}


@app.head("/health", response_class=Response, responses={200: {"description": "Healthy (no body)"}})
def health_head():
    """For monitors that check with HEAD: 200 without a body."""
    return Response()


# Recent FastAPI versions keep included routes inside their routers rather than in
# app.router.routes, so routes come from the routers themselves, plus every route declared on the
# app (/health and FastAPI's /openapi.json, /docs, /docs/oauth2-redirect and /redoc).
_routes = [route for router in _ROUTERS for route in router.routes]
_routes += [route for route in app.router.routes if isinstance(route, Route)]
app.add_exception_handler(405, method_not_allowed_handler(_routes))

_generate_openapi = app.openapi


def openapi():
    """The generated schema, plus the security schemes that describe signed agent requests."""
    if app.openapi_schema is None:
        schema = _generate_openapi()
        schema.setdefault("components", {}).setdefault("securitySchemes", {}).update(SIGNATURE_SECURITY_SCHEMES)
    return app.openapi_schema


app.openapi = openapi
