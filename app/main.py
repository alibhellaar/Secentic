from fastapi import FastAPI
from .database import Base, engine
from .routers import agents

Base.metadata.create_all(bind=engine)

app = FastAPI(title="Secentic — M1 Agent Discovery")
app.include_router(agents.router)


@app.get("/health")
def health():
    return {"status": "ok"}