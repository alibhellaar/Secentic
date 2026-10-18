import os
from sqlalchemy import create_engine, event
from sqlalchemy.exc import IntegrityError, OperationalError, ProgrammingError
from sqlalchemy.orm import sessionmaker, declarative_base
from dotenv import load_dotenv

load_dotenv()

# No default on purpose: a server missing its configuration must not quietly start on an
# empty local database. The app refuses to start without it (see main.py); tests supply their own.
DATABASE_URL = os.getenv("DATABASE_URL")


def make_engine(url: str):
    # check_same_thread is SQLite-only; other drivers (e.g. psycopg for PostgreSQL) reject it.
    sqlite = url.startswith("sqlite")
    engine = create_engine(url, connect_args={"check_same_thread": False} if sqlite else {})
    if sqlite:
        # SQLite only enforces foreign keys when asked, on every connection. Without it a row could
        # point at a deleted one (e.g. a key bound to an agent whose registration was just rejected),
        # which PostgreSQL refuses.
        @event.listens_for(engine, "connect")
        def _enforce_foreign_keys(dbapi_connection, _record):
            cursor = dbapi_connection.cursor()
            cursor.execute("PRAGMA foreign_keys=ON")
            cursor.close()
    return engine


engine = make_engine(DATABASE_URL) if DATABASE_URL else None
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()


def create_tables(bind) -> None:
    """Create missing tables. When several server processes start on an empty database at once,
    another may create some of them in between; the second pass then creates the rest."""
    try:
        Base.metadata.create_all(bind=bind)
    except (IntegrityError, OperationalError, ProgrammingError):
        Base.metadata.create_all(bind=bind)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
