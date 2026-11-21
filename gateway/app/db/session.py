import os
from typing import Generator

from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool, StaticPool

from app.core.config import get_settings
from app.db.base import Base

settings = get_settings()

# For SQLite, ensure parent directory exists and enable check_same_thread=False
connect_args = {}
engine_kwargs: dict = {
    "echo": (settings.log_level.upper() == "DEBUG"),
}
if settings.database_url.startswith("sqlite"):
    connect_args["check_same_thread"] = False
    connect_args["timeout"] = 5.0
    if ":memory:" in settings.database_url:
        engine_kwargs["poolclass"] = StaticPool
    else:
        db_path = settings.database_url.replace("sqlite:///", "")
        if "/" in db_path or "\\" in db_path:
            os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        engine_kwargs["poolclass"] = QueuePool
        engine_kwargs["pool_size"] = 8
        engine_kwargs["max_overflow"] = 16

engine = create_engine(
    settings.database_url,
    connect_args=connect_args,
    **engine_kwargs,
)


@event.listens_for(engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):
    """Configure SQLite for high-concurrency environments (WAL mode, busy_timeout & normal sync)."""
    if settings.database_url.startswith("sqlite"):
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA journal_mode=WAL;")
        cursor.execute("PRAGMA synchronous=NORMAL;")
        cursor.execute("PRAGMA busy_timeout=5000;")
        cursor.execute("PRAGMA temp_store=MEMORY;")
        cursor.execute("PRAGMA cache_size=-16000;")
        cursor.close()


SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def init_db() -> None:
    """Initialize database tables and run lightweight schema migrations."""
    # Import models so Base metadata is populated
    import app.db.models  # noqa: F401

    Base.metadata.create_all(bind=engine)

    if settings.database_url.startswith("sqlite"):
        try:
            from sqlalchemy import text
            with engine.connect() as conn:
                cursor = conn.execute(text("PRAGMA table_info(security_events)"))
                existing_cols = [row[1] for row in cursor.fetchall()]
                if "session_id" not in existing_cols:
                    conn.execute(text("ALTER TABLE security_events ADD COLUMN session_id VARCHAR(64)"))
                if "kill_chain_stage" not in existing_cols:
                    conn.execute(text("ALTER TABLE security_events ADD COLUMN kill_chain_stage VARCHAR(50)"))
                if "api_protocol" not in existing_cols:
                    conn.execute(text("ALTER TABLE security_events ADD COLUMN api_protocol VARCHAR(32)"))
                    conn.execute(
                        text(
                            "CREATE INDEX IF NOT EXISTS ix_security_events_api_protocol "
                            "ON security_events (api_protocol)"
                        )
                    )
                conn.commit()
        except Exception:
            pass


def get_db() -> Generator[Session, None, None]:
    """FastAPI Dependency for database session management."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
