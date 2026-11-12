from contextlib import contextmanager
import psycopg
from psycopg.rows import dict_row
from .config import settings

class DatabaseUnavailable(RuntimeError):
    pass

@contextmanager
def connection():
    if not settings.database_url:
        raise DatabaseUnavailable("DATABASE_URL is not configured")
    # Use Neon pooled endpoint (-pooler) for serverless traffic.
    conn = psycopg.connect(settings.database_url, row_factory=dict_row, connect_timeout=8)
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def fetch_all(sql, params=()):
    with connection() as conn:
        return list(conn.execute(sql, params).fetchall())

def fetch_one(sql, params=()):
    with connection() as conn:
        return conn.execute(sql, params).fetchone()
