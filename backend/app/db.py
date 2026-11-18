"""Accès à PostgreSQL via psycopg v3 : connexion et initialisation du schéma."""
from pathlib import Path

import psycopg

from app.config import settings

_SCHEMA_PATH = Path(__file__).with_name("schema.sql")


def get_conn() -> psycopg.Connection:
    """Ouvre une connexion à la base. L'appelant est responsable de la fermer."""
    return psycopg.connect(settings.database_url)


def init_db() -> None:
    """Crée les tables si elles n'existent pas (idempotent)."""
    schema = _SCHEMA_PATH.read_text(encoding="utf-8")
    with get_conn() as conn:
        conn.execute(schema)
        conn.commit()
