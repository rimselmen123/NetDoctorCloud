"""Lecture de auth.log et extraction des événements SSH vers la table events.

On ne garde que les lignes utiles à la détection (échecs, succès, utilisateur invalide).
Chaque fonction est pure et testable sans base ni réseau pour le parsing.
"""
import re
from datetime import datetime

from app.db import get_conn

# Exemples de lignes gérées :
#   Failed password for root from 45.133.1.77 port 51044 ssh2
#   Failed password for invalid user admin from 45.133.1.77 port 51046 ssh2
#   Accepted password for victime from 103.88.4.19 port 40110 ssh2
#   Invalid user admin from 45.133.1.77 port 51046
_RE_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\S+)"
)
_RE_ACCEPTED = re.compile(r"Accepted password for (?P<user>\S+) from (?P<ip>\S+)")
_RE_INVALID = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")

# Horodatage ISO 8601 en tête de ligne (format rsyslog moderne d'Ubuntu 24.04).
_RE_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T[\d:.]+[+\-]\d{2}:\d{2})")


def _parse_ts(line: str) -> datetime | None:
    """Extrait l'horodatage ISO en tête de ligne, ou None s'il est absent."""
    m = _RE_TS.match(line)
    if not m:
        return None
    try:
        return datetime.fromisoformat(m.group("ts"))
    except ValueError:
        return None


def parse_line(line: str) -> dict | None:
    """Transforme une ligne de auth.log en dict {ts, ip, username, outcome, raw}.

    Renvoie None si la ligne n'est pas un événement SSH pertinent.
    """
    line = line.rstrip("\n")
    ts = _parse_ts(line)

    # L'ordre compte : 'invalid user' contient aussi 'Failed password' parfois.
    m = _RE_FAILED.search(line)
    if m:
        outcome = "failed"
    else:
        m = _RE_ACCEPTED.search(line)
        if m:
            outcome = "accepted"
        else:
            m = _RE_INVALID.search(line)
            if m:
                outcome = "invalid_user"
            else:
                return None

    return {
        "ts": ts,
        "ip": m.group("ip"),
        "username": m.group("user"),
        "outcome": outcome,
        "raw": line,
    }


def collect(path: str) -> int:
    """Lit le fichier de logs et insère les nouvelles lignes dans events.

    Renvoie le nombre de lignes réellement ajoutées (les doublons sont ignorés).
    """
    inserted = 0
    with open(path, encoding="utf-8", errors="replace") as fh, get_conn() as conn:
        for line in fh:
            event = parse_line(line)
            if event is None:
                continue
            cur = conn.execute(
                """
                INSERT INTO events (ts, ip, username, outcome, raw)
                VALUES (%(ts)s, %(ip)s, %(username)s, %(outcome)s, %(raw)s)
                ON CONFLICT (raw) DO NOTHING
                """,
                event,
            )
            inserted += cur.rowcount
        conn.commit()
    return inserted
