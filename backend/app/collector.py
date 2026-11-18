"""Lecture de auth.log et extraction des événements SSH vers la table events.

On ne garde que les lignes utiles à la détection (échecs, succès, utilisateur invalide).
Chaque fonction est pure et testable sans base ni réseau pour le parsing.
"""
import ipaddress
import re
from datetime import datetime

from app.db import get_conn

# Le nom d'utilisateur est contrôlé par l'attaquant : il peut contenir du texte
# imitant « from <ip> port <n> » pour usurper l'IP. On se protège en deux temps :
#   1. on n'accepte que le message issu du démon « sshd[pid]: » ;
#   2. on extrait l'IP et le port UNIQUEMENT en fin de ligne (ancre $),
#      puis on valide l'IP avec ipaddress. Le nom d'utilisateur (non fiable)
#      reste capturé en mode non gourmand, sans pouvoir décaler l'IP réelle.
#
# Exemples de messages gérés :
#   Failed password for root from 45.133.1.77 port 51044 ssh2
#   Failed password for invalid user admin from 45.133.1.77 port 51046 ssh2
#   Accepted password for victime from 103.88.4.19 port 40110 ssh2
#   Invalid user admin from 45.133.1.77 port 51046
# Préfixe syslog : le tag « sshd[pid]: » avec un PID obligatoire (recherche linéaire).
_RE_PREFIX = re.compile(r"\ssshd(?:-session)?\[\d+\]:\s(?P<msg>.+)$")
# Nom d'utilisateur limité au jeu de caractères réellement accepté par sshd.
_USER = r"(?P<user>[A-Za-z0-9._@-]{1,64})"
_RE_FAILED = re.compile(
    rf"^Failed password for (?:invalid user )?{_USER} from (?P<ip>\S+) port \d+(?: ssh2)?$"
)
_RE_ACCEPTED = re.compile(
    rf"^Accepted password for {_USER} from (?P<ip>\S+) port \d+(?: ssh2)?$"
)
_RE_INVALID = re.compile(rf"^Invalid user {_USER} from (?P<ip>\S+) port \d+$")

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

    # On n'analyse que le message émis par le démon sshd (tag avec PID obligatoire).
    prefix = _RE_PREFIX.search(line)
    if not prefix:
        return None
    msg = prefix.group("msg")

    for pattern, outcome in (
        (_RE_FAILED, "failed"),
        (_RE_ACCEPTED, "accepted"),
        (_RE_INVALID, "invalid_user"),
    ):
        m = pattern.match(msg)
        if m:
            break
    else:
        return None

    # L'IP est prise en fin de ligne : on la valide pour rejeter toute usurpation.
    ip = m.group("ip")
    try:
        ipaddress.ip_address(ip)
    except ValueError:
        return None

    return {
        "ts": ts,
        "ip": ip,
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
