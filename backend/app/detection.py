"""Règles de détection : transforment les événements bruts en alertes.

Ce sont ces règles Python (et non le LLM) qui décident ce qui est suspect.
`detect` est une fonction pure, testable sans base de données.
"""
from collections import Counter, defaultdict

from app.db import get_conn

# Seuil d'échecs à partir duquel on parle de force brute.
BRUTE_FORCE_THRESHOLD = 5

# Gravité provisoire posée par la détection ; l'agent peut l'ajuster à la fermeture.
_PROVISIONAL_SEVERITY = {
    "success_after_failures": "critical",
    "brute_force": "high",
    "failed_login": "low",
}


def detect(events: list[dict]) -> list[dict]:
    """À partir d'une liste d'événements, renvoie les alertes à créer.

    Chaque événement est un dict avec au moins : ip, username, outcome.
    Alerte = {type, ip, username, count, severity}.
    """
    fails_by_ip: dict[str, int] = defaultdict(int)
    fail_users_by_ip: dict[str, Counter] = defaultdict(Counter)
    success_user_by_ip: dict[str, str] = {}

    for ev in events:
        ip = ev.get("ip")
        if not ip:
            continue
        if ev["outcome"] in ("failed", "invalid_user"):
            fails_by_ip[ip] += 1
            fail_users_by_ip[ip][ev.get("username", "?")] += 1
        elif ev["outcome"] == "accepted":
            success_user_by_ip[ip] = ev.get("username", "?")

    alerts: list[dict] = []
    for ip, fails in fails_by_ip.items():
        # Utilisateur le plus visé par cette IP.
        top_user = fail_users_by_ip[ip].most_common(1)[0][0]

        if fails >= BRUTE_FORCE_THRESHOLD and ip in success_user_by_ip:
            alert_type = "success_after_failures"
            username = success_user_by_ip[ip]
        elif fails >= BRUTE_FORCE_THRESHOLD:
            alert_type = "brute_force"
            username = top_user
        else:  # 1 à 4 échecs
            alert_type = "failed_login"
            username = top_user

        alerts.append({
            "type": alert_type,
            "ip": ip,
            "username": username,
            "count": fails,
            "severity": _PROVISIONAL_SEVERITY[alert_type],
        })
    return alerts


def run_detection() -> list[dict]:
    """Lit les events en base, applique les règles et insère les nouvelles alertes.

    Une alerte n'est pas recréée si une alerte ouverte de même (type, ip, username) existe.
    Renvoie la liste des alertes réellement insérées (avec leur id).
    """
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT ip, username, outcome FROM events"
        ).fetchall()
        events = [{"ip": r[0], "username": r[1], "outcome": r[2]} for r in rows]

        new_alerts = []
        for alert in detect(events):
            existing = conn.execute(
                """
                SELECT 1 FROM alerts
                WHERE type = %(type)s AND ip = %(ip)s AND username = %(username)s
                  AND status = 'open'
                """,
                alert,
            ).fetchone()
            if existing:
                continue
            new_id = conn.execute(
                """
                INSERT INTO alerts (type, ip, username, count, severity)
                VALUES (%(type)s, %(ip)s, %(username)s, %(count)s, %(severity)s)
                RETURNING id
                """,
                alert,
            ).fetchone()[0]
            new_alerts.append({**alert, "id": new_id})
        conn.commit()
    return new_alerts
