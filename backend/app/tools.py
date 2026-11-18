"""Outils de l'agent SOC.

Trois outils de lecture (enquête) et trois d'action (écriture dans notre base
uniquement). Aucun outil ne touche au système audité : block_ip génère la commande
mais ne l'exécute jamais. Chaque fonction renvoie un dict (jamais d'exception vers
le modèle), tronqué pour limiter les tokens.
"""
import ipaddress
import json
import re
import shlex

from app.config import settings
from app.db import get_conn

MAX_EVENTS = 20          # nombre maximum d'événements renvoyés au modèle
MAX_FIELD_CHARS = 2000   # troncature par champ texte

# Nom d'utilisateur POSIX. Les commandes générées sont copiées par un humain dans un
# shell : on refuse tout nom hors de ce jeu pour empêcher une injection de commande.
_USERNAME_RE = re.compile(r"^[a-z_][a-z0-9_-]{0,31}\$?$")


def _truncate(value: str) -> str:
    return value if len(value) <= MAX_FIELD_CHARS else value[:MAX_FIELD_CHARS] + "…"


# --------------------------------------------------------------------------- #
# Outils de lecture (enquête)
# --------------------------------------------------------------------------- #
def search_events(ip: str | None = None, user: str | None = None,
                  minutes: int | None = None) -> dict:
    """Cherche des événements bruts filtrés par IP et/ou utilisateur."""
    clauses, params = [], {}
    if ip:
        clauses.append("ip = %(ip)s")
        params["ip"] = ip
    if user:
        clauses.append("username = %(user)s")
        params["user"] = user
    where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
    with get_conn() as conn:
        rows = conn.execute(
            f"SELECT ts, ip, username, outcome FROM events {where} "
            f"ORDER BY ts DESC NULLS LAST LIMIT {MAX_EVENTS}",
            params,
        ).fetchall()
    events = [{"ts": str(r[0]), "ip": r[1], "user": r[2], "outcome": r[3]} for r in rows]
    return {"count": len(events), "events": events}


def ip_history(ip: str) -> dict:
    """Résume l'activité d'une IP : nombre d'échecs, de succès, comptes visés."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT username, outcome FROM events WHERE ip = %(ip)s", {"ip": ip}
        ).fetchall()
    fails = sum(1 for _, o in rows if o in ("failed", "invalid_user"))
    success = sum(1 for _, o in rows if o == "accepted")
    users = sorted({u for u, _ in rows})
    try:
        is_private = ipaddress.ip_address(ip).is_private
    except ValueError:
        is_private = None
    return {
        "ip": ip, "failures": fails, "successes": success,
        "targeted_users": users[:MAX_EVENTS], "is_private": is_private,
    }


def user_logins(user: str) -> dict:
    """Historique de connexion d'un compte, avec détection d'un succès après échecs."""
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT ts, ip, outcome FROM events WHERE username = %(u)s "
            "ORDER BY ts ASC NULLS LAST", {"u": user},
        ).fetchall()
    fails = sum(1 for _, _, o in rows if o in ("failed", "invalid_user"))
    success = sum(1 for _, _, o in rows if o == "accepted")
    # Un succès survenu après au moins un échec sur le même compte.
    success_after_failures = False
    seen_fail = False
    for _, _, outcome in rows:
        if outcome in ("failed", "invalid_user"):
            seen_fail = True
        elif outcome == "accepted" and seen_fail:
            success_after_failures = True
    return {
        "user": user, "failures": fails, "successes": success,
        "success_after_failures": success_after_failures,
    }


# --------------------------------------------------------------------------- #
# Outils d'action (écriture dans notre base uniquement)
# --------------------------------------------------------------------------- #
def block_ip(ip: str, reason: str = "") -> dict:
    """Enregistre un blocage d'IP et génère la commande iptables (sans l'exécuter)."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return {"ok": False, "error": f"IP invalide : {ip}"}

    # Une IPv6 à scope (fe80::1%eth0) est ambiguë : on la refuse.
    if getattr(addr, "scope_id", None):
        return {"ok": False, "error": "IP avec scope non supportée"}

    # Hors mode labo, on refuse de bloquer une IP privée/locale (réseau interne).
    if (addr.is_private or addr.is_loopback) and not settings.lab_mode:
        return {"ok": False, "error": "IP privée/locale refusée hors mode labo"}

    # On repart de la forme normalisée, puis on l'échappe (ceinture + bretelles).
    normalized = str(addr)
    binary = "iptables" if addr.version == 4 else "ip6tables"
    command = f"{binary} -A INPUT -s {shlex.quote(normalized)} -j DROP"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO actions (type, target, reason, command) "
            "VALUES ('block_ip', %(ip)s, %(reason)s, %(cmd)s)",
            {"ip": normalized, "reason": _truncate(reason), "cmd": command},
        )
        conn.commit()
    return {"ok": True, "action": "block_ip", "target": normalized, "command": command}


def flag_user(user: str, reason: str = "") -> dict:
    """Signale un compte comme potentiellement compromis."""
    if not _USERNAME_RE.match(user):
        return {"ok": False, "error": "nom d'utilisateur invalide"}
    command = f"passwd --expire {shlex.quote(user)}  # forcer le changement de mot de passe"
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO actions (type, target, reason, command) "
            "VALUES ('flag_user', %(u)s, %(reason)s, %(cmd)s)",
            {"u": user, "reason": _truncate(reason), "cmd": command},
        )
        conn.commit()
    return {"ok": True, "action": "flag_user", "target": user}


_VERDICTS = {"true_positive", "false_positive"}
_SEVERITIES = {"critical", "high", "medium", "low"}


def close_alert(alert_id: int, verdict: str, severity: str, reason: str) -> dict:
    """Clôt une alerte avec un verdict, une gravité et une justification."""
    if verdict not in _VERDICTS:
        return {"ok": False, "error": f"verdict invalide (attendu {_VERDICTS})"}
    if severity not in _SEVERITIES:
        return {"ok": False, "error": f"gravité invalide (attendu {_SEVERITIES})"}
    with get_conn() as conn:
        cur = conn.execute(
            "UPDATE alerts SET status='closed', verdict=%(v)s, severity=%(s)s, "
            "reason=%(r)s WHERE id=%(id)s AND status <> 'closed'",
            {"v": verdict, "s": severity, "r": _truncate(reason), "id": alert_id},
        )
        conn.commit()
    if cur.rowcount == 0:
        return {"ok": False, "error": f"alerte {alert_id} introuvable ou déjà close"}
    return {"ok": True, "alert_id": alert_id, "verdict": verdict, "severity": severity}


# --------------------------------------------------------------------------- #
# Registre : schémas Chat Completions + répartiteur
# --------------------------------------------------------------------------- #
_REGISTRY = {
    "search_events": search_events,
    "ip_history": ip_history,
    "user_logins": user_logins,
    "block_ip": block_ip,
    "flag_user": flag_user,
    "close_alert": close_alert,
}


def _fn(name, desc, props, required):
    return {
        "type": "function",
        "function": {
            "name": name, "description": desc,
            "parameters": {
                "type": "object", "properties": props,
                "required": required, "additionalProperties": False,
            },
        },
    }


TOOLS_SCHEMA = [
    _fn("search_events", "Cherche des événements de logs bruts par IP et/ou utilisateur.",
        {"ip": {"type": "string"}, "user": {"type": "string"},
         "minutes": {"type": "integer"}}, []),
    _fn("ip_history", "Résume l'activité d'une IP : échecs, succès, comptes visés, privée ou non.",
        {"ip": {"type": "string"}}, ["ip"]),
    _fn("user_logins", "Historique d'un compte ; indique s'il y a eu un succès après des échecs.",
        {"user": {"type": "string"}}, ["user"]),
    _fn("block_ip", "Enregistre le blocage d'une IP et génère la commande iptables (n'exécute rien).",
        {"ip": {"type": "string"}, "reason": {"type": "string"}}, ["ip"]),
    _fn("flag_user", "Signale un compte comme potentiellement compromis.",
        {"user": {"type": "string"}, "reason": {"type": "string"}}, ["user"]),
    _fn("close_alert",
        "Clôt l'alerte avec un verdict (true_positive/false_positive), une gravité "
        "(critical/high/medium/low) et une justification. À appeler en dernier.",
        {"alert_id": {"type": "integer"},
         "verdict": {"type": "string", "enum": sorted(_VERDICTS)},
         "severity": {"type": "string", "enum": sorted(_SEVERITIES)},
         "reason": {"type": "string"}},
        ["alert_id", "verdict", "severity", "reason"]),
]


def dispatch(name: str, args: dict) -> dict:
    """Exécute l'outil demandé. Renvoie une erreur au modèle sans rien exécuter si
    l'outil est inconnu ou si les arguments ne conviennent pas."""
    fn = _REGISTRY.get(name)
    if fn is None:
        return {"ok": False, "error": f"outil inconnu : {name}"}
    if not isinstance(args, dict):
        return {"ok": False, "error": "arguments invalides (objet JSON attendu)"}
    try:
        return fn(**args)
    except TypeError as exc:
        return {"ok": False, "error": f"arguments invalides : {exc}"}


def dumps(result: dict) -> str:
    """Sérialise un résultat d'outil en JSON compact pour le message 'tool'."""
    return _truncate(json.dumps(result, ensure_ascii=False, default=str))
