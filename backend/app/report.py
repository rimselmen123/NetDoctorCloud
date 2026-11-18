"""Rapport email de fin d'enquête.

Le rapport est construit en Python depuis la base (aucun token LLM) : il ne contient
que ce que l'agent a réellement fait. L'envoi se fait via Gmail SMTP (STARTTLS).
"""
import html
import smtplib
from email.message import EmailMessage

from app.config import settings
from app.db import get_conn

_SEV_COLOR = {"critical": "#FF2D55", "high": "#FF7A1A",
              "medium": "#FFC53D", "low": "#4D7CFF"}


def gather_stats() -> dict:
    """Rassemble les chiffres du rapport depuis la base."""
    with get_conn() as conn:
        alerts = conn.execute(
            "SELECT id, type, ip, username, verdict, severity, reason "
            "FROM alerts WHERE status = 'closed' ORDER BY id"
        ).fetchall()
        actions = conn.execute(
            "SELECT type, target, command FROM actions ORDER BY id"
        ).fetchall()
    alert_rows = [
        {"id": a[0], "type": a[1], "ip": a[2], "username": a[3],
         "verdict": a[4], "severity": a[5], "reason": a[6]}
        for a in alerts
    ]
    return {
        "alerts": alert_rows,
        "actions": [{"type": a[0], "target": a[1], "command": a[2]} for a in actions],
        "total": len(alert_rows),
        "true_positives": sum(1 for a in alert_rows if a["verdict"] == "true_positive"),
        "false_positives": sum(1 for a in alert_rows if a["verdict"] == "false_positive"),
    }


def build_report(stats: dict) -> str:
    """Rend le corps HTML du rapport (échappe toutes les valeurs des logs)."""
    def esc(v):
        return html.escape(str(v if v is not None else ""))

    rows = ""
    for a in stats["alerts"]:
        color = _SEV_COLOR.get(a["severity"], "#888")
        rows += (
            f"<tr>"
            f"<td>#{esc(a['id'])}</td><td>{esc(a['type'])}</td>"
            f"<td>{esc(a['ip'])}</td><td>{esc(a['username'])}</td>"
            f"<td style='color:{color};font-weight:bold'>{esc(a['severity'])}</td>"
            f"<td>{esc(a['verdict'])}</td><td>{esc(a['reason'])}</td></tr>"
        )
    actions = "".join(
        f"<li><code>{esc(a['type'])}</code> → {esc(a['target'])}"
        f" &nbsp; <code>{esc(a['command'])}</code></li>"
        for a in stats["actions"]
    ) or "<li>Aucune action.</li>"

    return (
        f"<h2>AgentDoctor — rapport d'enquête</h2>"
        f"<p>{stats['total']} alerte(s) traitée(s) · "
        f"{stats['true_positives']} vrai(s) positif(s) · "
        f"{stats['false_positives']} faux positif(s).</p>"
        f"<table border='1' cellpadding='6' cellspacing='0'>"
        f"<tr><th>#</th><th>Type</th><th>IP</th><th>Compte</th>"
        f"<th>Gravité</th><th>Verdict</th><th>Justification</th></tr>{rows}</table>"
        f"<h3>Actions recommandées</h3><ul>{actions}</ul>"
        f"<p style='color:#888'>Audit défensif sur cibles autorisées · lab WSL.</p>"
    )


def send_report() -> dict:
    """Construit puis envoie le rapport. Ne lève jamais : renvoie {ok, error, stats}."""
    stats = gather_stats()
    if stats["total"] == 0:
        return {"ok": False, "error": "aucune alerte traitée", "stats": stats}
    if not (settings.smtp_user and settings.smtp_app_password and settings.report_to):
        return {"ok": False, "error": "configuration SMTP incomplète", "stats": stats}

    msg = EmailMessage()
    msg["Subject"] = (f"AgentDoctor — {stats['total']} alerte(s), "
                      f"{stats['true_positives']} vrai(s) positif(s)")
    msg["From"] = settings.smtp_user
    msg["To"] = settings.report_to
    msg.set_content("Rapport AgentDoctor (version HTML requise).")
    msg.add_alternative(build_report(stats), subtype="html")

    try:
        with smtplib.SMTP("smtp.gmail.com", 587, timeout=10) as server:
            server.starttls()
            server.login(settings.smtp_user, settings.smtp_app_password)
            server.send_message(msg)
    except Exception as exc:  # pragma: no cover - dépend du réseau
        return {"ok": False, "error": f"échec SMTP : {type(exc).__name__}", "stats": stats}
    return {"ok": True, "error": None, "stats": stats}
