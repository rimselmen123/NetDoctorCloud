"""API FastAPI : expose la collecte, l'agent et la consultation des alertes."""
from fastapi import Depends, FastAPI, Header, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

from app.agent import run_agent
from app.collector import collect
from app.config import settings
from app.db import get_conn, init_db
from app.detection import run_detection
from app.report import send_report

app = FastAPI(title="AgentDoctor SOC")

# Autorise l'interface Angular (port 4200) à appeler l'API.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:4200"],
    allow_methods=["*"],
    allow_headers=["*"],
)


def require_app_header(x_requested_by: str = Header(default="")) -> None:
    """Exige un en-tête personnalisé sur les routes sensibles.

    Un en-tête non standard force un préflight CORS : comme l'API n'autorise que
    http://localhost:4200, cela bloque les requêtes CSRF venues d'un autre site.
    """
    if x_requested_by != "agentdoctor":
        raise HTTPException(status_code=403, detail="en-tête X-Requested-By manquant")


@app.on_event("startup")
def _startup() -> None:
    """Crée les tables au démarrage."""
    init_db()


@app.get("/health")
def health() -> dict:
    return {"status": "ok", "model": settings.llm_model}


@app.post("/collect", dependencies=[Depends(require_app_header)])
def collect_logs() -> dict:
    """Lit auth.log, insère les événements, puis lance la détection."""
    inserted = collect(settings.auth_log_path)
    new_alerts = run_detection()
    return {"events_inserted": inserted, "new_alerts": len(new_alerts),
            "alerts": new_alerts}


@app.post("/agent/run", dependencies=[Depends(require_app_header)])
def agent_run() -> dict:
    """Lance l'agent sur les alertes ouvertes puis envoie le rapport email."""
    result = run_agent()
    report = send_report()
    return {"processed": result["processed"],
            "email_sent": report["ok"], "email_error": report["error"]}


@app.get("/alerts")
def list_alerts() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, type, ip, username, count, status, verdict, severity, reason "
            "FROM alerts ORDER BY id DESC"
        ).fetchall()
    cols = ["id", "type", "ip", "username", "count", "status",
            "verdict", "severity", "reason"]
    return [dict(zip(cols, r)) for r in rows]


@app.get("/alerts/{alert_id}/steps")
def alert_steps(alert_id: int) -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT step, tool, args_json, result_json FROM agent_steps "
            "WHERE alert_id = %(id)s ORDER BY id",
            {"id": alert_id},
        ).fetchall()
    cols = ["step", "tool", "args_json", "result_json"]
    return [dict(zip(cols, r)) for r in rows]


@app.get("/actions")
def list_actions() -> list[dict]:
    with get_conn() as conn:
        rows = conn.execute(
            "SELECT type, target, reason, command, created_at FROM actions ORDER BY id DESC"
        ).fetchall()
    cols = ["type", "target", "reason", "command", "created_at"]
    return [dict(zip(cols, r)) for r in rows]


class ResetBody(BaseModel):
    confirm: bool = False


@app.post("/reset", dependencies=[Depends(require_app_header)])
def reset_demo(body: ResetBody) -> dict:
    """Remet la démo à zéro : vide les tables (utile avant une présentation).

    Réservé au mode labo pour éviter toute suppression accidentelle en production.
    """
    if not settings.lab_mode:
        raise HTTPException(status_code=403, detail="réservé au mode labo")
    if not body.confirm:
        return {"ok": False, "error": "confirmation requise"}
    with get_conn() as conn:
        conn.execute("DELETE FROM agent_steps")
        conn.execute("DELETE FROM actions")
        conn.execute("DELETE FROM alerts")
        conn.execute("DELETE FROM events")
        conn.commit()
    return {"ok": True}
