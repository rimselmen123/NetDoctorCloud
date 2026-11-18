"""Boucle de l'agent : enquête sur une alerte via le LLM et ses outils.

Le LLM choisit les outils ; c'est le code (dispatch) qui les exécute réellement.
Chaque étape est tracée dans agent_steps. La boucle est bornée par max_steps.
"""
import ipaddress
import json

from app.config import settings
from app.db import get_conn
from app.prompts import SOC_SYSTEM_PROMPT, alert_user_message
from app.tools import TOOLS_SCHEMA, dispatch, dumps

MAX_TOKENS = 400  # réponse courte → coût maîtrisé


def _same_ip(a, b) -> bool:
    """Compare deux IP sous forme normalisée (sinon False)."""
    try:
        return ipaddress.ip_address(str(a)) == ipaddress.ip_address(str(b))
    except ValueError:
        return False


def _action_guard(name: str, args: dict, alert: dict) -> dict | None:
    """Restreint les actions à l'alerte en cours (défense anti prompt-injection).

    Renvoie un message d'erreur à transmettre au modèle, ou None si l'action est
    autorisée. Pour close_alert, impose l'id de l'alerte côté serveur.
    """
    if name == "close_alert":
        args["alert_id"] = alert["id"]
        return None
    if name == "block_ip" and not _same_ip(args.get("ip"), alert["ip"]):
        return {"ok": False, "error": "block_ip limité à l'IP de l'alerte"}
    if name == "flag_user" and args.get("user") != alert["username"]:
        return {"ok": False, "error": "flag_user limité au compte de l'alerte"}
    return None


def _record_step(alert_id: int, step: int, tool: str, args: dict, result: dict) -> None:
    """Enregistre une étape de l'agent dans la base (traçabilité)."""
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO agent_steps (alert_id, step, tool, args_json, result_json) "
            "VALUES (%(a)s, %(s)s, %(t)s, %(ar)s, %(r)s)",
            {"a": alert_id, "s": step, "t": tool,
             "ar": json.dumps(args, ensure_ascii=False, default=str),
             "r": dumps(result)},
        )
        conn.commit()


def _assistant_message(message, tool_calls) -> dict:
    """Reconstruit le message assistant (avec ses tool_calls) pour l'historique."""
    return {
        "role": "assistant", "content": message.content or "",
        "tool_calls": [
            {"id": tc.id, "type": "function",
             "function": {"name": tc.function.name, "arguments": tc.function.arguments}}
            for tc in tool_calls
        ],
    }


def _run_tool_call(tc, alert: dict, step: int) -> dict:
    """Exécute un appel d'outil (avec garde-fous) et renvoie {name, args, result}."""
    name = tc.function.name
    try:
        args = json.loads(tc.function.arguments or "{}")
    except json.JSONDecodeError:
        args, result = {}, {"ok": False, "error": "arguments JSON invalides"}
    else:
        guard = _action_guard(name, args, alert) if isinstance(args, dict) else None
        result = guard if guard is not None else dispatch(name, args)

    _record_step(alert["id"], step, name, args, result)
    return {"tool": name, "args": args, "result": result}


def run_on_alert(alert: dict, client) -> dict:
    """Traite une alerte. Renvoie {alert_id, steps, closed}.

    `client` expose client.chat.completions.create(...) (compatible OpenAI),
    ce qui permet de le remplacer par un faux client dans les tests.
    """
    messages = [
        {"role": "system", "content": SOC_SYSTEM_PROMPT},
        {"role": "user", "content": alert_user_message(alert)},
    ]
    steps: list[dict] = []
    closed = False

    for step in range(1, settings.max_steps + 1):
        response = client.chat.completions.create(
            model=settings.llm_model, messages=messages,
            tools=TOOLS_SCHEMA, max_tokens=MAX_TOKENS,
        )
        message = response.choices[0].message
        tool_calls = getattr(message, "tool_calls", None)

        # Réponse texte sans outil : l'agent a fini de parler, on arrête.
        if not tool_calls:
            break

        messages.append(_assistant_message(message, tool_calls))

        for tc in tool_calls:
            outcome = _run_tool_call(tc, alert, step)
            steps.append({"step": step, **outcome})
            messages.append({
                "role": "tool", "tool_call_id": tc.id, "content": dumps(outcome["result"]),
            })
            if outcome["tool"] == "close_alert" and outcome["result"].get("ok"):
                closed = True

        if closed:
            break

    return {"alert_id": alert["id"], "steps": steps, "closed": closed}


def run_agent(client=None) -> dict:
    """Traite toutes les alertes ouvertes (dans la limite de max_alerts)."""
    if client is None:
        from app.llm_client import make_client
        client = make_client()

    with get_conn() as conn:
        rows = conn.execute(
            "SELECT id, type, ip, username, count FROM alerts "
            "WHERE status = 'open' ORDER BY id LIMIT %(n)s",
            {"n": settings.max_alerts},
        ).fetchall()
    alerts = [{"id": r[0], "type": r[1], "ip": r[2], "username": r[3], "count": r[4]}
              for r in rows]

    results = [run_on_alert(a, client) for a in alerts]
    return {"processed": len(results), "results": results}
