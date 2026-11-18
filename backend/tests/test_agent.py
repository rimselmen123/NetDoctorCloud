"""Test de la boucle agent avec un faux client LLM (aucun réseau, aucune vraie base)."""
import json
from types import SimpleNamespace

import pytest

import app.agent as agent


def _tool_call(call_id, name, args):
    return SimpleNamespace(
        id=call_id, type="function",
        function=SimpleNamespace(name=name, arguments=json.dumps(args)),
    )


def _response(message):
    return SimpleNamespace(choices=[SimpleNamespace(message=message)])


class FakeLLM:
    """Renvoie une séquence de messages prédéfinis, un par appel create()."""

    def __init__(self, messages):
        self._messages = list(messages)
        self.calls = 0
        self.chat = SimpleNamespace(completions=SimpleNamespace(create=self._create))

    def _create(self, **kwargs):
        msg = self._messages[self.calls]
        self.calls += 1
        return _response(msg)


@pytest.fixture(autouse=True)
def _no_db(monkeypatch):
    """Neutralise l'écriture des étapes et la vraie exécution des outils."""
    monkeypatch.setattr(agent, "_record_step", lambda *a, **k: None)
    monkeypatch.setattr(agent, "dispatch",
                        lambda name, args: {"ok": True, "tool": name})
    # Le filet de sécurité appelle directement ces outils : on les neutralise aussi.
    monkeypatch.setattr("app.tools.block_ip", lambda ip, reason="": {"ok": True})
    monkeypatch.setattr("app.tools.flag_user", lambda user, reason="": {"ok": True})


def test_boucle_sarrete_a_close_alert(monkeypatch):
    seq = [
        SimpleNamespace(content=None,
                        tool_calls=[_tool_call("c1", "ip_history", {"ip": "1.2.3.4"})]),
        SimpleNamespace(content=None,
                        tool_calls=[_tool_call("c2", "close_alert",
                                               {"alert_id": 1, "verdict": "true_positive",
                                                "severity": "high", "reason": "ok"})]),
        # Ne devrait jamais être atteint (on s'arrête après close_alert).
        SimpleNamespace(content="fin", tool_calls=None),
    ]
    llm = FakeLLM(seq)
    alert = {"id": 1, "type": "brute_force", "ip": "1.2.3.4", "username": "root", "count": 9}

    out = agent.run_on_alert(alert, llm)

    assert out["closed"] is True
    assert llm.calls == 2  # s'est arrêté dès close_alert, sans 3e appel
    # ip_history, close_alert, puis le blocage garanti par le filet de sécurité (high).
    assert [s["tool"] for s in out["steps"]] == ["ip_history", "close_alert", "block_ip"]


def test_reponse_texte_arrete_la_boucle():
    llm = FakeLLM([SimpleNamespace(content="Rien à signaler.", tool_calls=None)])
    alert = {"id": 2, "type": "failed_login", "ip": "10.0.0.1", "username": "bob", "count": 1}
    out = agent.run_on_alert(alert, llm)
    assert out["closed"] is False
    assert out["steps"] == []


def test_respecte_max_steps(monkeypatch):
    monkeypatch.setattr(agent.settings, "max_steps", 3)
    # L'agent appelle toujours un outil sans jamais clôturer.
    loop_msg = SimpleNamespace(
        content=None, tool_calls=[_tool_call("c", "ip_history", {"ip": "1.1.1.1"})])
    llm = FakeLLM([loop_msg] * 10)
    alert = {"id": 3, "type": "brute_force", "ip": "1.1.1.1", "username": "x", "count": 7}
    out = agent.run_on_alert(alert, llm)
    assert out["closed"] is False
    assert llm.calls == 3  # borné par max_steps


def test_verdict_plancher_force_true_positive(monkeypatch):
    """Même si le LLM tente false_positive/low sur une force brute, le code force
    true_positive et une gravité au moins high."""
    captured = {}
    monkeypatch.setattr(agent, "dispatch",
                        lambda name, args: captured.update(args) or {"ok": True})
    seq = [SimpleNamespace(content=None, tool_calls=[_tool_call(
        "c1", "close_alert",
        {"alert_id": 99, "verdict": "false_positive", "severity": "low", "reason": "x"})])]
    llm = FakeLLM(seq)
    alert = {"id": 5, "type": "brute_force", "ip": "1.2.3.4", "username": "root", "count": 20}
    agent.run_on_alert(alert, llm)
    assert captured["verdict"] == "true_positive"
    assert captured["severity"] == "high"
    assert captured["alert_id"] == 5  # id imposé côté serveur


def test_filet_securite_garantit_le_blocage(monkeypatch):
    """Si le LLM clôt une alerte critique sans agir, le code bloque l'IP et
    signale le compte automatiquement."""
    calls = []
    monkeypatch.setattr("app.tools.block_ip",
                        lambda ip, reason="": calls.append(("block", ip)) or {"ok": True})
    monkeypatch.setattr("app.tools.flag_user",
                        lambda user, reason="": calls.append(("flag", user)) or {"ok": True})
    # Le LLM clôt directement en critical, sans block ni flag.
    seq = [SimpleNamespace(content=None, tool_calls=[_tool_call(
        "c1", "close_alert",
        {"alert_id": 1, "verdict": "true_positive", "severity": "critical", "reason": "x"})])]
    llm = FakeLLM(seq)
    alert = {"id": 1, "type": "success_after_failures", "ip": "9.9.9.9",
             "username": "victime", "count": 11}
    agent.run_on_alert(alert, llm)
    assert ("block", "9.9.9.9") in calls
    assert ("flag", "victime") in calls
