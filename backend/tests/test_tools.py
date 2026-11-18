"""Tests des outils de l'agent. La base est isolée via une connexion mockée."""
import json

import pytest

import app.tools as tools


@pytest.fixture
def fake_db(monkeypatch):
    """Remplace get_conn par une fausse base en mémoire pour chaque test."""
    state = {"events": [], "alerts": {}, "actions": []}

    class FakeCursor:
        def __init__(self, rows=None, rowcount=0):
            self._rows = rows or []
            self.rowcount = rowcount

        def fetchall(self):
            return self._rows

        def fetchone(self):
            return self._rows[0] if self._rows else None

    class FakeConn:
        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def commit(self):
            pass

        def execute(self, sql, params=None):
            params = params or {}
            s = " ".join(sql.split())
            if s.startswith("SELECT ts, ip, username, outcome FROM events"):
                rows = [(e["ts"], e["ip"], e["username"], e["outcome"])
                        for e in state["events"]
                        if (not params.get("ip") or e["ip"] == params["ip"])
                        and (not params.get("user") or e["username"] == params["user"])]
                return FakeCursor(rows)
            if s.startswith("SELECT username, outcome FROM events"):
                rows = [(e["username"], e["outcome"]) for e in state["events"]
                        if e["ip"] == params["ip"]]
                return FakeCursor(rows)
            if s.startswith("SELECT ts, ip, outcome FROM events"):
                rows = [(e["ts"], e["ip"], e["outcome"]) for e in state["events"]
                        if e["username"] == params["u"]]
                return FakeCursor(rows)
            if s.startswith("INSERT INTO actions"):
                state["actions"].append(params)
                return FakeCursor()
            if s.startswith("UPDATE alerts SET status='closed'"):
                aid = params["id"]
                if aid in state["alerts"]:
                    state["alerts"][aid].update(status="closed", verdict=params["v"],
                                                severity=params["s"])
                    return FakeCursor(rowcount=1)
                return FakeCursor(rowcount=0)
            return FakeCursor()

    monkeypatch.setattr(tools, "get_conn", lambda: FakeConn())
    monkeypatch.setattr(tools.settings, "lab_mode", True)
    return state


def test_ip_history(fake_db):
    fake_db["events"] = [
        {"ts": None, "ip": "1.2.3.4", "username": "root", "outcome": "failed"},
        {"ts": None, "ip": "1.2.3.4", "username": "admin", "outcome": "failed"},
    ]
    r = tools.ip_history("1.2.3.4")
    assert r["failures"] == 2
    assert set(r["targeted_users"]) == {"root", "admin"}


def test_user_logins_success_after_failures(fake_db):
    fake_db["events"] = [
        {"ts": 1, "ip": "9.9.9.9", "username": "victime", "outcome": "failed"},
        {"ts": 2, "ip": "9.9.9.9", "username": "victime", "outcome": "accepted"},
    ]
    r = tools.user_logins("victime")
    assert r["success_after_failures"] is True


def test_block_ip_genere_commande(fake_db):
    r = tools.block_ip("203.0.113.5", reason="force brute")
    assert r["ok"] is True
    assert r["command"] == "iptables -A INPUT -s 203.0.113.5 -j DROP"
    assert fake_db["actions"][0]["ip"] == "203.0.113.5"


def test_block_ip_refuse_ip_invalide(fake_db):
    r = tools.block_ip("pas-une-ip")
    assert r["ok"] is False


def test_block_ip_privee_refusee_hors_lab(fake_db, monkeypatch):
    monkeypatch.setattr(tools.settings, "lab_mode", False)
    r = tools.block_ip("192.168.1.10")
    assert r["ok"] is False
    assert "labo" in r["error"]


def test_block_ip_privee_acceptee_en_lab(fake_db):
    # lab_mode=True par défaut dans la fixture.
    r = tools.block_ip("127.0.0.1")
    assert r["ok"] is True


def test_close_alert_met_a_jour(fake_db):
    fake_db["alerts"][7] = {"status": "open"}
    r = tools.close_alert(7, "true_positive", "high", "ok")
    assert r["ok"] is True
    assert fake_db["alerts"][7]["status"] == "closed"


def test_close_alert_verdict_invalide(fake_db):
    r = tools.close_alert(7, "maybe", "high", "x")
    assert r["ok"] is False


def test_dispatch_outil_inconnu(fake_db):
    r = tools.dispatch("outil_fantome", {})
    assert r["ok"] is False
    assert "inconnu" in r["error"]


def test_dispatch_arguments_invalides(fake_db):
    r = tools.dispatch("ip_history", {"mauvais_arg": 1})
    assert r["ok"] is False


def test_dumps_est_du_json(fake_db):
    assert json.loads(tools.dumps({"ok": True, "x": "é"}))["x"] == "é"
