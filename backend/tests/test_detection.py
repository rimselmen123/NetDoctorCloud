"""Tests des règles de détection (fonction pure, sans base)."""
from app.detection import detect


def _fails(ip, user, n):
    return [{"ip": ip, "username": user, "outcome": "failed"} for _ in range(n)]


def test_brute_force():
    alerts = detect(_fails("45.133.1.77", "root", 6))
    assert len(alerts) == 1
    a = alerts[0]
    assert a["type"] == "brute_force"
    assert a["severity"] == "high"
    assert a["count"] == 6
    assert a["ip"] == "45.133.1.77"


def test_failed_login_isole():
    alerts = detect(_fails("192.168.1.24", "rayen", 2))
    assert alerts[0]["type"] == "failed_login"
    assert alerts[0]["severity"] == "low"


def test_success_after_failures_est_critique():
    events = _fails("103.88.4.19", "victime", 5)
    events.append({"ip": "103.88.4.19", "username": "victime", "outcome": "accepted"})
    alerts = detect(events)
    assert alerts[0]["type"] == "success_after_failures"
    assert alerts[0]["severity"] == "critical"
    assert alerts[0]["username"] == "victime"


def test_succes_sans_assez_echecs_reste_failed_login():
    # 2 échecs puis un succès : pas de force brute, donc simple failed_login.
    events = _fails("10.0.0.5", "bob", 2)
    events.append({"ip": "10.0.0.5", "username": "bob", "outcome": "accepted"})
    alerts = detect(events)
    assert alerts[0]["type"] == "failed_login"


def test_plusieurs_ip():
    events = _fails("1.1.1.1", "root", 6) + _fails("2.2.2.2", "admin", 1)
    alerts = detect(events)
    types = {a["ip"]: a["type"] for a in alerts}
    assert types["1.1.1.1"] == "brute_force"
    assert types["2.2.2.2"] == "failed_login"
