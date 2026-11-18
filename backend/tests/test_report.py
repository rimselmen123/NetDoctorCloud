"""Tests du rapport email : contenu HTML et gestion d'erreur SMTP (mock)."""
import app.report as report


_STATS = {
    "alerts": [
        {"id": 1, "type": "brute_force", "ip": "45.133.1.77", "username": "root",
         "verdict": "true_positive", "severity": "high", "reason": "force brute"},
        {"id": 3, "type": "failed_login", "ip": "192.168.1.24", "username": "rayen",
         "verdict": "false_positive", "severity": "low", "reason": "faute de frappe"},
    ],
    "actions": [{"type": "block_ip", "target": "45.133.1.77",
                 "command": "iptables -A INPUT -s 45.133.1.77 -j DROP"}],
    "total": 2, "true_positives": 1, "false_positives": 1,
}


def test_build_report_contient_chiffres_et_actions():
    html_out = report.build_report(_STATS)
    assert "2 alerte(s) traitée(s)" in html_out
    assert "45.133.1.77" in html_out
    assert "iptables -A INPUT -s 45.133.1.77 -j DROP" in html_out


def test_build_report_echappe_le_html():
    stats = {**_STATS, "alerts": [
        {"id": 9, "type": "x", "ip": "1.1.1.1", "username": "<script>alert(1)</script>",
         "verdict": "true_positive", "severity": "high", "reason": "r"}]}
    html_out = report.build_report(stats)
    assert "<script>alert(1)</script>" not in html_out
    assert "&lt;script&gt;" in html_out


def test_send_report_appelle_smtp(monkeypatch):
    sent = {}

    class FakeSMTP:
        def __init__(self, host, port, timeout=None):
            sent["host"] = host
        def __enter__(self): return self
        def __exit__(self, *a): return False
        def starttls(self): sent["tls"] = True
        def login(self, u, p): sent["login"] = u
        def send_message(self, msg): sent["to"] = msg["To"]

    monkeypatch.setattr(report, "gather_stats", lambda: _STATS)
    monkeypatch.setattr(report.smtplib, "SMTP", FakeSMTP)
    monkeypatch.setattr(report.settings, "smtp_user", "me@gmail.com")
    monkeypatch.setattr(report.settings, "smtp_app_password", "secret")
    monkeypatch.setattr(report.settings, "report_to", "me@gmail.com")

    r = report.send_report()
    assert r["ok"] is True
    assert sent["host"] == "smtp.gmail.com"
    assert sent["tls"] is True
    assert sent["to"] == "me@gmail.com"


def test_send_report_capture_erreur_smtp(monkeypatch):
    def boom(*a, **k):
        raise OSError("connexion refusée")

    monkeypatch.setattr(report, "gather_stats", lambda: _STATS)
    monkeypatch.setattr(report.smtplib, "SMTP", boom)
    monkeypatch.setattr(report.settings, "smtp_user", "me@gmail.com")
    monkeypatch.setattr(report.settings, "smtp_app_password", "secret")
    monkeypatch.setattr(report.settings, "report_to", "me@gmail.com")

    r = report.send_report()
    assert r["ok"] is False
    assert "SMTP" in r["error"]


def test_send_report_sans_alerte(monkeypatch):
    monkeypatch.setattr(report, "gather_stats",
                        lambda: {"alerts": [], "actions": [], "total": 0,
                                 "true_positives": 0, "false_positives": 0})
    r = report.send_report()
    assert r["ok"] is False
