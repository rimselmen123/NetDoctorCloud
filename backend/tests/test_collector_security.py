"""Vérifie que le parser résiste à l'usurpation d'IP via le nom d'utilisateur."""
from app.collector import parse_line


def test_ip_spoofing_par_le_username():
    # Le nom d'utilisateur tente d'injecter « from 9.9.9.9 port 22 ssh2 ».
    # Propriété de sécurité : l'IP usurpée 9.9.9.9 ne doit JAMAIS être retenue.
    line = ("2026-11-18T02:10:01+01:00 host sshd[2211]: Failed password for "
            "pwn from 9.9.9.9 port 22 ssh2 from 45.133.1.77 port 51044 ssh2")
    r = parse_line(line)
    assert r is None or r["ip"] != "9.9.9.9"


def test_username_dangereux_capture_mais_ip_correcte():
    # Un username forgé est conservé (détection complète) mais l'IP reste la vraie.
    # L'échappement se fait plus tard, au point d'usage (flag_user).
    line = ("2026-11-18T02:10:01+01:00 host sshd[2211]: "
            "Failed password for root; rm -rf / from 45.133.1.77 port 51044 ssh2")
    r = parse_line(line)
    assert r is not None
    assert r["ip"] == "45.133.1.77"
    assert r["outcome"] == "failed"


def test_prefixe_sshd_sans_pid_rejete():
    # Le PID est obligatoire : « sshd: » sans [pid] n'est pas accepté.
    line = ("2026-11-18T02:10:01+01:00 host sshd: "
            "Failed password for root from 45.133.1.77 port 51044 ssh2")
    assert parse_line(line) is None


def test_ip_invalide_rejetee():
    line = ("2026-11-18T02:10:01+01:00 host sshd[2211]: Failed password for "
            "root from not-an-ip port 51044 ssh2")
    assert parse_line(line) is None


def test_ligne_sans_prefixe_sshd_ignoree():
    # Même si le texte ressemble à un événement, sans « sshd[...]: » on ignore.
    line = "2026-11-18T02:10:01+01:00 host cron: Failed password for root from 1.2.3.4 port 22 ssh2"
    assert parse_line(line) is None
