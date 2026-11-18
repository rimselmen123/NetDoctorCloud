"""Tests du parser de auth.log (aucune base ni réseau requis)."""
from app.collector import parse_line


def test_failed_password():
    line = ("2026-11-18T02:10:01.100000+01:00 host sshd[2211]: "
            "Failed password for root from 45.133.1.77 port 51044 ssh2")
    r = parse_line(line)
    assert r["outcome"] == "failed"
    assert r["username"] == "root"
    assert r["ip"] == "45.133.1.77"
    assert r["ts"] is not None


def test_failed_invalid_user():
    line = ("2026-11-18T02:10:04.400000+01:00 host sshd[2214]: "
            "Failed password for invalid user admin from 45.133.1.77 port 51046 ssh2")
    r = parse_line(line)
    assert r["outcome"] == "failed"
    assert r["username"] == "admin"
    assert r["ip"] == "45.133.1.77"


def test_accepted_password():
    line = ("2026-11-18T02:14:02.200000+01:00 host sshd[2290]: "
            "Accepted password for victime from 103.88.4.19 port 40110 ssh2")
    r = parse_line(line)
    assert r["outcome"] == "accepted"
    assert r["username"] == "victime"
    assert r["ip"] == "103.88.4.19"


def test_invalid_user_line():
    line = ("2026-11-18T02:10:03.300000+01:00 host sshd[2213]: "
            "Invalid user admin from 45.133.1.77 port 51046")
    r = parse_line(line)
    assert r["outcome"] == "invalid_user"
    assert r["username"] == "admin"


def test_non_ssh_line_ignored():
    assert parse_line("2026-11-18T02:10:03+01:00 host sudo: session opened for root") is None


def test_line_without_timestamp():
    # Format classique sans année : on garde l'événement, ts vaut None.
    r = parse_line("Nov 18 02:10:01 host sshd[1]: Failed password for root from 10.0.0.1 port 22 ssh2")
    assert r is not None
    assert r["ts"] is None
    assert r["ip"] == "10.0.0.1"
