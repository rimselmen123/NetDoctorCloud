# AgentDoctor — Agent SOC autonome

Agent IA de type SOC : à partir de vrais logs SSH, il détecte les attaques (règles
Python), **enquête** via le LLM et ses outils, **agit** (bloque une IP, signale un
compte, clôt l'alerte), puis envoie un **rapport par email**. Projet étudiant défensif.

## Architecture

```
auth.log (WSL Ubuntu)  →  collector  →  events
                                           ↓  règles Python
                                        alerts  →  Agent (LLM + outils)  →  actions
                                                          ↓
                                              PostgreSQL + rapport email
```

- **Backend** : FastAPI + PostgreSQL (`AgentDoctor`), SDK OpenAI (Chat Completions + tools).
- **Source** : serveur SSH dans WSL Ubuntu (port 2222) ; attaques depuis WSL Kali (hydra).
- **Sécurité** : parser durci (anti-usurpation d'IP), verdict verrouillé en code
  (le LLM ne peut pas minimiser une attaque), actions bornées à l'alerte, aucune
  commande exécutée sur le système, en-tête anti-CSRF sur les routes POST.

## Lancer le backend

```bash
cd backend
python -m venv .venv
.venv/Scripts/python -m pip install -r requirements.txt   # Windows
.venv/Scripts/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Configuration dans `.env` à la racine (voir `.env.example`) : clé OpenAI, `DATABASE_URL`
(base `AgentDoctor`), `AUTH_LOG_PATH`, identifiants Gmail (`SMTP_*`).

Avant une démo, dans WSL Ubuntu : `sudo service rsyslog start && sudo service ssh start`.

## Démo (3 scénarios)

Depuis Kali : `python3 backend/scripts/attack_lab.py brute` puis `... success`.
Puis, côté API (en-tête requis) :

```bash
curl -X POST localhost:8000/collect   -H "X-Requested-By: agentdoctor"
curl -X POST localhost:8000/agent/run -H "X-Requested-By: agentdoctor"
```

1. Force brute → vrai positif, **high**, IP bloquée.
2. Force brute réussie sur `victime` → **critique**, IP bloquée + compte signalé.
3. Quelques échecs depuis une IP privée → **faux positif**, aucune action.

Un rapport récapitulatif est envoyé par email à la fin.

## Tests

```bash
cd backend && .venv/Scripts/python -m pytest -q
```

Les tests n'utilisent ni réseau ni clé API (mocks).
