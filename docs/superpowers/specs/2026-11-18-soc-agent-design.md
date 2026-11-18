# NetDoctor SOC — Agent SOC minimal (conception)

Date : 2026-11-18 · Démo : aujourd'hui · Remplace PLAN.md (audit) pour la démo.

## But
Un agent IA SOC qui, sur clic, enquête sur des alertes de sécurité issues de **vrais logs SSH**, décide (vrai/faux positif, gravité) et **agit** (bloquer IP, signaler compte, fermer alerte) via des outils. Chaque étape de raisonnement est visible.

## Stack
- Frontend : Angular, un seul `AppModule` + un seul `AppRoutingModule`, une page.
- Backend : FastAPI (Python 3.13), SDK `openai` (Chat Completions + tools).
- Base : PostgreSQL 17 local, base **`AgentDoctor`** (driver `psycopg` v3).
- Email : Gmail SMTP (`smtp.gmail.com:587`, STARTTLS) avec mot de passe d'application.
- Config : `.env` (`OPENAI_API_KEY`, `LLM_MODEL=gpt-4o-mini`, `DATABASE_URL=postgresql://postgres:<mdp>@localhost:5432/AgentDoctor`, `AUTH_LOG_PATH`, `LAB_MODE=true`, `SMTP_USER`, `SMTP_APP_PASSWORD`, `REPORT_TO`).

## Source de données
- Victime : WSL **Ubuntu-24.04** (`openssh-server` + `rsyslog`, utilisateur `victime`) → `/var/log/auth.log`.
- Attaquant : WSL **Kali** (`hydra`/`ssh`) ou script `scripts/attack_lab.py`, uniquement contre l'Ubuntu locale.
- Lecture côté Windows : `\\wsl$\Ubuntu-24.04\var\log\auth.log` (chemin dans `AUTH_LOG_PATH`).
- Plan B : `samples/auth.log` (extrait réaliste) si WSL indisponible.

## Flux
1. `POST /collect` : lit le log, parse les lignes SSH (`Failed password`, `Accepted password`, `Invalid user`) → table `events` (dédoublonnage par ligne brute).
2. Détection Python (même appel) → table `alerts` :
   - `brute_force` : ≥ 5 échecs même IP en 10 min ;
   - `failed_login` : 1–4 échecs (candidat faux positif) ;
   - `success_after_failures` : succès d'une IP ayant ≥ 5 échecs.
3. `POST /agent/run` : pour chaque alerte `open` (max 10), boucle agent (max 6 étapes) ; doit se terminer par `close_alert`.
4. Fin de `POST /agent/run` : envoi automatique du rapport email (voir ci-dessous) ; la réponse contient `email_sent` et `email_error`.
5. `GET /alerts`, `GET /alerts/{id}/steps`, `GET /actions`.

## Rapport email
- Construit **en Python** depuis la base (aucun token LLM) : uniquement ce que l'agent a réellement fait.
- Contenu (HTML + texte brut) : nb d'alertes traitées, vrais/faux positifs ; tableau par alerte (IP, compte, verdict, gravité, raison) ; actions (IP bloquées, comptes signalés, commandes générées) ; tokens consommés et coût estimé.
- Envoyé seulement si au moins une alerte a été traitée. Échec SMTP → l'agent ne plante pas, l'erreur est renvoyée à l'interface.
- Le mot de passe d'application n'apparaît jamais dans les logs ni dans les réponses API.

## Outils de l'agent
Lecture : `search_events(ip?, user?, minutes?)`, `ip_history(ip)`, `user_logins(user)`.
Action : `block_ip(ip, reason)` (enregistre + génère la commande `iptables`, **n'exécute rien**), `flag_user(user, reason)`, `close_alert(alert_id, verdict, severity, reason)`.
- `verdict` ∈ {true_positive, false_positive} ; `severity` ∈ {critical, high, medium, low}.
- Schémas JSON stricts (`additionalProperties: false`) ; outil inconnu ou JSON invalide → erreur renvoyée au modèle.
- `block_ip` refuse IP privées/loopback sauf si `LAB_MODE=true`.
- Résultats d'outils tronqués (≤ 20 événements, ≤ 2000 caractères) pour limiter les tokens.

## Tables
- `events(id, ts, ip, username, outcome, raw UNIQUE)`
- `alerts(id, type, ip, username, count, status, verdict, severity, reason, created_at)`
- `agent_steps(id, alert_id, step, tool, args_json, result_json, created_at)`
- `actions(id, alert_id, type, target, reason, command, created_at)`
- Création automatique au démarrage.

## Interface (une page)
Boutons « Collecter les logs » et « Lancer l'agent » ; tableau des alertes (statut, verdict, gravité colorée) ; clic sur une alerte → étapes de l'agent (outil, arguments, résultat) ; liste des actions (IP bloquées, comptes signalés, commandes générées).

## Budget et sécurité
- Modèle mini, `max_tokens` 400 par appel, 10 alertes × 6 étapes max par clic, tokens consommés journalisés.
- Clé uniquement dans `.env` (gitignored). Aucune commande système exécutée par l'agent.

## Tests (sans réseau ni clé)
Parser sur extrait `auth.log` ; règles de détection ; outils sur base de test ; boucle agent avec faux client LLM (tool_call puis close_alert) ; rapport email avec `smtplib.SMTP` mocké (contenu + gestion d'erreur).

## Scénarios de démo
1. Une seule erreur de mot de passe → faux positif, alerte fermée sans action.
2. Hydra/script : 20 échecs sur root/admin → vrai positif, `high`, IP bloquée.
3. Échecs puis succès sur `victime` → `critical`, IP bloquée + compte signalé.

## Hors périmètre aujourd'hui
Audit machine/site web de PLAN.md, PDF, planification, Docker, CI, logs Windows, AbuseIPDB.
