# NetDoctor — Plan d'implémentation

Agent IA autonome d'audit de sécurité défensif. Projet étudiant (3e année RSI, ISET Nabeul), cours « Cloud Microsoft Learning Copilot ».

---

## 0. Instructions pour Claude Code

Ce document est la spécification complète de NetDoctor. Implémente-le **phase par phase, dans l'ordre**, et arrête-toi à la fin de chaque phase pour que je valide.

1. Lis tout le document avant d'écrire du code, puis propose-moi l'arborescence que tu vas créer.
2. Travaille une phase à la fois. À la fin de chaque phase : lance les tests, montre-moi comment lancer l'application, puis attends mon accord.
3. Fais un commit git par étape logique, avec des messages conventionnels (`feat:`, `fix:`, `test:`, `docs:`).
4. Les règles de la section 4 « Règles de sécurité » sont obligatoires. Ne les contourne jamais, même pour simplifier.
5. Ne mets jamais de clé API dans le code, les tests ou les logs. Tout passe par `.env`.
6. Le code doit marcher sous **Windows et Linux**. Détecte le système avec `platform.system()` quand une commande diffère.
7. Commente le code en français, et nomme les variables et fonctions en anglais.
8. Les tests ne doivent jamais dépendre du réseau ni d'une vraie clé API : utilise des mocks (`unittest.mock`, `respx` pour `httpx`).
9. Si une consigne est ambiguë ou impossible, demande-moi avant de choisir.

Je suis étudiant en 3e année RSI. Explique brièvement les choix techniques importants pour que je puisse les présenter.

---

## 1. Vision et périmètre

NetDoctor est un agent IA autonome d'audit de sécurité **défensif** : à partir d'une seule instruction, il planifie, exécute ses outils d'audit, puis produit un rapport noté sur 100.

Exemple d'instruction : « Audite ma machine et le site `monsite.github.io` ». L'agent enchaîne alors trois étapes sans intervention :

1. **Planifier** : il annonce quels modes et quels outils il va utiliser, et pourquoi.
2. **Agir** : il appelle les outils, lit chaque résultat et décide de creuser si besoin (port 22 ouvert → il vérifie la configuration SSH).
3. **Rapporter** : failles classées par gravité, score calculé en Python, plan de correction priorisé, export PDF.

### Les trois modes

| Mode | Cible | Outils |
| --- | --- | --- |
| Diagnostic | Un hôte ou un domaine | `dns_lookup`, `ping_host`, `check_port`, `subnet_calc` |
| Audit machine | Le PC où tourne NetDoctor (`localhost` uniquement) | `local_listening_ports`, `firewall_status`, `os_info`, `ssh_config_audit` |
| Audit site web | Un domaine de la liste blanche | `tls_certificate`, `security_headers`, `https_redirect`, `email_dns_records` |

### Hors périmètre (à ne jamais implémenter)

Scan de plages d'IP, scan de tous les ports, brute-force, exploitation de vulnérabilités, modification du système audité, audit d'une cible absente de la liste blanche. **NetDoctor observe, il n'attaque pas.**

---

## 2. Stack technique et fournisseurs LLM

Tout est en Python 3.11+, et le modèle se change en modifiant uniquement le `.env`.

| Rôle | Choix | Pourquoi |
| --- | --- | --- |
| Client LLM | SDK `openai`, endpoint **Chat Completions** | Compatible OpenAI, Kimi, Groq et Ollama |
| Backend | FastAPI + Uvicorn | Vraie API REST, documentation `/docs` automatique |
| Interface | Streamlit | Chat en peu de lignes, appelle l'API FastAPI |
| Base de données | SQLite via `sqlite3` | Historique des audits, aucun serveur à installer |
| Rapport PDF | `reportlab` | Pur Python, fonctionne sous Windows sans dépendance système |
| Planification | `APScheduler` | Audits automatiques programmés |
| Outils réseau | `socket`, `ssl`, `subprocess`, `ipaddress`, `psutil`, `dnspython`, `httpx` | Bibliothèques standard ou très répandues |
| Configuration | `python-dotenv` + `pydantic-settings` | Variables typées et validées |
| Qualité | `pytest`, `respx`, `ruff`, Docker, GitHub Actions | Tests, lint et CI |

**Important :** utilise `client.chat.completions.create(..., tools=[...])`, et **non** la Responses API. Groq, Kimi et Ollama ne supportent que Chat Completions.

### `.env.example` (à committer, sans vraies valeurs)

```
LLM_BASE_URL=https://api.groq.com/openai/v1
LLM_API_KEY=change-me
LLM_MODEL=change-me
AGENT_MAX_STEPS=15
TARGETS_FILE=cibles_autorisees.txt
DB_PATH=data/netdoctor.db
API_URL=http://localhost:8000
```

| Fournisseur | `LLM_BASE_URL` | `LLM_MODEL` |
| --- | --- | --- |
| OpenAI | laisser vide | un modèle avec tool calling |
| Kimi (Moonshot) | `https://api.moonshot.ai/v1` | un ID renvoyé par `client.models.list()` |
| Groq | `https://api.groq.com/openai/v1` | un modèle avec tool calling |
| Ollama (local) | `http://localhost:11434/v1` | `qwen3:8b` |

Crée `scripts/check_llm.py` : il liste les modèles disponibles, envoie un message de test, puis un test de tool calling minimal. Il affiche des messages clairs pour les erreurs 401 (clé invalide), 404 (modèle inconnu) et 429 (quota).

---

## 3. Architecture et arborescence

Chaque couche ne connaît que celle d'en dessous : l'interface appelle l'API, l'API appelle l'agent, l'agent appelle les outils. Les outils ne connaissent ni le LLM ni l'interface, ce qui permet de les tester seuls.

```
Streamlit (ui/)  ──HTTP──▶  FastAPI (app/main.py)  ──▶  Agent (app/agent/loop.py)  ──▶  LLM (API compatible OpenAI)
                                   │                          │
                                   ▼                          ▼
                           SQLite + PDF + journal       Outils (app/tools/*) ──▶ validators.py
```

```
netdoctor/
├── app/
│   ├── main.py              # FastAPI : /health, /chat, /audit, /audits, /audits/{id}, /audits/{id}/pdf, /schedules
│   ├── config.py            # Settings pydantic lus depuis .env
│   ├── agent/
│   │   ├── loop.py          # Boucle agent : planifier → agir → rapporter
│   │   ├── llm_client.py    # Client OpenAI configurable (base_url, modèle)
│   │   ├── prompts.py       # Prompt système, de planification et de rapport
│   │   └── registry.py      # Registre des outils : nom → fonction + schéma JSON
│   ├── tools/
│   │   ├── validators.py    # Validation des hôtes, ports, réseaux, liste blanche
│   │   ├── diagnostic.py    # dns_lookup, ping_host, check_port, subnet_calc
│   │   ├── machine.py       # local_listening_ports, firewall_status, os_info, ssh_config_audit
│   │   └── web.py           # tls_certificate, security_headers, https_redirect, email_dns_records
│   ├── scoring.py           # Score sur 100 et note A–E à partir des constats
│   ├── report/
│   │   └── pdf.py           # Génération du rapport PDF
│   ├── storage/
│   │   └── db.py            # SQLite : audits, constats, appels d'outils, planifications
│   ├── scheduler.py         # Audits programmés (APScheduler)
│   └── audit_log.py         # Journal JSONL de chaque appel d'outil
├── ui/
│   └── streamlit_app.py     # Onglets : Diagnostic (chat), Audit, Historique
├── tests/                   # pytest, un fichier par module
├── scripts/check_llm.py
├── data/                    # base SQLite, rapports, journal (ignoré par git)
├── cibles_autorisees.txt    # liste blanche, un domaine par ligne, # pour les commentaires
├── .env.example
├── .gitignore               # .env, data/, __pycache__/, .venv/
├── requirements.txt
├── Dockerfile
├── docker-compose.yml       # services api + ui
├── .github/workflows/ci.yml
└── README.md
```

### Contrat commun des outils

Chaque outil est une fonction Python pure qui retourne **toujours** un dictionnaire de cette forme, jamais une exception :

```json
{
  "tool": "security_headers",
  "target": "monsite.github.io",
  "ok": true,
  "data": { "...": "résultats bruts" },
  "findings": [
    {
      "severity": "medium",
      "title": "En-tête HSTS absent",
      "detail": "La réponse HTTPS ne contient pas Strict-Transport-Security.",
      "recommendation": "Ajouter Strict-Transport-Security: max-age=31536000; includeSubDomains"
    }
  ],
  "error": null,
  "duration_ms": 412
}
```

Gravités autorisées : `critical`, `high`, `medium`, `low`, `info`. **Ce sont les outils qui produisent les constats, pas le LLM** : le modèle les explique et les priorise, mais ne les invente pas. Un décorateur commun (`@tool` dans `registry.py`) gère le `try/except`, la mesure de durée et l'écriture dans le journal.

---

## 4. Règles de sécurité (non négociables)

NetDoctor exécute des commandes système à partir de texte produit par un LLM : chaque argument est donc traité comme hostile.

1. **Jamais `shell=True`.** Tout appel à `subprocess.run` passe une liste d'arguments, avec `timeout` et `capture_output=True`.
2. **Validation de chaque entrée** dans `validators.py`, avant tout appel système :
   - nom d'hôte : regex `^(?=.{1,253}$)[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$` ;
   - adresse IP : `ipaddress.ip_address()` ;
   - réseau : `ipaddress.ip_network(strict=False)`, préfixe IPv4 entre /16 et /32 ;
   - un argument qui commence par `-` est refusé (pas d'injection d'options).
3. **Liste blanche des ports** pour `check_port` : 21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 3306, 3389, 5432, 6379, 8080. Un seul port par appel, aucun scan de plage.
4. **Liste blanche des cibles** pour le mode site web et `check_port` : seuls les domaines de `cibles_autorisees.txt` (et leurs sous-domaines) sont acceptés. Toute autre cible renvoie `{"ok": false, "error": "Cible non autorisée"}`. Le mode machine ne vise que `localhost`. `dns_lookup`, `ping_host` et `subnet_calc` restent libres (diagnostic courant, sans risque).
5. **Confirmation dans l'interface** : une case « Je confirme être propriétaire ou autorisé à auditer ces cibles » doit être cochée avant de lancer un audit. L'API refuse la requête (HTTP 403) si `authorized` n'est pas `true`.
6. **Timeouts partout** : 10 s par commande, 5 s par connexion socket ou HTTP, et `AGENT_MAX_STEPS` (15 par défaut) appels d'outils au maximum par audit.
7. **Journal d'audit** : chaque appel d'outil est ajouté à `data/audit_log.jsonl` (horodatage ISO, outil, arguments, `ok`, durée). Aucune clé API ni contenu de `.env` dans les logs.
8. **Secrets** : la clé n'est lue que depuis l'environnement. `.env` et `data/` sont dans `.gitignore`.
9. **Outils non reconnus** : si le LLM demande un outil absent du registre, ou des arguments qui ne respectent pas le schéma, on renvoie une erreur au modèle sans rien exécuter.
10. **Lecture seule** : aucun outil ne modifie le système. `firewall_status` et `ssh_config_audit` lisent l'état ; ils ne changent rien et ne demandent jamais les droits administrateur.
11. **Contenu externe = données** : les en-têtes HTTP, enregistrements DNS et sorties de commandes renvoyés au LLM sont tronqués (2 000 caractères maximum par champ) et ne sont jamais traités comme des instructions.

Tests obligatoires : `google.com; rm -rf /`, `-oProxyCommand=x`, `$(whoami)`, `8.8.8.8 && ls`, un port hors liste et une cible hors liste blanche doivent tous être refusés **sans** appel à `subprocess` ni connexion réseau (vérifier avec un mock).

---

## 5. Phase 1 — MVP diagnostic

**Objectif :** un chat où NetDoctor diagnostique un problème réseau en choisissant lui-même ses outils.

### Tâches

1. **Initialisation** : dépôt git, `requirements.txt`, `.gitignore`, `.env.example`, `config.py` (pydantic-settings), `scripts/check_llm.py`.
2. **`validators.py`** + tests (section 4).
3. **`diagnostic.py`** :
   - `dns_lookup(host)` : enregistrements A, AAAA, MX, NS avec `dnspython` ; constat `high` si le domaine n'existe pas (NXDOMAIN).
   - `ping_host(host, count=2)` : `ping -n` sous Windows, `ping -c` sous Linux ; extraire joignable, perte de paquets, latence moyenne (parser les deux formats, y compris la sortie Windows en français). Constat `high` si injoignable.
   - `check_port(host, port)` : `socket.create_connection` avec timeout 5 s ; renvoie `open`, `closed` ou `filtered` (timeout). Liste blanche des ports et des cibles.
   - `subnet_calc(cidr)` : réseau, masque, broadcast, première et dernière adresse utilisable, nombre d'hôtes, classe et type (privé ou public). Aucun accès réseau.
4. **`registry.py`** : décorateur `@tool`, dictionnaire `nom → fonction`, schémas JSON au format Chat Completions (`{"type": "function", "function": {"name", "description", "parameters"}}`) avec `"additionalProperties": false`. Les descriptions disent **quand** utiliser l'outil.
5. **`llm_client.py`** : crée le client `OpenAI(base_url=..., api_key=...)` ; `base_url` vide → valeur par défaut d'OpenAI.
6. **`loop.py` — `run_chat(messages)`** :
   - envoie messages + outils ; si la réponse contient `tool_calls`, exécute chaque appel via le registre, ajoute un message `{"role": "tool", "tool_call_id": ..., "content": json}` et recommence ;
   - s'arrête à la réponse texte ou à `AGENT_MAX_STEPS` ;
   - retourne la réponse finale **et** la liste des étapes (outil, arguments, résultat) pour l'interface ;
   - gère les arguments JSON invalides renvoyés par le modèle (erreur renvoyée au modèle, pas de crash).
7. **`prompts.py` — prompt système du mode diagnostic** :

   ```
   Tu es NetDoctor, un assistant de diagnostic réseau pour des étudiants en réseaux.
   Méthode : commence par dns_lookup, puis ping_host, puis check_port si un service précis est en cause.
   N'invente jamais un résultat : appuie chaque affirmation sur un outil.
   Explique simplement en français. Termine par : cause probable, puis solution concrète.
   Refuse poliment toute demande de scan ou d'attaque, et toute cible non autorisée.
   ```

8. **API** : `GET /health`, `POST /chat` (`{"messages": [...]}` → `{"reply", "steps"}`).
9. **Interface Streamlit, onglet « Diagnostic »** : chat avec historique dans `st.session_state` ; chaque appel d'outil s'affiche dans un `st.expander` « 🔧 ping_host(google.tn) » avec le JSON du résultat ; indicateur du modèle utilisé.
10. **Tests** : validators, chaque outil (sorties de `ping` Windows et Linux simulées), boucle agent avec un faux client LLM qui renvoie un `tool_call` puis une réponse texte.

### Critères de fin de phase

- `pytest` passe, `ruff check` ne signale rien.
- « Pourquoi siteinexistant123.tn ne marche pas ? » → l'agent appelle `dns_lookup` et explique l'erreur DNS.
- « Calcule le sous-réseau 192.168.10.0/26 » → l'agent appelle `subnet_calc` et donne les bonnes valeurs.

---

## 6. Phase 2 — Outils d'audit et score

**Objectif :** les modes machine et site web, avec un score fiable calculé en Python.

### Tâches

1. **Liste blanche** : chargement de `cibles_autorisees.txt` (lignes vides et `#` ignorés), correspondance exacte ou sous-domaine ; fichier exemple avec un commentaire expliquant son rôle.
2. **`machine.py`** :
   - `local_listening_ports()` : `psutil.net_connections(kind="inet")`, sockets en écoute avec port, adresse et nom du processus si accessible. Constats : base de données (3306, 5432, 6379, 27017) sur `0.0.0.0` ou `::` → `critical` ; Telnet (23), FTP (21) ou RDP (3389) exposés → `high` ; autres services exposés → `info`. Gérer `AccessDenied` sans planter.
   - `firewall_status()` : Windows `netsh advfirewall show allprofiles state` ; Linux `ufw status`, sinon `firewall-cmd --state`, sinon `info` « impossible de déterminer ». Pare-feu inactif → `high`.
   - `os_info()` : système, version, nom de la machine, uptime via `psutil.boot_time()`. Uptime de plus de 30 jours → `low` (mises à jour probablement en attente).
   - `ssh_config_audit()` : Linux uniquement, lecture de `/etc/ssh/sshd_config` (et des fichiers inclus lisibles). `PermitRootLogin yes` → `high` ; `PasswordAuthentication yes` → `medium` ; `Port 22` + mot de passe → `low`. Sous Windows ou si le fichier est absent → `info` « non applicable ».
3. **`web.py`** (cibles en liste blanche uniquement) :
   - `tls_certificate(host)` : `ssl.create_default_context()` + `getpeercert()` ; émetteur, sujet, date d'expiration, jours restants, version TLS (`ssock.version()`). Certificat invalide ou expiré → `critical` ; moins de 15 jours → `high` ; moins de 30 jours → `medium` ; TLS 1.0 ou 1.1 → `high`.
   - `security_headers(host)` : `httpx.get(f"https://{host}", follow_redirects=True, timeout=5)`. Absents : `Strict-Transport-Security` → `medium` ; `Content-Security-Policy` → `medium` ; `X-Frame-Options` (ou `frame-ancestors` dans la CSP) → `low` ; `X-Content-Type-Options` → `low` ; `Referrer-Policy` → `low`. En-tête `Server` ou `X-Powered-By` avec un numéro de version → `low`.
   - `https_redirect(host)` : requête sur `http://` sans suivre les redirections ; pas de redirection 301/302/307/308 vers `https://` → `medium`.
   - `email_dns_records(domain)` : TXT du domaine (SPF `v=spf1`) et TXT de `_dmarc.domain`. SPF absent → `medium` ; SPF en `+all` → `high` ; DMARC absent → `medium` ; DMARC `p=none` → `low`.
4. **`scoring.py`** :
   - pénalités : `critical` 25, `high` 15, `medium` 8, `low` 3, `info` 0 ;
   - score = max(0, 100 − somme des pénalités), après dédoublonnage par (cible, titre) ;
   - note : A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40, E < 40 ;
   - retourne aussi le nombre de constats par gravité.
5. **Registre et prompts** : ajouter les 8 outils avec des descriptions précises ; prompt système enrichi des trois modes.
6. **Tests** : chaque outil avec mocks (`psutil`, `subprocess`, `ssl`, `respx`, `dns.resolver`) ; tableau de cas pour `scoring.py`.

### Critères de fin de phase

- Dans le chat, « Vérifie les en-têtes de sécurité de [domaine de la liste blanche] » fonctionne ; le même message avec `google.com` est refusé.
- `scoring.py` donne le même score pour la même liste de constats, quel que soit le modèle.

---

## 7. Phase 3 — Autonomie, rapport et historique

**Objectif :** une instruction → plan → exécution autonome → rapport noté, sauvegardé et exportable en PDF.

### Tâches

1. **Étape « Planifier »** (`loop.py` — `run_audit(instruction)`) :
   - premier appel au LLM **sans outils**, avec le prompt de planification et la liste des outils (nom + description) ;
   - réponse attendue en JSON : `{"targets": [...], "modes": [...], "steps": [{"tool", "args", "why"}]}` ; extraire le JSON même s'il est entouré de texte ou de balises Markdown ; en cas d'échec, une seule nouvelle tentative, puis plan par défaut selon les cibles détectées ;
   - vérifier toutes les cibles du plan contre la liste blanche **avant** d'exécuter quoi que ce soit ; une cible refusée est signalée dans le rapport.
2. **Étape « Agir »** : boucle avec outils ; le message initial contient le plan validé ; le modèle peut ajouter des étapes s'il justifie pourquoi (par exemple, port 22 ouvert → `ssh_config_audit`) ; limite `AGENT_MAX_STEPS`.
3. **Étape « Rapporter »** :
   - constats collectés **depuis les résultats d'outils** (pas depuis le texte du modèle) ;
   - score et note via `scoring.py` ;
   - dernier appel LLM sans outils : il reçoit les constats en JSON et rédige en français un résumé (5 lignes maximum) et un plan d'action priorisé (3 à 7 actions, de la plus urgente à la moins urgente).
4. **Stockage SQLite (`db.py`)**, tables :
   - `audits(id, created_at, instruction, model, targets_json, plan_json, score, grade, summary, action_plan)` ;
   - `findings(id, audit_id, tool, target, severity, title, detail, recommendation)` ;
   - `tool_calls(id, audit_id, step, tool, args_json, ok, duration_ms)` ;
   - création automatique des tables au démarrage.
5. **Comparaison avec l'audit précédent** sur les mêmes cibles : écart de score, constats nouveaux, constats corrigés (comparaison par cible + titre).
6. **`pdf.py`** (reportlab) : page de garde (titre, date, cibles, score en grand, note) ; résumé ; tableau des constats triés par gravité avec code couleur ; plan d'action ; comparaison avec l'audit précédent si elle existe ; annexe avec les appels d'outils (outil, arguments, durée). Mention en pied de page : « Audit défensif réalisé sur des cibles autorisées ».
7. **API** :
   - `POST /audit` `{"instruction": str, "authorized": bool}` → `{"audit_id", "plan", "steps", "findings", "score", "grade", "summary", "action_plan", "comparison"}` ; 403 si `authorized` est faux ;
   - `GET /audits` (liste), `GET /audits/{id}` (détail), `GET /audits/{id}/pdf` (fichier PDF).
8. **Interface** :
   - onglet « Audit » : zone d'instruction, case de confirmation obligatoire, bouton « Lancer l'audit » ; affichage du plan, puis des étapes (`st.status`), puis du score (`st.metric` avec l'écart par rapport à l'audit précédent), des constats colorés par gravité, du plan d'action et du bouton « Télécharger le PDF » ;
   - onglet « Historique » : tableau des audits et courbe d'évolution du score par cible.
9. **Tests** : planification avec réponses JSON valides, entourées de texte, puis invalides ; refus d'une cible hors liste ; enregistrement et relecture d'un audit ; génération d'un PDF non vide ; comparaison entre deux audits.

### Critères de fin de phase

- « Audite ma machine et [domaine autorisé] » produit un plan, au moins 6 appels d'outils, un score et un PDF lisible.
- Un deuxième audit affiche l'écart de score et les constats corrigés.

---

## 8. Phase 4 — Vitrine : planification, Docker, CI, README

**Objectif :** un projet présentable sur GitHub et sur un CV.

### Tâches

1. **Audits programmés (`scheduler.py`)** : `APScheduler` avec stockage des tâches en SQLite ; `POST /schedules` `{"instruction", "cron", "authorized": true}`, `GET /schedules`, `DELETE /schedules/{id}` ; alerte enregistrée en base (et affichée dans l'interface) si le score baisse d'au moins 10 points ou si un nouveau constat `critical` apparaît. Onglet ou section « Planification » dans l'interface.
2. **Docker** :
   - `Dockerfile` (python:3.12-slim, utilisateur non root, `iputils-ping` installé) ;
   - `docker-compose.yml` avec les services `api` (port 8000) et `ui` (port 8501), `env_file: .env`, volume `./data` ;
   - préciser dans le README que, dans Docker, le mode machine audite le conteneur et non le PC hôte : pour auditer son PC, lancer NetDoctor hors Docker.
3. **CI (`.github/workflows/ci.yml`)** : à chaque push et pull request, `ruff check` puis `pytest`, sur `ubuntu-latest` et `windows-latest`, Python 3.11 et 3.12. Aucune clé API nécessaire grâce aux mocks.
4. **README.md** :
   - pitch en deux phrases, badge CI, GIF ou capture de la démo ;
   - schéma d'architecture en Mermaid ;
   - fonctionnalités, installation (venv et Docker), configuration du `.env` avec le tableau des fournisseurs ;
   - section « Sécurité et éthique » (listes blanches, lecture seule, journal, confirmation) ;
   - limites connues et pistes d'amélioration ;
   - section « Ce que j'ai appris ».
5. **Nettoyage** : typage des fonctions publiques, docstrings, suppression du code mort, vérification qu'aucun secret n'est présent dans l'historique git.

### Critères de fin de phase

- `docker compose up` lance l'API et l'interface.
- La CI passe sur Linux et Windows.
- Un audit programmé toutes les heures s'exécute et une alerte apparaît quand on dégrade volontairement une cible de test.

---

## 9. Critères d'acceptation et scénarios de démo

### Critères globaux

- [ ] Changer de fournisseur LLM (Groq, Kimi, Ollama, OpenAI) ne demande que la modification du `.env`.
- [ ] Toutes les entrées malveillantes de la section 4 sont refusées sans exécution.
- [ ] Le score est calculé en Python et identique d'un modèle à l'autre pour les mêmes constats.
- [ ] Chaque appel d'outil apparaît dans l'interface et dans `data/audit_log.jsonl`.
- [ ] Aucune clé API dans le dépôt git ni dans les logs.
- [ ] Les tests passent sans réseau ni clé API.

### Scénarios de démo (10 minutes)

1. **Diagnostic** — « Pourquoi siteinexistant123.tn ne répond pas ? » → `dns_lookup`, erreur DNS expliquée.
2. **Raisonnement visible** — « Mon serveur web ne marche pas sur [domaine autorisé] » → DNS, puis ping, puis `check_port 443` : l'agent explique la différence entre hôte joignable et service arrêté.
3. **Sécurité de l'agent** — « Ping google.com; rm -rf / » → refus par la validation, visible dans le journal. « Scanne tous les ports de 192.168.1.0/24 » → refus poliment expliqué.
4. **Audit autonome** — « Audite ma machine et [domaine autorisé] » → plan affiché, étapes en direct, score, plan d'action, PDF téléchargé.
5. **Amélioration mesurée** — corriger un constat (par exemple ajouter un en-tête de sécurité sur le site de test), relancer l'audit → l'écart de score et le constat corrigé apparaissent.
6. **Portabilité** — changer `LLM_BASE_URL` et `LLM_MODEL` dans le `.env`, relancer → même audit avec un autre modèle, même score.

### Cible de démo conseillée

Un site personnel gratuit (par exemple GitHub Pages) dont tu es propriétaire, ajouté à `cibles_autorisees.txt`.
