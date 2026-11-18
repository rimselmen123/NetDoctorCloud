# Guide de test — AgentDoctor

Deux tests : les tests automatiques (rapides) et le test réel (vraie attaque → agent → email).

---

## Test 1 — Tests automatiques

Dans **CMD** :

```cmd
cd /d D:\NetDoctorCloud\backend
.venv\Scripts\python.exe -m pytest -q
```

✅ Résultat attendu : `38 passed`.
Ces tests n'utilisent ni Internet ni la clé OpenAI.

---

## Test 2 — Test réel (de bout en bout)

### Étape 1 — Ubuntu : démarrer les services
Ouvrir **Ubuntu** (`wsl -d Ubuntu-24.04`) :

```bash
sudo service rsyslog start && sudo service ssh start
```

### Étape 2 — CMD : lancer le serveur
Laisser cette fenêtre **ouverte** :

```cmd
cd /d D:\NetDoctorCloud\backend
.venv\Scripts\python.exe -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

Attendre le message : `Application startup complete`.

### Étape 3 — Ubuntu : lancer l'attaque
Dans **Ubuntu** (pas Kali). À chaque `password:`, taper un **mauvais** mot de passe + Entrée.

6 échecs sur `root` :
```bash
for i in $(seq 1 6); do ssh -p 2222 -o PubkeyAuthentication=no root@127.0.0.1 true; done
```

5 échecs puis 1 succès sur `victime` (le dernier mot de passe est `Test1234`) :
```bash
for i in $(seq 1 5); do ssh -p 2222 -o PubkeyAuthentication=no victime@127.0.0.1 true; done
ssh -p 2222 -o PubkeyAuthentication=no victime@127.0.0.1 true
```

Vérifier que les lignes sont bien écrites :
```bash
grep "password" /var/log/auth.log | tail
```

### Étape 4 — CMD : lancer l'agent
Nouvelle fenêtre **CMD**. L'en-tête `X-Requested-By` est obligatoire.

```cmd
curl -X POST localhost:8000/collect   -H "X-Requested-By: agentdoctor"
curl -X POST localhost:8000/agent/run -H "X-Requested-By: agentdoctor"
```

### Étape 5 — Vérifier le résultat
```cmd
curl localhost:8000/alerts
curl localhost:8000/actions
```

✅ On doit voir :
- une alerte **critique**, `verdict: true_positive` ;
- des actions `block_ip` et `flag_user` ;
- un **email** reçu sur rimselmen123@gmail.com (voir aussi les spams).

---

## Remettre à zéro (avant de recommencer)

```cmd
curl -X POST localhost:8000/reset -H "X-Requested-By: agentdoctor" -H "Content-Type: application/json" -d "{\"confirm\":true}"
```

---

## Dépannage

| Problème | Cause | Solution |
|---|---|---|
| `curl` renvoie **403** | en-tête manquant | ajouter `-H "X-Requested-By: agentdoctor"` |
| `collect` renvoie `0` | pas de nouvelles attaques | relancer l'étape 3, vérifier que les services tournent |
| le serveur ne démarre pas | ancien serveur sur le port 8000 | fermer l'ancienne fenêtre, ou relancer |
| port 8000 occupé | processus resté actif | dans CMD : `netstat -ano | findstr :8000` puis `taskkill /PID <pid> /F` |

---

## Notes

- En WSL, les attaques partent de `127.0.0.1` → on obtient **une** alerte critique groupée (c'est normal).
- L'attaque se lance depuis **Ubuntu**, car c'est Ubuntu qui héberge le serveur SSH et écrit `auth.log`. Depuis Kali, `127.0.0.1` ne pointerait pas vers Ubuntu.
- Interface web pour tester sans curl : **http://localhost:8000/docs**
