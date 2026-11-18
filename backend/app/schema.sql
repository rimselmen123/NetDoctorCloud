-- Schéma de la base AgentDoctor. Idempotent : exécuté à chaque démarrage.

-- Événements bruts extraits de auth.log
CREATE TABLE IF NOT EXISTS events (
    id       SERIAL PRIMARY KEY,
    ts       TIMESTAMPTZ,
    ip       TEXT,
    username TEXT,
    outcome  TEXT,                 -- 'failed' | 'accepted' | 'invalid_user'
    raw      TEXT UNIQUE           -- ligne brute, sert à éviter les doublons
);

-- Alertes produites par les règles de détection (Python, pas le LLM)
CREATE TABLE IF NOT EXISTS alerts (
    id         SERIAL PRIMARY KEY,
    type       TEXT NOT NULL,      -- 'brute_force' | 'failed_login' | 'success_after_failures'
    ip         TEXT,
    username   TEXT,
    count      INT DEFAULT 0,
    status     TEXT DEFAULT 'open',    -- 'open' | 'closed'
    verdict    TEXT,                   -- 'true_positive' | 'false_positive'
    severity   TEXT,                   -- 'critical' | 'high' | 'medium' | 'low'
    reason     TEXT,
    created_at TIMESTAMPTZ DEFAULT now()
);

-- Étapes de raisonnement de l'agent (traçabilité complète)
CREATE TABLE IF NOT EXISTS agent_steps (
    id          SERIAL PRIMARY KEY,
    alert_id    INT REFERENCES alerts(id),
    step        INT,
    tool        TEXT,
    args_json   TEXT,
    result_json TEXT,
    created_at  TIMESTAMPTZ DEFAULT now()
);

-- Actions concrètes décidées par l'agent (jamais exécutées sur le système)
CREATE TABLE IF NOT EXISTS actions (
    id         SERIAL PRIMARY KEY,
    alert_id   INT REFERENCES alerts(id),
    type       TEXT,               -- 'block_ip' | 'flag_user'
    target     TEXT,
    reason     TEXT,
    command    TEXT,               -- commande générée, à exécuter par un humain
    created_at TIMESTAMPTZ DEFAULT now()
);
