"""Vérifie que la configuration lit bien les variables d'environnement."""
import importlib


def test_settings_lit_env(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://u:p@localhost/AgentDoctor")
    monkeypatch.setenv("OPENAI_API_KEY", "x")
    monkeypatch.setenv("LLM_MODEL", "gpt-4o-mini")

    import app.config as config
    importlib.reload(config)  # recharge pour prendre en compte les variables injectées

    s = config.Settings()
    assert s.llm_model == "gpt-4o-mini"
    assert s.database_url.endswith("AgentDoctor")
    # Valeurs par défaut des garde-fous
    assert s.max_alerts == 10
    assert s.max_steps == 6
    assert s.lab_mode is True
