"""Configuration typée de l'application, lue depuis les variables d'environnement (.env)."""
from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

# Racine du projet (…/NetDoctorCloud) pour localiser le .env quel que soit le dossier courant.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]


class Settings(BaseSettings):
    """Paramètres de l'application. Chaque champ correspond à une variable du .env."""

    # LLM (OpenAI ou compatible)
    openai_api_key: str = ""
    llm_model: str = "gpt-4o-mini"

    # Base de données PostgreSQL
    database_url: str = ""

    # Source des logs et mode laboratoire
    auth_log_path: str = ""
    lab_mode: bool = True

    # Rapport email (Gmail SMTP)
    smtp_user: str = ""
    smtp_app_password: str = ""
    report_to: str = ""

    # Garde-fous de l'agent (limites de coût)
    max_alerts: int = 10
    max_steps: int = 6

    model_config = SettingsConfigDict(
        env_file=_PROJECT_ROOT / ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )


# Instance unique réutilisée dans toute l'application.
settings = Settings()
