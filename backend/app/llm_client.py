"""Création du client LLM compatible OpenAI (OpenAI, Groq, Kimi, Ollama…)."""
from openai import OpenAI

from app.config import settings


def make_client() -> OpenAI:
    """Construit le client à partir du .env. base_url vide → OpenAI par défaut."""
    kwargs = {"api_key": settings.openai_api_key}
    base_url = getattr(settings, "llm_base_url", "") or ""
    if base_url:
        kwargs["base_url"] = base_url
    return OpenAI(**kwargs)
