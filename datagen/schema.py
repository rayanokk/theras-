"""Formes strictes de ce que le LLM doit renvoyer (Forge — A).

Le LLM n'HABILLE que le contenu : un document réaliste, et pour une injection,
l'instruction cachée + son placement. Il ne renvoie JAMAIS de verdict, de règle
ni de classification : ces faits sont fixés par l'oracle avant l'appel.

Toute réponse hors de ces modèles est rejetée (et régénérée une fois).
"""
from __future__ import annotations

from pydantic import BaseModel, ConfigDict, Field


class GeneratedDocument(BaseModel):
    """Sortie LLM pour un document (piégé ou non)."""
    model_config = ConfigDict(extra="ignore")   # on tolère des champs en trop, on ignore

    title: str = Field(min_length=3, max_length=200)
    body: str = Field(min_length=20, max_length=4000)
    # Renseignés UNIQUEMENT pour un document piégé :
    hidden_instruction: str | None = Field(default=None, max_length=600)
    placement: str | None = Field(default=None, max_length=60)  # ex. "bas de page", "métadonnées"


class GeneratedEmailBody(BaseModel):
    """Sortie LLM pour le corps d'un mail légitime (pas d'injection)."""
    model_config = ConfigDict(extra="ignore")

    subject: str = Field(min_length=2, max_length=200)
    body: str = Field(min_length=5, max_length=2000)
