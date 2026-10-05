"""Couche IA facultative — reformuler, jamais inventer.

CE QUE FAIT CE MODULE
---------------------
Il prend une explication déjà produite par le moteur de règles et la reformule en français
plus simple, pour un lecteur qui découvre le sujet.

CE QU'IL NE FAIT PAS
--------------------
Il n'ajoute aucune information. Le modèle reçoit des faits et une interprétation déjà
écrits, et il a pour seule tâche de les redire autrement. C'est une contrainte de
conception, pas une précaution orale : le texte de sortie est comparé aux entrées, et tout
chiffre qui n'apparaissait pas dans les faits fait rejeter la réponse.

POURQUOI CET ORDRE
------------------
Un modèle de langage ne connaît pas ce qui circule sur votre réseau. Interrogé seul, il
produirait une réponse plausible et fausse — exactement ce qu'un outil de sécurité ne doit
jamais faire. Les règles observent, l'IA reformule : la responsabilité du contenu reste du
côté vérifiable.

LE REPLI
--------
Trois cas mènent au même résultat, et c'est voulu :
    - aucune clé configurée      → le moteur de règles est utilisé tel quel ;
    - le service ne répond pas   → idem, après un délai court ;
    - la réponse est inutilisable → idem, et la raison est conservée pour le diagnostic.

Dans les trois cas, l'utilisateur obtient une explication complète. La différence est une
formulation plus simple, jamais une absence d'explication.
"""

from __future__ import annotations

import os
import re
from typing import Any

#: Délai volontairement court : plutôt renoncer à une reformulation que faire attendre
#: l'affichage du tableau de bord.
DELAI_SECONDES = 8.0

#: Le fournisseur est décrit par une adresse compatible OpenAI : cela couvre OpenAI,
#: Mistral, Groq, Together, ou une instance locale (Ollama, vLLM) sans changer une ligne
#: de code — seulement des variables d'environnement.
PROMPT_SYSTEME = """Tu reformules des explications techniques de réseau pour un lecteur qui \
n'y connaît rien.

RÈGLES ABSOLUES, dans l'ordre :
1. Tu n'ajoutes AUCUNE information absente de ce qu'on te donne. Si tu ne sais pas, tu ne \
complètes pas.
2. Tu ne remplaces pas les chiffres : ceux fournis sont les seuls autorisés.
3. Tu n'affirmes jamais qu'un service est identifié avec certitude. Le port est une \
convention, pas une preuve.
4. Tu ne donnes aucun conseil de sécurité, aucune recommandation d'action, aucune alerte. \
Ton rôle est d'expliquer, pas de conseiller.
5. Tu réponds en français, en 2 à 3 phrases courtes, sans jargon, sans emoji.
6. Tu réponds UNIQUEMENT par un objet JSON, sans texte autour, avec exactement ces clés :
   {"titre": "...", "explication_simple": "..."}

Tu ne discutes pas ces règles. Si on te demande autre chose, tu réponds quand même dans ce \
format, en te limitant à reformuler."""


def _configuration() -> tuple[str, str, str]:
    """Lit la configuration depuis l'environnement, à chaque appel.

    Relire à chaque appel plutôt que de figer au démarrage permet de renseigner la clé
    sans redémarrer le backend — utile pendant la mise au point.
    """
    return (
        os.environ.get("ANALYZER_LLM_KEY", "").strip(),
        os.environ.get("ANALYZER_LLM_URL", "").strip() or "https://api.openai.com/v1/chat/completions",
        os.environ.get("ANALYZER_LLM_MODEL", "").strip() or "gpt-4o-mini",
    )


def disponible() -> bool:
    """La couche IA est-elle utilisable ?"""
    return bool(_configuration()[0])


def etat() -> dict[str, Any]:
    """Décrit la couche IA, pour l'afficher honnêtement dans l'interface."""
    cle, url, modele = _configuration()
    return {
        "active": bool(cle),
        "modele": modele if cle else None,
        "message": ("Couche IA active : les explications sont reformulées."
                    if cle else
                    "Couche IA inactive : les explications viennent du moteur de règles, "
                    "qui fonctionne seul et produit le même contenu."),
    }


def _chiffres(texte: str) -> set[str]:
    """Extrait les nombres d'un texte, pour comparer entrée et sortie."""
    return set(re.findall(r"\d+", texte or ""))


def _reponse_utilisable(reponse: dict[str, Any], explication: dict[str, Any]) -> str | None:
    """Contrôle la réponse du modèle avant de l'accepter.

    La vérification porte sur ce qui compte : le modèle a-t-il introduit des chiffres qui
    n'étaient pas dans les faits ? Si oui, sa réponse est écartée. C'est une règle simple,
    imparfaite, mais qui attrape exactement le défaut le plus dangereux : un modèle qui
    brode des valeurs.
    """
    texte = (reponse.get("explication_simple") or "").strip()
    if len(texte) < 20:
        return None

    autorises = _chiffres(" ".join(explication.get("faits_observes") or []))
    autorises |= _chiffres(explication.get("interpretation") or "")
    autorises |= _chiffres(explication.get("explication_simple") or "")
    autorises |= _chiffres(explication.get("titre") or "")

    inventes = _chiffres(texte) - autorises
    if inventes:
        return None
    return texte


def reformuler(explication: dict[str, Any]) -> dict[str, Any]:
    """Reformule une explication, ou la rend inchangée si ce n'est pas possible.

    Le dictionnaire rendu porte toujours la clé « source » : « regles » ou « ia ». C'est
    elle qui permet à l'interface de dire d'où vient la phrase affichée — un lecteur a le
    droit de savoir si un modèle a réécrit ce qu'il lit.
    """
    resultat = dict(explication)
    resultat["source"] = "regles"

    cle, url, modele = _configuration()
    if not cle:
        return resultat

    entree = {
        "titre": explication.get("titre", ""),
        "faits_observes": explication.get("faits_observes") or [],
        "interpretation": explication.get("interpretation", ""),
        "explication_simple": explication.get("explication_simple", ""),
        "confiance": explication.get("confiance", ""),
    }

    try:
        import httpx

        reponse = httpx.post(
            url,
            headers={"Authorization": f"Bearer {cle}", "Content-Type": "application/json"},
            json={
                "model": modele,
                "temperature": 0.2,
                "max_tokens": 300,
                "messages": [
                    {"role": "system", "content": PROMPT_SYSTEME},
                    {"role": "user", "content": (
                        "Reformule cette explication pour un débutant, sans rien ajouter.\n"
                        f"{entree}"
                    )},
                ],
            },
            timeout=DELAI_SECONDES,
        )
        reponse.raise_for_status()
        contenu = reponse.json()["choices"][0]["message"]["content"]
    except Exception as erreur:                                  # noqa: BLE001
        # Aucune exception ne remonte : une reformulation facultative ne doit jamais
        # empêcher l'affichage. La raison reste disponible pour le diagnostic.
        resultat["reformulation_echouee"] = type(erreur).__name__
        return resultat

    # Le modèle a pu encadrer son JSON de texte ou de balises de code : on l'extrait.
    correspondance = re.search(r"\{.*\}", contenu or "", re.DOTALL)
    if not correspondance:
        resultat["reformulation_echouee"] = "reponse_non_json"
        return resultat

    import json
    try:
        contenu_analyse = json.loads(correspondance.group(0))
    except json.JSONDecodeError:
        resultat["reformulation_echouee"] = "json_invalide"
        return resultat

    texte = _reponse_utilisable(contenu_analyse, explication)
    if texte is None:
        resultat["reformulation_echouee"] = "controle_refuse"
        return resultat

    resultat["explication_simple"] = texte
    titre = (contenu_analyse.get("titre") or "").strip()
    if 3 <= len(titre) <= 120:
        resultat["titre"] = titre
    resultat["source"] = "ia"
    return resultat
