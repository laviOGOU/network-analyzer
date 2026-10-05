"""Dépendances partagées entre les routes.

Pourquoi une couche de dépendances plutôt qu'un objet global importé partout
----------------------------------------------------------------------------
Les routes déclarent ce dont elles ont besoin (« donne-moi le stockage ») sans savoir
comment il est construit. FastAPI appelle la fonction et fournit le résultat.

L'intérêt n'est pas théorique : un test peut remplacer cette dépendance par un stockage
neuf, propre à lui, sans toucher au code des routes et sans risquer qu'un test laisse des
paquets qui fausseraient le suivant.

    application.dependency_overrides[obtenir_stockage] = lambda: Stockage(10)

C'est aussi ce qui permettra, en phase 5, de renvoyer un stockage fondé sur Supabase sans
modifier une seule route.
"""

from __future__ import annotations

from backend.config import configuration
from backend.storage import Stockage

#: Instance unique, construite au premier appel. La taille vient de la configuration :
#: aucun nombre magique dans le code des routes.
_stockage: Stockage | None = None


def obtenir_stockage() -> Stockage:
    """Rend le stockage de l'application (créé à la première demande)."""
    global _stockage
    if _stockage is None:
        _stockage = Stockage(taille_max=configuration.taille_memoire)
    return _stockage


def reinitialiser_stockage() -> Stockage:
    """Remplace le stockage par un neuf. Utilisé par les tests."""
    global _stockage
    _stockage = Stockage(taille_max=configuration.taille_memoire)
    return _stockage
