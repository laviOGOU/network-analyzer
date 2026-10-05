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

import logging

from backend.config import configuration
from backend.enrichment import Enrichissement
from backend.storage import Stockage

logger = logging.getLogger(__name__)

#: Instance unique, construite au premier appel. La taille vient de la configuration :
#: aucun nombre magique dans le code des routes.
_stockage: Stockage | None = None


def obtenir_stockage():
    """Rend le stockage de l'application (créé à la première demande).

    Le choix se fait **ici, et nulle part ailleurs**. Une chaîne de connexion configurée
    donne le stockage PostgreSQL ; sans elle, le stockage en mémoire. Aucune route ne
    connaît la différence : elles appellent les mêmes méthodes, avec les mêmes noms.

    C'est ce qui permet à la démonstration locale de fonctionner sans base de données, et
    au déploiement en ligne de conserver l'historique — sans deux versions du code.
    """
    global _stockage
    if _stockage is None:
        if configuration.base_de_donnees:
            from backend.stockage_postgres import StockagePostgres

            logger.info("Stockage : PostgreSQL (historique conservé)")
            _stockage = StockagePostgres(configuration.base_de_donnees,
                                         taille_max=configuration.taille_memoire)
        else:
            logger.info("Stockage : en mémoire (rien n'est conservé après l'arrêt)")
            _stockage = Stockage(taille_max=configuration.taille_memoire)
    return _stockage


def reinitialiser_stockage() -> Stockage:
    """Remplace le stockage par un neuf. Utilisé par les tests."""
    global _stockage
    _stockage = Stockage(taille_max=configuration.taille_memoire)
    return _stockage


#: Enrichissement : une seule instance, et pour une raison précise. Le cache et le
#: limiteur de débit doivent être **partagés** par toutes les requêtes ; une instance par
#: requête redemanderait vingt fois la même adresse et épuiserait le quota des services
#: gratuits en quelques minutes.
_enrichissement: Enrichissement | None = None


def obtenir_enrichissement() -> Enrichissement:
    """Rend l'enrichissement de l'application (créé à la première demande)."""
    global _enrichissement
    if _enrichissement is None:
        _enrichissement = Enrichissement(cle_ipinfo=configuration.cle_ipinfo,
                                         cle_abuseipdb=configuration.cle_abuseipdb)
    return _enrichissement
