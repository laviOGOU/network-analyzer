"""Configuration du backend, lue dans l'environnement.

Aucune valeur secrète n'est écrite dans le code ni dans un fichier versionné. Le fichier
`.env` est ignoré par Git ; `.env.example` montre les clés attendues, sans valeur.

Le jeton d'agent
----------------
L'endpoint d'ingestion est le seul point d'entrée qui écrit des données : il est protégé
par un jeton partagé entre l'agent et le backend. Ce n'est pas une authentification
d'utilisateur — il n'y a pas d'utilisateur — mais cela empêche n'importe qui sur Internet
de remplir la base de données de paquets inventés.

En développement, si le jeton est absent, l'application en engendre un et l'affiche dans
la console. C'est plus commode qu'un refus de démarrer ; en production, il faut le refuser
explicitement, sinon un jeton aléatoire serait recréé à chaque redémarrage et l'agent ne
pourrait plus rien envoyer.
"""

from __future__ import annotations

import logging
import os
import secrets
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv

RACINE = Path(__file__).resolve().parent.parent

# `.env` à la racine du dépôt. `override=False` : une variable déjà présente dans
# l'environnement l'emporte sur le fichier, ce qui permet de la changer sans le modifier.
load_dotenv(RACINE / ".env", override=False)

logger = logging.getLogger(__name__)


def _texte(cle: str, defaut: str = "") -> str:
    return (os.getenv(cle) or defaut).strip()


def _entier(cle: str, defaut: int) -> int:
    """Entier lu dans l'environnement, avec repli sur la valeur par défaut.

    Une valeur illisible ne doit pas empêcher le démarrage : on prévient et on continue.
    """
    brut = _texte(cle)
    if not brut:
        return defaut
    try:
        return int(brut)
    except ValueError:
        logger.warning("%s = %r n'est pas un nombre entier ; valeur par défaut : %d",
                       cle, brut, defaut)
        return defaut


def _liste(cle: str, defaut: list[str]) -> list[str]:
    """Liste séparée par des virgules."""
    brut = _texte(cle)
    if not brut:
        return list(defaut)
    return [element.strip() for element in brut.split(",") if element.strip()]


@dataclass
class Configuration:
    """Réglages du backend. Instanciée une fois, au démarrage."""

    #: Jeton partagé avec l'agent.
    jeton_agent: str = ""
    #: En production, un jeton absent est une erreur fatale.
    env: str = "developpement"

    hote: str = "127.0.0.1"
    port: int = 8000

    #: Nombre de paquets conservés en mémoire (phase 1 : pas encore de base de données).
    taille_memoire: int = 2000

    #: Origines autorisées pour les appels depuis un navigateur. Restrictif par défaut :
    #: le tableau de bord est servi par ce même serveur, donc aucune origine externe n'a
    #: besoin d'appeler l'API.
    origines_cors: list[str] = field(default_factory=lambda: ["http://127.0.0.1:8000",
                                                              "http://localhost:8000"])
    #: Nombre maximal de requêtes d'ingestion par minute, par adresse.
    limite_ingestion: int = 120

    @classmethod
    def depuis_environnement(cls) -> "Configuration":
        """Construit la configuration et vérifie sa cohérence."""
        env = _texte("ANALYZER_ENV", "developpement").lower()
        jeton = _texte("ANALYZER_AGENT_TOKEN")

        if not jeton:
            if env in ("production", "preproduction"):
                raise SystemExit(
                    "ANALYZER_AGENT_TOKEN est obligatoire en "
                    f"environnement « {env} ».\n"
                    "  Engendrer un jeton :  python -c \"import secrets; "
                    "print(secrets.token_urlsafe(32))\"\n"
                    "  Le placer dans .env, puis redémarrer."
                )
            jeton = secrets.token_urlsafe(32)
            logger.warning("Aucun ANALYZER_AGENT_TOKEN : jeton engendré pour cette "
                           "exécution.\n  À transmettre à l'agent :\n    %s", jeton)

        return cls(
            jeton_agent=jeton,
            env=env,
            hote=_texte("ANALYZER_HOST", "127.0.0.1"),
            port=_entier("ANALYZER_PORT", 8000),
            taille_memoire=_entier("ANALYZER_TAILLE_MEMOIRE", 2000),
            origines_cors=_liste("ANALYZER_ORIGINES_CORS",
                                 ["http://127.0.0.1:8000", "http://localhost:8000"]),
            limite_ingestion=_entier("ANALYZER_LIMITE_INGESTION", 120),
        )

    @property
    def en_production(self) -> bool:
        return self.env in ("production", "preproduction")


#: Instance partagée, construite à l'import du module.
configuration = Configuration.depuis_environnement()
