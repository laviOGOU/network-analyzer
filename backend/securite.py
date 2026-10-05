"""Protection de l'endpoint d'ingestion.

Deux mécanismes, deux objectifs différents
------------------------------------------
**Le jeton d'agent** protège contre un inconnu : sans lui, n'importe qui sur Internet
pourrait écrire des paquets inventés dans le tableau de bord. Il ne s'agit pas d'une
authentification d'utilisateur — il n'y a pas d'utilisateur — mais d'un partage de secret
entre l'agent et le backend.

**La limitation de débit** protège contre un agent légitime mais emballé (boucle
d'erreur, redémarrage en rafale) et contre un porteur de jeton qui enverrait des millions
de lots. Elle ne remplace pas le jeton : elle limite les dégâts quand il a fuité.

Deux détails qui comptent
-------------------------
1. La comparaison des jetons se fait en **temps constant** (`secrets.compare_digest`).
   Une comparaison ordinaire s'arrête au premier caractère différent : en mesurant le temps
   de réponse, on peut deviner le jeton caractère par caractère.
2. Le message d'erreur ne dit jamais si le jeton était « presque » bon. Il ne renseigne
   pas l'attaquant.
"""

from __future__ import annotations

import logging
import secrets
import threading
import time
from collections import defaultdict, deque
from typing import Annotated

from fastapi import Header, HTTPException, Request, status

from backend.config import configuration

logger = logging.getLogger(__name__)

#: Nom de l'en-tête portant le jeton. Un en-tête plutôt qu'un paramètre d'adresse : il
#: n'apparaît pas dans les journaux des serveurs intermédiaires.
ENTETE_JETON = "X-Agent-Token"


def verifier_jeton(
    x_agent_token: Annotated[str | None, Header(alias=ENTETE_JETON)] = None,
) -> None:
    """Dépendance FastAPI : refuse la requête si le jeton est absent ou faux.

    On ne lève pas volontairement d'exception ici : `request.client` n'est pas
    disponible dans une simple dépendance sans requête, donc l'origine est journalisée
    par l'appelant.
    """
    attendu = configuration.jeton_agent
    if not attendu:
        # Ne devrait pas arriver : la configuration en engendre un. Si cela se produit,
        # mieux vaut refuser que laisser l'endpoint ouvert.
        logger.error("Aucun jeton d'agent configuré : ingestion refusée")
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="Ingestion indisponible : jeton d'agent non configuré.")

    if not x_agent_token or not secrets.compare_digest(str(x_agent_token), attendu):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED,
                            detail="Jeton d'agent absent ou invalide.")


class LimiteurDebit:
    """Fenêtre glissante en mémoire : `limite` autorisations par minute et par origine.

    Fenêtre glissante plutôt que compteur remis à zéro chaque minute : un compteur fixe
    autorise deux fois la limite en franchissant la minute (120 requêtes à 11 h 59 min 59 s,
    120 autres à midi), ce qui est exactement le comportement qu'on cherche à éviter.

    La mémoire est bornée : on ne garde que les horodatages de la dernière minute.
    """

    def __init__(self, limite: int = 120, fenetre: float = 60.0) -> None:
        self.limite = limite
        self.fenetre = fenetre
        self._verrou = threading.Lock()
        self._historique: dict[str, deque[float]] = defaultdict(deque)

    def autoriser(self, origine: str) -> tuple[bool, int]:
        """Autorise ou refuse. Renvoie (autorisé, requêtes dans la fenêtre)."""
        maintenant = time.monotonic()
        with self._verrou:
            horodatages = self._historique[origine]
            # On retire tout ce qui est sorti de la fenêtre.
            while horodatages and maintenant - horodatages[0] > self.fenetre:
                horodatages.popleft()

            if len(horodatages) >= self.limite:
                return False, len(horodatages)

            horodatages.append(maintenant)
            # Ménage des origines inactives : sans cela, le dictionnaire grandirait
            # indéfiniment au fil des adresses rencontrées.
            if len(self._historique) > 512:
                for cle in [c for c, h in self._historique.items() if not h][:256]:
                    self._historique.pop(cle, None)
            return True, len(horodatages)


#: Instance partagée par l'application.
limiteur = LimiteurDebit(limite=configuration.limite_ingestion)


def verifier_debit(request: Request) -> None:
    """Dépendance FastAPI : applique la limitation de débit à l'ingestion."""
    origine = (request.client.host if request.client else "inconnue") or "inconnue"
    autorise, nombre = limiteur.autoriser(origine)
    if not autorise:
        logger.warning("Limite d'ingestion atteinte pour %s (%d requêtes)", origine, nombre)
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Trop de requêtes d'ingestion ({nombre} dans la dernière minute). "
                   "Réessayez dans quelques instants.",
            headers={"Retry-After": "30"},
        )
