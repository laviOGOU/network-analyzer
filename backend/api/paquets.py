"""Routes de lecture : paquets, statistiques, sessions.

Toutes ces routes sont en lecture seule et **ne demandent pas de jeton** : le tableau de
bord est public (décision prise avec l'auteur du projet). Ce qui est protégé, c'est
l'écriture — n'importe qui peut lire, personne ne peut inventer.

Elles ne calculent rien elles-mêmes : le tri, le comptage et le classement sont faits par
le stockage. Une route qui compte, ici, serait une route à réécrire le jour où les données
viendront de PostgreSQL.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, Depends, Query

from backend.dependances import obtenir_stockage
from backend.storage import Stockage

router = APIRouter(tags=["lecture"])


@router.get("/packets", summary="Derniers paquets capturés")
def lister_paquets(
    stockage: Annotated[Stockage, Depends(obtenir_stockage)],
    limite: Annotated[int, Query(ge=1, le=1000, description="Nombre de paquets à rendre")] = 100,
    protocole: Annotated[str | None, Query(max_length=32, description="Filtre : TCP, UDP, DNS…")] = None,
    session: Annotated[str | None, Query(max_length=64, description="Identifiant de session")] = None,
    recherche: Annotated[str | None, Query(max_length=64, description="Recherche libre (IP, domaine, port)")] = None,
) -> dict[str, Any]:
    """Rend les paquets les plus récents d'abord.

    Les bornes de `Query` ne sont pas décoratives : sans elles, `?limite=100000000`
    demanderait au serveur de préparer une réponse énorme, pour rien.
    """
    paquets = stockage.paquets(limite=limite, protocole=protocole,
                               session=session, recherche=recherche)
    return {
        "paquets": paquets,
        "affiches": len(paquets),
        "statistiques": stockage.statistiques(),
    }


@router.get("/flows", summary="Communications (Connections)")
def lister_communications(
    stockage: Annotated[Stockage, Depends(obtenir_stockage)],
    limite: Annotated[int, Query(ge=1, le=1000)] = 100,
    etat: Annotated[str | None, Query(max_length=32, description="tentative, établie, fermée…")] = None,
    protocole: Annotated[str | None, Query(max_length=32)] = None,
    session: Annotated[str | None, Query(max_length=64, description="Identifiant de session")] = None,
    recherche: Annotated[str | None, Query(max_length=64, description="IP, port, état")] = None,
) -> dict[str, Any]:
    """Communications regroupées, la plus récente d'abord.

    Chaque communication porte `etat` et `etat_certain`. Ce second champ doit être
    affiché, pas seulement stocké : une communication vue en cours de route ne peut pas
    être présentée avec la même assurance qu'une ouverture observée en entier.
    """
    communications = stockage.communications(limite=limite, etat=etat, protocole=protocole,
                                             session=session, recherche=recherche)
    return {"communications": communications, "affichees": len(communications),
            "statistiques": stockage.statistiques()}


@router.get("/stats", summary="Chiffres du tableau de bord")
def statistiques(stockage: Annotated[Stockage, Depends(obtenir_stockage)]) -> dict[str, Any]:
    """Compteurs, répartitions et classements."""
    return stockage.statistiques()


@router.get("/sessions", summary="Sessions de capture connues")
def lister_sessions(stockage: Annotated[Stockage, Depends(obtenir_stockage)]) -> dict[str, Any]:
    """Sessions reçues depuis le démarrage, la plus récente d'abord.

    En phase 1 cette liste vit en mémoire : elle disparaît au redémarrage. La phase 5 la
    rendra persistante, sans changer cette adresse.
    """
    sessions = stockage.sessions()
    return {"sessions": sessions, "total": len(sessions)}


@router.get("/health", summary="État du service — Health")
def sante() -> dict[str, Any]:
    """Contrôle de disponibilité, utilisé par les hébergeurs et les scripts.

    Sans jeton et sans données : il doit répondre même quand tout le reste va mal, sinon
    il ne sert à rien.
    """
    from backend.config import configuration

    return {"etat": "ok", "environnement": configuration.env}
