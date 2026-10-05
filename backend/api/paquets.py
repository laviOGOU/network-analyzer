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

from fastapi import APIRouter, Depends, HTTPException, Query

try:
    # Les seuils de détection sont définis dans l'agent, qui les applique. On les lit
    # pour les rendre visibles dans l'interface — c'est une exigence du sujet de pouvoir
    # savoir à partir de quoi une détection se déclenche.
    #
    # L'import est protégé parce que les deux moitiés du projet ne se déploient pas
    # ensemble : l'agent tourne sur la machine à surveiller, le backend est en ligne. Si
    # le dossier de l'agent n'est pas livré avec le backend, l'interface perd la liste des
    # seuils — et rien d'autre. Une dépendance obligatoire entre les deux ferait échouer
    # le déploiement en ligne pour une information d'agrément.
    from agent.detection import SEUILS
except ImportError:                                  # pragma: no cover
    SEUILS: dict[str, int] = {}

from backend.dependances import obtenir_stockage
from backend.explain import llm
from backend.explain import rules as moteur_explication
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

    # Une explication « de liste » accompagne chaque communication. Elle est volontairement
    # générale — elle répond à « de quel genre de communication s'agit-il ? » — et mise en
    # cache : la reformuler pour chacune des cent cinquante lignes affichées serait du
    # travail perdu, puisque seules trois valeurs (protocole, port, état) la déterminent.
    # L'explication complète, elle, tient compte des adresses, des volumes et du sens de
    # l'échange : c'est celle que renvoie la route de détail.
    for communication in communications:
        port = communication.get("port_b") or communication.get("port_a")
        communication["explication"] = moteur_explication.expliquer_resume(
            communication.get("protocole") or "",
            int(port) if port is not None else None,
            communication.get("etat") or "",
            bool(communication.get("etat_certain")),
        )
    return {"communications": communications, "affichees": len(communications),
            "statistiques": stockage.statistiques()}


@router.get("/alerts", summary="Détections de comportements inhabituels")
def lister_detections(
    stockage: Annotated[Stockage, Depends(obtenir_stockage)],
    limite: Annotated[int, Query(ge=1, le=500, description="Nombre de détections à rendre")] = 100,
    niveau: Annotated[str | None, Query(pattern="^(observation|hypothèse|alerte)$",
                                        description="Filtre par niveau de certitude")] = None,
    session: Annotated[str | None, Query(max_length=64)] = None,
) -> dict[str, Any]:
    """Rend les détections connues, la plus récente d'abord.

    Le nom de la route est `alerts`, comme le demandait le sujet, mais le vocabulaire
    employé dans les données est celui du moteur : « observation », « hypothèse »,
    « alerte ». Un niveau « alerte » n'est pas un incident confirmé — c'est un faisceau
    d'indices convergents, et le texte de chaque détection le dit.
    """
    detections = stockage.detections(limite=limite, niveau=niveau, session=session)
    return {
        "detections": detections,
        "affichees": len(detections),
        "par_niveau": stockage.statistiques().get("detections_par_niveau", {}),
        "seuils": SEUILS,
    }


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


@router.get("/flows/explications", summary="Toutes les explications d'une communication")
def explications_communication(
    stockage: Annotated[Stockage, Depends(obtenir_stockage)],
    cle: Annotated[str, Query(max_length=256, description="Clé de la communication")],
    session: Annotated[str | None, Query(max_length=64, description="Session, si la clé apparaît dans plusieurs")] = None,
    reformuler: Annotated[bool, Query(description="Confier la reformulation à la couche IA si elle est active")] = False,
) -> dict[str, Any]:
    """Rend le détail complet d'une communication : faits observés, interprétation, confiance.

    La clé est passée en paramètre plutôt que dans le chemin : elle contient des caractères
    qui n'ont pas leur place dans une adresse (le séparateur « | », les deux-points des
    ports). La placer dans l'URL obligerait à l'encoder, puis à la décoder — une source de
    bogues pour aucun bénéfice.

    Le paramètre `reformuler` est explicite et vaut « faux » par défaut : confier une
    explication à un service externe se demande, cela ne se subit pas.
    """
    communication = stockage.communication(cle, session)
    if communication is None:
        raise HTTPException(status_code=404, detail="Communication inconnue")

    explications = moteur_explication.explications(communication)
    if reformuler and llm.disponible():
        explications = [llm.reformuler(explication) for explication in explications]

    return {
        "communication": communication,
        "explications": explications,
        "principale": explications[0] if explications else None,
        "couche_ia": llm.etat(),
    }


@router.get("/health", summary="État du service — Health")
def sante() -> dict[str, Any]:
    """Contrôle de disponibilité, utilisé par les hébergeurs et les scripts.

    Sans jeton et sans données : il doit répondre même quand tout le reste va mal, sinon
    il ne sert à rien.
    """
    from backend.config import configuration

    return {
        "etat": "ok",
        "environnement": configuration.env,
        # L'état de la couche IA figure ici, et non dans une route séparée : c'est une
        # information d'état du service, et l'interface la lit déjà à cet endroit.
        "couche_ia": llm.etat(),
        "base_de_connaissances": {"services": moteur_explication.services_connus()},
    }
