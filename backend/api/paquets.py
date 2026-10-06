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

import datetime as dt
import io
import zipfile

from fastapi import APIRouter, Depends, HTTPException, Query, Response
from pydantic import BaseModel

from backend.securite import verifier_jeton

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

from backend import export as mod_export
from backend import filtres as mod_filtres
from backend import noms as mod_noms
from backend import recit as mod_recit
from backend import profils as mod_profils
from backend import statistiques as mod_statistiques

#: L'analyse des anomalies vit avec l'agent, qui voit passer les paquets. Le backend ne doit
#: pas dépendre de ce dossier : un déploiement peut les séparer — et c'est le cas prévu par
#: `docs/DEPLOIEMENT.md`. L'import est donc défensif, et la route le dit quand il échoue.
try:
    from agent import anomalies as mod_anomalies
except ImportError:                                      # pragma: no cover
    mod_anomalies = None
from backend import filtres_sql as mod_filtres_sql
from backend.dependances import obtenir_enrichissement, obtenir_stockage
from backend.enrichment import Enrichissement
from backend.explain import couches as mod_couches
from backend.explain import llm
from backend.explain import rules as moteur_explication
from backend.storage import Stockage

router = APIRouter(tags=["lecture"])


#: Index des noms de domaine, partagé par les routes et gardé quelques secondes.
#: Le reconstruire à chaque rafraîchissement — toutes les trois secondes — ferait relire
#: des milliers de paquets pour retrouver les mêmes noms.
_cache_noms = mod_noms.CacheNoms()


def noms_connus(stockage: Stockage) -> dict:
    """Rend l'association adresse → nom, construite depuis les réponses DNS conservées."""
    return _cache_noms.obtenir(lambda: stockage.paquets(limite=mod_noms.PAQUETS_RELUS))


def criteres_du_filtre(filtre: str | None, table: str) -> tuple[list, list[str]]:
    """Traduit un filtre d'affichage pour une vue précise.

    Rend les critères applicables, et la liste des champs écartés parce qu'ils ne
    concernent pas cette vue. Un champ écarté est **annoncé**, jamais tu : l'interface le
    réaffiche, et l'utilisateur sait ce qui n'a pas été filtré.

    Une expression incomprise est refusée par un **400** — pas un 500, et surtout pas un
    résultat vide. Le message énumère les champs valides, ce qui permet de corriger sans
    consulter la documentation.
    """
    try:
        criteres = mod_filtres.analyser(filtre)
    except mod_filtres.ErreurFiltre as erreur:
        raise HTTPException(status_code=400, detail=str(erreur)) from erreur

    applicables, ignorees = mod_filtres_sql.separer(criteres, table)
    return applicables, [critere.champ for critere in ignorees]


@router.get("/packets", summary="Derniers paquets capturés")
def lister_paquets(
    stockage: Annotated[Stockage, Depends(obtenir_stockage)],
    limite: Annotated[int, Query(ge=1, le=1000, description="Nombre de paquets à rendre")] = 100,
    protocole: Annotated[str | None, Query(max_length=32, description="Filtre : TCP, UDP, DNS…")] = None,
    session: Annotated[str | None, Query(max_length=64, description="Identifiant de session")] = None,
    recherche: Annotated[str | None, Query(max_length=64, description="Recherche libre (IP, domaine, port)")] = None,
    filtre: Annotated[str | None, Query(max_length=300,
        description="Filtre d'affichage : proto:tcp port:443 ip:192.168.1.")] = None,
) -> dict[str, Any]:
    """Rend les paquets les plus récents d'abord.

    Les bornes de `Query` ne sont pas décoratives : sans elles, `?limite=100000000`
    demanderait au serveur de préparer une réponse énorme, pour rien.
    """
    criteres, ignores = criteres_du_filtre(filtre, "paquets")
    paquets = stockage.paquets(limite=limite, protocole=protocole,
                               session=session, recherche=recherche, filtre=criteres)
    return {
        "paquets": paquets,
        "affiches": len(paquets),
        "statistiques": stockage.statistiques(),
        "filtre_ignores": ignores,
    }


@router.get("/flows", summary="Communications (Connections)")
def lister_communications(
    stockage: Annotated[Stockage, Depends(obtenir_stockage)],
    limite: Annotated[int, Query(ge=1, le=1000)] = 100,
    etat: Annotated[str | None, Query(max_length=32, description="tentative, établie, fermée…")] = None,
    protocole: Annotated[str | None, Query(max_length=32)] = None,
    session: Annotated[str | None, Query(max_length=64, description="Identifiant de session")] = None,
    recherche: Annotated[str | None, Query(max_length=64, description="IP, port, état")] = None,
    filtre: Annotated[str | None, Query(max_length=300,
        description="Filtre d'affichage : proto:tcp port:443 etat:établie")] = None,
) -> dict[str, Any]:
    """Communications regroupées, la plus récente d'abord.

    Chaque communication porte `etat` et `etat_certain`. Ce second champ doit être
    affiché, pas seulement stocké : une communication vue en cours de route ne peut pas
    être présentée avec la même assurance qu'une ouverture observée en entier.
    """
    noms = noms_connus(stockage)
    criteres, ignores = criteres_du_filtre(filtre, "communications")
    communications = stockage.communications(limite=limite, etat=etat, protocole=protocole,
                                             session=session, recherche=recherche,
                                             filtre=criteres)

    # Chaque extrémité reçoit le nom que le DNS lui a donné, **en plus** de son adresse.
    # L'adresse n'est jamais retirée : le nom est une commodité, l'adresse est le fait, et
    # masquer l'adresse rendrait impossible la vérification de ce qui a été observé.
    communications = [mod_noms.nommer(communication, noms) for communication in communications]

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
            "statistiques": stockage.statistiques(),
            # Les critères qui ne concernent pas cette vue. L'interface les réaffiche :
            # un filtre partiellement appliqué doit se voir, pas se deviner.
            "filtre_ignores": ignores}


@router.get("/enrichment", summary="Contexte externe d'une adresse IP")
def enrichir_adresse(
    enrichissement: Annotated[Enrichissement, Depends(obtenir_enrichissement)],
    ip: Annotated[str, Query(min_length=2, max_length=45, description="Adresse à situer")],
) -> dict[str, Any]:
    """Rend la situation géographique et la réputation d'une adresse, si elles sont connues.

    Deux choses que cette route ne fait pas, et qui comptent :

    Elle n'enrichit **jamais une adresse privée**. Les adresses de votre réseau local ne
    sortent pas sur Internet : aucun service tiers ne peut rien en dire, et les
    interroger reviendrait à publier la topologie de votre réseau. La réponse le dit
    explicitement plutôt que de renvoyer une erreur.

    Elle ne bloque **jamais**. Si le quota est atteint ou si le service ne répond pas,
    la réponse arrive quand même, avec la raison. Le tableau de bord n'attend pas après
    un service externe pour s'afficher.
    """
    if not enrichissement.disponible():
        return {
            "ip": ip, "enrichi": False,
            "raison": "Enrichissement inactif : aucune clé configurée.",
            "configuration": enrichissement.etat(),
        }

    resultat = enrichissement.enrichir(ip)
    return {
        "ip": ip,
        "enrichi": resultat is not None and not resultat.get("en_attente"),
        "donnees": resultat or {},
        "resume": Enrichissement.resume(resultat),
        "avertissement": ("Données fournies par des tiers, à un instant donné. Un score de "
                          "réputation n'est pas une preuve : c'est l'avis d'un service, "
                          "et il peut être faux."),
    }


@router.get("/alerts", summary="Détections de comportements inhabituels")
def lister_detections(
    stockage: Annotated[Stockage, Depends(obtenir_stockage)],
    limite: Annotated[int, Query(ge=1, le=500, description="Nombre de détections à rendre")] = 100,
    niveau: Annotated[str | None, Query(pattern="^(observation|hypothèse|alerte)$",
                                        description="Filtre par niveau de certitude")] = None,
    session: Annotated[str | None, Query(max_length=64)] = None,
    filtre: Annotated[str | None, Query(max_length=300,
        description="Filtre d'affichage : niveau:hypothèse ip:192.168.1.")] = None,
) -> dict[str, Any]:
    """Rend les détections connues, la plus récente d'abord.

    Le nom de la route est `alerts`, comme le demandait le sujet, mais le vocabulaire
    employé dans les données est celui du moteur : « observation », « hypothèse »,
    « alerte ». Un niveau « alerte » n'est pas un incident confirmé — c'est un faisceau
    d'indices convergents, et le texte de chaque détection le dit.
    """
    criteres, ignores = criteres_du_filtre(filtre, "detections")
    detections = stockage.detections(limite=limite, niveau=niveau, session=session,
                                     filtre=criteres)
    return {
        "detections": detections,
        "affichees": len(detections),
        "par_niveau": stockage.statistiques().get("detections_par_niveau", {}),
        "seuils": SEUILS,
        "filtre_ignores": ignores,
    }


@router.get("/layers", summary="Les couches réseau et leur rôle")
def couches_reseau() -> dict[str, Any]:
    """Rend la description des couches, pour la vue détaillée d'un paquet.

    La connaissance reste ici, côté serveur : l'interface l'interroge une fois et la
    réutilise. La placer dans le JavaScript aurait mis du savoir métier dans un fichier
    que personne ne relit, et l'aurait rendu indiffusable à un autre client de l'API.
    """
    return mod_couches.description()


@router.get("/export", summary="Exporter une vue en CSV ou JSON")
def exporter(
    stockage: Annotated[Stockage, Depends(obtenir_stockage)],
    quoi: Annotated[str, Query(pattern="^(paquets|communications|detections)$",
                               description="Ce qu'on exporte")] = "communications",
    format: Annotated[str, Query(pattern="^(csv|json)$",
                                 description="Format du fichier")] = "csv",
    limite: Annotated[int, Query(ge=1, le=5000)] = 5000,
    filtre: Annotated[str | None, Query(max_length=300)] = None,
) -> Response:
    """Rend les données affichées sous forme de fichier téléchargeable.

    Ce qui sort est exactement ce que le tableau de bord montre : des métadonnées. Aucun
    contenu de message n'est conservé par l'outil, donc aucun ne peut être exporté — la
    règle du projet vaut aussi pour les fichiers qu'il produit.

    Le filtre d'affichage s'applique : on exporte ce que l'on voit, et non tout ce qui
    existe. Exporter davantage que ce qui est affiché serait une surprise désagréable.
    """
    criteres, _ignores = criteres_du_filtre(filtre, quoi)

    if quoi == "paquets":
        lignes = stockage.paquets(limite=limite, filtre=criteres)
    elif quoi == "communications":
        lignes = stockage.communications(limite=limite, filtre=criteres)
    else:
        lignes = stockage.detections(limite=limite, filtre=criteres)

    maintenant = dt.datetime.now(dt.timezone.utc).isoformat()
    nom = mod_export.nom_de_fichier(quoi, format, maintenant)

    if format == "json":
        contenu = mod_export.vers_json(lignes, quoi)
        type_media = "application/json"
    else:
        contenu = mod_export.vers_csv(lignes, quoi)
        type_media = "text/csv"

    return Response(
        content=contenu,
        media_type=f"{type_media}; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{nom}"'},
    )


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


@router.get("/profils", summary="Profils d'analyse enregistrés")
def lister_profils() -> dict[str, Any]:
    """Rend les profils disponibles : un nom, un filtre, une phrase qui dit à quoi il sert."""
    profils = mod_profils.charger()
    return {"profils": profils, "total": len(profils)}


@router.post("/profils", summary="Enregistrer un profil d'analyse")
def enregistrer_profil(
    profil: dict[str, Any],
    _jeton: Annotated[None, Depends(verifier_jeton)],
) -> dict[str, Any]:
    """Ajoute ou remplace un profil. **Écriture : jeton exigé.**

    Le filtre est validé à l'enregistrement, par le même parseur que celui qui l'appliquera.
    Un profil ne peut donc pas être enregistré avec une expression que l'application
    refusera plus tard : l'erreur est refusée maintenant, quand celui qui la commet est
    encore devant l'écran.
    """
    try:
        profils = mod_profils.enregistrer(profil)
    except mod_profils.ProfilInvalide as erreur:
        raise HTTPException(status_code=400, detail=str(erreur)) from erreur
    return {"profils": profils, "total": len(profils)}


@router.delete("/profils/{nom}", summary="Supprimer un profil d'analyse")
def supprimer_profil(
    nom: str,
    _jeton: Annotated[None, Depends(verifier_jeton)],
) -> dict[str, Any]:
    """Retire un profil. Supprimer un nom absent n'est pas une erreur : le résultat voulu est
    atteint."""
    profils = mod_profils.supprimer(nom)
    return {"profils": profils, "total": len(profils)}


@router.get("/statistiques", summary="Répartitions, extrémités et débit")
def statistiques_detaillees(
    stockage: Annotated[Stockage, Depends(obtenir_stockage)],
    limite: Annotated[int, Query(ge=1, le=3000, description="Paquets relus")] = 3000,
) -> dict[str, Any]:
    """Répartition par protocole en pourcentages, classement des machines, débit dans le temps.

    Les pourcentages portent toujours leur **total** : « 62 % de TCP » ne veut rien dire si
    l'on ignore ce que font les 38 % restants. Et les paquets d'analyse partielle sont
    comptés à part, jamais fondus dans un protocole connu — leur classer une famille serait
    inventer ce que le parseur n'a pas su lire.
    """
    return mod_statistiques.ensemble(stockage.paquets(limite=limite))


@router.get("/anomalies", summary="Expert Info — ce qui sort de l'ordinaire")
def lister_anomalies(
    stockage: Annotated[Stockage, Depends(obtenir_stockage)],
    limite: Annotated[int, Query(ge=1, le=mod_anomalies.PAQUETS_ANALYSES if mod_anomalies else 3000)] = 3000,
) -> dict[str, Any]:
    """Rend les anomalies TCP observées dans les paquets conservés.

    Une anomalie est un **fait mesuré** — « ce numéro de séquence a été envoyé deux fois » —
    jamais une conclusion. Ce n'est pas un détail de rédaction : une retransmission signale
    presque toujours un réseau lent, pas une attaque, et la présenter comme une menace
    rendrait l'outil inutilisable en pratique. Le niveau rendu est donc `observation`, et
    aucune anomalie isolée ne produit une alerte.
    """
    if mod_anomalies is None:
        # Le backend ne dépend pas du dossier de l'agent : l'analyse vit avec la capture.
        # On le dit, plutôt que de rendre une liste vide qu'on croirait être une absence
        # d'anomalie.
        return {
            "disponible": False,
            "paquets_examines": 0, "total": 0, "comptes": {}, "anomalies": [],
            "niveau": "observation",
            "note": "L'analyse des anomalies n'est pas disponible dans ce déploiement "
                    "(module agent/anomalies.py absent). Une liste vide ici ne veut pas "
                    "dire « rien d'anormal ».",
        }

    paquets = stockage.paquets(limite=limite)
    resultat = mod_anomalies.analyser(paquets)
    resultat["disponible"] = True
    return resultat


@router.get("/flows/recit", summary="Récit d'une communication, en langage humain")
def recit_communication(
    stockage: Annotated[Stockage, Depends(obtenir_stockage)],
    cle: Annotated[str, Query(max_length=256, description="Clé de la communication")],
    session: Annotated[str | None, Query(max_length=64, description="Session, si la clé apparaît dans plusieurs")] = None,
) -> dict[str, Any]:
    """Raconte une conversation : sa chronologie, puis son récit.

    La chronologie ne retient que les **événements** — ouverture, acceptation, fermeture,
    rupture. Quarante échanges de données ne racontent rien de plus que le premier ; les
    compter, si.

    Chaque phrase du récit porte son genre, `fait` ou `lecture`. C'est la règle du projet
    appliquée à la phrase : un lecteur doit pouvoir dire, à chaque ligne, ce qui a été
    observé et ce qui a été interprété.
    """
    communication = stockage.communication(cle, session)
    if communication is None:
        raise HTTPException(status_code=404, detail="Communication inconnue")

    # Les paquets de cette conversation : le couple (adresse, port) des deux extrémités doit
    # correspondre, dans un sens ou dans l'autre. On lit une fenêtre bornée — la même que
    # celle de l'index des noms — pour ne pas relire toute la base à chaque demande.
    extremites = {
        (communication.get("ip_a"), communication.get("port_a")),
        (communication.get("ip_b"), communication.get("port_b")),
    }
    paquets = []
    for paquet in stockage.paquets(limite=mod_noms.PAQUETS_RELUS):
        if (paquet.get("ip_source"), paquet.get("port_source")) not in extremites:
            continue
        if (paquet.get("ip_destination"), paquet.get("port_destination")) not in extremites:
            continue
        paquets.append(paquet)

    moments = mod_recit.chronologie(paquets)
    nommee = mod_noms.nommer(communication, noms_connus(stockage))

    return {
        "communication": nommee,
        "moments": moments,
        "recit": mod_recit.raconter(nommee, moments),
        "paquets_analyses": len(paquets),
    }


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
        "enrichissement": obtenir_enrichissement().etat(),
        "stockage": _diagnostic_stockage(),
    }


def _diagnostic_stockage() -> dict[str, Any]:
    """Dit QUEL stockage est actif et si la base repond — jamais avec quoi on s'y connecte.

    Cette fonction existe parce qu'un tableau de bord en ligne renvoyait une erreur 500 sans
    donner la moindre piste : la lecture echouait, l'ecriture aussi, et rien n'indiquait si le
    probleme venait du code, du reseau ou de la configuration. Une page d'erreur qui ne dit rien
    oblige a deviner, et deviner coute plus cher que mesurer.

    CE QU'ELLE N'EXPOSE PAS, ET C'EST DELIBERE : ni l'adresse du serveur, ni le nom d'utilisateur,
    ni le mot de passe. Ces trois choses ne regardent personne — pas meme un diagnostic. Seuls
    le TYPE de stockage et la raison de l'echec sont publies, dans la limite de ce qui aide.

    ELLE NE DOIT JAMAIS FAIRE ECHOUER LA ROUTE QUI L'APPELLE : /health est la route qu'on
    interroge quand tout va mal. Si elle tombait avec la base, elle ne servirait a rien.
    """
    import re as _re

    try:
        depot = obtenir_stockage()
        depot.statistiques()
        return {"type": type(depot).__name__, "joignable": True}
    except Exception as erreur:                      # noqa: BLE001 - on veut TOUT attraper
        detail = f"{type(erreur).__name__} : {erreur}"
        # Defense en profondeur : meme si une bibliotheque ecrivait la chaine de connexion
        # dans son message, on la masque avant de la publier.
        detail = _re.sub(r"://[^@\s]+@", "://<identifiants masques>@", detail)
        return {"type": "inconnu", "joignable": False, "erreur": detail[:220]}

class DemandeExportCouche(BaseModel):
    """Ce que l'interface envoie pour telecharger l'explication d'une couche.

    L'interface n'envoie PAS la description de la couche : seulement sa cle. La connaissance
    reste au serveur, et le fichier produit ne peut donc pas contenir autre chose que ce que
    le serveur sait. Un client qui enverrait sa propre description pourrait faire ecrire
    n'importe quoi dans un document presente comme celui de FlowScope.
    """

    cle: str
    valeurs: dict[str, Any] = {}
    formats: list[str] = ["txt"]


@router.post("/layers/export", summary="Telecharger l'explication d'une couche")
def exporter_couche(demande: DemandeExportCouche) -> Response:
    """Rend l'explication d'une couche en fichier, dans les formats demandes.

    Un seul format demande : on rend le fichier lui-meme, avec son type et son nom. Plusieurs
    formats : on rend une archive ZIP qui les contient tous, parce qu'un navigateur qui recoit
    quatre fichiers d'un coup en bloque trois et l'utilisateur ne comprend pas pourquoi. Un
    fichier unique est toujours ce qui arrive le mieux.

    Un format inconnu est REFUSE (400), jamais ignore en silence : l'utilisateur qui coche une
    case doit obtenir le fichier correspondant, ou savoir pourquoi il ne l'obtient pas.
    """
    formats_connus = ("pdf", "json", "csv", "txt")
    demandes = [f for f in (demande.formats or ["txt"]) if f]
    if not demandes:
        raise HTTPException(status_code=400, detail="Aucun format demande.")
    inconnus = [f for f in demandes if f not in formats_connus]
    if inconnus:
        raise HTTPException(
            status_code=400,
            detail=f"Format inconnu : {', '.join(inconnus)}. "
                   f"Formats acceptes : {', '.join(formats_connus)}.")

    couche = next((c for c in mod_couches.description().get("couches", [])
                   if c.get("cle") == demande.cle), None)
    if couche is None:
        raise HTTPException(status_code=404, detail=f"Couche inconnue : {demande.cle}")

    horodatage = dt.datetime.now().strftime("%d/%m/%Y %H:%M")
    horodatage_fichier = dt.datetime.now().strftime("%Y%m%d-%H%M%S")
    produit: dict[str, bytes] = {}
    for format_ in demandes:
        if format_ == "pdf":
            produit["pdf"] = mod_export.vers_pdf_couche(couche, demande.valeurs, horodatage)
        elif format_ == "txt":
            produit["txt"] = mod_export.vers_texte_couche(
                couche, demande.valeurs, horodatage).encode("utf-8")
        elif format_ == "json":
            produit["json"] = mod_export.vers_json(
                [{"couche": couche, "valeurs": demande.valeurs}],
                f"couche-{demande.cle}").encode("utf-8")
        else:
            produit["csv"] = mod_export.vers_csv_couche(
                couche, demande.valeurs).encode("utf-8")

    types = {"pdf": "application/pdf", "json": "application/json",
             "csv": "text/csv; charset=utf-8", "txt": "text/plain; charset=utf-8"}

    if len(produit) == 1:
        format_, contenu = next(iter(produit.items()))
        nom = mod_export.nom_de_fichier(f"couche-{demande.cle}", format_, horodatage_fichier)
        return Response(content=contenu, media_type=types[format_], headers={
            "Content-Disposition": f'attachment; filename="{nom}"'})

    tampon = io.BytesIO()
    with zipfile.ZipFile(tampon, "w", zipfile.ZIP_DEFLATED) as archive:
        for format_, contenu in sorted(produit.items()):
            nom = mod_export.nom_de_fichier(f"couche-{demande.cle}", format_, horodatage_fichier)
            archive.writestr(nom, contenu)
    nom = mod_export.nom_de_fichier(f"couche-{demande.cle}", "zip", horodatage_fichier)
    return Response(content=tampon.getvalue(), media_type="application/zip", headers={
        "Content-Disposition": f'attachment; filename="{nom}"'})

