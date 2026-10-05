"""Pilotage de la capture et flux en direct.

Toutes les écritures demandent le jeton, comme l'ingestion : **n'importe qui peut lire,
personne ne peut lancer une capture sur cette machine sans y être autorisé**. Le flux, lui,
est en lecture — il diffuse ce qui a déjà été accepté.
"""

from __future__ import annotations

from typing import Annotated, Any

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import StreamingResponse

from backend import pilotage

router = APIRouter(tags=["capture"])

#: Un lancement de capture n'est accepté que depuis la machine qui l'exécute.
LOCALES = {"127.0.0.1", "::1", "localhost", "::ffff:127.0.0.1"}


def depuis_la_machine(request: Request) -> None:
    """Refuse un lancement de capture venant d'ailleurs que du poste lui-même.

    **Pourquoi pas le jeton d'agent, comme pour l'ingestion ?** Parce que le bouton est dans
    le navigateur : lui faire porter le jeton obligerait à l'écrire dans la page, donc à
    l'exposer — et un secret exposé cesse d'être un secret. La règle retenue est plus juste :
    la capture a lieu **sur cette machine**, donc seul quelqu'un devant cette machine peut la
    lancer. Depuis le réseau, elle reste impossible.
    """
    hote = request.client.host if request.client else ""
    if hote not in LOCALES:
        raise HTTPException(
            status_code=403,
            detail="Une capture ne peut être lancée que depuis la machine qui la réalise.",
        )


@router.get("/interfaces", summary="Interfaces réseau réellement présentes")
def interfaces() -> dict[str, Any]:
    """Les interfaces sur lesquelles une capture peut être lancée.

    La liste vient du système, jamais d'un fichier écrit à la main : proposer une interface
    absente ferait échouer la capture au fond d'un journal.
    """
    disponibles = pilotage.lister_interfaces()
    return {"interfaces": disponibles, "total": len(disponibles)}


@router.get("/capture/etat", summary="État de la capture")
def etat_capture() -> dict[str, Any]:
    """Dit si une capture est en cours, sur quelle interface, depuis combien de temps.

    Le journal de l'agent accompagne l'état : c'est là qu'apparaît un refus de capture —
    droits insuffisants, interface occupée — et le cacher ferait chercher longtemps.
    """
    etat = pilotage.pilote.etat()
    etat["jeton_configure"] = bool(__import__("os").environ.get("ANALYZER_AGENT_TOKEN", "").strip())
    return etat


@router.post("/capture/demarrer", summary="Démarrer une capture")
def demarrer_capture(
    request: Request,
    interface: Annotated[str, Query(max_length=64, description="Nom de l'interface")],
    filtre: Annotated[str, Query(max_length=200, description="Filtre de capture BPF, optionnel")] = "",
    nom: Annotated[str, Query(max_length=60, description="Nom de la session")] = "",
) -> dict[str, Any]:
    """Lance l'agent de capture **sur la machine du serveur**.

    Le filtre, s'il est fourni, est validé par l'agent avant le démarrage de la capture :
    un filtre de capture masque définitivement ce qu'il exclut, contrairement au filtre
    d'affichage.
    """
    depuis_la_machine(request)
    try:
        etat = pilotage.pilote.demarrer(interface, filtre, nom)
    except pilotage.ErreurPilotage as erreur:
        raise HTTPException(status_code=400, detail=str(erreur)) from erreur
    return etat


@router.post("/capture/arreter", summary="Arrêter une capture")
def arreter_capture(request: Request) -> dict[str, Any]:
    """Arrête la capture en cours. **Ce qui a été capturé reste** : c'est l'historique."""
    depuis_la_machine(request)
    return pilotage.pilote.arreter()


@router.get("/live", summary="Flux des paquets en direct")
def flux_live() -> StreamingResponse:
    """Diffuse chaque paquet au moment où il est accepté.

    Sans ce flux, la page interroge le serveur toutes les trois secondes : le trafic
    apparaît par vagues, et un paquet peut défiler avant qu'on ait pu cliquer dessus.

    Chaque navigateur reçoit **sa propre copie** : un onglet resté ouvert ne retarde pas les
    autres. Au-delà de cinq cents paquets non lus, les plus anciens sont écartés — une liste
    vivante décrit ce qui arrive, pas ce qui est arrivé.
    """
    file_ = pilotage.diffusion.abonner()

    def generer():
        try:
            yield from pilotage.evenements(file_)
        finally:
            # Toujours se retirer, y compris si la connexion est coupée : sinon la file
            # resterait à alimenter pour personne.
            pilotage.diffusion.desabonner(file_)

    return StreamingResponse(generer(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})
