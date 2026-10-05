"""Application FastAPI : assemblage, pages, et traitement des erreurs.

Ce fichier ne contient aucune règle métier. Il relie les pièces : les routes, les
gabarits, la politique de sécurité des échanges entre navigateur et serveur.

Ce qui est visible par un utilisateur en cas de panne
-----------------------------------------------------
Une trace technique (« Traceback (most recent call last)… ») n'apprend rien à qui la lit,
et révèle au passage la structure du code, les chemins de fichiers et parfois les données.
Elle part donc dans le journal, et l'utilisateur reçoit une phrase qui dit ce qui s'est
passé et ce qu'il peut faire.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any

# `python backend/main.py` met le dossier « backend » en tête des chemins d'import, et
# `backend` n'est alors plus trouvable. On rétablit la racine du dépôt : les deux
# lancements — direct et `python -m backend.main` — fonctionnent, et personne ne perd
# dix minutes sur un message d'erreur incompréhensible.
RACINE_DEPOT = Path(__file__).resolve().parent.parent
if str(RACINE_DEPOT) not in sys.path:
    sys.path.insert(0, str(RACINE_DEPOT))

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from backend.api import ingestion, paquets
from backend.config import configuration

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("backend")

DOSSIER_WEB = RACINE_DEPOT / "web"

gabarits = Jinja2Templates(directory=str(DOSSIER_WEB / "templates"))

application = FastAPI(
    title="Intelligent Network Packet Analyzer",
    description=(
        "Reçoit les paquets analysés par l'agent local, les conserve et les présente.\n\n"
        "L'écriture (`/api/v1/ingest`) exige un jeton d'agent ; la lecture est publique."
    ),
    version="0.1.0",
)


def _origines_cors() -> list[str]:
    """Origines autorisées à appeler l'API depuis un navigateur.

    Le tableau de bord est servi par ce même serveur : aucune origine externe n'a besoin
    d'appeler l'API. Une liste vide signifie donc « personne », et non « tout le monde » —
    mettre `["*"]` ouvrirait l'API à n'importe quel site web visité par l'utilisateur.
    """
    return configuration.origines_cors


application.add_middleware(
    CORSMiddleware,
    allow_origins=_origines_cors(),
    allow_credentials=False,     # aucun cookie d'authentification : rien à transmettre
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-Agent-Token"],
)

application.include_router(ingestion.router, prefix="/api/v1")
application.include_router(paquets.router, prefix="/api/v1")

application.mount("/static", StaticFiles(directory=str(DOSSIER_WEB / "static")), name="static")


# --------------------------------------------------------------------------- #
#  Pages
# --------------------------------------------------------------------------- #
@application.get("/", response_class=HTMLResponse, include_in_schema=False)
def tableau_de_bord(request: Request):
    """Page principale : rendue avec les données du moment, puis rafraîchie par le
    navigateur. Le premier affichage est donc immédiat, sans attendre un aller-retour."""
    from backend.dependances import obtenir_stockage

    stockage = obtenir_stockage()
    return gabarits.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "statistiques": stockage.statistiques(),
            "paquets": stockage.paquets(limite=50),
            "sessions": stockage.sessions()[:10],
            "environnement": configuration.env,
        },
    )


# --------------------------------------------------------------------------- #
#  Erreurs
# --------------------------------------------------------------------------- #
def _veut_du_json(request: Request) -> bool:
    """Le demandeur attend-il du JSON ou une page ?

    Un appel d'API veut du JSON ; un navigateur veut une page lisible. Répondre du JSON à
    un navigateur afficherait `{"detail":"..."}` en texte brut — compréhensible pour un
    développeur, pas pour un utilisateur.
    """
    accepte = (request.headers.get("accept") or "").lower()
    return "application/json" in accepte and "text/html" not in accepte


@application.exception_handler(Exception)
async def erreur_inattendue(request: Request, exc: Exception) -> Any:
    """Filet de sécurité : aucune trace technique ne sort du serveur."""
    logger.exception("Erreur inattendue sur %s %s", request.method, request.url.path)
    message = ("Le serveur a rencontré un problème inattendu. "
               "Les détails sont dans le journal du serveur.")
    if _veut_du_json(request):
        return JSONResponse(status_code=500, content={"detail": message})
    return gabarits.TemplateResponse(
        request=request,
        name="erreur.html",
        context={"code": 500, "titre": "Erreur du serveur", "message": message},
        status_code=500,
    )


@application.exception_handler(404)
async def page_introuvable(request: Request, exc: Exception) -> Any:
    """Adresse inconnue : une page qui explique, plutôt qu'un JSON brut."""
    message = "Cette adresse n'existe pas sur ce serveur."
    if _veut_du_json(request):
        return JSONResponse(status_code=404, content={"detail": message})
    return gabarits.TemplateResponse(
        request=request,
        name="erreur.html",
        context={"code": 404, "titre": "Page introuvable",
                 "message": message + " Vérifiez l'adresse, ou revenez au tableau de bord."},
        status_code=404,
    )


def afficher_demarrage() -> None:
    """Résumé du démarrage : ce qui est utile pour comprendre pourquoi ça ne marche pas."""
    logger.info("Backend démarré — environnement « %s »", configuration.env)
    logger.info("  écoute          : http://%s:%d", configuration.hote, configuration.port)
    logger.info("  jeton d'agent   : %s", "défini" if configuration.jeton_agent else "ABSENT")
    logger.info("  tampon mémoire  : %d paquets", configuration.taille_memoire)
    logger.info("  origines CORS   : %s",
                ", ".join(configuration.origines_cors) or "aucune")
    if not configuration.en_production:
        logger.info("  Pour l'agent    : --backend http://%s:%d --jeton <%s>",
                    configuration.hote, configuration.port, "voir ci-dessus")


if __name__ == "__main__":                          # pragma: no cover
    import uvicorn

    afficher_demarrage()
    uvicorn.run(application, host=configuration.hote, port=configuration.port,
                log_level="info")
