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
import threading
import time
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

import atexit
import hashlib
from pathlib import Path

from backend import pilotage
from backend.api import capture, ingestion, paquets
from backend.config import configuration

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s  %(levelname)-7s %(name)s  %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("backend")

DOSSIER_WEB = RACINE_DEPOT / "web"

gabarits = Jinja2Templates(directory=str(DOSSIER_WEB / "templates"))

def version_statique() -> str:
    """Empreinte des fichiers statiques, calculée une fois au démarrage.

    **Sans elle, le navigateur ne redemande jamais la feuille de style.** Servie sans numéro
    de version, elle reste en cache — chez l'auteur comme chez le visiteur — et un changement
    de thème n'atteint personne. Le symptôme est trompeur : le fichier est bien modifié sur le
    disque, le serveur le sert bien, et l'écran ne bouge pas.

    L'empreinte mêle les noms et les dates de modification : la moindre retouche d'un fichier
    change l'adresse, donc force la relecture. Les autres fichiers ne changent pas d'adresse,
    donc ils restent en cache — c'est le but.
    """
    racine = Path(__file__).resolve().parent.parent / "web" / "static"
    empreinte = hashlib.sha256()
    try:
        for fichier in sorted(racine.rglob("*")):
            if fichier.is_file():
                empreinte.update(fichier.name.encode("utf-8"))
                empreinte.update(str(fichier.stat().st_mtime_ns).encode("ascii"))
    except OSError:
        # Un dossier illisible ne doit pas empêcher le serveur de démarrer : on rend une
        # empreinte neutre, et le cache reprend son cours.
        return "0"
    return empreinte.hexdigest()[:10]


# L'empreinte est posée comme fonction globale des gabarits : chaque modèle peut l'appeler
# sans qu'on ait à l'ajouter à chacun des contextes de rendu, et un modèle ajouté demain
# l'aura sans que personne n'y pense.
gabarits.env.globals["version_statique"] = version_statique


application = FastAPI(
    title="FlowScope — Network Traffic Analyzer",
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
application.include_router(capture.router, prefix="/api/v1")

# À l'extinction du serveur, la capture lancée depuis l'interface est arrêtée. Sans cela,
# l'agent survivrait au serveur : il garderait son interface réseau ouverte et continuerait
# d'envoyer des paquets à un service disparu — un orphelin qu'on ne retrouve que par le
# gestionnaire de tâches.
# `atexit` plutôt qu'un événement de cycle de vie : cette version de FastAPI ne l'expose
# plus, et un agent orphelin est exactement le piège qu'on veut éviter ici. Il ne se déclenche
# pas sur un arrêt brutal — c'est écrit dans les limites du README.
atexit.register(pilotage.pilote.arreter_si_besoin)

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


def lancer_purge_periodique(intervalle_heures: float = 24.0) -> threading.Thread | None:
    """Supprime périodiquement les sessions plus anciennes que la durée de conservation.

    Rien à faire tant que le stockage est en mémoire : la question ne se pose pas, tout
    disparaît à l'arrêt. Avec PostgreSQL, en revanche, une base qui ne se purge jamais
    grossit indéfiniment — et personne ne s'en aperçoit avant qu'elle ne coûte cher.

    Le fil est un démon : il ne retient pas l'arrêt du backend. Il attend d'abord un
    intervalle complet avant sa première exécution, pour ne pas lancer un `DELETE` global
    pendant que la base reçoit ses premières écritures.
    """
    from backend.config import configuration
    from backend.dependances import obtenir_stockage

    stockage = obtenir_stockage()
    if not hasattr(stockage, "purger"):
        # Stockage en mémoire : il n'y a rien à conserver, donc rien à supprimer.
        return None

    def boucle() -> None:
        while True:
            time.sleep(intervalle_heures * 3600)
            try:
                supprimees = stockage.purger(configuration.retention_jours)
                if supprimees:
                    logger.info("Purge automatique : %d session(s) de plus de %d jours",
                                supprimees, configuration.retention_jours)
            except Exception as erreur:                              # noqa: BLE001
                # Une purge qui échoue ne doit jamais arrêter le backend : elle sera
                # retentée au prochain tour. On le consigne et on continue.
                logger.warning("Purge automatique en échec (%s) — nouvelle tentative "
                               "dans %.0f h", type(erreur).__name__, intervalle_heures)

    fil = threading.Thread(target=boucle, name="purge-periodique", daemon=True)
    fil.start()
    logger.info("Purge automatique active : conservation de %d jours",
                configuration.retention_jours)
    return fil


class FiltreFermeturesBrutales(logging.Filter):
    """Tait une erreur de Windows — celle-là, et aucune autre.

    Quand un client ferme brutalement sa connexion (un navigateur qu'on rafraîchit, un
    script qui s'arrête), la boucle d'événements Windows signale parfois un
    ConnectionResetError pendant le nettoyage de la connexion — **après** que la réponse a
    été servie. La requête a réussi ; l'erreur ne concerne que le rangement derrière.

    Elle remplit le journal d'une trace alarmante alors que tout va bien, et un lecteur qui
    découvre le projet en conclut que l'application casse. On la tait donc.

    Deux conditions doivent être réunies : la fonction d'où vient l'erreur, et son type.
    Toute autre exception passe et reste visible — un filtre plus large masquerait de
    vraies pannes, ce qui serait pire que le bruit qu'on supprime.

    Un détail qui a son importance : asyncio annonce « Exception in callback … » sans
    jamais nommer l'erreur. Le nom de l'exception n'est pas dans le message, il est dans
    `exc_info`. Un filtre qui chercherait « ConnectionResetError » dans le texte ne
    filtrerait donc rien du tout — et c'est exactement ce que faisait la première version,
    ce qu'un test a montré.
    """

    def filter(self, enregistrement: logging.LogRecord) -> bool:
        message = enregistrement.getMessage()
        if "_call_connection_lost" not in message:
            return True

        erreur = enregistrement.exc_info[1] if enregistrement.exc_info else None
        if isinstance(erreur, ConnectionResetError):
            return False

        # Repli : certaines versions d'asyncio placent le nom de l'erreur dans le texte.
        return "ConnectionResetError" not in f"{message} {enregistrement.args}"


def apaiser_le_journal() -> None:
    """Applique le filtre au journal de la boucle d'événements."""
    logging.getLogger("asyncio").addFilter(FiltreFermeturesBrutales())


if __name__ == "__main__":                          # pragma: no cover
    import uvicorn

    afficher_demarrage()
    apaiser_le_journal()
    lancer_purge_periodique()
    uvicorn.run(application, host=configuration.hote, port=configuration.port,
        # DERRIERE UN REVERSE PROXY, ET C'EST LE CAS DE TOUT HEBERGEUR EN LIGNE : le TLS est
        # termine en amont, et la requete arrive ici en clair. Sans ces deux arguments,
        # l'application croit qu'on l'appelle en http et fabrique des liens en http - un
        # navigateur peut alors refuser de charger la feuille de style. Les en-tetes
        # X-Forwarded-* sont la seule source fiable de l'adresse reellement demandee.
        proxy_headers=True,
        forwarded_allow_ips="*",
                log_level="info")
