"""FlowScope en application de bureau : une fenetre native, sans navigateur.

CE FICHIER NE REMPLACE RIEN : il se contente de lancer l'application existante et de l'afficher
dans une fenetre Windows. `backend.main` reste la seule source du serveur, et le tableau de bord
reste le meme HTML. Une correction faite dans l'application profite donc aux deux modes.

DEUX DOSSIERS, ET C'EST LE PIEGE PRINCIPAL D'UN EXE GELE :

  - les RESSOURCES (gabarits HTML, feuille de style, JavaScript) sont livrees DANS l'executable.
    Windows les extrait dans un dossier temporaire a chaque lancement et le SUPPRIME en sortant.
    On les lit donc depuis `sys._MEIPASS`, et on ne leur ecrit jamais rien.

  - l'ETAT (le fichier .env, avec l'adresse de la base et le jeton) appartient a l'utilisateur. Il
    vit dans %LOCALAPPDATA%\FlowScope, donc il survit a la fermeture. Le placer a cote de
    l'executable aurait paru plus simple mais casse des qu'on deplace le dossier ; le placer dans
    le dossier temporaire l'aurait efface a chaque fois.
"""

from __future__ import annotations

import os
import socket
import sys
import threading
import time
from pathlib import Path

NOM_APPLICATION = "FlowScope"
LARGEUR, HAUTEUR = 1280, 860


def activer_conscience_dpi() -> None:
    """Un exe fenetre sans ce reglage est etire par Windows : le contenu deborde de la fenetre.

    L'appel doit avoir lieu AVANT de creer la moindre fenetre, sinon il n'a plus d'effet.
    """
    import ctypes

    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
        return
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


def dossiers() -> tuple[Path, Path]:
    """Rend (ressources, donnees) : ce qu'on lit, et ce qu'on garde."""
    degroupe = getattr(sys, "_MEIPASS", None)
    if degroupe:                                  # exe gele
        ressources = Path(degroupe)
    else:                                         # execution depuis les sources
        ressources = Path(__file__).resolve().parent
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    donnees = Path(base) / NOM_APPLICATION
    donnees.mkdir(parents=True, exist_ok=True)
    return ressources, donnees


def preparer_configuration(ressources: Path, donnees: Path) -> Path:
    """Cree le .env de l'utilisateur au premier lancement, et n'y touche plus ensuite.

    Le jeton est engendre sur place : le recopier d'une installation a l'autre donnerait a tout le
    monde le meme, donc a personne un secret.
    """
    import secrets

    chemin = donnees / ".env"
    if not chemin.exists():
        # ON REPREND LA CONFIGURATION DEJA PRESENTE, si elle existe a cote du programme.
        # Quelqu'un qui a deja regle FlowScope en ligne de commande ne doit pas avoir a le refaire :
        # son .env contient l'adresse de sa base et son jeton. Sans cette reprise, l'application de
        # bureau demarrait sur une base vide EN MEMOIRE, et l'utilisateur ne comprenait pas ou
        # etaient passes ses paquets.
        voisin = ressources / ".env"
        modele = voisin if voisin.exists() else (ressources / ".env.example")
        contenu = modele.read_text(encoding="utf-8") if modele.exists() else ""
        # UN JETON DEJA PRESENT EST CONSERVE, ET C'EST ESSENTIEL. Le regenerer a chaque reprise
        # de configuration a produit deux jetons differents : celui du projet, dont se sert
        # l'agent local, et celui de l'application de bureau. L'agent se faisait alors refuser
        # avec un 401, et rien dans l'interface ne l'expliquait. Un jeton ne se fabrique que
        # lorsqu'il n'y en a pas.
        deja = ""
        for ligne in contenu.split("\n"):
            if ligne.strip().startswith("ANALYZER_AGENT_TOKEN="):
                deja = ligne.split("=", 1)[1].strip()
                break
        jeton = deja or secrets.token_urlsafe(32)
        lignes = []
        remplace = False
        for ligne in contenu.split("\n"):
            if ligne.strip().startswith("ANALYZER_AGENT_TOKEN="):
                lignes.append("ANALYZER_AGENT_TOKEN=" + jeton)
                remplace = True
            else:
                lignes.append(ligne)
        if not remplace:
            lignes.append("ANALYZER_AGENT_TOKEN=" + jeton)
        chemin.write_text("\n".join(lignes), encoding="utf-8")
    return chemin


def charger_configuration(chemin: Path) -> None:
    """Place les reglages de l'utilisateur dans l'environnement, avant tout import du backend.

    `backend.config` lit l'environnement en priorite sur tout fichier : il suffit donc de definir
    les variables ici pour que l'application s'y conforme, sans modifier une ligne de son code.
    """
    from dotenv import load_dotenv

    load_dotenv(chemin, override=True)


def lancer_serveur(port: int) -> None:
    """Demarre le backend dans un fil : la fenetre doit rester maitresse de son fil principal."""
    import uvicorn

    from backend.main import application

    uvicorn.run(application, host="127.0.0.1", port=port, log_level="warning")


def attendre_port(port: int, delai: float = 60.0) -> bool:
    """Attend que le serveur accepte les connexions. La base distante demande dix a quinze secondes."""
    limite = time.monotonic() + delai
    while time.monotonic() < limite:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=1):
                return True
        except OSError:
            time.sleep(0.3)
    return False


def main() -> int:
    activer_conscience_dpi()
    ressources, donnees = dossiers()

    # L'application resout ses gabarits par des chemins relatifs : on se place donc la ou ils sont.
    os.chdir(ressources)
    if str(ressources) not in sys.path:
        sys.path.insert(0, str(ressources))

    configuration = preparer_configuration(ressources, donnees)
    charger_configuration(configuration)

    port = int(os.environ.get("ANALYZER_PORT", "8000"))

    # UNE SEULE INSTANCE, ET ELLE SE FAIT CONNAITRE. Sans ce test, un double-clic de trop donnait
    # une deuxieme application qui ne pouvait pas prendre le port : uvicorn echouait, le fil
    # mourait, et l'utilisateur voyait une fenetre vide sans le moindre message. On regarde donc
    # si un serveur repond deja - si oui, c'est la meme application, et on s'y branche.
    deja_la = False
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            deja_la = True
    except OSError:
        pass

    if not deja_la:
        threading.Thread(target=lancer_serveur, args=(port,), daemon=True).start()

    import webview

    fenetre = webview.create_window(
        f"{NOM_APPLICATION} - analyseur de trafic reseau",
        f"http://127.0.0.1:{port}",
        width=LARGEUR, height=HAUTEUR, min_size=(1024, 700),
        text_select=True,
    )
    # La fenetre attend le serveur AVANT d'afficher la page : sans cela, l'utilisateur verrait
    # une page d'erreur pendant les dix a quinze secondes de connexion a la base.
    if deja_la:
        print(f"  Une instance de {NOM_APPLICATION} repond deja sur le port {port} : "
              "on l'affiche sans en demarrer une seconde.", flush=True)
    else:
        threading.Thread(target=lambda: (attendre_port(port), fenetre.load_url(
            f"http://127.0.0.1:{port}")), daemon=True).start()
    webview.start()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
