"""Pilotage d'une capture, et diffusion des paquets en direct.

DEUX RESPONSABILITÉS, ET POURQUOI ELLES SONT ICI ENSEMBLE
---------------------------------------------------------
**Piloter** : démarrer et arrêter l'agent de capture. **Diffuser** : faire parvenir chaque
paquet à la page au moment où il arrive, au lieu qu'elle interroge le serveur toutes les trois
secondes. Les deux vont ensemble parce qu'elles se répondent : c'est le pilotage qui produit
le flux, et le flux qui rend le pilotage visible.

LA LIMITE, ÉCRITE ICI POUR NE PAS ÊTRE DÉCOUVERTE PLUS TARD
-----------------------------------------------------------
Aujourd'hui l'agent **pousse** vers le serveur : il n'obéit pas. Pour qu'un bouton le démarre,
le serveur doit lancer lui-même le processus. Cela suppose que **l'agent tourne sur la même
machine que le serveur** — c'est le cas de la démonstration, ce n'est pas le cas général. Un
agent installé ailleurs continuerait de pousser ses paquets sans pouvoir être commandé depuis
cette interface.

Ce module ne prétend donc pas piloter un agent distant. Il pilote celui du poste.
"""

from __future__ import annotations

import logging
import os
import queue
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Iterator

logger = logging.getLogger(__name__)

#: Racine du projet : c'est depuis là que `python -m agent.main` se résout.
RACINE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

#: Durée maximale d'une capture lancée depuis l'interface, en secondes. Elle ne borne pas la
#: démonstration — le bouton Arrêter termine bien avant — mais elle évite qu'un processus
#: lancé par distraction tourne indéfiniment.
DUREE_MAXIMALE = 3600

#: Au-delà de ce nombre de paquets en attente pour un navigateur, les plus anciens sont
#: écartés. Un onglet resté ouvert sans être regardé ne doit pas faire grossir la mémoire du
#: serveur indéfiniment.
TAILLE_FILE_DIFFUSION = 500


class ErreurPilotage(RuntimeError):
    """Capture refusée, avec un motif compréhensible."""


# --------------------------------------------------------------------------- #
#  Les interfaces réellement présentes
# --------------------------------------------------------------------------- #
def lister_interfaces() -> list[dict[str, Any]]:
    """Les interfaces qui peuvent capturer, telles que le système les expose.

    Aucune liste écrite à la main : elle proposerait des choix qui échouent. Sur la machine
    de développement, Scapy en voit treize dont plusieurs sans adresse — seules celles qui
    portent un nom utilisable sont rendues.
    """
    try:
        from agent.capture import lister_interfaces as lister
    except ImportError:                                  # pragma: no cover
        return []
    try:
        interfaces = lister()
    except Exception as erreur:                          # noqa: BLE001
        logger.warning("Interfaces illisibles : %s", erreur)
        return []

    rendues = []
    for interface in interfaces:
        nom = getattr(interface, "nom", None) or (interface.get("nom") if isinstance(interface, dict) else None)
        if not nom:
            continue
        rendues.append({
            "nom": str(nom),
            "adresse": str(getattr(interface, "adresse", "") or ""),
            "description": str(getattr(interface, "description", "") or ""),
        })
    return rendues


# --------------------------------------------------------------------------- #
#  La diffusion aux navigateurs
# --------------------------------------------------------------------------- #
class Diffusion:
    """Distribue les paquets reçus aux navigateurs qui écoutent.

    Chaque navigateur a **sa propre file** : un onglet lent ou resté ouvert ne doit pas
    retarder les autres. Au-delà de `TAILLE_FILE_DIFFUSION` paquets en attente, les plus
    anciens sont écartés — c'est une liste vivante, pas un historique ; l'historique est en
    base, et c'est là qu'on le consulte.
    """

    def __init__(self) -> None:
        self._files: set[queue.Queue] = set()
        self._verrou = threading.Lock()
        self._total = 0

    def abonner(self) -> queue.Queue:
        file_: queue.Queue = queue.Queue(maxsize=TAILLE_FILE_DIFFUSION)
        with self._verrou:
            self._files.add(file_)
        return file_

    def desabonner(self, file_: queue.Queue) -> None:
        with self._verrou:
            self._files.discard(file_)

    def publier(self, paquets: list[dict[str, Any]]) -> None:
        """Diffuse des paquets. **Ne bloque jamais l'ingestion.**"""
        if not paquets:
            return
        with self._verrou:
            files = list(self._files)
        self._total += len(paquets)

        for file_ in files:
            for paquet in paquets:
                try:
                    file_.put_nowait(paquet)
                except queue.Full:
                    # On jette le plus ancien pour faire de la place : la file décrit ce qui
                    # arrive, pas ce qui est arrivé.
                    try:
                        file_.get_nowait()
                        file_.put_nowait(paquet)
                    except (queue.Empty, queue.Full):
                        pass

    @property
    def abonnes(self) -> int:
        with self._verrou:
            return len(self._files)

    @property
    def total_diffuse(self) -> int:
        return self._total


#: Instance unique, partagée par l'ingestion et par le flux.
diffusion = Diffusion()


# --------------------------------------------------------------------------- #
#  Le pilotage
# --------------------------------------------------------------------------- #
@dataclass
class Capture:
    """L'état d'une capture lancée depuis l'interface."""

    interface: str = ""
    filtre: str = ""
    nom: str = ""
    demarree_a: float = 0.0
    processus: subprocess.Popen | None = None
    journal: list[str] = field(default_factory=list)

    @property
    def en_cours(self) -> bool:
        return self.processus is not None and self.processus.poll() is None

    def secondes(self) -> float:
        return round(time.monotonic() - self.demarree_a, 1) if self.demarree_a else 0.0


class Pilote:
    """Une capture à la fois. Deux captures simultanées se mélangeraient dans le même
    tableau de bord, et personne ne saurait plus ce qui vient d'où."""

    def __init__(self) -> None:
        self._capture = Capture()
        self._verrou = threading.Lock()

    def etat(self) -> dict[str, Any]:
        with self._verrou:
            capture = self._capture
            return {
                "en_cours": capture.en_cours,
                "interface": capture.interface,
                "filtre": capture.filtre,
                "nom": capture.nom,
                "secondes": capture.secondes(),
                "code_sortie": None if capture.en_cours or capture.processus is None
                                else capture.processus.returncode,
                "abonnes": diffusion.abonnes,
                # Les dernières lignes du journal de l'agent : c'est là qu'apparaît un refus
                # de capture, et le cacher ferait chercher longtemps.
                "journal": capture.journal[-8:],
            }

    def demarrer(self, interface: str, filtre: str = "", nom: str = "") -> dict[str, Any]:
        """Lance l'agent de capture sur cette machine."""
        interface = (interface or "").strip()
        if not interface:
            raise ErreurPilotage("Choisissez une interface réseau avant de démarrer.")

        connues = [i["nom"] for i in lister_interfaces()]
        if connues and interface not in connues:
            # On refuse un nom inventé : lancer une capture sur une interface inexistante
            # produirait une erreur obscure au fond du journal.
            raise ErreurPilotage(
                f"Interface inconnue : « {interface} ». Disponibles : {', '.join(connues[:8])}."
            )

        jeton = os.environ.get("ANALYZER_AGENT_TOKEN", "").strip()
        if not jeton:
            raise ErreurPilotage(
                "Aucun jeton d'agent n'est configuré : le serveur ne peut pas autoriser la "
                "capture qu'il lance. Renseignez ANALYZER_AGENT_TOKEN."
            )

        port = os.environ.get("ANALYZER_PORT", "8000")
        backend = f"http://127.0.0.1:{port}"

        with self._verrou:
            if self._capture.en_cours:
                raise ErreurPilotage(
                    f"Une capture est déjà en cours sur « {self._capture.interface} ». "
                    "Arrêtez-la avant d'en lancer une autre."
                )

            commande = [
                sys.executable, "-m", "agent.main",
                "--interface", interface,
                "--backend", backend,
                "--jeton", jeton,
                "--nom", (nom or f"interface:{interface}")[:60],
                "--duree", str(DUREE_MAXIMALE),
            ]
            if filtre.strip():
                commande += ["--filtre", filtre.strip()]

            drapeaux = getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0
            try:
                processus = subprocess.Popen(
                    commande, cwd=RACINE,
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, encoding="utf-8", errors="replace",
                    creationflags=drapeaux,
                )
            except OSError as erreur:
                raise ErreurPilotage(f"L'agent n'a pas pu être lancé : {erreur}") from erreur

            self._capture = Capture(
                interface=interface, filtre=filtre.strip(), nom=nom,
                demarree_a=time.monotonic(), processus=processus,
            )
            logger.info("Capture lancée sur %s (pid %s)", interface, processus.pid)

        # Le journal de l'agent est lu en continu : c'est là qu'apparaissent le manque de
        # droits et les filtres refusés. Sans cette lecture, le tube finirait par se remplir
        # et l'agent se figerait.
        threading.Thread(target=self._lire_journal, args=(processus,), daemon=True,
                         name="journal-capture").start()
        return self.etat()

    def _lire_journal(self, processus: subprocess.Popen) -> None:
        if processus.stdout is None:
            return
        for ligne in processus.stdout:
            ligne = ligne.strip()
            if not ligne:
                continue
            with self._verrou:
                if self._capture.processus is processus:
                    self._capture.journal.append(ligne)
                    self._capture.journal = self._capture.journal[-40:]
        logger.debug("Agent : %s", ligne)

    def arreter(self) -> dict[str, Any]:
        """Arrête la capture. Ce qui a été capturé reste : c'est l'historique."""
        with self._verrou:
            capture = self._capture
            processus = capture.processus
            if processus is None or processus.poll() is not None:
                capture.processus = None
                return self.etat()

        processus.terminate()
        try:
            # L'agent vide sa file avant de rendre la main : on lui laisse le temps de finir,
            # sinon les derniers paquets seraient perdus au moment même où on les regarde.
            processus.wait(timeout=8)
        except subprocess.TimeoutExpired:
            logger.warning("L'agent ne s'est pas arrêté seul : arrêt forcé.")
            processus.kill()
            processus.wait(timeout=5)

        with self._verrou:
            self._capture.processus = None
        logger.info("Capture arrêtée")
        return self.etat()

    def arreter_si_besoin(self) -> None:
        """Utilisé à l'extinction du serveur : ne laisse pas un agent orphelin derrière lui."""
        with self._verrou:
            en_cours = self._capture.en_cours
        if en_cours:
            try:
                self.arreter()
            except Exception as erreur:                  # noqa: BLE001
                logger.warning("Arrêt de la capture impossible : %s", erreur)


#: Instance unique du pilote.
pilote = Pilote()


def evenements(file_: queue.Queue, battement: float = 15.0) -> Iterator[str]:
    """Transforme une file de paquets en flux d'événements pour le navigateur.

    Un **battement** est émis quand rien n'arrive : sans lui, un intermédiaire réseau
    fermerait une connexion restée silencieuse, et la page cesserait de recevoir les paquets
    sans que personne ne le remarque.

    **La coupure du client est un cas normal, pas une erreur.** Quand un onglet se ferme ou
    recharge, le serveur continue d'écrire dans un flux que personne ne lit : le navigateur
    signale alors `ERR_INCOMPLETE_CHUNKED_ENCODING`, qui apparaît comme une erreur alors qu'il
    ne s'est rien passé d'anormal. On arrête donc proprement dès que l'écriture n'aboutit plus,
    au lieu de laisser la réponse se rompre.
    """
    import json

    dernier = time.monotonic()
    while True:
        try:
            paquet = file_.get(timeout=1.0)
        except queue.Empty:
            if time.monotonic() - dernier >= battement:
                dernier = time.monotonic()
                yield ": battement\n\n"
            continue

        dernier = time.monotonic()
        try:
            yield f"data: {json.dumps(paquet, ensure_ascii=False)}\n\n"
        except GeneratorExit:
            # Le navigateur a fermé la connexion : on rend la main sans bruit.
            raise
        except Exception as erreur:                      # noqa: BLE001
            logger.debug("Flux interrompu : %s", erreur)
            return
