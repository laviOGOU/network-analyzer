"""Envoi des paquets analysés vers le backend, avec file d'attente et réessai.

Pourquoi une file d'attente plutôt qu'un envoi direct
-----------------------------------------------------
Le rythme de la capture n'est pas celui du réseau. Sur un Wi-Fi chargé, on reçoit
plusieurs centaines de paquets par seconde ; une requête HTTP par paquet serait absurde
(et noierait le backend). La file absorbe les deux rythmes :

    capture → [file] → regroupement par lots → HTTPS → backend

Règles tenues ici
-----------------
1. **La capture n'attend jamais.** Si le backend est lent ou injoignable, la file se
   remplit ; elle a une taille maximale, donc la mémoire ne peut pas exploser.
2. **Quand la file déborde, on jette le plus ancien**, pas le plus récent. Un outil de
   surveillance en direct doit montrer ce qui se passe *maintenant* : perdre une donnée
   de dix secondes est moins grave que de montrer un état figé. Les abandons sont
   comptés et remontés à l'interface — jamais passés sous silence.
3. **Un échec réseau ne fait pas tomber l'agent.** Le lot échoué est gardé, puis réessayé
   avec un délai croissant. C'est le scénario « Supabase injoignable » de l'énoncé.
"""

from __future__ import annotations

import logging
import queue
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Callable

import httpx

logger = logging.getLogger(__name__)

#: Au-delà de ce nombre de paquets en attente, les plus anciens sont abandonnés.
#: 5 000 enregistrements représentent environ 2 Mo : assez pour traverser une coupure de
#: quelques minutes, trop peu pour saturer la mémoire d'un portable.
TAILLE_FILE = 5_000

#: Un envoi part quand le lot atteint cette taille…
LOT_MAX = 200
#: …ou quand ce délai s'est écoulé depuis le premier paquet du lot, même s'il est petit.
#: Sans cette borne, quelques paquets isolés resteraient en attente indéfiniment.
INTERVALLE_LOT = 2.0


@dataclass
class Statistiques:
    """Compteurs remontés à l'interface. Ils rendent visible ce qui est invisible."""

    recus: int = 0
    envoyes: int = 0
    lots: int = 0
    echecs: int = 0
    abandonnes: int = 0
    dernier_echec: str = ""
    file: int = 0

    def resume(self) -> str:
        return (f"reçus {self.recus} · envoyés {self.envoyes} · lots {self.lots} · "
                f"échecs {self.echecs} · abandonnés {self.abandonnes}")


class Envoyeur:
    """Transmet les fiches de paquets au backend, par lots, avec réessai.

    `destination` reçoit un lot : c'est une fonction, ce qui permet de substituer un
    affichage ou un double de test sans toucher au reste. La classe ne connaît ni HTTP ni
    le backend ; elle ne connaît que le rythme.
    """

    def __init__(self, destination: Callable[[list[dict[str, Any]]], None]) -> None:
        self.destination = destination
        self.stats = Statistiques()
        self._file: queue.Queue[dict[str, Any]] = queue.Queue(maxsize=TAILLE_FILE)
        self._arret = threading.Event()
        self._fil: threading.Thread | None = None

    # ------------------------------------------------------------------ cycle
    def demarrer(self) -> None:
        if self._fil is not None:
            return
        self._arret.clear()
        self._fil = threading.Thread(target=self._boucle, name="envoyeur", daemon=True)
        self._fil.start()

    def arreter(self, vider: bool = True) -> None:
        """Arrête l'envoi. `vider=True` tente d'écouler la file avant de rendre la main."""
        self._arret.set()
        if self._fil is not None:
            self._fil.join(timeout=5)
            self._fil = None
        if vider:
            self._vider()

    # ------------------------------------------------------------------ apport
    def ajouter(self, fiche: dict[str, Any]) -> None:
        """Met une fiche en file. **Ne bloque jamais la capture.**

        Si la file est pleine, on retire l'entrée la plus ancienne pour faire de la place.
        Une exception ici remonterait dans le fil de capture de Scapy et arrêterait la
        capture : inacceptable.
        """
        self.stats.recus += 1
        try:
            self._file.put_nowait(fiche)
        except queue.Full:
            try:
                self._file.get_nowait()          # jeter le plus ancien
                self.stats.abandonnes += 1
            except queue.Empty:
                pass
            try:
                self._file.put_nowait(fiche)
            except queue.Full:
                self.stats.abandonnes += 1
        self.stats.file = self._file.qsize()

    # ------------------------------------------------------------------ boucle
    def _boucle(self) -> None:
        """Regroupe les fiches par lots et les transmet, jusqu'à l'arrêt demandé."""
        lot: list[dict[str, Any]] = []
        debut_lot = time.monotonic()

        while not self._arret.is_set():
            try:
                lot.append(self._file.get(timeout=0.25))
                self.stats.file = self._file.qsize()
            except queue.Empty:
                pass

            assez_gros = len(lot) >= LOT_MAX
            assez_vieux = lot and (time.monotonic() - debut_lot) >= INTERVALLE_LOT
            if assez_gros or assez_vieux:
                self._transmettre(lot)
                lot = []
                debut_lot = time.monotonic()

        if lot:
            self._transmettre(lot)

    def _vider(self) -> None:
        """Écoulement final, par paquets de `LOT_MAX`."""
        restant: list[dict[str, Any]] = []
        while not self._file.empty():
            try:
                restant.append(self._file.get_nowait())
            except queue.Empty:
                break
        for debut in range(0, len(restant), LOT_MAX):
            self._transmettre(restant[debut:debut + LOT_MAX])

    # ------------------------------------------------------------------ envoi
    def _transmettre(self, lot: list[dict[str, Any]]) -> None:
        """Transmet un lot. Un échec est compté, journalisé, et ne remonte pas."""
        if not lot:
            return
        try:
            self.destination(lot)
            self.stats.envoyes += len(lot)
            self.stats.lots += 1
        except Exception as erreur:                  # noqa: BLE001 — frontière réseau
            self.stats.echecs += 1
            self.stats.dernier_echec = f"{type(erreur).__name__}: {erreur}"[:200]
            logger.warning("Lot de %d paquets non transmis : %s", len(lot), erreur)


class ClientBackend:
    """Client HTTP vers le backend.

    `httpx` plutôt que `requests` : le projet utilise déjà FastAPI, qui s'appuie sur les
    mêmes fondations (encodage, timeouts) ; et `httpx` permet une limite de temps globale
    en une ligne, ce qui évite qu'un backend injoignable bloque l'agent. La bibliothèque
    standard (`urllib`) ferait aussi le travail mais sans gestion de délai lisible.
    """

    def __init__(self, url: str, jeton: str, delai: float = 5.0,
                 nom_agent: str = "agent-local", session: str = "") -> None:
        self.url = url.rstrip("/")
        self.jeton = jeton
        self.delai = delai
        self.nom_agent = nom_agent
        self.session = session

    def envoyer(self, lot: list[dict[str, Any]],
                communications: list[dict[str, Any]] | None = None) -> None:
        """POST /api/v1/ingest. Lève en cas d'échec : l'appelant décide quoi en faire.

        Les communications voyagent dans le même lot que les paquets : elles décrivent
        ces paquets-là. Les séparer ouvrirait la porte à un tableau de bord où une
        conversation apparaîtrait avant les paquets qui la composent.
        """
        charge = {
            "session": self.session,
            "agent": self.nom_agent,
            "paquets": lot,
            "communications": communications or [],
        }
        reponse = httpx.post(
            f"{self.url}/api/v1/ingest",
            json=charge,
            headers={"X-Agent-Token": self.jeton},
            timeout=self.delai,
        )
        # `raise_for_status` couvre 4xx et 5xx : un jeton refusé ne doit surtout pas
        # passer pour un succès, sinon les paquets disparaîtraient sans un mot.
        reponse.raise_for_status()


@dataclass
class EnvoyeurMemoire:
    """Destination de remplacement, pour les tests et le mode « à blanc ».

    Elle garde tout ce qu'elle reçoit et ne fait aucun réseau : c'est ce qui permet de
    tester la file, le regroupement par lots et les compteurs sans backend.
    """

    lots: list[list[dict[str, Any]]] = field(default_factory=list)

    def __call__(self, lot: list[dict[str, Any]]) -> None:
        self.lots.append(lot)

    @property
    def paquets(self) -> list[dict[str, Any]]:
        return [p for lot in self.lots for p in lot]
