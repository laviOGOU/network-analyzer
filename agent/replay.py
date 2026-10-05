"""Mode replay — rejouer un fichier .pcap comme s'il arrivait du réseau.

POURQUOI CE MODE EXISTE
-----------------------
Trois raisons, et la troisième est la plus importante :

1. **Reproductibilité.** Deux exécutions sur le même fichier donnent exactement le même
   résultat : mêmes communications, mêmes états, mêmes détections. C'est ce qui permet de
   comparer, de vérifier une correction, et de démontrer l'outil sans dépendre du trafic
   du moment.

2. **Démonstration hors ligne.** Une salle d'examen, une machine sans réseau, un
   ordinateur dont l'interface ne capture rien : le fichier suffit.

3. **C'est la preuve que la capture n'est pas le cœur du système.** Un outil dont tout le
   raisonnement serait soudé à la capture en direct ne pourrait pas rejouer un fichier.
   Ici, le replay traverse **exactement la même chaîne** que la capture — même analyseur,
   même table de communications, même détection, même transmission au backend. Seule la
   source des paquets change. C'est le meilleur argument en faveur de la séparation des
   responsabilités du dépôt, et il est vérifiable.

LE POINT DÉLICAT : LE TEMPS
---------------------------
Un fichier capturé hier contient des horodatages d'hier. Deux choix :

    - utiliser l'heure courante : simple, et faux. Un SYN daté d'hier paraîtrait vieux de
      plusieurs heures, donc « sans réponse depuis longtemps », et toutes les connexions
      seraient marquées en échec probable ;
    - **utiliser l'heure du paquet** : le déroulement est fidèle, et les délais se
      calculent sur la même échelle que pendant la capture.

Le second choix est le bon, et il n'a pas demandé de travail particulièr : la table des
communications mesure l'âge d'un paquet **par rapport au dernier paquet vu**, et non par
rapport à l'horloge de la machine. Cette décision, prise en phase 2 pour rendre les tests
possibles, rend le replay juste aujourd'hui.
"""

from __future__ import annotations

import datetime as dt
import logging
import threading
import time
from pathlib import Path
from typing import Any, Callable

logger = logging.getLogger(__name__)


class ErreurReplay(RuntimeError):
    """Le fichier ne peut pas être rejoué, et le message dit pourquoi."""


class ReplayPcap:
    """Lit un fichier .pcap et le rejoue paquet par paquet.

    La classe expose la même surface que la capture en direct — `demarrer`, `arreter`,
    `recus`, `erreurs_analyse` — ce qui permet à la ligne de commande de les traiter de
    façon identique. C'est délibéré : tout le reste de l'agent ignore d'où viennent les
    paquets.
    """

    def __init__(self, chemin: str | Path, sur_paquet: Callable[[dict[str, Any]], None],
                 vitesse: float = 0.0) -> None:
        self.chemin = Path(chemin)
        self.sur_paquet = sur_paquet
        #: 0 = aussi vite que possible, 1 = au rythme réel, 10 = dix fois plus vite.
        self.vitesse = vitesse
        self.recus = 0
        self.erreurs_analyse = 0
        #: Paquets lus mais dont le traitement a échoué. Distincts des erreurs d'analyse :
        #: les premiers disent un défaut de l'agent, les seconds un paquet abîmé.
        self.erreurs_traitement = 0
        self._echecs_consecutifs = 0
        self.termine = False
        self._fil: threading.Thread | None = None
        self._arret = threading.Event()
        #: Instant du dernier paquet lu : c'est le « maintenant » du rejeu.
        self._dernier_instant: dt.datetime | None = None
        self._verrou_temps = threading.Lock()

        if not self.chemin.is_file():
            raise ErreurReplay(f"Fichier introuvable : {self.chemin}")
        # .pcapng est accepté : Scapy le lit nativement, et c'est le format par défaut
        # des versions récentes de Wireshark. Refuser un format que l'on sait lire
        # obligerait à une conversion sans raison.
        if self.chemin.suffix.lower() not in (".pcap", ".pcapng", ".cap"):
            raise ErreurReplay(
                f"Extension inattendue : « {self.chemin.suffix} ».\n"
                "  Ce mode attend une capture réseau : .pcap, .pcapng ou .cap,\n"
                "  écrite par Wireshark, tcpdump, ou l'enregistreur de cet outil.\n"
                "  Un fichier texte, un journal ou une image ne contiendra jamais de\n"
                "  paquets, et le dire tout de suite évite de chercher pourquoi le\n"
                "  rejeu ne produit rien."
            )

    # ------------------------------------------------------------------ surface
    def demarrer(self) -> None:
        """Lance la lecture dans un fil séparé.

        Un fil, et non une boucle bloquante : l'agent doit continuer à vider sa file
        d'envoi et à afficher son avancement pendant la lecture. Sur un fichier de
        plusieurs centaines de milliers de paquets, une lecture bloquante ferait
        paraître l'outil figé.
        """
        self._fil = threading.Thread(target=self._rejouer, name="replay-pcap", daemon=True)
        self._fil.start()

    def arreter(self) -> None:
        """Demande l'arrêt et attend la fin du fil."""
        self._arret.set()
        if self._fil and self._fil.is_alive():
            self._fil.join(timeout=5)

    def maintenant(self) -> dt.datetime:
        """L'instant du dernier paquet lu — et non l'heure de la machine.

        C'est la pièce qui rend le rejeu juste de bout en bout. La table des
        communications et le détecteur ont besoin de savoir « quelle heure est-il » pour
        décider qu'une connexion est restée sans réponse ou qu'une conversation est
        terminée. Dans un fichier, « maintenant » est la date du dernier paquet lu.

        Sans cela, un SYN enregistré il y a neuf mois serait comparé à l'horloge du jour :
        il paraîtrait abandonné depuis neuf mois, et **toutes** les connexions d'un
        fichier ancien seraient déclarées en échec probable. Le rejeu produirait
        exactement le contraire de ce que contient le fichier.
        """
        with self._verrou_temps:
            return self._dernier_instant or dt.datetime.now(dt.timezone.utc)

    @property
    def perdues(self) -> int:
        """Un fichier ne perd rien par construction : il est déjà écrit.

        La propriété existe pour que la ligne de commande puisse afficher le même
        récapitulatif dans les deux modes, sans condition.
        """
        return 0

    # ------------------------------------------------------------------ lecture
    def _rejouer(self) -> None:
        from scapy.utils import PcapReader

        from agent import parser as mod_parser

        debut_reel = time.monotonic()
        premier_paquet: float | None = None

        try:
            with PcapReader(str(self.chemin)) as lecteur:
                for paquet in lecteur:
                    if self._arret.is_set():
                        break

                    horodatage = dt.datetime.fromtimestamp(float(paquet.time),
                                                           tz=dt.timezone.utc)
                    with self._verrou_temps:
                        self._dernier_instant = horodatage
                    try:
                        fiche = mod_parser.analyser(paquet, horodatage=horodatage)
                    except Exception:                            # noqa: BLE001
                        # Un paquet illisible dans un fichier ne doit pas arrêter le
                        # replay : on le compte, et on continue. Même principe que la
                        # capture en direct.
                        self.erreurs_analyse += 1
                        continue

                    self.recus += 1
                    try:
                        self.sur_paquet(fiche)
                    except Exception as erreur:                  # noqa: BLE001
                        # Une erreur dans le traitement d'un paquet ne doit pas emporter
                        # tout le rejeu — mais elle ne doit pas non plus passer inaperçue.
                        # On compte les échecs **consécutifs** et on s'arrête au bout de
                        # cinq : si le traitement est cassé pour tous les paquets, mieux
                        # vaut s'arrêter en le disant que parcourir un million de paquets
                        # en silence en affichant « 0 envoyé ».
                        self.erreurs_traitement += 1
                        self._echecs_consecutifs += 1
                        if self._echecs_consecutifs == 1:
                            logger.error("Traitement d'un paquet en échec : %s — %s",
                                         type(erreur).__name__, erreur)
                        if self._echecs_consecutifs >= 5:
                            logger.error(
                                "Cinq paquets de suite n'ont pas pu être traités : le "
                                "rejeu s'arrête. La cause est signalée ci-dessus ; "
                                "relancer avec -v pour la trace complète.")
                            break
                        continue
                    self._echecs_consecutifs = 0

                    if self.vitesse > 0:
                        # Rythme respecté : on attend l'écart entre ce paquet et le
                        # premier, divisé par la vitesse demandée.
                        if premier_paquet is None:
                            premier_paquet = float(paquet.time)
                        ecart = (float(paquet.time) - premier_paquet) / self.vitesse
                        attente = ecart - (time.monotonic() - debut_reel)
                        if attente > 0:
                            time.sleep(min(attente, 5.0))
                    else:
                        # Rythme libre : on rend la main régulièrement pour que le fil
                        # d'envoi puisse travailler, sans quoi le fichier serait lu
                        # entièrement avant qu'un seul lot ne parte.
                        if self.recus % 250 == 0:
                            time.sleep(0)
        except Exception as erreur:                              # noqa: BLE001
            logger.error("Lecture du fichier interrompue : %s", erreur)
        finally:
            self.termine = True


def resumer_fichier(chemin: str | Path) -> dict[str, Any]:
    """Inspecte un fichier sans le rejouer : nombre de paquets, période couverte.

    Sert à répondre à la question « ce fichier contient-il quelque chose ? » avant de
    lancer un replay qui ne produirait rien.
    """
    from scapy.utils import PcapReader

    chemin = Path(chemin)
    if not chemin.is_file():
        raise ErreurReplay(f"Fichier introuvable : {chemin}")

    nombre = 0
    premier: float | None = None
    dernier: float | None = None
    with PcapReader(str(chemin)) as lecteur:
        for paquet in lecteur:
            nombre += 1
            instant = float(paquet.time)
            premier = instant if premier is None else premier
            dernier = instant

    periode = (dernier - premier) if (premier is not None and dernier is not None) else 0.0
    return {
        "fichier": str(chemin),
        "octets": chemin.stat().st_size,
        "paquets": nombre,
        "debut": (dt.datetime.fromtimestamp(premier, tz=dt.timezone.utc).isoformat()
                  if premier else None),
        "fin": (dt.datetime.fromtimestamp(dernier, tz=dt.timezone.utc).isoformat()
                if dernier else None),
        "duree_secondes": round(periode, 3),
    }
