"""Capture de paquets sur une interface réseau.

Pourquoi Scapy plutôt qu'une bibliothèque plus bas niveau
---------------------------------------------------------
Scapy lit et écrit les protocoles en Python pur. On pourrait utiliser un socket brut
(`socket.AF_PACKET` sous Linux, `SOCK_RAW` sous Windows), mais il faudrait alors écrire
soi-même le décodage d'Ethernet, d'IP, de TCP, d'UDP, de DNS — plusieurs milliers de
lignes, et autant d'occasions de se tromper. Scapy apporte ce décodage, et surtout il
sait **réduire un paquet à ses couches** (`paquet.layers()`), ce dont dépend tout le
reste du projet.

Le prix à payer : Scapy est plus lent qu'un décodeur en C. Pour un exercice de formation
sur un réseau domestique, c'est sans conséquence ; sur un lien à 10 Gbit/s, il faudrait
un autre outil. Cette limite est écrite dans le README.

Sous Windows, Scapy s'appuie sur le pilote **Npcap**. Sans lui, aucune capture n'est
possible — d'où le message explicite produit ici plutôt qu'une erreur illisible.
"""

from __future__ import annotations

import datetime as dt
import logging
import threading
from dataclasses import dataclass, field
from typing import Any, Callable

from scapy.all import AsyncSniffer, conf
from scapy.interfaces import get_working_ifaces

logger = logging.getLogger(__name__)

#: Filtre appliqué par défaut : rien. Un filtre vide montre TOUT, ce qui est le bon
#: réglage pour un outil pédagogique — on veut voir ce qui passe, pas ce qu'on espérait.
FILTRE_PAR_DEFAUT = ""


class ErreurCapture(RuntimeError):
    """Capture impossible, avec un motif compréhensible par l'utilisateur."""


@dataclass
class Interface:
    """Une interface réseau telle qu'on peut la présenter à un humain.

    `nom` est le nom **lisible** (« Wi-Fi », « Ethernet ») : Scapy sait le résoudre, et
    c'est lui qu'on affiche. `nom_technique` est l'identifiant du pilote
    (`\\Device\\NPF{...}`) : illisible, mais indispensable au diagnostic quand deux
    cartes portent des noms voisins.
    """

    nom: str
    description: str
    adresses_ipv4: list[str] = field(default_factory=list)
    adresses_ipv6: list[str] = field(default_factory=list)
    adresse_mac: str = ""
    nom_technique: str = ""

    @property
    def adresses(self) -> list[str]:
        """Toutes les adresses, IPv4 d'abord : c'est celle qu'un humain reconnaît."""
        return list(self.adresses_ipv4) + list(self.adresses_ipv6)

    def resume(self) -> str:
        morceaux = [self.nom]
        if self.description and self.description != self.nom:
            morceaux.append(f"({self.description})")
        morceaux.append(", ".join(self.adresses) if self.adresses else "sans adresse")
        return "  ".join(morceaux)


def moteur_disponible() -> str:
    """Nom du moteur de capture réellement utilisé.

    Sous Windows avec Npcap, Scapy bascule sur libpcap ; sinon il tente un socket brut.
    Savoir lequel est actif permet de comprendre la plupart des échecs de capture.
    """
    return "Npcap / libpcap" if conf.use_pcap else "socket brut"


def lister_interfaces() -> list[Interface]:
    """Interfaces disponibles, avec un nom compréhensible.

    Scapy nomme les interfaces `\\Device\\NPF_{GUID}` sous Windows : illisible, et
    impossible à choisir sans se tromper. On joint donc le nom technique à la
    description fournie par le système et aux adresses configurées.

    Les interfaces sans adresse (donc sans trafic attendu) sont conservées : certaines
    cartes n'ont pas d'adresse au moment de l'appel et en reçoivent une ensuite.
    """
    interfaces: list[Interface] = []
    for iface in get_working_ifaces():
        interfaces.append(Interface(
            nom=str(getattr(iface, "name", "") or ""),
            description=str(getattr(iface, "description", "") or ""),
            adresses_ipv4=_adresses_de(iface, 4),
            adresses_ipv6=_adresses_de(iface, 6),
            adresse_mac=str(getattr(iface, "mac", "") or ""),
            nom_technique=_nom_technique(iface),
        ))
    # Une interface sans nom exploitable ne peut pas être choisie : on l'écarte plutôt
    # que d'afficher une entrée vide dans la liste.
    return [i for i in interfaces if i.nom]


def _adresses_de(iface: Any, famille: int) -> list[str]:
    """Adresses d'une famille (4 ou 6) d'une interface, chacune sous forme lisible.

    Scapy range les adresses dans un dictionnaire `{4: [...], 6: [...]}`. On lit
    défensivement : une interface sans adresse est un cas normal, pas une erreur.
    """
    try:
        valeurs = (getattr(iface, "ips", None) or {}).get(famille, []) or []
    except Exception:                                # noqa: BLE001
        return []
    adresses: list[str] = []
    for valeur in valeurs:
        # Une adresse peut arriver sous forme « 192.168.1.6/24 » : on garde l'adresse
        # seule, le masque n'aidant pas à choisir une carte.
        texte = str(valeur).split("/")[0].strip()
        if texte and texte not in adresses:
            adresses.append(texte)
    return adresses


def _nom_technique(iface: Any) -> str:
    """Nom du pilote, quand Scapy le connaît (utile au diagnostic)."""
    for attribut in ("network_name", "name"):
        valeur = getattr(iface, attribut, None)
        if isinstance(valeur, str) and valeur.startswith("\\Device"):
            return valeur
    return ""


def choisir_interface(demande: str | None) -> str | None:
    """Résout une interface par son nom, sa description ou son adresse.

    La recherche est volontairement souple : l'utilisateur écrit « Wi-Fi », « wi-fi »
    ou « 192.168.1.6 » et doit obtenir la même carte. Rendre une interface par défaut
    silencieusement serait pire : on capturerait sur la mauvaise sans le dire.
    """
    if not demande:
        return None
    besoin = demande.strip().lower()
    interfaces = lister_interfaces()

    for iface in interfaces:
        if iface.nom == demande:
            return iface.nom

    for iface in interfaces:
        if besoin in (iface.description or "").lower():
            return iface.nom
    for iface in interfaces:
        if any(besoin == adresse for adresse in iface.adresses):
            return iface.nom
    for iface in interfaces:
        if besoin in iface.nom.lower() or besoin == iface.adresse_mac.lower():
            return iface.nom

    connues = "\n".join(f"  - {i.resume()}" for i in interfaces[:15])
    raise ErreurCapture(
        f"Aucune interface ne correspond à « {demande} ». Disponibles :\n{connues}"
    )


class Capture:
    """Capture en arrière-plan, démarrer / arrêter, avec compte des paquets.

    On ne bloque jamais le fil principal : `AsyncSniffer` capture dans son propre fil et
    appelle une fonction pour chaque paquet. L'agent peut ainsi afficher son avancement
    pendant que la capture tourne.
    """

    def __init__(self, interface: str | None = None, filtre: str = FILTRE_PAR_DEFAUT,
                 sur_paquet: Callable[[dict[str, Any]], None] | None = None) -> None:
        self.interface = interface
        self.filtre = filtre or None          # None = tous les paquets
        self.sur_paquet = sur_paquet
        self._sniffer: AsyncSniffer | None = None
        self._verrou = threading.Lock()
        self.recus = 0
        self.erreurs_analyse = 0

    # ------------------------------------------------------------------ état
    @property
    def active(self) -> bool:
        return self._sniffer is not None and self._sniffer.running

    # -------------------------------------------------------------- contrôle
    def demarrer(self) -> None:
        """Ouvre la capture. Lève `ErreurCapture` avec un motif utile si c'est refusé."""
        with self._verrou:
            if self.active:
                return
            try:
                self._sniffer = AsyncSniffer(
                    iface=self.interface,
                    filter=self.filtre,
                    prn=self._traiter,
                    store=False,        # ne rien garder en mémoire : on transmet au fil de l'eau
                )
                self._sniffer.start()
            except Exception as erreur:              # noqa: BLE001 — on traduit le message
                self._sniffer = None
                raise ErreurCapture(_expliquer(erreur)) from erreur

    def attendre_premier_paquet(self, delai: float = 2.0) -> bool:
        """Vérifie que la capture reçoit vraiment quelque chose.

        Ouvrir une capture ne prouve rien : sur une interface au mauvais nom, ou sans
        trafic, Scapy démarre sans erreur et ne reçoit jamais rien. Ce contrôle évite de
        laisser croire que tout va bien.
        """
        import time

        limite = time.monotonic() + delai
        while time.monotonic() < limite:
            if self.recus:
                return True
            time.sleep(0.1)
        return self.recus > 0

    def maintenant(self) -> "dt.datetime":
        """L'instant courant, pour la capture en direct.

        La méthode existe pour que les deux sources — le réseau et un fichier — soient
        interchangeables sans que le reste de l'agent ait à savoir laquelle il utilise.
        Une capture vit dans le présent ; un fichier vit à la date de ses paquets.
        """
        import datetime as dt

        return dt.datetime.now(dt.timezone.utc)

    def arreter(self) -> None:
        """Ferme la capture. Sans effet si elle n'est pas active."""
        with self._verrou:
            if self._sniffer is None:
                return
            try:
                self._sniffer.stop()
            except Exception as erreur:              # noqa: BLE001
                logger.warning("Arrêt de la capture : %s", erreur)
            finally:
                self._sniffer = None

    # -------------------------------------------------------------- traitement
    def _traiter(self, paquet: Any) -> None:
        """Appelé par Scapy pour chaque paquet : on le parse, puis on le transmet.

        Toute erreur est absorbée ici. Une exception qui remonte dans le fil de capture
        arrêterait le sniffer — un paquet malformé suffirait alors à faire taire
        l'analyseur, ce qui est exactement le contraire du but.
        """
        from agent import parser

        try:
            fiche = parser.analyser(paquet, dt.datetime.now(dt.timezone.utc))
            self.recus += 1
            if fiche.get("analyse_partielle"):
                self.erreurs_analyse += 1
            if self.sur_paquet:
                self.sur_paquet(fiche)
        except Exception as erreur:                  # noqa: BLE001
            self.erreurs_analyse += 1
            logger.warning("Paquet ignoré (%s) : %s", type(erreur).__name__, erreur)


def _expliquer(erreur: Exception) -> str:
    """Traduit un échec technique en message utilisable.

    C'est la partie que l'utilisateur voit. « PermissionError » ne lui dit pas quoi
    faire ; ces messages-là, si.
    """
    texte = f"{type(erreur).__name__}: {erreur}"
    bas = texte.lower()

    if "winerror 5" in bas or "permissionerror" in bas or "access is denied" in bas:
        return (
            "Accès refusé par le pilote de capture.\n"
            "  Cause probable : Npcap restreint la capture aux administrateurs.\n"
            "  Solutions, dans l'ordre :\n"
            "   1. relancer l'agent depuis un terminal « Exécuter en tant qu'administrateur » ;\n"
            "   2. ou réinstaller Npcap en décochant « Restrict Npcap driver's access to\n"
            "      Administrators only » pendant l'installation."
        )
    if "npcap" in bas or "wpcap" in bas or "libpcap" in bas:
        return (
            "Npcap n'est pas installé (ou sa DLL est introuvable).\n"
            "  Téléchargement : https://npcap.com/#download\n"
            "  Pendant l'installation, laisser cochée l'option « Install Npcap in WinPcap API\n"
            "  compatible Mode » : c'est ce mode que Scapy utilise."
        )
    if "no such device" in bas or "not found" in bas:
        return (
            "L'interface demandée n'existe pas ou n'est pas reconnue par le pilote.\n"
            "  Lancez `python agent/main.py --interfaces` pour voir la liste exacte."
        )
    if "timeout" in bas:
        return "La carte réseau n'a pas répondu dans le délai imparti. Réessayez."
    return f"Capture impossible. Détail technique : {texte}"
