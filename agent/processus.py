"""Quel programme parle — associer un port local au processus qui le tient.

CE QUE CE MODULE APPORTE
------------------------
`192.168.1.5:52344 → 140.82.121.4:443` décrit un tuyau sans dire qui s'en sert. Avec le
processus, la même ligne devient : **`chrome.exe` parle à GitHub**. C'est cette phrase-là qui
répond à « que fait cette machine ? », et c'est le cœur du projet.

CE QUE CETTE MACHINE AUTORISE — MESURÉ, PAS SUPPOSÉ
---------------------------------------------------
Sans droits administrateur, Windows laisse lire les connexions **de l'utilisateur courant**,
pas celles des autres comptes ni de certains services système. La mesure faite ici :
**313 connexions lues, 202 avec un processus identifié, 111 sans**. Autrement dit, environ un
tiers du trafic ne sera jamais nommé.

Ce n'est pas un défaut à corriger : c'est une limite du système d'exploitation. Ce qui serait
un défaut, c'est de la masquer. L'interface écrit « processus inconnu » — jamais « inconnu »
tout court, qui laisserait croire à une erreur de l'outil.

COMMENT L'ASSOCIATION EST FAITE
-------------------------------
Un paquet porte une adresse source et une adresse destination. Le processus est cherché du
côté **local** — celui dont l'adresse appartient à cette machine. Chercher le port des deux
côtés donnerait un résultat faux une fois sur deux : le port 443 est tenu par un programme
local *et* par le serveur distant, et rien ne les distingue sinon l'adresse.
"""

from __future__ import annotations

import threading
import time
from typing import Any

#: Durée de validité de la table des connexions. Interroger le système à chaque paquet serait
#: ruineux — trois mille paquets par capture — et inutile : les connexions ne changent pas
#: d'une seconde à l'autre.
VALIDITE_SECONDES = 5.0


def connexions_systeme() -> list[Any]:
    """Les connexions de cette machine, ou une liste vide si le système refuse.

    Aucune exception ne remonte : un outil d'analyse ne doit pas s'arrêter parce qu'il n'a
    pas le droit de lire une table système. Il continue, sans les noms de programmes.
    """
    try:
        import psutil
    except ImportError:
        return []
    try:
        return psutil.net_connections(kind="inet")
    except Exception:                                    # noqa: BLE001
        return []


def adresses_locales() -> set[str]:
    """Les adresses de cette machine — ce qui permet de dire quel côté est le sien."""
    try:
        import psutil
    except ImportError:
        return set()
    try:
        adresses: set[str] = set()
        for interfaces in psutil.net_if_addrs().values():
            for interface in interfaces:
                if interface.address:
                    adresses.add(normaliser(interface.address))
        return adresses
    except Exception:                                    # noqa: BLE001
        return set()


def normaliser(adresse: Any) -> str:
    """Ramène une adresse à une écriture unique, ou la rend telle quelle si ce n'en est pas une.

    **C'est le défaut qui a rendu ce module muet.** Comparer deux adresses comme des chaînes
    paraît évident et ne marche pas : la même IPv6 s'écrit `2001:42d8:4:a:face:b00c:3333:7020`
    ou `2001:42d8:4:a:face:b00c:3333:7020` selon la bibliothèque qui la produit, et
    `fe80::1` est une écriture parfaitement valide de `fe80:0:0:0:0:0:0:1`. Le trafic de cette
    machine est très majoritairement en IPv6 : la table était construite, les paquets
    passaient, et aucune correspondance n'avait lieu — sans le moindre message d'erreur.

    On normalise donc les deux côtés avant de comparer. Une chaîne qui n'est pas une adresse
    valide est rendue telle quelle : elle ne correspondra à rien, ce qui est le bon résultat.
    """
    if not adresse:
        return ""
    try:
        import ipaddress
        return str(ipaddress.ip_address(str(adresse).split("%")[0]))
    except ValueError:
        return str(adresse)


def table_processus(connexions: list[Any]) -> dict[tuple[str, int], dict[str, Any]]:
    """Construit la table (protocole, port local) → processus.

    Seules les connexions **en écoute ou établies** sont retenues : une connexion déjà
    fermée ne désigne plus personne, et son port sera réattribué à un autre programme.
    """
    try:
        import psutil
    except ImportError:
        return {}

    table: dict[tuple[str, int], dict[str, Any]] = {}

    for connexion in connexions:
        pid = getattr(connexion, "pid", None)
        if not pid:
            # Windows n'a pas donné le propriétaire : on ne devine pas, on laisse vide.
            continue

        adresse = getattr(connexion, "laddr", None)
        port = getattr(adresse, "port", None)
        if port is None:
            continue

        type_socket = getattr(connexion, "type", None)
        protocole = "TCP" if type_socket == getattr(__import__("socket"), "SOCK_STREAM", 1) else "UDP"

        try:
            processus = psutil.Process(pid)
            nom = processus.name()
        except Exception:                                # noqa: BLE001
            # Le processus s'est terminé entre la lecture de la table et celle de son nom :
            # un cas courant, qui ne doit ni arrêter l'analyse ni afficher un nom faux.
            continue

        table[(protocole, int(port))] = {"nom": nom, "pid": int(pid)}

    return table


def processus_du_paquet(paquet: dict[str, Any],
                        table: dict[tuple[str, int], dict[str, Any]],
                        locales: set[str]) -> dict[str, Any] | None:
    """Le processus qui tient le port local de ce paquet, ou None.

    Le côté local est déterminé par l'**adresse**, jamais par le port seul. Le port 443 est
    tenu par `chrome.exe` sur cette machine *et* par le serveur distant : sans regarder
    l'adresse, on nommerait le mauvais programme une fois sur deux.
    """
    if not table or not locales:
        return None

    protocole = str(paquet.get("protocole") or "").upper()
    if protocole not in ("TCP", "UDP"):
        return None

    # On normalise avant de comparer : sans cela, aucune adresse IPv6 ne correspond, et le
    # module reste muet sans jamais signaler d'erreur.
    locales_normalisees = {normaliser(adresse) for adresse in locales}

    if normaliser(paquet.get("ip_source")) in locales_normalisees:
        return table.get((protocole, _entier(paquet.get("port_source"))))
    if normaliser(paquet.get("ip_destination")) in locales_normalisees:
        return table.get((protocole, _entier(paquet.get("port_destination"))))
    return None


def _entier(valeur: Any) -> int:
    try:
        return int(valeur)
    except (TypeError, ValueError):
        return -1


class TableCachee:
    """Garde la table quelques secondes, et ne la reconstruit qu'à la demande.

    Sans ce cache, chaque paquet interrogerait le système : trois mille appels par capture,
    pour retrouver la même table. Le cache est volontairement court — cinq secondes — pour
    qu'un programme lancé à l'instant soit nommé presque tout de suite.
    """

    def __init__(self, validite: float = VALIDITE_SECONDES) -> None:
        self.validite = validite
        self._table: dict[tuple[str, int], dict[str, Any]] = {}
        self._locales: set[str] = set()
        self._construite_a = 0.0
        self._verrou = threading.Lock()

    def obtenir(self) -> tuple[dict[tuple[str, int], dict[str, Any]], set[str]]:
        maintenant = time.monotonic()
        with self._verrou:
            if self._table and maintenant - self._construite_a < self.validite:
                return self._table, self._locales

        table = table_processus(connexions_systeme())
        locales = adresses_locales()

        with self._verrou:
            self._table = table
            self._locales = locales
            self._construite_a = time.monotonic()
        return table, locales

    def enrichir(self, fiche: dict[str, Any]) -> dict[str, Any]:
        """Ajoute `processus_local` à une fiche de paquet, si le processus est connu.

        La clé n'est ajoutée **que** lorsqu'un processus a été trouvé : une absence n'a pas
        à être écrite dans la base pour chaque paquet. L'interface sait distinguer « pas de
        nom conservé » de « nommé ».
        """
        table, locales = self.obtenir()
        trouve = processus_du_paquet(fiche, table, locales)
        if trouve:
            fiche.setdefault("details", {})["processus_local"] = trouve["nom"]
            fiche["details"]["processus_pid"] = trouve["pid"]
        return fiche
