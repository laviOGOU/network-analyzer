"""Noms de domaine — relier une adresse IP au nom qui l'a désignée.

POURQUOI CE MODULE CHANGE TOUT
------------------------------
`93.184.216.34` ne dit rien à personne. Le même trafic, étiqueté `example.com`, devient
lisible : on reconnaît un site, un service, une application. C'est la différence entre
lire des adresses et comprendre ce qui se passe — et c'est exactement le sujet du projet.

D'où vient le nom
-----------------
Du réseau lui-même, et de nulle part ailleurs. Avant de joindre un serveur, une machine
demande « quelle adresse porte ce nom ? » ; la réponse contient le nom **et** l'adresse.
Ces réponses sont déjà dans les paquets conservés : il suffit de les relire à l'envers.

Aucun annuaire externe n'est interrogé, aucune requête supplémentaire n'est émise. Le nom
affiché est celui que la machine observée a réellement demandé — pas celui qu'un annuaire
tiendrait pour officiel.

CE QUE CE MODULE NE FAIT PAS
----------------------------
Il ne devine pas. Une adresse qui n'apparaît dans aucune réponse DNS reste sans nom, et
l'interface affiche l'adresse seule. Une adresse partagée par des dizaines de noms — un
hébergeur, une ferme de serveurs, un réseau de diffusion — reçoit le nom le plus récemment
observé, et l'interface le dit « d'après le DNS ».

**L'adresse IP n'est jamais remplacée, seulement accompagnée.** Le nom est une commodité ;
l'adresse est le fait. Masquer l'adresse derrière un nom rendrait impossible la
vérification de ce qui a réellement été observé.
"""

from __future__ import annotations

import threading
import time
from typing import Any

#: Durée de validité de l'index. Les noms ne changent pas d'une seconde à l'autre, et les
#: recalculer à chaque rafraîchissement du tableau de bord — toutes les trois secondes —
#: ferait relire des milliers de paquets pour rien.
VALIDITE_SECONDES = 15.0

#: Nombre de paquets relus pour construire l'index. Au-delà, l'index n'apprend plus grand
#: chose : les résolutions récentes suffisent à nommer le trafic récent.
PAQUETS_RELUS = 3000

#: Un nom plus long que cela n'est pas un nom de domaine : c'est un enregistrement TXT ou
#: une donnée détournée. On l'écarte plutôt que de l'afficher dans une colonne.
LONGUEUR_NOM_MAX = 100


def _nom_utilisable(nom: Any) -> str | None:
    """Rend un nom affichable, ou `None` si ce n'en est pas un."""
    if not nom:
        return None
    texte = str(nom).strip().rstrip(".")
    if not texte or len(texte) > LONGUEUR_NOM_MAX:
        return None
    # Un nom de domaine contient au moins un point et aucun caractère de contrôle. Le
    # filtrage protège l'affichage : ces valeurs viennent du réseau.
    if "." not in texte or any(ord(caractere) < 33 for caractere in texte):
        return None
    if not all(caractere.isalnum() or caractere in ".-_" for caractere in texte):
        return None
    return texte.lower()


def indexer(paquets: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    """Construit l'association adresse → nom, à partir des réponses DNS conservées.

    Le parcours va du plus récent au plus ancien et s'arrête au premier nom trouvé pour
    chaque adresse : une adresse qui a porté deux noms dans la fenêtre observée reçoit
    celui qui a été vu le plus récemment — c'est celui qui a le plus de chances de
    correspondre au trafic en cours.
    """
    # On trie nous-mêmes, du plus récent au plus ancien, au lieu de supposer que l'appelant
    # l'a fait. La première version s'en remettait à l'ordre reçu : elle fonctionnait avec
    # un stockage et donnait le mauvais nom avec un autre. Un ordre non garanti n'est pas un
    # ordre — et un test l'a montré.
    tries = sorted(paquets, key=lambda paquet: paquet.get("horodatage") or "", reverse=True)

    trouves: dict[str, dict[str, str]] = {}

    for paquet in tries:
        details = paquet.get("details") or {}
        nom = _nom_utilisable(details.get("dns_reponse_nom") or details.get("dns_question"))
        adresse = details.get("dns_adresse")
        if not nom or not adresse:
            continue

        adresse = str(adresse)
        if adresse in trouves:
            continue                       # le plus récent est déjà retenu

        trouves[adresse] = {
            "nom": nom,
            "vu_le": paquet.get("horodatage") or "",
            "source": "DNS observé",
        }

    return trouves


def nommer(fiche: dict[str, Any], noms: dict[str, dict[str, str]]) -> dict[str, Any]:
    """Ajoute les noms connus à une fiche, sans jamais retirer l'adresse.

    On ajoute deux clés plutôt que d'en remplacer une : l'adresse reste disponible, et
    c'est elle qui reste la référence. Un affichage qui remplacerait l'adresse par un nom
    rendrait impossible la vérification de ce qui a été observé.
    """
    if not noms:
        return fiche
    resultat = dict(fiche)
    for cote in ("a", "b"):
        adresse = resultat.get(f"ip_{cote}")
        information = noms.get(str(adresse)) if adresse else None
        if information:
            resultat[f"nom_{cote}"] = information["nom"]
            resultat[f"nom_{cote}_vu_le"] = information["vu_le"]
    return resultat


class CacheNoms:
    """Garde l'index quelques secondes, et le reconstruit à la demande.

    Sans ce cache, chaque rafraîchissement du tableau de bord — toutes les trois secondes —
    relirait trois mille paquets pour retrouver les mêmes noms. Le cache est volontairement
    court : un nom nouveau doit apparaître dans les secondes qui suivent, pas dans l'heure.
    """

    def __init__(self, validite: float = VALIDITE_SECONDES) -> None:
        self.validite = validite
        self._index: dict[str, dict[str, str]] = {}
        self._construit_a = 0.0
        self._verrou = threading.Lock()

    def obtenir(self, construire) -> dict[str, dict[str, str]]:
        """Rend l'index, en le reconstruisant s'il est trop vieux.

        `construire` est une fonction sans argument qui rend les paquets à parcourir :
        le cache ne sait pas d'où viennent les données, ce qui le rend utilisable avec le
        stockage en mémoire comme avec PostgreSQL.
        """
        maintenant = time.monotonic()
        with self._verrou:
            if self._index and maintenant - self._construit_a < self.validite:
                return self._index

        index = indexer(construire())

        with self._verrou:
            self._index = index
            self._construit_a = temps = time.monotonic()
        return index

    def vider(self) -> None:
        with self._verrou:
            self._index = {}
            self._construit_a = 0.0
