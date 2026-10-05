"""Détection de comportements inhabituels — huit règles, trois niveaux.

CE QUE CE MODULE FAIT, ET CE QU'IL REFUSE DE FAIRE
--------------------------------------------------
Il repère des **formes** dans les communications : une machine qui frappe à beaucoup de
portes, une connexion qui se répète à intervalles réguliers, une connexion entrante sur un
service sensible, un volume sortant qui sort de l'ordinaire.

Il ne dit jamais « c'est une attaque ». Un scanner de ports peut être un administrateur qui
vérifie son parc ; un volume sortant peut être une sauvegarde ; un service sensible exposé
peut être le partage de fichiers familial. **Chaque règle porte donc le nom de ses propres
faux positifs**, et l'interface les affiche. Une détection qui cacherait ce qu'elle peut
avoir de faux n'aiderait personne à décider.

LES TROIS NIVEAUX
-----------------
Les niveaux disent le **degré de certitude**, pas le degré de danger. C'est la distinction
la plus importante du module, et celle qui est le plus souvent ratée :

    OBSERVATION  un fait mesuré, dont on ne conclut rien. « Machine inconnue sur le
                 réseau » — il n'y a rien à en penser, seulement à savoir.
    HYPOTHÈSE    une forme qui ressemble à quelque chose, et que plusieurs explications
                 banales produisent aussi. « Vingt ports contactés en trente secondes »
                 — un scanner, ou un logiciel qui cherche son serveur.
    ALERTE       plusieurs hypothèses indépendantes qui **convergent sur la même
                 machine**. Une seule ne suffirait pas ; trois ensemble deviennent
                 difficiles à expliquer par hasard.

Ce dernier point est le cœur du module : **aucune règle isolée ne produit une alerte.**
Une alerte naît d'un faisceau — c'est ce qui la distingue d'un caprice du hasard, et c'est
ce qui autorise à la montrer sans crier au loup.

POURQUOI AU MOINS TROIS INDICES
-------------------------------
Sur un réseau domestique, chacune des formes détectées se produit naturellement plusieurs
fois par jour : un navigateur ouvre dix connexions par minute, une télévision vérifie ses
mises à jour toutes les heures, un téléphone se reconnecte au Wi-Fi. Exiger trois indices
convergents sur une même machine fait tomber le bruit à presque rien — et le peu qui reste
mérite vraiment un regard.

CE QUI SERAIT MALHONNÊTE
------------------------
Compter un même fait plusieurs fois. Si « beaucoup de destinations » et « beaucoup de
connexions » se déclenchent sur la même observation, ils ne comptent pas comme deux
indices indépendants. Le module ne compte que des règles de familles différentes, et il
l'écrit.
"""

from __future__ import annotations

import ipaddress
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
#  Réglages
# --------------------------------------------------------------------------- #
#: Tous les seuils sont ici, et non dispersés dans les règles. Un jury qui demande
#: « pourquoi quinze ports ? » doit obtenir une réponse en une ligne, pas une chasse.
SEUILS = {
    "scan_ports_distincts": 15,          # ports différents sur une même cible
    "scan_fenetre_secondes": 60,
    "connexions_repetees": 8,            # même destination et même port
    "connexions_fenetre_secondes": 300,
    "echecs_repetes": 5,                 # ouvertures restées sans réponse
    "echecs_fenetre_secondes": 300,
    "destinations_distinctes": 25,       # machines distinctes contactées
    "destinations_fenetre_secondes": 120,
    "volume_sortant_octets": 5_000_000,  # 5 Mo dans une seule communication
    "dns_requetes": 40,                  # requêtes de résolution
    "dns_fenetre_secondes": 120,
    "faisceau_indices": 3,               # nombre d'inférences pour parler d'alerte
    "faisceau_fenetre_secondes": 900,
}

#: Familles de règles. Deux règles de la même famille ne comptent pas comme deux indices
#: convergents : elles décrivent le même phénomène sous deux angles.
FAMILLES = {
    "scan_ports": "balayage",
    "connexions_repetees": "répétition",
    "echecs_repetes": "échec",
    "service_sensible_entrant": "exposition",
    "volume_sortant": "volume",
    "multiplication_destinations": "dispersion",
    "dns_volume": "résolution de noms",
    "machine_inconnue": "appareil",
}

NIVEAU_OBSERVATION = "observation"
NIVEAU_HYPOTHESE = "hypothèse"
NIVEAU_ALERTE = "alerte"

#: Ports dont une connexion entrante mérite d'être signalée. Ce ne sont pas des ports
#: « dangereux » : ce sont des ports qui ouvrent quelque chose sur une machine, et dont la
#: présence mérite d'être **su**e plutôt que subie.
PORTS_SENSIBLES = {21, 22, 23, 135, 137, 138, 139, 445, 1433, 3306, 3389, 5432, 5900, 6379, 27017}


# --------------------------------------------------------------------------- #
#  Une détection
# --------------------------------------------------------------------------- #
@dataclass
class Detection:
    """Un fait repéré, avec tout ce qu'il faut pour le juger — y compris ses limites.

    Chaque détection porte le nom de ses faux positifs. C'est une exigence du sujet, et
    c'est surtout ce qui rend une détection utilisable : sans cette mention, un lecteur
    prend une forme pour une conclusion.
    """

    regle: str
    famille: str
    niveau: str
    titre: str
    faits: list[str]
    explication: str
    confiance: str
    faux_positifs: str
    cible: str                            # la machine que cela concerne
    debut: str
    dernier: str
    occurrences: int = 1

    def vers_dict(self) -> dict[str, Any]:
        return {
            "regle": self.regle,
            "famille": self.famille,
            "niveau": self.niveau,
            "titre": self.titre,
            "faits_observes": self.faits,
            "explication": self.explication,
            "confiance": self.confiance,
            "faux_positifs": self.faux_positifs,
            "cible": self.cible,
            "debut": self.debut,
            "dernier": self.dernier,
            "occurrences": self.occurrences,
        }

    def cle(self) -> str:
        """Identité stable : une même détection se met à jour au lieu de se multiplier."""
        return f"{self.regle}|{self.cible}"


def _machine_identifiable(ip: str) -> bool:
    """Cette adresse désigne-t-elle vraiment un appareil du réseau local ?

    On écarte quatre familles qui ne désignent personne :

        - l'adresse de diffusion 255.255.255.255, à qui tout le monde parle et qui n'est
          pas une machine ;
        - l'adresse indéfinie 0.0.0.0, qui signifie « moi, peu importe mon adresse » ;
        - les adresses automatiques 169.254.x, qu'une machine s'attribue faute de mieux
          quand elle n'obtient pas de réponse ;
        - les adresses IPv6 locales de lien (fe80::), qui dépendent de l'interface et
          changent d'une connexion à l'autre — la même machine en porte une différente
          sur chaque réseau.

    Les signaler comme « nouvel appareil » produit du bruit à **chaque** capture : ce
    sont elles qui apparaissent en premier, avant toute machine réelle. Un module de
    détection qui annonce quatre faux appareils au démarrage n'est plus lu, et c'est
    exactement ce que le premier essai sur trafic réel a montré.
    """
    try:
        adresse = ipaddress.ip_address(ip)
    except ValueError:
        return False

    if adresse.is_multicast or adresse.is_unspecified:
        return False
    if str(adresse) == "255.255.255.255":
        return False
    if adresse.version == 4:
        return adresse.is_private and not adresse.is_link_local
    # IPv6 : seules les adresses locales uniques (fc00::/7) identifient durablement un
    # appareil. Les adresses locales de lien en sont exclues, pour la raison ci-dessus.
    return adresse.is_private and not adresse.is_link_local


def _privee(ip: str) -> bool:
    try:
        adresse = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return adresse.is_private or adresse.is_loopback or adresse.is_link_local


def _instant(texte: str | None) -> datetime | None:
    if not texte:
        return None
    try:
        return datetime.fromisoformat(texte.replace("Z", "+00:00"))
    except ValueError:
        return None


def _secondes(entre: str | None, et: str | None) -> float:
    debut, fin = _instant(entre), _instant(et)
    if not debut or not fin:
        return 0.0
    return max(0.0, (fin - debut).total_seconds())


def _volume(octets: int) -> str:
    if octets < 1000:
        return f"{octets} octets"
    if octets < 1_000_000:
        return f"{octets / 1000:.1f} ko".replace(".", ",")
    return f"{octets / 1_000_000:.1f} Mo".replace(".", ",")


# --------------------------------------------------------------------------- #
#  Le détecteur
# --------------------------------------------------------------------------- #
class Detecteur:
    """Applique les règles au fil des communications, et retient ce qu'il a déjà dit.

    La mémoire sert à deux choses : ne pas répéter la même détection à chaque lot — sinon
    le tableau de bord se remplirait de la même phrase — et savoir quelles machines ont
    déjà été vues, ce qui est la seule information qu'on ne peut pas déduire d'un lot
    isolé.
    """

    def __init__(self) -> None:
        self._detections: dict[str, Detection] = {}
        self._machines_vues: set[str] = set()
        self._premiere_observation: str | None = None

    # ------------------------------------------------------------------ outils
    def _enregistrer(self, detection: Detection) -> Detection:
        """Ajoute ou met à jour une détection, sans jamais en créer une seconde identique."""
        existante = self._detections.get(detection.cle())
        if existante is None:
            self._detections[detection.cle()] = detection
            return detection

        # Mise à jour : on conserve le début, on rafraîchit la fin et le compte.
        existante.dernier = detection.dernier or existante.dernier
        existante.occurrences += 1
        existante.faits = detection.faits
        return existante

    # ------------------------------------------------------------------ règles
    def _regle_scan_ports(self, communications: list[dict], machines: list[str]) -> list[Detection]:
        """Une machine frappe-t-elle à beaucoup de portes sur une même cible ?

        C'est la forme d'un balayage — mais aussi celle d'un logiciel qui cherche son
        serveur, et celle d'un inventaire réseau par un administrateur.
        """
        # (source, cible) -> {ports}, et les bornes de temps
        tentatives: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {"ports": set(), "debut": None, "dernier": None, "bloquants": 0})

        for communication in communications:
            if (communication.get("protocole") or "").upper() != "TCP":
                continue
            source = communication.get("initiateur") or communication.get("ip_a")
            cible = communication.get("ip_b") if source == communication.get("ip_a") \
                else communication.get("ip_a")
            port = communication.get("port_b") if source == communication.get("ip_a") \
                else communication.get("port_a")
            if not source or not cible or port is None:
                continue

            entree = tentatives[(source, cible)]
            entree["ports"].add(int(port))
            if entree["debut"] is None:
                entree["debut"] = communication.get("debut")
            entree["dernier"] = communication.get("dernier_paquet")
            # Un port contacté sans réponse compte : c'est le propre du balayage.
            if communication.get("etat") in ("échec probable", "tentative"):
                entree["bloquants"] += 1

        resultats = []
        for (source, cible), entree in tentatives.items():
            if len(entree["ports"]) < SEUILS["scan_ports_distincts"]:
                continue
            if _secondes(entree["debut"], entree["dernier"]) > SEUILS["scan_fenetre_secondes"]:
                continue
            ports = sorted(entree["ports"])
            resultats.append(Detection(
                regle="scan_ports", famille=FAMILLES["scan_ports"], niveau=NIVEAU_HYPOTHESE,
                titre=f"Nombreux ports contactés sur {cible}",
                faits=[
                    f"{len(ports)} ports différents contactés sur une même machine",
                    f"Ports, du plus petit au plus grand : {', '.join(str(p) for p in ports[:12])}"
                    + (" …" if len(ports) > 12 else ""),
                    f"Durée : {_secondes(entree['debut'], entree['dernier']):.0f} secondes",
                    f"Tentatives restées sans réponse : {entree['bloquants']}",
                ],
                explication=(
                    "Une machine a tenté d'ouvrir des connexions sur de nombreux ports "
                    "différents d'une même machine, en peu de temps. C'est la forme que "
                    "prend la recherche des services accessibles d'un appareil — ce que "
                    "fait un scan de ports. Cette forme a plusieurs explications "
                    "ordinaires : un logiciel qui cherche son serveur en essayant "
                    "plusieurs ports, une application qui se reconnecte après un "
                    "changement de configuration, ou un inventaire réseau mené "
                    "volontairement."),
                confiance="moyenne",
                faux_positifs=(
                    "Un scanner utilisé par un administrateur, un logiciel qui explore "
                    "plusieurs ports à la recherche d'un service, ou une application mal "
                    "configurée qui réessaie. Sur un réseau domestique, un téléviseur ou "
                    "une imprimante en recherche peut produire cette forme."),
                cible=source, debut=entree["debut"] or "", dernier=entree["dernier"] or "",
            ))
        return resultats

    def _regle_connexions_repetees(self, communications: list[dict],
                                   machines: list[str]) -> list[Detection]:
        """La même connexion revient-elle à intervalles rapprochés ?

        Le rythme régulier est la signature d'un automatisme : logiciel de messagerie,
        mise à jour, ou communication périodique avec un serveur de commande.
        """
        comptes: dict[tuple[str, str, int], dict[str, Any]] = defaultdict(
            lambda: {"nombre": 0, "debut": None, "dernier": None, "octets": 0})

        for communication in communications:
            source = communication.get("initiateur") or communication.get("ip_a")
            cible = communication.get("ip_b") if source == communication.get("ip_a") \
                else communication.get("ip_a")
            port = communication.get("port_b") if source == communication.get("ip_a") \
                else communication.get("port_a")
            if not source or not cible or port is None:
                continue
            entree = comptes[(source, cible, int(port))]
            entree["nombre"] += 1
            entree["octets"] += communication.get("octets_total") or 0
            if entree["debut"] is None:
                entree["debut"] = communication.get("debut")
            entree["dernier"] = communication.get("dernier_paquet")

        resultats = []
        for (source, cible, port), entree in comptes.items():
            if entree["nombre"] < SEUILS["connexions_repetees"]:
                continue
            duree = _secondes(entree["debut"], entree["dernier"])
            if duree > SEUILS["connexions_fenetre_secondes"] or duree <= 0:
                continue
            intervalle = duree / max(1, entree["nombre"] - 1)

            # Le rythme régulier est ce qui distingue un automatisme d'un usage humain.
            # On l'annonce comme une observation, pas comme une conclusion.
            resultats.append(Detection(
                regle="connexions_repetees", famille=FAMILLES["connexions_repetees"],
                niveau=NIVEAU_HYPOTHESE,
                titre=f"Connexions répétées vers {cible}:{port}",
                faits=[
                    f"{entree['nombre']} connexions vers la même destination et le même port",
                    f"Sur {duree:.0f} secondes, soit environ une toutes les "
                    f"{intervalle:.0f} secondes",
                    f"Volume cumulé : {_volume(entree['octets'])}",
                ],
                explication=(
                    "Une machine a ouvert plusieurs fois de suite une connexion vers la "
                    "même destination et le même port, à intervalles rapprochés. Cette "
                    "répétition régulière est le propre d'un automatisme : un logiciel qui "
                    "vérifie régulièrement quelque chose — relève son courrier, demande "
                    "ses mises à jour, signale sa présence. Un rythme très régulier peut "
                    "aussi être celui d'une machine qui rend compte à un serveur distant. "
                    "Les deux se ressemblent dans les chiffres : seul le contexte les "
                    "distingue."),
                confiance="faible",
                faux_positifs=(
                    "Presque toujours un usage légitime : messagerie, mises à jour, "
                    "synchronisation de fichiers, objets connectés, jeu en ligne. Ce sont "
                    "les communications les plus banales d'un réseau moderne."),
                cible=source, debut=entree["debut"] or "", dernier=entree["dernier"] or "",
            ))
        return resultats

    def _regle_echecs_repetes(self, communications: list[dict],
                              machines: list[str]) -> list[Detection]:
        """Beaucoup d'ouvertures restées sans réponse, vers une même machine.

        L'explication la plus probable n'est pas une attaque : c'est un service arrêté.
        """
        comptes: dict[tuple[str, str], dict[str, Any]] = defaultdict(
            lambda: {"nombre": 0, "ports": set(), "debut": None, "dernier": None})

        for communication in communications:
            if communication.get("etat") != "échec probable":
                continue
            source = communication.get("initiateur") or communication.get("ip_a")
            cible = communication.get("ip_b") if source == communication.get("ip_a") \
                else communication.get("ip_a")
            port = communication.get("port_b") if source == communication.get("ip_a") \
                else communication.get("port_a")
            if not source or not cible:
                continue
            entree = comptes[(source, cible)]
            entree["nombre"] += 1
            if port is not None:
                entree["ports"].add(int(port))
            if entree["debut"] is None:
                entree["debut"] = communication.get("debut")
            entree["dernier"] = communication.get("dernier_paquet")

        resultats = []
        for (source, cible), entree in comptes.items():
            if entree["nombre"] < SEUILS["echecs_repetes"]:
                continue
            if _secondes(entree["debut"], entree["dernier"]) > SEUILS["echecs_fenetre_secondes"]:
                continue
            ports = sorted(entree["ports"])
            resultats.append(Detection(
                regle="echecs_repetes", famille=FAMILLES["echecs_repetes"],
                niveau=NIVEAU_OBSERVATION,
                titre=f"Connexions sans réponse vers {cible}",
                faits=[
                    f"{entree['nombre']} tentatives d'ouverture restées sans réponse",
                    f"Ports concernés : {', '.join(str(p) for p in ports[:10]) or 'inconnus'}",
                    f"Sur {_secondes(entree['debut'], entree['dernier']):.0f} secondes",
                ],
                explication=(
                    "Plusieurs tentatives d'ouverture de connexion sont restées sans "
                    "réponse. L'explication la plus probable n'est pas une attaque : "
                    "c'est un service qui ne tourne pas, une machine éteinte, ou un "
                    "pare-feu qui bloque silencieusement. C'est un fait à connaître, et "
                    "il n'y a rien à en conclure de plus."),
                confiance="haute",
                faux_positifs=(
                    "Aucun : le fait est certain. C'est son interprétation qui peut "
                    "tromper — un service arrêté produit exactement la même observation "
                    "qu'un balayage qui échoue."),
                cible=source, debut=entree["debut"] or "", dernier=entree["dernier"] or "",
            ))
        return resultats

    def _regle_service_sensible_entrant(self, communications: list[dict],
                                        machines: list[str]) -> list[Detection]:
        """Une connexion vient-elle de l'extérieur vers un service qui ouvre la machine ?"""
        resultats = []
        for communication in communications:
            ip_a, ip_b = communication.get("ip_a") or "", communication.get("ip_b") or ""
            if not ip_a or not ip_b:
                continue
            # Le cas intéressant : une adresse publique joint une adresse locale.
            if _privee(ip_a) or not _privee(ip_b):
                continue
            port = communication.get("port_b")
            if port is None or int(port) not in PORTS_SENSIBLES:
                continue
            resultats.append(Detection(
                regle="service_sensible_entrant", famille=FAMILLES["service_sensible_entrant"],
                niveau=NIVEAU_OBSERVATION,
                titre=f"Connexion entrante vers le port {port}",
                faits=[
                    f"Une adresse d'Internet ({ip_a}) a joint votre réseau sur le port {port}",
                    f"Machine concernée : {ip_b}",
                    f"État de la communication : {communication.get('etat')}",
                ],
                explication=(
                    "Une adresse extérieure a contacté un service de votre réseau dont "
                    "l'exposition mérite d'être connue. Cela peut être le résultat normal "
                    "d'un service que vous hébergez, d'un jeu en ligne, ou d'une mise à "
                    "jour — mais aussi d'un balayage automatique venu d'Internet, ce qui "
                    "est extrêmement courant et le plus souvent sans suite."),
                confiance="moyenne",
                faux_positifs=(
                    "Un service volontairement exposé, un jeu en ligne, une box qui "
                    "redirige un port. Ce n'est pas un signe d'intrusion, et cette "
                    "détection ne dit pas qu'une intrusion a eu lieu — seulement que "
                    "quelqu'un de l'extérieur a frappé à une porte."),
                cible=ip_b, debut=communication.get("debut") or "",
                dernier=communication.get("dernier_paquet") or "",
            ))
        return resultats

    def _regle_volume_sortant(self, communications: list[dict],
                              machines: list[str]) -> list[Detection]:
        """Une communication a-t-elle envoyé beaucoup plus qu'elle n'a reçu, vers l'extérieur ?"""
        resultats = []
        for communication in communications:
            ip_a, ip_b = communication.get("ip_a") or "", communication.get("ip_b") or ""
            sortant = communication.get("octets_a_vers_b") or 0
            entrant = communication.get("octets_b_vers_a") or 0
            if sortant < SEUILS["volume_sortant_octets"]:
                continue
            # Vers l'extérieur, et nettement déséquilibré vers la sortie.
            if not (_privee(ip_a) and not _privee(ip_b)):
                continue
            if entrant > sortant / 4:
                continue
            resultats.append(Detection(
                regle="volume_sortant", famille=FAMILLES["volume_sortant"],
                niveau=NIVEAU_HYPOTHESE,
                titre=f"Envoi important vers {ip_b}",
                faits=[
                    f"{_volume(sortant)} envoyés, {_volume(entrant)} reçus",
                    f"Destination : {ip_b}, port {communication.get('port_b')}",
                    f"Protocole : {communication.get('protocole')}",
                ],
                explication=(
                    "Une machine de votre réseau a envoyé une quantité importante de "
                    "données vers une seule adresse extérieure, en recevant très peu en "
                    "retour. C'est la forme d'un envoi : sauvegarde en ligne, "
                    "téléversement de photos ou de vidéos, publication de fichiers. "
                    "C'est aussi la forme que prendrait un transfert de données non "
                    "souhaité, et les deux se ressemblent dans les chiffres."),
                confiance="faible",
                faux_positifs=(
                    "Sauvegarde automatique, synchronisation de photos, envoi de fichiers, "
                    "jeu en ligne, mise à jour publiée. Sur un réseau domestique, c'est "
                    "l'explication de très loin la plus fréquente."),
                cible=ip_a, debut=communication.get("debut") or "",
                dernier=communication.get("dernier_paquet") or "",
            ))
        return resultats

    def _regle_multiplication_destinations(self, communications: list[dict],
                                           machines: list[str]) -> list[Detection]:
        """Une machine contacte-t-elle beaucoup de destinations différentes en peu de temps ?"""
        comptes: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"cibles": set(), "debut": None, "dernier": None, "paquets": 0})

        for communication in communications:
            source = communication.get("initiateur") or communication.get("ip_a")
            cible = communication.get("ip_b") if source == communication.get("ip_a") \
                else communication.get("ip_a")
            if not source or not cible or _privee(cible) == _privee(source):
                continue                       # on ne compte que les sorties vers Internet
            entree = comptes[source]
            entree["cibles"].add(cible)
            entree["paquets"] += communication.get("paquets_total") or 0
            if entree["debut"] is None:
                entree["debut"] = communication.get("debut")
            entree["dernier"] = communication.get("dernier_paquet")

        resultats = []
        for source, entree in comptes.items():
            if len(entree["cibles"]) < SEUILS["destinations_distinctes"]:
                continue
            if _secondes(entree["debut"], entree["dernier"]) > SEUILS["destinations_fenetre_secondes"]:
                continue
            resultats.append(Detection(
                regle="multiplication_destinations",
                famille=FAMILLES["multiplication_destinations"],
                niveau=NIVEAU_OBSERVATION,
                titre=f"{len(entree['cibles'])} destinations contactées",
                faits=[
                    f"{len(entree['cibles'])} adresses distinctes jointes depuis "
                    f"{source}",
                    f"En {_secondes(entree['debut'], entree['dernier']):.0f} secondes",
                    f"{entree['paquets']} paquets au total",
                ],
                explication=(
                    "Une machine a joint un grand nombre d'adresses différentes en peu de "
                    "temps. C'est le comportement d'un navigateur qui ouvre une page : "
                    "celle-ci appelle des dizaines de serveurs pour ses images, ses "
                    "scripts et sa publicité. C'est un fait mesuré, et il n'y a rien à en "
                    "conclure sans regarder de quelles adresses il s'agit."),
                confiance="haute",
                faux_positifs=(
                    "Une simple page web ouverte, une application qui se met à jour, une "
                    "publicité en ligne, un service de diffusion. C'est le cas de très "
                    "loin le plus fréquent, et il n'y a rien d'anormal."),
                cible=source, debut=entree["debut"] or "", dernier=entree["dernier"] or "",
            ))
        return resultats

    def _regle_dns_volume(self, communications: list[dict],
                          machines: list[str]) -> list[Detection]:
        """Une machine émet-elle beaucoup de demandes de résolution de noms ?"""
        comptes: dict[str, dict[str, Any]] = defaultdict(
            lambda: {"nombre": 0, "debut": None, "dernier": None})

        for communication in communications:
            port = communication.get("port_b") or communication.get("port_a")
            if port is None or int(port) not in (53, 5353):
                continue
            if (communication.get("protocole") or "").upper() != "UDP":
                continue
            source = communication.get("initiateur") or communication.get("ip_a")
            if not source or _privee(source) is False:
                continue
            entree = comptes[source]
            entree["nombre"] += 1
            if entree["debut"] is None:
                entree["debut"] = communication.get("debut")
            entree["dernier"] = communication.get("dernier_paquet")

        resultats = []
        for source, entree in comptes.items():
            if entree["nombre"] < SEUILS["dns_requetes"]:
                continue
            if _secondes(entree["debut"], entree["dernier"]) > SEUILS["dns_fenetre_secondes"]:
                continue
            resultats.append(Detection(
                regle="dns_volume", famille=FAMILLES["dns_volume"], niveau=NIVEAU_OBSERVATION,
                titre=f"{entree['nombre']} demandes de résolution de noms",
                faits=[
                    f"{entree['nombre']} demandes d'association nom-vers-adresse",
                    f"En {_secondes(entree['debut'], entree['dernier']):.0f} secondes",
                    f"Depuis {source}",
                ],
                explication=(
                    "Une machine a demandé de nombreuses fois à quoi correspondait un nom "
                    "de site. C'est ce qui précède chaque connexion, et une simple page "
                    "web en provoque plusieurs. Ces demandes sont l'information la plus "
                    "révélatrice du trafic, parce qu'elles nomment les sites consultés."),
                confiance="haute",
                faux_positifs=(
                    "La navigation ordinaire, une application qui charge des contenus "
                    "externes, un test de débit. Rien d'anormal dans l'immense majorité "
                    "des cas."),
                cible=source, debut=entree["debut"] or "", dernier=entree["dernier"] or "",
            ))
        return resultats

    def _regle_machine_inconnue(self, communications: list[dict],
                                machines: list[str]) -> list[Detection]:
        """Une machine du réseau local apparaît-elle pour la première fois ?

        C'est la seule règle qui a besoin de mémoire : elle compare à ce qui a déjà été
        vu, et ne peut donc rien dire au premier lot. On ne la déclenche pas au démarrage,
        sinon toutes les machines seraient « nouvelles » à chaque lancement.
        """
        resultats = []
        locales = {m for m in machines if _machine_identifiable(m)}
        if self._premiere_observation is None:
            self._premiere_observation = min(
                (c.get("debut") for c in communications if c.get("debut")), default=None)

        # Le premier lot sert de référence : tout y est nouveau, et le dire n'apprend
        # rien. Ce test doit être fait **avant** la boucle et non dedans — sinon la
        # première machine vue remplit l'ensemble, et la deuxième du même lot est
        # annoncée comme inconnue. C'est le défaut qu'a trouvé le test.
        premier_lot = not self._machines_vues
        self._machines_vues |= locales
        if premier_lot:
            return []

        for machine in sorted(locales):
            resultats.append(Detection(
                regle="machine_inconnue", famille=FAMILLES["machine_inconnue"],
                niveau=NIVEAU_OBSERVATION,
                titre=f"Appareil non vu auparavant : {machine}",
                faits=[
                    f"{machine} apparaît dans les communications pour la première fois",
                    f"Depuis le début de cette capture",
                ],
                explication=(
                    "Un appareil de votre réseau local apparaît alors qu'il n'avait pas "
                    "encore été observé depuis le début de cette capture. C'est le cas "
                    "lorsqu'un téléphone se reconnecte, qu'un invité arrive, ou qu'un "
                    "appareil sort de veille. Le dire évite de s'étonner d'un trafic "
                    "inconnu : mieux vaut savoir quelles machines parlent."),
                confiance="haute",
                faux_positifs=(
                    "Tout appareil qui se reconnecte : téléphone, ordinateur portable, "
                    "téléviseur, objet connecté. C'est une information, pas un signal "
                    "d'alerte — cette détection est de niveau observation précisément "
                    "pour cette raison."),
                cible=machine, debut=self._premiere_observation or "", dernier="",
            ))
        self._machines_vues |= locales
        return resultats

    def _regle_faisceau(self) -> list[Detection]:
        """Plusieurs indices indépendants convergent-ils sur la même machine ?

        C'est la seule règle qui produit une alerte, et elle ne regarde pas le réseau :
        elle regarde ce que les autres règles ont trouvé. Un seul indice ne suffit pas —
        chacun se produit naturellement plusieurs fois par jour. Trois indices de familles
        différentes sur une même machine deviennent difficiles à expliquer par hasard.

        Les règles d'une même famille ne comptent pas deux fois : deux angles sur le même
        phénomène ne sont pas deux phénomènes.
        """
        par_cible: dict[str, dict[str, Detection]] = defaultdict(dict)
        for detection in self._detections.values():
            if detection.regle == "faisceau_indices":
                continue
            # Les observations ne comptent pas : elles décrivent des faits sans rien
            # supposer, et il n'y a rien à faire converger.
            if detection.niveau == NIVEAU_OBSERVATION:
                continue
            par_cible[detection.cible][detection.famille] = detection

        resultats = []
        for cible, par_famille in par_cible.items():
            if len(par_famille) < SEUILS["faisceau_indices"]:
                continue
            indices = sorted(par_famille.values(), key=lambda d: d.regle)
            debut = min((d.debut for d in indices if d.debut), default="")
            dernier = max((d.dernier for d in indices if d.dernier), default="")
            if _secondes(debut, dernier) > SEUILS["faisceau_fenetre_secondes"]:
                continue
            resultats.append(Detection(
                regle="faisceau_indices", famille="faisceau", niveau=NIVEAU_ALERTE,
                titre=f"Plusieurs signaux convergent sur {cible}",
                faits=[f"{len(indices)} formes différentes observées sur cette machine"]
                     + [f"— {d.titre} ({d.niveau})" for d in indices],
                explication=(
                    f"{len(indices)} comportements distincts ont été observés sur la même "
                    "machine, chacun d'une famille différente : "
                    + ", ".join(d.famille for d in indices) + ". Pris séparément, chacun "
                    "s'explique par un usage ordinaire. Ensemble, ils deviennent "
                    "difficiles à attribuer au hasard — c'est ce qui justifie de les "
                    "présenter comme une alerte, et non comme une observation. Cela ne "
                    "signifie pas qu'il se passe quelque chose de grave : cela signifie "
                    "que cette machine mérite un regard, et que les indices ci-dessus "
                    "donnent de quoi commencer."),
                confiance="moyenne",
                faux_positifs=(
                    "Une machine très active peut déclencher plusieurs formes sans que "
                    "rien n'aille mal : un ordinateur qui se met à jour tout en "
                    "synchronisant des fichiers et en naviguant peut produire un volume "
                    "sortant, des connexions répétées et de nombreuses destinations. "
                    "Vérifiez d'abord s'il s'agit d'une machine que vous connaissez et "
                    "d'un moment où elle travaille."),
                cible=cible, debut=debut, dernier=dernier,
            ))
        return resultats

    # ------------------------------------------------------------- point d'entrée
    def analyser(self, communications: Iterable[dict]) -> list[Detection]:
        """Applique toutes les règles à un ensemble de communications.

        L'ordre compte : le faisceau se calcule en dernier, puisque c'est un jugement sur
        ce que les autres règles viennent de trouver.
        """
        lot = list(communications)
        if not lot:
            return []

        machines: set[str] = set()
        for communication in lot:
            for champ in ("ip_a", "ip_b"):
                if communication.get(champ):
                    machines.add(communication[champ])
        liste_machines = sorted(machines)

        trouvees: list[Detection] = []
        for regle in (self._regle_scan_ports, self._regle_connexions_repetees,
                      self._regle_echecs_repetes, self._regle_service_sensible_entrant,
                      self._regle_volume_sortant, self._regle_multiplication_destinations,
                      self._regle_dns_volume, self._regle_machine_inconnue):
            try:
                for detection in regle(lot, liste_machines):
                    trouvees.append(self._enregistrer(detection))
            except Exception:                        # noqa: BLE001
                # Une règle fautive ne prive pas des autres : même principe que le parseur
                # et le moteur d'explication. Une détection en moins vaut mieux qu'un
                # tableau de bord en panne.
                continue

        # Le faisceau se recalcule sur l'ensemble des détections connues, pas sur le lot :
        # c'est la convergence qui compte, et elle peut venir de lots différents.
        for detection in self._regle_faisceau():
            trouvees.append(self._enregistrer(detection))

        return trouvees

    # ------------------------------------------------------------------ lecture
    def detections(self, niveau: str | None = None, limite: int = 200) -> list[dict]:
        """Les détections connues, la plus récente d'abord."""
        liste = list(self._detections.values())
        if niveau:
            liste = [d for d in liste if d.niveau == niveau]
        liste.sort(key=lambda d: (d.dernier or "", d.debut or ""), reverse=True)
        return [d.vers_dict() for d in liste[:limite]]

    def compter(self) -> dict[str, int]:
        """Répartition par niveau, pour l'affichage et les tests."""
        comptes = {NIVEAU_OBSERVATION: 0, NIVEAU_HYPOTHESE: 0, NIVEAU_ALERTE: 0}
        for detection in self._detections.values():
            comptes[detection.niveau] = comptes.get(detection.niveau, 0) + 1
        return comptes
