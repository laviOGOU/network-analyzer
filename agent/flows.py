"""Regroupement des paquets en communications — les « flows ».

Qu'est-ce qu'une communication
-------------------------------
Un flow est une conversation entre deux machines, vue des deux côtés à la fois. Un
paquet isolé ne dit presque rien : « 192.168.1.5 a envoyé un SYN vers 443 » n'indique ni
si la connexion s'est établie, ni combien de données ont circulé, ni si elle s'est
terminée proprement. Le flow répond à ces questions.

Trois décisions de conception
-----------------------------

**1. La clé est normalisée.** L'aller et le retour d'une même conversation doivent tomber
dans le même flow. On trie donc les deux extrémités : (A→B) et (B→A) donnent la même clé.
Sans cette normalisation, une connexion compterait comme deux communications distinctes, et
toutes les statistiques seraient fausses d'un facteur deux.

**2. Le sens est conservé.** La clé est triée, mais on retient qui a parlé le premier.
C'est ce qui permet de dire « 12 paquets à l'aller, 8 au retour » — et de distinguer un
client d'un serveur : c'est le client qui envoie le premier SYN.

**3. Un état incertain est annoncé comme incertain.** Si la capture commence au milieu
d'une conversation, on n'a pas vu le début : impossible de dire si la connexion s'est
établie normalement. Le flow porte alors `vu_depuis_le_debut=False` et son état est
marqué comme incertain. Un outil qui afficherait « établie » avec assurance dans ce cas
mentirait par omission.

Les délais d'expiration
-----------------------
Une communication ne se termine pas toujours proprement : un câble débranché, une machine
éteinte, et aucun paquet ne vient signaler la fin. On considère donc une communication
terminée après un silence :

  — TCP : 60 secondes. Une connexion TCP inactive plus d'une minute est presque toujours
    morte, même si aucun FIN n'a été vu.
  — UDP : 30 secondes. Sans notion de connexion, un silence veut dire « c'est fini ».
  — Après un FIN ou un RST : 2 secondes. La fin est explicite, pas besoin d'attendre — et
    une nouvelle connexion entre les mêmes machines ne doit pas se confondre avec
    l'ancienne.

Ces valeurs sont réglables : elles dépendent du réseau observé.
"""

from __future__ import annotations

import datetime as dt
from dataclasses import dataclass, field
from typing import Any, Iterable

# --------------------------------------------------------------------------- #
#  Délais par défaut, en secondes
# --------------------------------------------------------------------------- #
DELAI_TCP = 60.0
DELAI_UDP = 30.0
DELAI_AUTRE = 30.0
DELAI_APRES_FIN = 2.0

#: Durée au-delà de laquelle un SYN sans réponse est considéré comme un échec probable.
#: Trois secondes : c'est le délai après lequel une pile TCP réémet en général.
DELAI_SYN_SANS_REPONSE = 3.0

#: États possibles d'une communication. Les valeurs sont en français : elles finissent
#: affichées telles quelles dans l'interface.
ETAT_TENTATIVE = "tentative"
ETAT_ETABLIE = "etablie"
ETAT_EN_COURS = "en cours"
ETAT_FERMEE = "fermée"
ETAT_ECHEC = "échec probable"
ETAT_INCONNUE = "inconnue"


@dataclass
class Communication:
    """Une conversation entre deux machines, avec ses compteurs par sens."""

    cle: tuple
    protocole: str
    ip_a: str
    ip_b: str
    port_a: int | None
    port_b: int | None

    #: Machine qui a envoyé le premier paquet observé. C'est l'initiatrice présumée.
    initiateur: str = ""
    #: Vrai si l'on a vu le tout premier paquet de la conversation.
    vu_depuis_le_debut: bool = False

    debut: str = ""
    dernier_paquet: str = ""
    termine_le: str | None = None

    paquets_a_vers_b: int = 0
    paquets_b_vers_a: int = 0
    octets_a_vers_b: int = 0
    octets_b_vers_a: int = 0

    #: Indicateurs TCP observés, dans l'ordre d'apparition, sans doublon.
    indicateurs: list[str] = field(default_factory=list)
    #: Fermetures observées, **par sens**. Un seul FIN ne prouve pas une fermeture : il
    #: faut que les deux côtés aient envoyé le leur. Confondre les deux reviendrait à
    #: annoncer « connexion terminée » alors qu'un seul camp a raccroché.
    fin_a_vers_b: bool = False
    fin_b_vers_a: bool = False
    reset_vu: bool = False

    etat: str = ETAT_INCONNUE
    #: Vrai quand l'état repose sur l'observation complète de la conversation.
    etat_certain: bool = False
    note_etat: str = ""

    def duree(self) -> float | None:
        """Durée écoulée entre le premier et le dernier paquet, en secondes."""
        debut, fin = _vers_date(self.debut), _vers_date(self.dernier_paquet)
        if debut is None or fin is None:
            return None
        return max(0.0, (fin - debut).total_seconds())

    @property
    def paquets_total(self) -> int:
        return self.paquets_a_vers_b + self.paquets_b_vers_a

    @property
    def octets_total(self) -> int:
        return self.octets_a_vers_b + self.octets_b_vers_a

    def vers_dict(self) -> dict[str, Any]:
        """Forme transmissible et stockable."""
        return {
            "cle": "|".join(str(element) for element in self.cle),
            "protocole": self.protocole,
            "ip_a": self.ip_a, "ip_b": self.ip_b,
            "port_a": self.port_a, "port_b": self.port_b,
            "initiateur": self.initiateur,
            "vu_depuis_le_debut": self.vu_depuis_le_debut,
            "debut": self.debut, "dernier_paquet": self.dernier_paquet,
            "termine_le": self.termine_le,
            "duree_secondes": round(self.duree() or 0, 3),
            "paquets_a_vers_b": self.paquets_a_vers_b,
            "paquets_b_vers_a": self.paquets_b_vers_a,
            "paquets_total": self.paquets_total,
            "octets_a_vers_b": self.octets_a_vers_b,
            "octets_b_vers_a": self.octets_b_vers_a,
            "octets_total": self.octets_total,
            "indicateurs": ", ".join(self.indicateurs),
            "etat": self.etat,
            "etat_certain": self.etat_certain,
            "note_etat": self.note_etat,
        }


class SuiviCommunications:
    """Table des communications en cours, alimentée paquet par paquet.

    La classe ne fait aucun entrée-sortie : elle reçoit des fiches de paquets et rend des
    communications. C'est ce qui la rend testable sans réseau et réutilisable pour le mode
    replay.
    """

    def __init__(self, delai_tcp: float = DELAI_TCP, delai_udp: float = DELAI_UDP,
                 delai_autre: float = DELAI_AUTRE) -> None:
        self.delai_tcp = delai_tcp
        self.delai_udp = delai_udp
        self.delai_autre = delai_autre
        self._communications: dict[tuple, Communication] = {}

    # ------------------------------------------------------------------ apport
    def ajouter(self, fiche: dict[str, Any]) -> Communication | None:
        """Intègre une fiche de paquet et rend la communication concernée.

        Rend `None` pour un paquet sans adresses IP : un paquet ARP seul, ou une trame
        tronquée, ne constitue pas une conversation entre deux machines.
        """
        ip_source = fiche.get("ip_source")
        ip_destination = fiche.get("ip_destination")
        if not ip_source or not ip_destination:
            return None

        protocole = (fiche.get("protocole") or "inconnu").upper()
        port_source = fiche.get("port_source")
        port_destination = fiche.get("port_destination")

        cle = cle_normalisee(ip_source, port_source, ip_destination, port_destination, protocole)
        communication = self._communications.get(cle)

        if communication is None:
            communication = Communication(
                cle=cle, protocole=protocole,
                ip_a=ip_source, ip_b=ip_destination,
                port_a=port_source, port_b=port_destination,
                # Le premier paquet vu identifie l'initiatrice présumée. Sur un balayage
                # de ports, c'est cette information qui distingue celui qui frappe de
                # celui qui encaisse.
                initiateur=ip_source,
                debut=fiche.get("horodatage") or "",
                # On ne saura qu'à la fin si c'était vraiment le début : pour l'instant,
                # cet indicateur est faux par prudence, et le restera si le premier
                # paquet n'est ni un SYN ni un début plausible de conversation.
                vu_depuis_le_debut=_ressemble_a_un_debut(fiche),
            )
            self._communications[cle] = communication

        # Le sens est calculé une fois et transmis : le recalculer dans chaque fonction
        # les ferait diverger au premier changement de règle.
        meme_sens = (ip_source == communication.ip_a
                     and (port_source == communication.port_a or port_source is None))
        self._compter(communication, fiche, meme_sens)
        self._lire_indicateurs(communication, fiche, meme_sens)
        communication.dernier_paquet = fiche.get("horodatage") or communication.dernier_paquet
        # L'état est évalué par rapport à l'horodatage du dernier paquet, **pas** à
        # l'horloge de la machine. En capture directe les deux coïncident ; en mode
        # replay, ils n'ont rien à voir — et comparer une capture d'hier à l'heure
        # d'aujourd'hui ferait passer chaque SYN sans réponse pour un échec, alors que
        # la réponse est peut-être dans le fichier. C'est `completer_etat`, appelé avec
        # l'heure réelle, qui repère les SYN réellement restés sans réponse.
        maj_etat(communication,
                 _vers_date(communication.dernier_paquet) or dt.datetime.now(dt.timezone.utc))
        return communication

    def _compter(self, communication: Communication, fiche: dict[str, Any],
                 meme_sens: bool) -> None:
        """Incrémente les compteurs du bon sens."""
        taille = fiche.get("taille") or 0
        if meme_sens:
            communication.paquets_a_vers_b += 1
            communication.octets_a_vers_b += taille
        else:
            communication.paquets_b_vers_a += 1
            communication.octets_b_vers_a += taille

    def _lire_indicateurs(self, communication: Communication, fiche: dict[str, Any],
                          meme_sens: bool) -> None:
        """Retient les indicateurs TCP observés et de quel côté la fermeture vient."""
        indicateurs = fiche.get("flags_tcp")
        if not indicateurs:
            return
        for nom in ("SYN", "ACK", "FIN", "RST", "PSH"):
            if nom in indicateurs and nom not in communication.indicateurs:
                communication.indicateurs.append(nom)
        if "FIN" in indicateurs:
            if meme_sens:
                communication.fin_a_vers_b = True
            else:
                communication.fin_b_vers_a = True
            communication.termine_le = fiche.get("horodatage")
        if "RST" in indicateurs:
            communication.reset_vu = True
            communication.termine_le = fiche.get("horodatage")

    # ------------------------------------------------------------------ sortie
    def retirer_terminées(self, maintenant: dt.datetime | None = None) -> list[Communication]:
        """Sort les communications terminées ou expirées de la table.

        On les rend au lieu de les oublier : c'est à l'appelant de décider de les
        transmettre, de les archiver ou de les compter.
        """
        maintenant = maintenant or dt.datetime.now(dt.timezone.utc)
        terminees: list[Communication] = []
        for cle, communication in list(self._communications.items()):
            if self._est_terminee(communication, maintenant):
                terminees.append(communication)
                del self._communications[cle]
        return terminees

    def _est_terminee(self, communication: Communication,
                      maintenant: dt.datetime) -> bool:
        """Une communication est terminée si elle est finie, ou silencieuse trop longtemps."""
        dernier = _vers_date(communication.dernier_paquet)
        if dernier is None:
            return False
        age = (maintenant - dernier).total_seconds()

        # Fin explicite : on n'attend pas le délai complet. Une nouvelle conversation
        # entre les mêmes machines ne doit pas être confondue avec celle-ci.
        if communication.fin_a_vers_b or communication.fin_b_vers_a or communication.reset_vu:
            return age >= DELAI_APRES_FIN

        return age >= self._delai_pour(communication.protocole)

    def _delai_pour(self, protocole: str) -> float:
        if protocole.startswith("TCP"):
            return self.delai_tcp
        if protocole.startswith("UDP"):
            return self.delai_udp
        return self.delai_autre

    def actives(self) -> list[Communication]:
        """Communications en cours, la plus récente d'abord."""
        return sorted(self._communications.values(),
                      key=lambda c: c.dernier_paquet, reverse=True)

    def completer_etat(self, maintenant: dt.datetime | None = None) -> None:
        """Réévalue l'état des communications actives, sans attendre un nouveau paquet.

        Utile pour repérer un SYN resté sans réponse : sans cet appel, l'état ne serait
        recalculé qu'à l'arrivée du paquet suivant — qui n'arrivera jamais, justement.
        """
        maintenant = maintenant or dt.datetime.now(dt.timezone.utc)
        for communication in self._communications.values():
            maj_etat(communication, maintenant)

    def vider(self) -> list[Communication]:
        """Rend toutes les communications et vide la table."""
        toutes = list(self._communications.values())
        self._communications.clear()
        return toutes


# --------------------------------------------------------------------------- #
#  Clé normalisée
# --------------------------------------------------------------------------- #
def cle_normalisee(ip_a: str, port_a: int | None, ip_b: str, port_b: int | None,
                   protocole: str) -> tuple:
    """Clé de communication, identique dans les deux sens.

    On trie les deux extrémités — après les avoir rendues comparables. Un port absent vaut
    moins un : sans cela, ICMP (qui n'a pas de port) produirait une clé contenant `None`,
    et deux paquets ICMP entre les mêmes machines ne se regrouperaient pas.
    """
    extremite_a = (ip_a or "", port_a if port_a is not None else -1)
    extremite_b = (ip_b or "", port_b if port_b is not None else -1)
    premiere, seconde = sorted([extremite_a, extremite_b])
    return (protocole, premiere, seconde)


def _ressemble_a_un_debut(fiche: dict[str, Any]) -> bool:
    """Ce paquet peut-il être le premier d'une conversation ?

    Trois cas seulement : un SYN sans ACK (ouverture), un premier datagramme UDP (rien
    n'annonce un début), ou un paquet ICMP de demande. Tout le reste — un ACK, un FIN, un
    paquet de données — signifie qu'on est arrivé en cours de route.
    """
    protocole = (fiche.get("protocole") or "").upper()
    indicateurs = fiche.get("flags_tcp") or ""
    if protocole == "TCP":
        return "SYN" in indicateurs and "ACK" not in indicateurs
    return protocole in ("UDP", "ICMP", "ICMPV6")


def maj_etat(communication: Communication,
             maintenant: dt.datetime | None = None) -> Communication:
    """Déduit l'état d'une communication à partir de ce qui a été observé.

    Règle absolue : ne jamais présenter une déduction comme une certitude. Chaque état
    posé sur des indices incomplets porte `etat_certain=False` et une note qui explique
    ce qui manque.
    """
    maintenant = maintenant or dt.datetime.now(dt.timezone.utc)
    protocole = communication.protocole
    indicateurs = communication.indicateurs

    # --- Fin explicite : le cas le plus sûr ---------------------------------
    if communication.reset_vu:
        communication.etat = ETAT_FERMEE
        communication.etat_certain = True
        communication.note_etat = ("Fermeture immédiate (RST) : la connexion a été "
                                   "refusée ou interrompue, pas terminée normalement.")
        return communication

    if communication.fin_a_vers_b or communication.fin_b_vers_a:
        communication.etat = ETAT_FERMEE
        # Un FIN vu d'un seul côté ne suffit pas : l'autre peut encore envoyer des
        # données. On ne déclare la fermeture certaine que lorsque les deux ont raccroché.
        des_deux_cotes = communication.fin_a_vers_b and communication.fin_b_vers_a
        communication.etat_certain = des_deux_cotes
        communication.note_etat = ("Fermeture ordonnée observée des deux côtés."
                                   if des_deux_cotes else
                                   "Fermeture entamée : un seul côté a été vu envoyer son FIN, "
                                   "l'autre peut encore transmettre.")
        return communication

    if protocole == "TCP":
        syn = "SYN" in indicateurs
        ack = "ACK" in indicateurs

        if not communication.vu_depuis_le_debut:
            # On est arrivé en cours de route : l'état ne peut pas être établi.
            communication.etat = ETAT_EN_COURS
            communication.etat_certain = False
            communication.note_etat = ("Capture commencée après le début de cette "
                                       "communication : son ouverture n'a pas été observée.")
            return communication

        if syn and not ack and communication.paquets_b_vers_a == 0:
            # SYN seul : soit la connexion est en train de s'ouvrir, soit personne n'a
            # répondu. C'est le délai qui tranche.
            age = _age(communication.dernier_paquet, maintenant)
            if age >= DELAI_SYN_SANS_REPONSE:
                communication.etat = ETAT_ECHEC
                communication.etat_certain = True
                communication.note_etat = (f"Aucune réponse {DELAI_SYN_SANS_REPONSE:.0f} s "
                                          "après la demande d'ouverture : le service est "
                                          "probablement fermé ou filtré.")
            else:
                communication.etat = ETAT_TENTATIVE
                communication.etat_certain = True
                communication.note_etat = "Demande d'ouverture envoyée, réponse non encore observée."
            return communication

        if syn and ack:
            # SYN-ACK vu : le serveur a accepté. Sans le troisième message, la connexion
            # n'est pas encore établie du point de vue du client.
            if communication.paquets_a_vers_b >= 2 and communication.paquets_b_vers_a >= 1:
                communication.etat = ETAT_ETABLIE
                communication.etat_certain = True
                communication.note_etat = "Ouverture complète observée (SYN, SYN-ACK, ACK)."
            else:
                communication.etat = ETAT_TENTATIVE
                communication.etat_certain = False
                communication.note_etat = ("Réponse du serveur observée, mais la "
                                           "confirmation du client ne l'est pas encore.")
            return communication

    # --- Protocoles sans notion de connexion --------------------------------
    # ARP en fait partie : une question et sa réponse, sans ouverture ni fermeture.
    # Inventer un état de connexion pour ARP serait une déduction sans fondement.
    if protocole in ("UDP", "ICMP", "ICMPV6", "ARP"):
        communication.etat = ETAT_EN_COURS
        communication.etat_certain = communication.vu_depuis_le_debut
        communication.note_etat = ("Échanges en cours." if communication.vu_depuis_le_debut
                                   else "Échanges observés en cours de route.")
        return communication

    communication.etat = ETAT_INCONNUE
    communication.etat_certain = False
    communication.note_etat = ("Protocole non reconnu : aucun état de connexion ne peut "
                               "en être déduit.")
    return communication


def _age(horodatage: str | None, maintenant: dt.datetime) -> float:
    date = _vers_date(horodatage)
    if date is None:
        return 0.0
    return max(0.0, (maintenant - date).total_seconds())


def _vers_date(horodatage: str | None) -> dt.datetime | None:
    """Convertit un horodatage ISO en date, sans jamais lever."""
    if not horodatage:
        return None
    try:
        date = dt.datetime.fromisoformat(str(horodatage))
    except (TypeError, ValueError):
        return None
    if date.tzinfo is None:
        date = date.replace(tzinfo=dt.timezone.utc)
    return date


def resume_chiffre(communications: Iterable[Communication]) -> dict[str, Any]:
    """Quelques chiffres sur un ensemble de communications, pour l'affichage."""
    liste = list(communications)
    par_etat: dict[str, int] = {}
    for communication in liste:
        par_etat[communication.etat] = par_etat.get(communication.etat, 0) + 1
    return {
        "communications": len(liste),
        "par_etat": par_etat,
        "octets_total": sum(c.octets_total for c in liste),
        "etats_incertains": sum(1 for c in liste if not c.etat_certain),
    }
