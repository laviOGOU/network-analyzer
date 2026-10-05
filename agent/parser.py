"""Transformation d'un paquet Scapy en enregistrement structuré et sûr.

Principe directeur
------------------
Aucun champ n'est obligatoire. Un paquet peut être tronqué, appartenir à un protocole
que Scapy ne connaît pas, ou être capturé au milieu d'une conversation sans son début.
Le parseur rend alors ce qu'il a compris, et `None` partout ailleurs.

Il ne complète **jamais** un champ manquant par une valeur plausible. Une donnée
inventée serait indétectable en aval : la détection produirait des alertes sur des faits
qui n'existent pas, et l'explication affirmerait des choses fausses. « Je ne sais pas »
est un résultat acceptable ; « probablement 443 » n'en est pas un.

Aucune charge utile applicative n'est conservée : uniquement des métadonnées. Le contenu
d'un message privé n'a aucune raison de finir dans une base partagée.
"""

from __future__ import annotations

import datetime as dt
from typing import Any

from scapy.layers.dns import DNS
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

#: Protocoles reconnus, tels qu'ils seront affichés. Le nom est normalisé (majuscules)
#: pour que « tcp », « TCP » et « Tcp » ne deviennent pas trois catégories différentes
#: dans les statistiques.
PROTOCOLES_CONNUS = {
    "TCP": "TCP",
    "UDP": "UDP",
    "ICMP": "ICMP",
    "ICMPv6": "ICMPv6",
    "ARP": "ARP",
    "DNS": "DNS",
}

#: Au-delà de cette taille, on ne tente même pas de lire un nom DNS : un paquet
#: anormalement gros est plus probablement une attaque ou une corruption qu'une requête.
TAILLE_MAX_ANALYSE = 65_535

#: Longueur maximale d'un nom conservé. Un nom DNS peut faire 255 octets ; au-delà de
#: cette limite il est tronqué, avec le marqueur visible, plutôt que rejeté.
LONGUEUR_MAX_NOM = 255


def analyser(paquet: Any, horodatage: dt.datetime | None = None) -> dict[str, Any]:
    """Rend la fiche structurée d'un paquet. **Ne lève jamais d'exception.**

    En cas d'échec inattendu, la fiche porte `analyse_partielle=True` et un motif
    lisible : un paquet incompris doit apparaître dans l'interface, pas disparaître. Un
    parseur qui lève une exception sur un paquet malformé permet à un attaquant de faire
    taire la capture entière avec un seul paquet bien choisi.
    """
    fiche: dict[str, Any] = {
        "horodatage": (horodatage or dt.datetime.now(dt.timezone.utc)).isoformat(),
        "taille": None,
        "taille_capturee": None,
        "protocole": "inconnu",
        "couches": [],
        "ip_source": None,
        "ip_destination": None,
        "mac_source": None,
        "mac_destination": None,
        "version_ip": None,
        "port_source": None,
        "port_destination": None,
        "flags_tcp": None,
        "ttl": None,
        "longueur_transport": None,
        "resume": "",
        "analyse_partielle": False,
        "motif_partiel": None,
        "details": {},
    }

    try:
        fiche["resume"] = _tronquer(paquet.summary(), 200)
        fiche["couches"] = _couches(paquet)
        fiche["taille_capturee"] = len(paquet)

        # `wirelen` est la taille du paquet sur le réseau ; `len()` est ce qu'on a
        # réellement reçu. Les deux diffèrent sur un paquet tronqué, et l'écart est
        # précisément l'information intéressante.
        originelle = getattr(paquet, "wirelen", None)
        fiche["taille"] = originelle if originelle else fiche["taille_capturee"]
        if len(paquet) < TAILLE_MAX_ANALYSE and (originelle or 0) > len(paquet):
            fiche["details"]["tronque"] = True

        _adresses_l2(paquet, fiche)
        _adresses_l3(paquet, fiche)
        _transport(paquet, fiche)
        _applicatif(paquet, fiche)
    except Exception as erreur:                     # noqa: BLE001 — arbitraire assumé
        # Frontière de confiance du projet : tout ce qui entre ici vient du réseau, donc
        # de nulle part. On note l'incident et on rend la fiche partielle.
        fiche["analyse_partielle"] = True
        fiche["motif_partiel"] = f"{type(erreur).__name__}: {erreur}"[:200]

    return fiche


# --------------------------------------------------------------------------- #
#  Couches présentes
# --------------------------------------------------------------------------- #
def _couches(paquet: Any) -> list[str]:
    """Noms des couches réellement présentes, dans l'ordre du paquet.

    C'est ce qui permet à l'interface de dire « ce paquet contient Ethernet, IP et TCP »
    sans que personne ait à connaître Scapy.
    """
    try:
        return [couche.__name__ for couche in paquet.layers()]
    except Exception:                               # noqa: BLE001
        return []


# --------------------------------------------------------------------------- #
#  Adresses
# --------------------------------------------------------------------------- #
def _adresses_l2(paquet: Any, fiche: dict[str, Any]) -> None:
    """Adresses matérielles, quand il y a une couche Ethernet."""
    if paquet.haslayer(Ether):
        trame = paquet[Ether]
        fiche["mac_source"] = _texte(getattr(trame, "src", None))
        fiche["mac_destination"] = _texte(getattr(trame, "dst", None))
        fiche["details"]["type_ethernet"] = _texte(getattr(trame, "type", None))


def _adresses_l3(paquet: Any, fiche: dict[str, Any]) -> None:
    """Adresses logiques. IPv4 et IPv6 sont traités, ARP aussi, le reste est ignoré."""
    if paquet.haslayer(IP):
        entete = paquet[IP]
        fiche["ip_source"] = _texte(getattr(entete, "src", None))
        fiche["ip_destination"] = _texte(getattr(entete, "dst", None))
        fiche["version_ip"] = 4
        fiche["ttl"] = _entier(getattr(entete, "ttl", None))
    elif paquet.haslayer(IPv6):
        entete = paquet[IPv6]
        fiche["ip_source"] = _texte(getattr(entete, "src", None))
        fiche["ip_destination"] = _texte(getattr(entete, "dst", None))
        fiche["version_ip"] = 6
        # En IPv6, le champ équivalent au TTL s'appelle « hop limit ».
        fiche["ttl"] = _entier(getattr(entete, "hlim", None))
    elif paquet.haslayer(ARP):
        arp = paquet[ARP]
        fiche["protocole"] = "ARP"
        fiche["ip_source"] = _texte(getattr(arp, "psrc", None))
        fiche["ip_destination"] = _texte(getattr(arp, "pdst", None))
        fiche["details"]["operation_arp"] = _operation_arp(getattr(arp, "op", None))


def _operation_arp(valeur: Any) -> str | None:
    """Traduit le code d'opération ARP en mot lisible."""
    return {1: "demande", 2: "réponse"}.get(_entier(valeur))


# --------------------------------------------------------------------------- #
#  Transport
# --------------------------------------------------------------------------- #
def _transport(paquet: Any, fiche: dict[str, Any]) -> None:
    """Protocole de transport, ports et indicateurs. Le premier trouvé gagne."""
    if paquet.haslayer(TCP):
        tcp = paquet[TCP]
        fiche["protocole"] = "TCP"
        fiche["port_source"] = _entier(getattr(tcp, "sport", None))
        fiche["port_destination"] = _entier(getattr(tcp, "dport", None))
        fiche["flags_tcp"] = _flags_tcp(tcp)
        fiche["longueur_transport"] = _entier(getattr(tcp, "dataofs", None))

        # Numéros de séquence et fenêtre. Sans eux, deux questions restaient sans réponse :
        # « ce paquet a-t-il déjà été envoyé ? » (retransmission) et « ce paquet est-il
        # arrivé dans l'ordre ? » — c'est-à-dire l'essentiel de l'Expert Info.
        #
        # `dataofs` donne la longueur de l'**en-tête**, pas celle des données : la
        # confondre avec la charge utile fausserait tout calcul de volume applicatif.
        fiche["details"]["seq"] = _entier(getattr(tcp, "seq", None))
        fiche["details"]["ack"] = _entier(getattr(tcp, "ack", None))
        fiche["details"]["fenetre"] = _entier(getattr(tcp, "window", None))

        # On ne conserve que la **taille** de la charge utile, jamais son contenu. Un
        # analyseur qui stockerait le contenu d'un échange finirait par stocker un mot de
        # passe — et il suffirait d'une fois. Une longueur suffit à repérer une
        # retransmission ou une fenêtre saturée.
        try:
            fiche["details"]["charge_utile"] = len(bytes(tcp.payload))
        except Exception:                                # noqa: BLE001
            fiche["details"]["charge_utile"] = 0
    elif paquet.haslayer(UDP):
        udp = paquet[UDP]
        fiche["protocole"] = "UDP"
        fiche["port_source"] = _entier(getattr(udp, "sport", None))
        fiche["port_destination"] = _entier(getattr(udp, "dport", None))
        fiche["longueur_transport"] = _entier(getattr(udp, "len", None))
    elif paquet.haslayer(ICMP):
        icmp = paquet[ICMP]
        fiche["protocole"] = "ICMP"
        fiche["details"]["type_icmp"] = _entier(getattr(icmp, "type", None))
        fiche["details"]["icmp_lisible"] = _type_icmp(_entier(getattr(icmp, "type", None)))
    elif paquet.haslayer(IPv6) and _entier(getattr(paquet[IPv6], "nh", None)) == 58:
        # 58 = ICMPv6 dans l'en-tête « next header ». On ne descend pas dans les
        # classes ICMPv6 : le nom du protocole suffit, et les sous-types sont rares
        # dans une conversation ordinaire.
        fiche["protocole"] = "ICMPv6"


def _flags_tcp(tcp: Any) -> str | None:
    """Indicateurs TCP sous forme lisible : « SYN, ACK ».

    On les lit un par un plutôt que d'afficher le champ brut, parce que c'est cette
    lecture qui permettra de déduire l'état d'une connexion : un SYN seul ouvre une
    tentative, un SYN-ACK y répond.
    """
    try:
        if not hasattr(tcp, "flags") or not tcp.flags:
            return None
        actifs = []
        for nom in ("F", "S", "R", "P", "A", "U", "E", "C"):
            if nom in str(tcp.flags):
                actifs.append({"F": "FIN", "S": "SYN", "R": "RST", "P": "PSH",
                               "A": "ACK", "U": "URG", "E": "ECE", "C": "CWR"}[nom])
        return ", ".join(actifs) if actifs else None
    except Exception:                               # noqa: BLE001
        return None


def _type_icmp(code: Any) -> str | None:
    """Traduit les types ICMP courants en mots."""
    return {
        0: "réponse d'écho (ping)",
        3: "destination injoignable",
        8: "demande d'écho (ping)",
        11: "délai dépassé",
        5: "redirection",
    }.get(code)


# --------------------------------------------------------------------------- #
#  Informations applicatives
# --------------------------------------------------------------------------- #
def _applicatif(paquet: Any, fiche: dict[str, Any]) -> None:
    """Ce qu'on peut dire de la couche applicative **sans lire le contenu**.

    On s'en tient aux métadonnées : un nom de domaine demandé, un type de requête. Le
    contenu transporté n'est jamais conservé.
    """
    if not paquet.haslayer(DNS):
        return
    dns = paquet[DNS]
    fiche["details"]["dns_reponse"] = bool(_entier(getattr(dns, "qr", 0)))

    # La section « question » n'existe pas toujours, et Scapy lève alors une erreur
    # d'index en la lisant plutôt que de rendre une valeur vide. Le cas se rencontre en
    # vrai : les réponses mDNS d'une télévision du réseau n'ont pas de question, et le
    # message de découverte est ainsi tronqué sans raison. On lit donc défensivement.
    question = _question_dns(dns)
    if question is not None:
        nom = _nom_dns(getattr(question, "qname", None))
        if nom:
            fiche["details"]["dns_question"] = nom
        type_question = _type_dns(getattr(question, "qtype", None))
        if type_question:
            fiche["details"]["dns_type"] = type_question

    # Dans une réponse, le nom utile est celui qui est *résolu*, et il se trouve dans la
    # section des réponses, pas dans la question.
    if fiche["details"]["dns_reponse"]:
        reponse = _premiere_reponse_dns(dns)
        if reponse is not None:
            nom_repondu = _nom_dns(getattr(reponse, "rrname", None))
            if nom_repondu:
                fiche["details"].setdefault("dns_question", nom_repondu)
                fiche["details"]["dns_reponse_nom"] = nom_repondu
            adresse = getattr(reponse, "rdata", None)
            if isinstance(adresse, str) and _ressemble_a_une_adresse(adresse):
                fiche["details"]["dns_adresse"] = adresse

    # On compte les enregistrements réellement présents plutôt que de lire le champ
    # d'en-tête correspondant : Scapy ne calcule ce champ qu'au moment où le paquet est
    # sérialisé. Sur un paquet reconstruit il vaut `None`, et une valeur lue à la place
    # du contenu devient fausse sans prévenir.
    enregistrements = _enregistrements_dns(dns, "an")
    if enregistrements:
        fiche["details"]["dns_reponses"] = len(enregistrements)
    # Un échec de résolution est une information utile : la requête part, la réponse
    # dit « ce nom n'existe pas ».
    if _entier(getattr(dns, "rcode", 0)):
        fiche["details"]["dns_rcode"] = _entier(dns.rcode)

    # TLS et HTTP sont lus à part, et après le DNS : ce sont des protocoles applicatifs
    # distincts, et un paquet n'en porte qu'un. Chacun se protège de ses propres erreurs.
    _applicatif_tls(paquet, fiche)
    _applicatif_http(paquet, fiche)


def _applicatif_tls(paquet: Any, fiche: dict[str, Any]) -> None:
    """Extrait le nom du serveur visé depuis un ClientHello TLS — et rien d'autre.

    C'est la seule information lisible d'une session chiffrée : avant de chiffrer, le
    client annonce en clair le nom du serveur qu'il veut joindre (l'extension SNI), sans
    quoi un hébergeur ne saurait pas quel certificat présenter.

    Ce que ce module ne fait pas, et ne fera pas : déchiffrer quoi que ce soit. Le contenu
    de la session — l'adresse visitée, les données échangées, tout ce qui suit le
    handshake — reste illisible, et c'est le principe même de TLS. Un outil qui prétendrait
    le contraire utiliserait un proxy d'interception, ce que ce projet s'interdit.
    """
    try:
        from scapy.layers.tls.handshake import TLSClientHello
    except ImportError:                                  # pragma: no cover
        return

    try:
        if not paquet.haslayer(TLSClientHello):
            return
        client_hello = paquet[TLSClientHello]

        # La version annoncée dit ce que le client sait faire, pas ce qui sera négocié.
        version = getattr(client_hello, "version", None)
        if version is not None:
            fiche["details"]["tls_version"] = _tronquer(str(version), 20)

        for extension in getattr(client_hello, "ext", []) or []:
            noms = getattr(extension, "servernames", None)
            if not noms:
                continue
            premier = noms[0] if isinstance(noms, (list, tuple)) and noms else noms
            valeur = getattr(premier, "servername", None)
            if valeur:
                texte = valeur.decode("utf-8", "replace") if isinstance(valeur, bytes) else valeur
                fiche["details"]["tls_sni"] = _tronquer(texte, 120)
                break
    except Exception as erreur:                          # noqa: BLE001
        # Un ClientHello malformé ne doit pas faire échouer l'analyse du paquet.
        fiche["details"]["tls_illisible"] = type(erreur).__name__


def _applicatif_http(paquet: Any, fiche: dict[str, Any]) -> None:
    """Extrait la méthode, l'hôte et le code de réponse du HTTP **en clair uniquement**.

    Deux principes, et le second est le plus important :

    **1. Seuls les en-têtes nécessaires sont lus.** `Authorization`, `Cookie`, les jetons
    de session : ils ne sont jamais extraits, donc jamais conservés, donc jamais affichés.
    Ce n'est pas un masquage après coup — c'est un choix de lecture. Ce qu'on ne lit pas ne
    peut pas fuir.

    **2. Rien du corps du message n'est conservé.** Ni le formulaire envoyé, ni la page
    reçue. Un outil qui stockerait le contenu d'un échange HTTP en clair stockerait, un
    jour ou l'autre, un mot de passe ou un jeton — et il suffirait d'une fois.
    """
    try:
        from scapy.layers.http import HTTP, HTTPRequest, HTTPResponse
    except ImportError:                                  # pragma: no cover
        return

    try:
        if not paquet.haslayer(HTTP):
            return

        if paquet.haslayer(HTTPRequest):
            requete = paquet[HTTPRequest]
            methode = _texte(getattr(requete, "Method", None))
            if methode is not None:
                fiche["details"]["http_methode"] = _tronquer(methode, 16)
            hote = _texte(getattr(requete, "Host", None))
            if hote is not None:
                fiche["details"]["http_hote"] = _tronquer(hote, 120)
            chemin = _texte(getattr(requete, "Path", None))
            if chemin is not None:
                fiche["details"]["http_chemin"] = _tronquer(chemin, 200)
        elif paquet.haslayer(HTTPResponse):
            code = _entier(getattr(paquet[HTTPResponse], "Status_Code", None))
            if code is not None:
                fiche["details"]["http_code"] = code
    except Exception as erreur:                          # noqa: BLE001
        fiche["details"]["http_illisible"] = type(erreur).__name__



def _enregistrements_dns(dns: Any, section: str) -> list:
    """Enregistrements d'une section DNS, **toujours** rendus sous forme de liste.

    Trois cas à couvrir, tous rencontrés :
      — la section est absente et Scapy lève une erreur d'index au lieu de rendre vide
        (les réponses mDNS d'une télévision du réseau, section « question » absente) ;
      — la section est vide (`[]`) : un paquet de découverte sans réponse ;
      — la section contient un seul objet, non indexable : Scapy ne l'enferme pas
        systématiquement dans une liste.

    Une lecture qui suppose une liste plante sur un enregistrement unique, et une lecture
    qui suppose un objet plante sur une liste. On normalise, puis on travaille.
    """
    try:
        valeur = getattr(dns, section, None)
    except (IndexError, AttributeError, TypeError):
        return []
    if valeur is None:
        return []
    if isinstance(valeur, (list, tuple)):
        return [enregistrement for enregistrement in valeur if enregistrement is not None]
    return [valeur]


def _question_dns(dns: Any) -> Any | None:
    """Première question DNS, ou None quand la section est absente."""
    questions = _enregistrements_dns(dns, "qd")
    return questions[0] if questions else None


def _premiere_reponse_dns(dns: Any) -> Any | None:
    """Premier enregistrement de la section « réponse », ou None."""
    reponses = _enregistrements_dns(dns, "an")
    return reponses[0] if reponses else None


def _ressemble_a_une_adresse(valeur: str) -> bool:
    """Vrai si le texte est une adresse IP. Évite de recopier un enregistrement MX ou TXT."""
    import ipaddress

    try:
        ipaddress.ip_address(valeur)
        return True
    except ValueError:
        return False


def _nom_dns(valeur: Any) -> str | None:
    """Décode un nom DNS en texte, sans jamais lever."""
    if isinstance(valeur, bytes):
        for encodage in ("idna", "utf-8"):
            try:
                return valeur.decode(encodage).rstrip(".")[:LONGUEUR_MAX_NOM]
            except (UnicodeError, ValueError):
                continue
        return valeur.decode("utf-8", "replace").rstrip(".")[:LONGUEUR_MAX_NOM]
    return _texte(valeur)


def _type_dns(valeur: Any) -> str | None:
    """Types d'enregistrement DNS les plus fréquents."""
    return {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX",
        16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS",
    }.get(_entier(valeur))


# --------------------------------------------------------------------------- #
#  Conversions défensives
# --------------------------------------------------------------------------- #
def _texte(valeur: Any) -> str | None:
    """Texte propre, ou None. Aucune valeur inventée."""
    if valeur is None:
        return None
    if isinstance(valeur, bytes):
        return valeur.decode("utf-8", "replace") or None
    texte = str(valeur).strip()
    return texte or None


def _entier(valeur: Any) -> int | None:
    """Entier, ou None si la valeur n'en est pas un.

    Scapy rend certains champs numériques en **octets** — `b"404"` pour un code de réponse
    HTTP, par exemple. `int()` refuse les octets : sans ce décodage, la lecture semblait
    fonctionner mais ne produisait rien, et l'interface affichait un vide sans explication.
    """
    if valeur is None or isinstance(valeur, bool):
        return None
    if isinstance(valeur, bytes):
        valeur = valeur.decode("ascii", "replace").strip()
    try:
        return int(valeur)
    except (TypeError, ValueError):
        return None


def _tronquer(texte: Any, longueur: int) -> str:
    """Coupe un texte trop long, avec un marqueur visible plutôt qu'une coupe muette."""
    texte = str(texte or "")
    return texte if len(texte) <= longueur else texte[: longueur - 1] + "…"
