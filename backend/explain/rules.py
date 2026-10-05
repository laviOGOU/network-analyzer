"""Moteur d'explication déterministe — la colonne vertébrale du projet.

Ce module transforme des données structurées et vérifiables en phrases compréhensibles.
Il ne devine rien : il applique des règles écrites, sur des faits observés, et il rend
toujours les mêmes phrases pour les mêmes entrées. C'est ce qui le rend vérifiable — un
jury peut demander pourquoi une phrase est là, et la réponse est une règle nommée.

LA RÈGLE ABSOLUE
----------------
**Ne jamais présenter une hypothèse comme une certitude.**

Le port 443 ne **prouve** pas HTTPS. Il y a un consensus très fort, mais rien n'interdit
à quelqu'un de faire tourner autre chose sur ce port. Une explication qui affirmerait
« HTTPS » serait fausse dans le principe, même si elle tombe juste neuf fois sur dix.
On écrit donc « probablement HTTPS », et on écrit *pourquoi* on le pense.

Cette prudence n'est pas une coquetterie : un outil qui affirme des choses fausses avec
assurance n'est plus consulté, et à juste titre.

LA STRUCTURE FIXE
-----------------
Chaque explication a cinq parties, toujours les mêmes :

    titre                « Communication HTTPS probable »
    faits_observes       liste de faits tirés des données, chacun vérifiable
    interpretation       ce qu'on en déduit, formulé prudemment
    confiance            faible | moyenne | haute
    explication_simple   le texte destiné à un lecteur non spécialiste

Séparer les faits de l'interprétation oblige à savoir ce qu'on a vu et ce qu'on suppose.
C'est la raison d'être de cette structure, et ce que l'interface doit rendre visible.
"""

from __future__ import annotations

import ipaddress
import re
from functools import lru_cache
from typing import Any

# --------------------------------------------------------------------------- #
#  Base de connaissances — les services
# --------------------------------------------------------------------------- #
# Chaque entrée : (nom lisible, ce que c'est, à quoi ça sert, sensible ?)
#
# « sensible » signale un service dont l'exposition est un vrai sujet de sécurité :
# soit il est ancien et sans chiffrement (Telnet, FTP), soit il ouvre l'accès à une
# machine (RDP, SMB, SSH). Ce n'est PAS un jugement sur l'utilisateur : sur un réseau
# local, un partage SMB est parfaitement normal.
SERVICES: dict[int, tuple[str, str, str, bool]] = {
    20: ("FTP (données)", "transfert de fichiers", "protocole ancien, sans chiffrement", True),
    21: ("FTP (commandes)", "transfert de fichiers", "protocole ancien, sans chiffrement", True),
    22: ("SSH", "accès distant chiffré", "ouvre une session sur une machine", True),
    23: ("Telnet", "accès distant en clair", "protocole obsolète, mots de passe lisibles", True),
    25: ("SMTP", "envoi de courrier", "les serveurs modernes chiffrent, mais pas toujours", False),
    53: ("DNS", "résolution de noms", "traduit un nom de site en adresse", False),
    67: ("DHCP", "attribution d'adresses", "donne son adresse à un appareil qui se connecte", False),
    68: ("DHCP (client)", "attribution d'adresses", "l'appareil demande une adresse", False),
    80: ("HTTP", "navigation en clair", "protocole non chiffré, le contenu est lisible", True),
    110: ("POP3", "relève de courrier", "souvent sans chiffrement", True),
    123: ("NTP", "mise à l'heure", "synchronise les horloges des machines", False),
    135: ("RPC Windows", "échange interne Windows", "surface d'attaque connue, à ne pas exposer", True),
    137: ("NetBIOS (noms)", "découverte locale Windows", "protocole ancien de partage de noms", True),
    138: ("NetBIOS (datagrammes)", "découverte locale Windows", "protocole ancien", True),
    139: ("NetBIOS (sessions)", "partage de fichiers Windows", "protocole ancien, souvent visé", True),
    143: ("IMAP", "consultation de courrier", "courrier conservé sur le serveur", False),
    161: ("SNMP", "supervision d'équipements", "communautés souvent laissées par défaut", True),
    389: ("LDAP", "annuaire d'entreprise", "souvent sans chiffrement", True),
    443: ("HTTPS", "navigation chiffrée", "le contenu ne peut pas être lu par un tiers", False),
    445: ("SMB", "partage de fichiers Windows", "cible classique de rançongiciels", True),
    465: ("SMTP chiffré", "envoi de courrier", "chiffré d'emblée", False),
    514: ("Syslog", "journaux système", "envoi de journaux, souvent en clair", False),
    587: ("SMTP (soumission)", "envoi de courrier", "chiffré après négociation", False),
    631: ("IPP", "impression réseau", "communication avec une imprimante", False),
    993: ("IMAP chiffré", "consultation de courrier", "chiffré", False),
    995: ("POP3 chiffré", "relève de courrier", "chiffré", False),
    1194: ("OpenVPN", "tunnel chiffré privé", "met en place un réseau privé virtuel", False),
    1433: ("SQL Server", "base de données", "base de données exposée sur le réseau", True),
    1521: ("Oracle", "base de données", "base de données exposée sur le réseau", True),
    1723: ("PPTP", "tunnel privé ancien", "chiffrement obsolète, considéré comme cassé", True),
    1883: ("MQTT", "messagerie d'objets connectés", "souvent sans authentification", True),
    1900: ("SSDP", "découverte d'appareils", "utilisé par les objets connectés pour se signaler", False),
    2049: ("NFS", "partage de fichiers Unix", "partage réseau, souvent sans authentification forte", True),
    3000: ("Serveur de développement", "application web locale", "port courant de développement, rarement exposé exprès", False),
    3306: ("MySQL / MariaDB", "base de données", "base de données exposée sur le réseau", True),
    3389: ("RDP", "bureau à distance Windows", "ouvre une session complète sur la machine", True),
    4443: ("Alternative HTTPS", "navigation chiffrée", "port chiffré alternatif, souvent un serveur applicatif", False),
    5000: ("Serveur applicatif", "application web", "port courant de développement ou d'API", False),
    5228: ("Google (GServices)", "services Google mobiles", "utilisé par Android pour ses notifications", False),
    5353: ("mDNS", "découverte locale", "les appareils s'annoncent sur le réseau local", False),
    5432: ("PostgreSQL", "base de données", "base de données exposée sur le réseau", True),
    5672: ("AMQP", "file de messages", "communication entre applications", False),
    5900: ("VNC", "bureau à distance", "souvent sans chiffrement de la session", True),
    6379: ("Redis", "base de données en mémoire", "souvent sans authentification par défaut", True),
    8000: ("Serveur applicatif", "application web", "port de développement ou d'API", False),
    8080: ("Proxy ou serveur web", "application web", "souvent un serveur non chiffré", False),
    8443: ("HTTPS alternatif", "navigation chiffrée", "port chiffré alternatif", False),
    8883: ("MQTT chiffré", "messagerie d'objets connectés", "version chiffrée de MQTT", False),
    9090: ("Interface d'administration", "outil web", "souvent une console d'administration", True),
    9200: ("Elasticsearch", "moteur de recherche", "souvent sans authentification par défaut", True),
    27017: ("MongoDB", "base de données", "base de données exposée sur le réseau", True),
}

# --------------------------------------------------------------------------- #
#  Base de connaissances — les protocoles
# --------------------------------------------------------------------------- #
PROTOCOLES: dict[str, tuple[str, str]] = {
    "TCP": ("TCP — transport fiable",
            "Protocole qui établit une connexion avant d'échanger des données, et qui "
            "vérifie que tout arrive. C'est lui qui porte le web, le courrier et les "
            "téléchargements."),
    "UDP": ("UDP — transport rapide sans connexion",
            "Protocole qui envoie les données sans établir de connexion et sans garantir "
            "leur arrivée. Plus rapide que TCP, utilisé quand la rapidité compte plus que "
            "la certitude — comme pour la résolution de noms ou la vidéo en direct."),
    "ICMP": ("ICMP — messages de contrôle",
             "Protocole de signalisation du réseau : il transporte les messages que les "
             "machines s'échangent pour dire « je suis là » ou « je n'ai pas pu livrer »."),
    "ICMPV6": ("ICMPv6 — messages de contrôle IPv6",
               "Équivalent d'ICMP pour IPv6, avec un rôle supplémentaire : il sert aussi "
               "à découvrir les autres machines du réseau."),
    "ARP": ("ARP — traduction d'adresses locales",
            "Protocole qui demande « quelle carte réseau porte cette adresse ? » sur le "
            "réseau local. C'est ce qui permet à deux machines de se trouver avant de "
            "s'échanger le moindre paquet."),
    "INCONNU": ("Protocole non reconnu",
                "L'analyseur n'a pas su identifier ce protocole. C'est un résultat valide : "
                "mieux vaut ne rien dire que d'inventer une interprétation."),
    "IP": ("IP — protocole de routage",
           "Protocole qui achemine les paquets entre les machines, en les faisant passer "
           "de réseau en réseau."),
}

# --------------------------------------------------------------------------- #
#  Base de connaissances — les états de connexion
# --------------------------------------------------------------------------- #
ETATS: dict[str, tuple[str, str]] = {
    "tentative": ("Demande d'ouverture en cours",
                  "Une machine a demandé à ouvrir une connexion. La réponse n'a pas encore "
                  "été observée — c'est soit que la conversation est très récente, soit "
                  "que personne ne répond."),
    "établie": ("Connexion établie",
                "L'ouverture complète a été observée : demande, acceptation, confirmation. "
                "Les deux machines se sont comprises et peuvent échanger des données."),
    "en cours": ("Échanges en cours",
                 "Des données circulent. Pour un protocole sans connexion (UDP, ICMP, ARP), "
                 "c'est le fonctionnement normal."),
    "fermée": ("Connexion terminée",
               "La conversation est finie — soit proprement, soit par une rupture."),
    "échec probable": ("Aucune réponse à la demande d'ouverture",
                       "Une machine a demandé à ouvrir une connexion et rien n'est venu en "
                       "retour. Cela signifie le plus souvent que le service n'écoute pas, "
                       "ou qu'un pare-feu bloque la demande."),
    "inconnue": ("État indéterminable",
                 "L'analyseur ne peut pas dire où en est cette conversation : son protocole "
                 "n'est pas reconnu, ou trop d'éléments manquent."),
}


# --------------------------------------------------------------------------- #
#  Fabrication d'une explication
# --------------------------------------------------------------------------- #
def _explication(titre: str, faits: list[str], interpretation: str, confiance: str,
                 explication_simple: str, regle: str) -> dict[str, Any]:
    """Assemble une explication dans la structure fixe.

    Une seule fabrique pour toutes les règles : c'est ce qui garantit que chaque
    explication du projet a exactement la même forme, et que la structure ne peut pas
    dériver au fil des ajouts.
    """
    return {
        "titre": titre,
        "faits_observes": [fait for fait in faits if fait],
        "interpretation": interpretation,
        "confiance": confiance,
        "explication_simple": explication_simple,
        "regle": regle,
    }


def _fuir(texte: str) -> str:
    """Neutralise ce qui ressemble à du balisage avant affichage.

    Les noms de domaine et les descriptions viennent du réseau : ils sont affichés, donc
    ils doivent être traités comme des données hostiles.
    """
    return re.sub(r"[<>]", "", str(texte or ""))[:200]


def _adresse_privee(ip: str) -> bool:
    """Vrai pour une adresse qui ne sort pas sur Internet."""
    try:
        adresse = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return adresse.is_private or adresse.is_loopback or adresse.is_link_local


def _resume_volume(communication: dict[str, Any]) -> str:
    """Une phrase chiffrée sur ce qui a circulé."""
    paquets = communication.get("paquets_total") or 0
    octets = communication.get("octets_total") or 0
    sens_a = communication.get("paquets_a_vers_b") or 0
    sens_b = communication.get("paquets_b_vers_a") or 0

    if paquets == 0:
        return ""
    # Virgule décimale, comme le reste de l'interface : un « 1.8 ko » à l'anglaise au milieu
    # d'un texte français se lit mal, et deux conventions dans le même écran font désordre.
    taille = (f"{octets} octets" if octets < 1000
              else f"{octets / 1000:.1f} ko".replace(".", ","))
    if sens_b == 0:
        return f"{paquets} paquet(s), {taille}, dans un seul sens"
    return f"{paquets} paquet(s), {taille}, dans les deux sens ({sens_a} et {sens_b})"


# --------------------------------------------------------------------------- #
#  Règles
# --------------------------------------------------------------------------- #
def _regle_service(communication: dict[str, Any]) -> dict[str, Any] | None:
    """Le port de destination correspond-il à un service connu ?

    Le port de destination est utilisé ici, et non le port source : c'est lui qui désigne
    le service joint. Le port source est tiré au hasard par la machine qui appelle et
    n'apprend rien.
    """
    port = communication.get("port_b") or communication.get("port_a")
    if port is None:
        return None

    # Le service se trouve côté serveur : si l'initiateur est ip_a, le service est en b.
    if communication.get("initiateur") and communication.get("initiateur") != communication.get("ip_a"):
        port = communication.get("port_a")

    service = SERVICES.get(int(port))
    if service is None:
        return None

    nom, quoi, pourquoi, sensible = service
    protocole = (communication.get("protocole") or "").upper()

    # Le degré de confiance dépend de ce qu'on sait vraiment : un service sur TCP est
    # beaucoup mieux identifié que le même port sur UDP, où les conventions sont plus
    # lâches.
    confiance = "haute" if protocole == "TCP" else "moyenne"

    faits = [
        f"Port de destination = {port}",
        f"Protocole = {protocole or 'non reconnu'}",
        _resume_volume(communication),
    ]
    if sensible:
        faits.append("Le port correspond à un service dont l'exposition mérite attention")

    interpretation = (
        f"Le port {port} est généralement associé à {nom} ({quoi}) : {pourquoi}. "
        "Rien ne garantit que ce soit bien ce service — un port est une convention, pas "
        "une preuve. Le contenu échangé n'est pas analysé par cet outil."
    )

    if sensible:
        interpretation += (
            " Ce service étant sensible, il vaut la peine de vérifier qu'il est "
            "volontairement exposé. Ce n'est pas un signe d'attaque."
        )

    simple = (
        f"Une de vos machines a communiqué avec un service de type « {nom} » "
        f"(port {port}). {quoi.capitalize()} — {pourquoi}. "
        "Cette information vient du numéro de port : elle est probable, pas certaine."
    )

    return _explication(
        f"Communication {nom} probable", faits, interpretation, confiance, simple,
        "port_service_connu_sensible" if sensible else "port_service_connu")


def _regle_port_non_repertorie(communication: dict[str, Any]) -> dict[str, Any] | None:
    """Un port qui ne correspond à aucun service connu : le dire, sans broder."""
    port = communication.get("port_b") or communication.get("port_a")
    if port is None or int(port) in SERVICES:
        return None
    if int(port) < 1024:
        return None      # port système non répertorié ici : cas déjà couvert ailleurs
    return _explication(
        "Service non répertorié",
        [f"Port de destination = {port}", _resume_volume(communication)],
        f"Le port {port} ne correspond à aucun service courant dans la base de "
        "connaissances de cet outil. Cela ne veut pas dire qu'il est suspect : beaucoup "
        "d'applications utilisent des ports qui leur sont propres, et c'est un usage "
        "normal. Cela veut simplement dire que l'analyseur ne peut rien en dire.",
        "faible",
        f"La communication utilise le port {port}, que l'outil ne reconnaît pas. Il n'y a "
        "rien à en conclure — seulement que le service est particulier à cette "
        "application.",
        "port_non_repertorie")


def _regle_dns(communication: dict[str, Any]) -> dict[str, Any] | None:
    """Une résolution de nom : dire quel nom a été demandé, et pourquoi c'est sensible."""
    port = int(communication.get("port_b") or communication.get("port_a") or 0)
    if port not in (53, 5353) or (communication.get("protocole") or "").upper() != "UDP":
        return None

    local = port == 5353
    faits = [f"Port = {port}", "Protocole = UDP",
             f"Réseau {'local' if local else 'vers un serveur de noms'}"]
    faits.append(_resume_volume(communication))

    if local:
        return _explication(
            "Annonce entre appareils sur le réseau local (mDNS)",
            faits,
            "Le mDNS permet aux appareils d'un même réseau de se découvrir sans serveur "
            "central : une imprimante, une télévision ou une enceinte s'annoncent par leur "
            "nom. Ces annonces sont périodiques et parfaitement normales.",
            "haute",
            "Des appareils de votre réseau se signalent entre eux. C'est ainsi qu'une "
            "télévision apparaît automatiquement dans la liste des appareils à projeter, "
            "par exemple. Rien d'anormal.",
            "mdns_decouverte")

    interprete = (
        "Une machine a demandé l'adresse correspondant à un nom de domaine. C'est ce qui "
        "se passe avant chaque connexion : le nom est traduit en adresse IP. "
        "**Les noms demandés révèlent les sites consultés** — c'est l'information la plus "
        "sensible que cet outil affiche, davantage que les adresses IP."
    )
    return _explication(
        "Résolution de nom de domaine (DNS)", faits, interprete,
        "haute",
        "Votre machine a demandé à quel serveur correspondait un nom de site. Cette étape "
        "a lieu avant chaque connexion. À retenir : ces requêtes disent quels sites sont "
        "consultés depuis votre réseau.",
        "dns_resolution")


def _regle_icmp(communication: dict[str, Any]) -> dict[str, Any] | None:
    """ICMP : distinguer un ping d'un message d'erreur."""
    if not (communication.get("protocole") or "").upper().startswith("ICMP"):
        return None
    paquets = communication.get("paquets_total") or 0
    bidirectionnel = (communication.get("paquets_b_vers_a") or 0) > 0

    if bidirectionnel:
        return _explication(
            "Test de disponibilité (ping)",
            [f"Protocole = {communication.get('protocole')}",
             _resume_volume(communication)],
            "Un aller-retour ICMP complet correspond à un test de disponibilité : une "
            "machine a demandé « es-tu là ? » et l'autre a répondu « oui ». C'est le "
            "comportement de la commande « ping ».",
            "haute",
            "Deux machines se sont testées mutuellement pour vérifier que la liaison "
            "fonctionne. C'est ce que fait la commande ping, et c'est normal.",
            "icmp_ping")
    return _explication(
        "Message de contrôle réseau (ICMP)",
        [f"Protocole = {communication.get('protocole')}", f"{paquets} paquet(s) dans un seul sens"],
        "Des messages ICMP circulent sans réponse. Cela peut être un test de disponibilité "
        "en cours, ou un message d'erreur signalant qu'un paquet n'a pas pu être livré.",
        "moyenne",
        "Des messages techniques circulent entre machines sans réponse pour l'instant. "
        "Cela signifie soit qu'un test est en cours, soit qu'une machine n'arrive pas à "
        "joindre une autre.",
        "icmp_message")


def _regle_arp(communication: dict[str, Any]) -> dict[str, Any] | None:
    if (communication.get("protocole") or "").upper() != "ARP":
        return None
    return _explication(
        "Recherche d'adresse sur le réseau local (ARP)",
        [f"Protocole = ARP", _resume_volume(communication)],
        "Un appareil cherche quelle carte réseau porte une adresse locale. Sans ARP, deux "
        "machines du même réseau ne pourraient pas se parler : elles connaissent l'adresse "
        "à atteindre, mais pas l'identité matérielle de la carte.",
        "haute",
        "Votre réseau traduit une adresse en carte réseau physique, comme une sorte "
        "d'annuaire interne. C'est indispensable et parfaitement banal.",
        "arp_recherche")


def _regle_etat(communication: dict[str, Any]) -> dict[str, Any] | None:
    """Traduire l'état de la connexion, en conservant son degré de certitude."""
    etat = communication.get("etat")
    if not etat or etat not in ETATS:
        return None
    titre, texte = ETATS[etat]
    certain = bool(communication.get("etat_certain"))
    note = communication.get("note_etat") or ""

    faits = [f"État observé = {etat}",
             f"Indicateurs vus : {communication.get('indicateurs') or 'aucun'}"]
    if certain:
        faits.append("L'état repose sur une observation complète")
    else:
        faits.append("L'état est une déduction : la capture n'a pas tout observé")
    if note:
        faits.append(note)

    # Le degré de confiance suit la certitude de l'observation, sans la maquiller.
    confiance = "haute" if certain else "faible"
    interpretation = texte
    if not certain:
        interpretation += (
            " Attention : cette description est une déduction. " + note
            if note else " Attention : cette description est une déduction, pas un fait observé."
        )

    return _explication(titre, faits, interpretation, confiance,
                        texte + (f" À savoir : {note}" if note else ""),
                        "etat_observe" if certain else "etat_deduit")


def _regle_direction(communication: dict[str, Any]) -> dict[str, Any] | None:
    """Distinguer un vrai échange d'un appel resté sans réponse."""
    if (communication.get("protocole") or "").upper() != "TCP":
        return None
    sens_b = communication.get("paquets_b_vers_a") or 0
    sens_a = communication.get("paquets_a_vers_b") or 0
    if sens_a == 0 or sens_b == 0:
        return None

    total = sens_a + sens_b
    if total < 6:
        return None

    # Un déséquilibre très marqué a un sens : on demande plus qu'on ne reçoit.
    if sens_a >= sens_b * 4:
        return _explication(
            "Échange très déséquilibré",
            [f"{sens_a} paquets sortants pour {sens_b} entrants",
             _resume_volume(communication)],
            "Les données partent presque toutes dans le même sens. C'est le profil d'un "
            "envoi : téléversement de fichier, publication de photos, sauvegarde en ligne.",
            "moyenne",
            "Cette communication envoie beaucoup plus qu'elle ne reçoit : quelque chose a "
            "été transféré vers l'extérieur.",
            "echange_desequilibre")
    if sens_b >= sens_a * 4:
        return _explication(
            "Réception de données",
            [f"{sens_b} paquets entrants pour {sens_a} sortants",
             _resume_volume(communication)],
            "Les données arrivent presque toutes dans le même sens. C'est le profil d'un "
            "téléchargement ou d'une page web : on demande une petite chose, on reçoit un "
            "ensemble volumineux.",
            "moyenne",
            "Cette communication reçoit beaucoup plus qu'elle n'envoie : quelque chose a "
            "été téléchargé.",
            "echange_desequilibre")
    return None


def _regle_local_ou_externe(communication: dict[str, Any]) -> dict[str, Any] | None:
    """Situer la communication : sur le réseau local, ou vers l'extérieur.

    C'est le contexte qui manque le plus à quelqu'un qui découvre ce genre d'outil : voir
    « 192.168.1.42 → 142.250.x.x » ne dit rien sans savoir que la première est chez soi.
    """
    ip_a, ip_b = communication.get("ip_a") or "", communication.get("ip_b") or ""
    if not ip_a or not ip_b:
        return None
    a_privee, b_privee = _adresse_privee(ip_a), _adresse_privee(ip_b)

    if a_privee and b_privee:
        return _explication(
            "Échange interne au réseau local",
            [f"{_fuir(ip_a)} et {_fuir(ip_b)} appartiennent au réseau local"],
            "Les deux machines sont sur votre réseau. Une communication interne ne sort pas "
            "sur Internet : elle ne quitte pas votre box.",
            "haute",
            "Deux appareils de chez vous se sont parlé directement, sans passer par "
            "Internet.",
            "echange_local")

    if a_privee and not b_privee:
        # Le cas le plus fréquent de tous : c'est le trafic de navigation ordinaire. Il
        # méritait sa propre règle, et son absence était un manque — la première version ne
        # traitait que local-contre-local et public-contre-public, c'est-à-dire tout sauf
        # ce qui se produit cent fois par heure sur un réseau domestique.
        return _explication(
            "Communication vers l'extérieur",
            [f"{_fuir(ip_a)} appartient au réseau local, {_fuir(ip_b)} est publique"],
            "Une machine de votre réseau a joint une adresse située sur Internet. C'est le "
            "profil de toute navigation : ouvrir un site, relever son courrier, consulter "
            "une application. Le fait d'aller vers l'extérieur n'a rien d'anormal — c'est "
            "même le fonctionnement attendu d'un réseau connecté.",
            "haute",
            "Un appareil de chez vous a contacté un serveur sur Internet. C'est ce qui se "
            "passe à chaque fois que vous ouvrez un site ou consultez une application.",
            "vers_exterieur")

    if not a_privee and b_privee:
        # Situation plus rare, et nettement plus intéressante : c'est de la connexion
        # entrante. La plupart du temps elle est attendue (service hébergé, jeu en ligne,
        # mise à jour), mais elle mérite d'être comprise plutôt que subie.
        return _explication(
            "Connexion entrante depuis Internet",
            [f"{_fuir(ip_a)} est publique, {_fuir(ip_b)} appartient au réseau local"],
            "Une adresse d'Internet a contacté une machine de votre réseau local. C'est le "
            "résultat normal d'un service que vous hébergez, d'un jeu en ligne ou de "
            "certaines mises à jour — mais aussi d'un balayage automatique, extrêmement "
            "courant et le plus souvent sans suite. Cette situation mérite d'être "
            "comprise : elle n'est pas en soi un signe d'attaque, et elle n'est pas "
            "non plus à ignorer.",
            "haute",
            "Quelqu'un sur Internet a contacté l'un de vos appareils. Si vous n'attendez "
            "rien de tel — pas de serveur, pas de jeu en ligne — cela vaut la peine de "
            "comprendre de quoi il s'agit.",
            "connexion_entrante")

    return _explication(
        "Échange entre deux adresses publiques",
        [f"{_fuir(ip_a)} et {_fuir(ip_b)} sont des adresses publiques"],
        "Aucune des deux extrémités n'appartient au réseau local. Ce cas se rencontre sur "
        "un réseau routé, une liaison entre deux sites, ou lorsque la capture observe un "
        "routeur plutôt qu'un poste de travail.",
        "moyenne",
        "Cette conversation ne concerne pas directement vos appareils : les deux "
        "extrémités sont extérieures.",
        "echange_public")


#: Ordre d'application. La première règle applicable devient l'explication principale.
#:
#: Cet ordre répond à la question qu'un lecteur se pose en premier — « **qu'est-ce que
#: c'est ?** » — avant de répondre à « où cela se passe-t-il ? » et « dans quel état ? ».
#: Identifier le service avant de situer la communication donne « probablement HTTPS »
#: puis « vers l'extérieur », plutôt que l'inverse, qui n'apprend rien.
#:
#: Les règles générales viennent en dernier : elles s'appliquent à tout, elles ne doivent
#: donc pas masquer une règle précise. Avant ce tri, une requête DNS vers la box recevait
#: pour toute explication « échange interne au réseau local » — vrai, et inutile.
REGLES = (
    _regle_service,
    _regle_dns,
    _regle_icmp,
    _regle_arp,
    _regle_port_non_repertorie,
    _regle_etat,
    _regle_direction,
    _regle_local_ou_externe,
)


# --------------------------------------------------------------------------- #
#  Point d'entrée
# --------------------------------------------------------------------------- #
def expliquer(communication: dict[str, Any]) -> dict[str, Any]:
    """Rend l'explication principale d'une communication.

    C'est la première explication applicable, et la plus forte : celle qui répond à la
    question « que se passe-t-il ici ? ». Les autres sont accessibles séparément, pour qui
    veut le détail.
    """
    toutes = explications(communication)
    if not toutes:
        return _explication(
            "Communication sans interprétation",
            ["Aucune règle de la base de connaissances ne s'applique à cette communication"],
            "L'analyseur n'a pas de règle pour décrire cette communication. Il préfère le "
            "dire plutôt que de produire une phrase sans fondement.",
            "faible",
            "L'outil ne sait pas décrire cette communication. C'est un résultat honnête : "
            "mieux vaut une absence d'explication qu'une explication inventée.",
            "aucune_regle")
    return toutes[0]


def explications(communication: dict[str, Any]) -> list[dict[str, Any]]:
    """Toutes les explications applicables, dans l'ordre de lecture."""
    resultats = []
    for regle in REGLES:
        try:
            explication = regle(communication)
        except Exception as erreur:                  # noqa: BLE001 — une règle ne doit jamais
            # Une règle fautive ne doit pas priver l'utilisateur de toutes les autres. On
            # note l'incident et on continue : c'est le même principe que le parseur.
            explication = _explication(
                "Règle en échec",
                [f"{regle.__name__} a échoué : {type(erreur).__name__}"],
                "Cette règle n'a pas pu s'appliquer. Les autres explications restent valables.",
                "faible", "", "regle_en_echec")
        if explication:
            resultats.append(explication)
    return resultats


@lru_cache(maxsize=2048)
def expliquer_resume(protocole: str, port: int | None, etat: str,
                     certain: bool) -> dict[str, Any]:
    """Version mise en cache, pour les listes.

    Une même combinaison (protocole, port, état) produit toujours la même explication :
    la recalculer pour chacune des cent cinquante communications affichées serait du
    travail perdu. Le cache est borné — au-delà de 2 048 combinaisons, les plus anciennes
    sont oubliées.
    """
    return expliquer({
        "protocole": protocole, "port_b": port, "port_a": port,
        "etat": etat, "etat_certain": certain, "paquets_total": 0, "octets_total": 0,
        "paquets_a_vers_b": 0, "paquets_b_vers_a": 0,
    })


def services_connus() -> int:
    """Nombre de services dans la base, pour l'afficher dans l'interface."""
    return len(SERVICES)
