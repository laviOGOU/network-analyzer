"""Tests du parseur : chaque fait lu dans un paquet est vérifié.

Le principe de ces tests est celui du parseur lui-même : on vérifie des **faits**, et
quand un champ est absent on vérifie qu'il vaut `None` — jamais qu'il contient une valeur
plausible. Un test qui accepterait « probablement 443 » validerait exactement le défaut
qu'on cherche à empêcher.
"""

from __future__ import annotations

import pytest
from scapy.layers.inet import IP, TCP

from agent import parser


# --------------------------------------------------------------------------- #
#  Poignée de main TCP
# --------------------------------------------------------------------------- #
def test_syn_seul(syn):
    """Un SYN : la demande d'ouverture, avec le port de destination et le TTL."""
    fiche = parser.analyser(syn)

    assert fiche["protocole"] == "TCP"
    assert fiche["ip_source"] == "192.168.1.5"
    assert fiche["ip_destination"] == "93.184.216.34"
    assert fiche["port_source"] == 49703
    assert fiche["port_destination"] == 443
    assert "SYN" in fiche["flags_tcp"]
    assert "ACK" not in fiche["flags_tcp"]
    assert fiche["ttl"] == 64
    assert fiche["version_ip"] == 4
    assert fiche["analyse_partielle"] is False


def test_syn_ack(syn_ack):
    """Un SYN-ACK : deux indicateurs à la fois, et un TTL différent (le serveur)."""
    fiche = parser.analyser(syn_ack)

    assert "SYN" in fiche["flags_tcp"] and "ACK" in fiche["flags_tcp"]
    assert fiche["port_source"] == 443
    assert fiche["port_destination"] == 49703
    assert fiche["ttl"] == 55


def test_poignee_de_main_complete(poignee_de_main):
    """Les trois messages portent les mêmes adresses et des indicateurs distincts.

    C'est cette suite qui permettra de dire « connexion établie » en phase suivante.
    """
    fiches = [parser.analyser(paquet) for paquet in poignee_de_main]

    assert len(fiches) == 3
    assert all(f["protocole"] == "TCP" for f in fiches)
    assert all({f["ip_source"], f["ip_destination"]}
               == {"192.168.1.5", "93.184.216.34"} for f in fiches)
    assert [f["flags_tcp"] for f in fiches] == ["SYN", "SYN, ACK", "ACK"]


def test_reinitialisation(rst):
    """Un RST : la connexion est rompue, pas ouverte."""
    fiche = parser.analyser(rst)

    assert "RST" in fiche["flags_tcp"]
    assert "SYN" not in fiche["flags_tcp"]


def test_cloture(fin):
    """FIN + ACK : clôture ordonnée."""
    fiche = parser.analyser(fin)

    assert "FIN" in fiche["flags_tcp"]
    assert "ACK" in fiche["flags_tcp"]


# --------------------------------------------------------------------------- #
#  DNS
# --------------------------------------------------------------------------- #
def test_requete_dns(dns_requete):
    """Une question DNS donne le nom demandé et le port de destination 53."""
    fiche = parser.analyser(dns_requete)

    assert fiche["protocole"] == "UDP"          # le transport reste UDP
    assert fiche["port_destination"] == 53
    assert fiche["details"]["dns_question"] == "example.com"
    assert fiche["details"]["dns_type"] == "A"
    assert fiche["details"]["dns_reponse"] is False


def test_reponse_dns(dns_reponse):
    """Une réponse DNS : le nom résolu et l'adresse obtenue."""
    fiche = parser.analyser(dns_reponse)

    assert fiche["details"]["dns_reponse"] is True
    assert fiche["details"]["dns_question"] == "example.com"
    assert fiche["details"]["dns_adresse"] == "93.184.216.34"
    assert fiche["details"]["dns_reponses"] == 1


def test_mdns_sans_section_question(mdns_sans_question):
    """Régression : une réponse sans section question ne doit plus faire échouer l'analyse.

    Ce cas a été trouvé sur le réseau réel — une télévision qui annonce son nom en mDNS.
    Scapy lève une erreur d'index en lisant la section absente. Le parseur doit rendre une
    fiche complète, et le nom annoncé doit s'y trouver, dans la section des réponses.
    """
    fiche = parser.analyser(mdns_sans_question)

    assert fiche["analyse_partielle"] is False, fiche["motif_partiel"]
    assert fiche["protocole"] == "UDP"
    assert fiche["port_destination"] == 5353
    assert fiche["details"]["dns_reponse"] is True
    assert fiche["details"]["dns_reponse_nom"] == "Smart-TV.local"
    assert fiche["details"]["dns_adresse"] == "192.168.1.42"


# --------------------------------------------------------------------------- #
#  ICMP, ARP, UDP, IPv6
# --------------------------------------------------------------------------- #
def test_icmp_demande_echo(icmp_echo):
    """Une demande d'écho est traduite en mots, pas en numéro de type."""
    fiche = parser.analyser(icmp_echo)

    assert fiche["protocole"] == "ICMP"
    assert fiche["details"]["type_icmp"] == 8
    assert "écho" in fiche["details"]["icmp_lisible"]
    assert fiche["port_destination"] is None       # ICMP n'a pas de port


def test_icmp_reponse_echo(icmp_reponse):
    """Une réponse d'écho se distingue d'une demande."""
    fiche = parser.analyser(icmp_reponse)

    assert fiche["details"]["icmp_lisible"] == "réponse d'écho (ping)"


def test_arp(arp_demande):
    """ARP : les adresses sont dans les champs psrc/pdst, pas dans un en-tête IP."""
    fiche = parser.analyser(arp_demande)

    assert fiche["protocole"] == "ARP"
    assert fiche["ip_source"] == "192.168.1.5"
    assert fiche["ip_destination"] == "192.168.1.1"
    assert fiche["details"]["operation_arp"] == "demande"
    assert fiche["mac_source"] == "aa:bb:cc:dd:ee:01"
    assert fiche["mac_destination"] == "ff:ff:ff:ff:ff:ff"
    assert fiche["version_ip"] is None             # ARP n'est pas IP


def test_udp_sans_application(udp_quelconque):
    """UDP sans application connue : le transport est identifié, rien de plus."""
    fiche = parser.analyser(udp_quelconque)

    assert fiche["protocole"] == "UDP"
    assert fiche["port_source"] == 5353
    assert "dns_question" not in fiche["details"]


def test_ipv6(ipv6_tcp):
    """IPv6 : version 6 annoncée, et le « hop limit » lu comme un TTL."""
    fiche = parser.analyser(ipv6_tcp)

    assert fiche["version_ip"] == 6
    assert fiche["ip_source"] == "2001:db8::1"
    assert fiche["ip_destination"] == "2001:db8::2"
    assert fiche["ttl"] == 64
    assert fiche["protocole"] == "TCP"


# --------------------------------------------------------------------------- #
#  Cas dégradés — le parseur ne doit jamais lever
# --------------------------------------------------------------------------- #
def test_trame_ethernet_seule(ethernet_seul):
    """Sans adresse IP, les champs réseau valent None : ils ne sont pas inventés."""
    fiche = parser.analyser(ethernet_seul)

    assert fiche["protocole"] == "inconnu"
    assert fiche["ip_source"] is None
    assert fiche["ip_destination"] is None
    assert fiche["mac_source"] == "aa:bb:cc:dd:ee:01"
    assert fiche["analyse_partielle"] is False


def test_protocole_inconnu(protocole_inconnu):
    """« Non reconnu » est un résultat valide, et il est annoncé comme tel."""
    fiche = parser.analyser(protocole_inconnu)

    assert fiche["protocole"] == "inconnu"
    assert fiche["ip_source"] == "192.168.1.5"
    assert fiche["port_destination"] is None
    assert fiche["analyse_partielle"] is False


def test_charge_utile_binaire(charge_utile_binaire):
    """Une charge utile illisible n'empêche pas de lire les en-têtes."""
    fiche = parser.analyser(charge_utile_binaire)

    assert fiche["protocole"] == "TCP"
    assert fiche["port_destination"] == 8080
    assert fiche["analyse_partielle"] is False


def test_aucun_paquet_ne_fait_planter_le_parseur(poignee_de_main, dns_requete,
                                                 mdns_sans_question, arp_demande,
                                                 icmp_echo, ipv6_tcp, ethernet_seul,
                                                 protocole_inconnu, scan_de_ports):
    """Passe tous les cas d'un coup : le parseur rend toujours une fiche exploitable."""
    paquets = list(poignee_de_main) + [dns_requete, mdns_sans_question, arp_demande,
                                       icmp_echo, ipv6_tcp, ethernet_seul,
                                       protocole_inconnu] + list(scan_de_ports)

    for paquet in paquets:
        fiche = parser.analyser(paquet)
        assert isinstance(fiche, dict)
        assert fiche["protocole"], "un protocole est toujours annoncé, même « inconnu »"
        assert fiche["analyse_partielle"] is False, fiche.get("motif_partiel")


def test_objet_non_paquet():
    """Même un objet qui n'est pas un paquet rend une fiche partielle, sans exception."""
    fiche = parser.analyser(object())

    assert fiche["analyse_partielle"] is True
    assert fiche["motif_partiel"]
    assert fiche["protocole"] == "inconnu"


def test_scan_de_ports_forge(scan_de_ports):
    """Le jeu de test du scan est exploitable : douze ports distincts, même source."""
    fiches = [parser.analyser(paquet) for paquet in scan_de_ports]

    ports = {f["port_destination"] for f in fiches}
    sources = {f["ip_source"] for f in fiches}
    assert len(ports) == 12
    assert sources == {"10.0.0.9"}
    assert all("SYN" in f["flags_tcp"] for f in fiches)


# --------------------------------------------------------------------------- #
#  Cohérence générale
# --------------------------------------------------------------------------- #
def test_tous_les_champs_attendus_sont_presents(syn):
    """La fiche contient exactement les clés du contrat avec le backend.

    Ce test est le garde-fou du contrat : si une clé est renommée dans le parseur sans
    l'être dans le modèle Pydantic, l'ingestion refuserait tous les lots en production.
    """
    attendus = {
        "horodatage", "taille", "taille_capturee", "protocole", "couches",
        "ip_source", "ip_destination", "mac_source", "mac_destination", "version_ip",
        "port_source", "port_destination", "flags_tcp", "ttl", "longueur_transport",
        "resume", "analyse_partielle", "motif_partiel", "details",
    }
    assert set(parser.analyser(syn).keys()) == attendus


def test_taille_du_paquet(syn):
    """La taille annoncée est celle du paquet sur le réseau."""
    fiche = parser.analyser(syn)

    assert fiche["taille"] == len(syn)
    assert fiche["taille"] > 0


def test_horodatage_fourni_est_conserve(syn):
    """L'horodatage passé en argument est repris tel quel, à la seconde près."""
    import datetime as dt

    quand = dt.datetime(2026, 10, 5, 14, 30, tzinfo=dt.timezone.utc)
    fiche = parser.analyser(syn, quand)

    assert fiche["horodatage"].startswith("2026-10-05T14:30")
