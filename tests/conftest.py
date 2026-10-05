"""Paquets de test, forgés avec Scapy.

Pourquoi forger plutôt que rejouer une capture
----------------------------------------------
Un fichier `.pcap` fige tout : si le parseur change d'avis sur la lecture d'un champ, le
test continue de passer sur l'ancien fichier. Un paquet construit en Python dit
exactement ce qu'il contient — on lit le test et on sait ce qu'on vérifie.

Les fixtures couvrent les cas que l'énoncé demande, plus deux que la capture réelle a
imposés :

  • poignée de main TCP complète (SYN, SYN-ACK, ACK) ;
  • SYN sans réponse ;
  • réinitialisation (RST) ;
  • requête DNS et réponse DNS ;
  • **réponse mDNS sans section question** — cas rencontré en vrai sur le réseau, qui
    faisait échouer l'analyse d'un message de découverte ;
  • écho ICMP, ARP, UDP, IPv6 ;
  • paquet tronqué, charge utile inconnue ;
  • protocole inconnu d'IP ;
  • trame Ethernet seule.
"""

from __future__ import annotations

import pytest
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether

A = "192.168.1.5"        # le poste observé
B = "93.184.216.34"      # un serveur distant quelconque
PORT_CLIENT = 49703


# --------------------------------------------------------------------------- #
#  Poignée de main TCP
# --------------------------------------------------------------------------- #
@pytest.fixture
def syn() -> Ether:
    """Premier message : la demande de connexion, sans réponse."""
    return (Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src=A, dst=B, ttl=64)
            / TCP(sport=PORT_CLIENT, dport=443, flags="S", seq=1000))


@pytest.fixture
def syn_ack() -> Ether:
    """Réponse du serveur : elle accepte et propose son propre numéro de séquence."""
    return (Ether(src="aa:bb:cc:dd:ee:02", dst="aa:bb:cc:dd:ee:01")
            / IP(src=B, dst=A, ttl=55)
            / TCP(sport=443, dport=PORT_CLIENT, flags="SA", seq=5000, ack=1001))


@pytest.fixture
def ack() -> Ether:
    """Troisième message : la connexion est établie."""
    return (Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")
            / IP(src=A, dst=B, ttl=64)
            / TCP(sport=PORT_CLIENT, dport=443, flags="A", seq=1001, ack=5001))


@pytest.fixture
def poignee_de_main(syn, syn_ack, ack) -> list:
    """Les trois messages de l'ouverture d'une connexion, dans l'ordre."""
    return [syn, syn_ack, ack]


@pytest.fixture
def rst() -> Ether:
    """Réinitialisation : la connexion est coupée net."""
    return (Ether()
            / IP(src=B, dst=A)
            / TCP(sport=443, dport=PORT_CLIENT, flags="R", seq=5001))


@pytest.fixture
def fin() -> Ether:
    """Clôture ordonnée d'une connexion."""
    return (Ether()
            / IP(src=A, dst=B)
            / TCP(sport=PORT_CLIENT, dport=443, flags="FA", seq=2000, ack=6000))


# --------------------------------------------------------------------------- #
#  DNS
# --------------------------------------------------------------------------- #
@pytest.fixture
def dns_requete() -> Ether:
    """Question de résolution : « quelle est l'adresse de example.com ? »"""
    return (Ether()
            / IP(src=A, dst="8.8.8.8")
            / UDP(sport=51000, dport=53)
            / DNS(rd=1, qd=DNSQR(qname="example.com", qtype="A")))


@pytest.fixture
def dns_reponse() -> Ether:
    """Réponse de résolution, avec l'adresse trouvée."""
    return (Ether()
            / IP(src="8.8.8.8", dst=A)
            / UDP(sport=53, dport=51000)
            / DNS(id=1234, qr=1, aa=1, rd=1, ra=1,
                  qd=DNSQR(qname="example.com", qtype="A"),
                  an=DNSRR(rrname="example.com", type="A", rdata="93.184.216.34")))


@pytest.fixture
def mdns_sans_question() -> Ether:
    """Réponse mDNS **sans section question**.

    C'est le cas qui a fait échouer l'analyseur en vrai, sur les messages de découverte
    d'une télévision du réseau. Scapy lève une erreur d'index en lisant une section
    absente ; le parseur doit la traiter comme une absence, pas comme une panne.
    """
    # On construit le paquet, on le sérialise, puis on le relit : c'est exactement ce
    # qui se passe sur le réseau. Assembler les couches à la main ne reproduit pas ce
    # que Scapy reçoit vraiment — les compteurs d'en-tête, notamment, ne sont calculés
    # qu'à la sérialisation, et un paquet jamais sérialisé porte `None` à leur place.
    construit = (Ether()
                 / IP(src="192.168.1.42", dst="224.0.0.251")
                 / UDP(sport=5353, dport=5353)
                 / DNS(id=0, qr=1, aa=1, qd=[], an=DNSRR(rrname="Smart-TV.local",
                                                          type="A", rdata="192.168.1.42")))
    return Ether(bytes(construit))


# --------------------------------------------------------------------------- #
#  ICMP, ARP, UDP, IPv6
# --------------------------------------------------------------------------- #
@pytest.fixture
def icmp_echo() -> Ether:
    """Demande d'écho : la commande « ping »."""
    return (Ether()
            / IP(src=A, dst="1.1.1.1", ttl=64)
            / ICMP(type=8, id=1, seq=1))


@pytest.fixture
def icmp_reponse() -> Ether:
    """Réponse d'écho : la machine distante est joignable."""
    return (Ether()
            / IP(src="1.1.1.1", dst=A, ttl=57)
            / ICMP(type=0, id=1, seq=1))


@pytest.fixture
def arp_demande() -> Ether:
    """« Qui a l'adresse 192.168.1.1 ? » — la question posée au réseau local."""
    return (Ether(src="aa:bb:cc:dd:ee:01", dst="ff:ff:ff:ff:ff:ff")
            / ARP(op=1, psrc=A, pdst="192.168.1.1", hwsrc="aa:bb:cc:dd:ee:01",
                  hwdst="00:00:00:00:00:00"))


@pytest.fixture
def udp_quelconque() -> Ether:
    """Un datagramme UDP sans protocole applicatif connu."""
    return (Ether()
            / IP(src=A, dst="8.8.4.4")
            / UDP(sport=5353, dport=5353)
            / b"charge utile opaque")


@pytest.fixture
def ipv6_tcp() -> Ether:
    """TCP sur IPv6 : le champ de durée de vie s'appelle « hop limit »."""
    return (Ether()
            / IPv6(src="2001:db8::1", dst="2001:db8::2", hlim=64)
            / TCP(sport=40000, dport=443, flags="S"))


# --------------------------------------------------------------------------- #
#  Cas dégradés
# --------------------------------------------------------------------------- #
@pytest.fixture
def ethernet_seul() -> Ether:
    """Trame Ethernet sans rien derrière : un paquet tronqué à l'extrême."""
    return Ether(src="aa:bb:cc:dd:ee:01", dst="aa:bb:cc:dd:ee:02")


@pytest.fixture
def protocole_inconnu() -> Ether:
    """Protocole IP 99 : ni TCP, ni UDP, ni ICMP. « Non reconnu » est un résultat valide."""
    return (Ether()
            / IP(src=A, dst=B, proto=99)
            / b"\x01\x02\x03\x04")


@pytest.fixture
def charge_utile_binaire() -> Ether:
    """Charge utile illisible : le parseur ne doit pas tenter de l'interpréter."""
    return (Ether()
            / IP(src=A, dst=B)
            / TCP(sport=PORT_CLIENT, dport=8080, flags="PA")
            / bytes(range(256)))


@pytest.fixture
def scan_de_ports() -> list:
    """Douze tentatives de connexion sur douze ports différents, depuis la même machine.

    Ce n'est pas encore une détection — c'est le matériau qui servira en phase 4. Le
    forgeage est ici parce que le cas doit être reproductible à volonté.
    """
    return [(Ether()
             / IP(src="10.0.0.9", dst="10.0.0.1", ttl=64)
             / TCP(sport=40000 + indice, dport=port, flags="S"))
            for indice, port in enumerate((21, 22, 23, 25, 80, 110, 139, 443, 445,
                                           1433, 3306, 3389))]
