"""Tests du mode replay (phase 5).

LA PROPRIÉTÉ CENTRALE
---------------------
Un fichier capturé hier contient des horodatages d'hier. Si le replay utilisait l'heure
courante, un SYN daté d'hier paraîtrait vieux de plusieurs heures — donc « sans réponse
depuis longtemps » — et **toutes** les connexions ressortiraient en échec probable. Le
rejeu produirait exactement le contraire de ce que contient le fichier.

Le test qui suit éprouve cette propriété directement : il rejoue un fichier daté, et
vérifie que les communications portent la date du fichier et que leurs états sont
inchangés. C'est le test qui compte ; les autres vérifient la robustesse.

Aucun test n'utilise de fichier .pcap versionné : les fichiers sont fabriqués à la volée
avec Scapy. Un fichier réel contiendrait le trafic d'une machine, et n'a rien à faire
dans un dépôt — même en apparence anodin, il révèle une topologie réseau.
"""

from __future__ import annotations

import datetime as dt
import time

import pytest
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.utils import wrpcap

from agent import replay as module
from agent.flows import SuiviCommunications

#: 1ᵉʳ janvier 2026 à 10:00 UTC — une date franchement passée, et fixe.
DEBUT = 1767261600.0


def paquet_tcp(source, destination, port_source, port, drapeaux, instant, numero=0):
    """Un paquet TCP complet, horodaté comme dans un vrai fichier."""
    paquet = (Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
              / IP(src=source, dst=destination, ttl=64, id=numero)
              / TCP(sport=port_source, dport=port, flags=drapeaux, seq=1000 + numero))
    paquet.time = instant
    return paquet


def paquet_udp(source, destination, port_source, port, instant, numero=0):
    paquet = (Ether(src="aa:bb:cc:dd:ee:ff", dst="11:22:33:44:55:66")
              / IP(src=source, dst=destination, ttl=64, id=numero)
              / UDP(sport=port_source, dport=port))
    paquet.time = instant
    return paquet


def rejouer(chemin, table, vitesse=0.0, delai=10.0):
    """Rejoue un fichier et attend qu'il soit entièrement lu.

    On ne peut pas appeler `arreter` juste après `demarrer` : l'arrêt est immédiat, et
    le rejeu s'interromprait avant d'avoir lu le premier paquet. C'est le comportement
    voulu pour une capture interrompue par l'utilisateur — et la raison pour laquelle un
    rejeu automatique doit attendre le drapeau `termine`.
    """
    rejeu = module.ReplayPcap(chemin, sur_paquet=table.ajouter, vitesse=vitesse)
    rejeu.demarrer()
    limite = time.monotonic() + delai
    while not rejeu.termine and time.monotonic() < limite:
        time.sleep(0.01)
    assert rejeu.termine, "le rejeu n'a pas terminé dans le délai imparti"
    return rejeu


@pytest.fixture
def fichier_capture(tmp_path):
    """Un fichier .pcap contenant une poignée de communications reconnaissables.

    Fabriqué à la volée : aucune donnée de réseau réel ne circule dans les tests.
    """
    paquets = [
        # Une connexion TCP complète : SYN, SYN-ACK, ACK, puis un échange.
        paquet_tcp("192.168.1.5", "93.184.216.34", 51000, 443, "S", DEBUT + 0),
        paquet_tcp("93.184.216.34", "192.168.1.5", 443, 51000, "SA", DEBUT + 0.05),
        paquet_tcp("192.168.1.5", "93.184.216.34", 51000, 443, "A", DEBUT + 0.10),
        paquet_tcp("192.168.1.5", "93.184.216.34", 51000, 443, "PA", DEBUT + 0.20),
        # Une seconde connexion, restée sans réponse.
        paquet_tcp("192.168.1.5", "93.184.216.34", 51001, 8080, "S", DEBUT + 0.30),
        # Une résolution de noms.
        paquet_udp("192.168.1.5", "192.168.1.1", 53000, 53, DEBUT + 0.40),
    ]
    chemin = tmp_path / "capture.pcap"
    wrpcap(str(chemin), paquets)
    return chemin


# --------------------------------------------------------------------------- #
#  La propriété centrale : le temps vient du fichier
# --------------------------------------------------------------------------- #
def test_les_horodatages_viennent_du_fichier(fichier_capture):
    """Le rejeu doit utiliser la date du fichier, pas l'heure courante.

    Sans cela, un fichier ancien produirait un rapport entièrement faux : toutes les
    connexions paraîtraient abandonnées depuis des heures.
    """
    table = SuiviCommunications()
    rejeu = rejouer(fichier_capture, table)

    assert rejeu.recus == 6
    communications = {c.cle: c for c in table.actives()}

    connexion = next(c for c in communications.values() if c.port_b == 443)
    debut = dt.datetime.fromisoformat(connexion.debut.replace("Z", "+00:00"))
    attendu = dt.datetime.fromtimestamp(DEBUT, tz=dt.timezone.utc)
    assert abs((debut - attendu).total_seconds()) < 1, \
        "la communication ne porte pas la date du fichier"


def test_une_connexion_sans_reponse_reste_une_tentative(fichier_capture):
    """Le piège que le choix des horodatages évite, éprouvé de bout en bout.

    Le fichier est ancien de plusieurs mois. Si le rejeu datait les paquets d'aujourd'hui
    en gardant la date du fichier pour l'état, la connexion sans réponse serait déclarée
    « échec probable » — et ce serait faux : au moment du fichier, elle venait tout juste
    d'être demandée.
    """
    table = SuiviCommunications()
    rejeu = rejouer(fichier_capture, table)
    # On passe l'heure du fichier, exactement comme le fait l'agent (`capteur.maintenant()`).
    # C'est le cœur de la propriété : « maintenant » est la date du dernier paquet lu.
    table.completer_etat(rejeu.maintenant())

    sans_reponse = next(c for c in table.actives() if c.port_b == 8080)
    assert sans_reponse.etat == "tentative"
    assert "échec" not in sans_reponse.etat


def test_le_rejeu_produit_les_memes_communications_que_la_capture(
        fichier_capture):
    """Deux rejeux du même fichier donnent exactement le même résultat.

    C'est ce qui rend le mode utile : une correction peut être vérifiée, et une
    démonstration rejouée à l'identique.
    """
    resultats = []
    for _ in range(2):
        table = SuiviCommunications()
        rejouer(fichier_capture, table)
        resultats.append(sorted(
            (c.cle, c.paquets_a_vers_b, c.paquets_b_vers_a, c.etat)
            for c in table.actives()))
    assert resultats[0] == resultats[1]


# --------------------------------------------------------------------------- #
#  L'inspection du fichier
# --------------------------------------------------------------------------- #
def test_l_inspection_decrit_le_fichier(fichier_capture):
    """Savoir ce que contient un fichier avant de le rejouer."""
    resume = module.resumer_fichier(fichier_capture)
    assert resume["paquets"] == 6
    assert resume["octets"] > 0
    assert resume["duree_secondes"] == pytest.approx(0.40, abs=0.02)
    assert resume["debut"].startswith("2026-01-01")


def test_un_fichier_absent_est_signale_clairement(tmp_path):
    with pytest.raises(module.ErreurReplay) as erreur:
        module.ReplayPcap(tmp_path / "absent.pcap", sur_paquet=lambda fiche: None)
    assert "introuvable" in str(erreur.value).lower()


def test_une_extension_inattendue_est_signalee(tmp_path):
    """Un message qui dit quoi faire, plutôt qu'une erreur de lecture incompréhensible."""
    fichier = tmp_path / "notes.txt"
    fichier.write_bytes(b"ceci n'est pas une capture")
    with pytest.raises(module.ErreurReplay) as erreur:
        module.ReplayPcap(fichier, sur_paquet=lambda fiche: None)
    assert ".txt" in str(erreur.value)
    assert "paquets" in str(erreur.value)


# --------------------------------------------------------------------------- #
#  La robustesse
# --------------------------------------------------------------------------- #
def test_un_paquet_illisible_n_arrete_pas_le_rejeu(tmp_path):
    """Un paquet abîmé dans un fichier ne doit pas priver des autres.

    On écrit un fichier valide auquel on ajoute des octets incohérents : Scapy en lira
    ce qu'il peut. Le compteur d'erreurs existe pour que le récapitulatif dise la
    vérité plutôt que d'afficher un total rassurant.
    """
    paquets = [paquet_tcp("192.168.1.5", "93.184.216.34", 51000, 443, "S", DEBUT)]
    chemin = tmp_path / "partiel.pcap"
    wrpcap(str(chemin), paquets)
    with open(chemin, "ab") as fichier:
        fichier.write(b"\x00" * 64)

    lus = []
    rejeu = rejouer(chemin, type("Table", (), {"ajouter": staticmethod(lus.append)})())
    # Une lecture sans exception est déjà l'essentiel : le fichier abîmé ne fait pas
    # échouer le rejeu, il le termine — et le au moins un paquet valide est passé.
    assert rejeu.termine is True
    assert rejeu.recus >= 1


def test_l_arret_interrompt_un_rejeu_en_cours(tmp_path):
    """Un rejeu qui dure doit pouvoir être interrompu, comme une capture."""
    paquets = [paquet_tcp("192.168.1.5", "93.184.216.34", 51000 + i, 443, "S", DEBUT + i)
               for i in range(2000)]
    chemin = tmp_path / "long.pcap"
    wrpcap(str(chemin), paquets)

    lus = []
    rejeu = module.ReplayPcap(chemin, sur_paquet=lus.append, vitesse=0)
    rejeu.demarrer()
    time.sleep(0.05)
    rejeu.arreter()
    assert rejeu.termine is True


def test_le_rejeu_peut_etre_ferme_avant_la_fin(tmp_path):
    """`arreter` ne doit pas rester bloqué, même avant que le fil ait commencé."""
    chemin = tmp_path / "vide.pcap"
    wrpcap(str(chemin), [])
    rejeu = module.ReplayPcap(chemin, sur_paquet=lambda fiche: None)
    rejeu.arreter()                       # jamais démarré : ne doit pas lever
    assert rejeu.recus == 0


def test_la_vitesse_ralentit_sans_changer_le_resultat(tmp_path):
    """Rejouer au rythme réel doit donner le même contenu, seulement plus lentement."""
    paquets = [paquet_tcp("192.168.1.5", "93.184.216.34", 51000, 443, "S", DEBUT),
               paquet_tcp("192.168.1.5", "93.184.216.34", 51000, 443, "A", DEBUT + 0.02)]
    chemin = tmp_path / "rapide.pcap"
    wrpcap(str(chemin), paquets)

    debut = time.monotonic()
    lus = []
    rejeu = rejouer(chemin, type("Table", (), {"ajouter": staticmethod(lus.append)})(),
                    vitesse=1.0)
    ecoule = time.monotonic() - debut

    assert rejeu.recus == 2
    # Deux centièmes de seconde d'écart : l'attente est réelle, mais courte. On vérifie
    # le comportement sans mesurer finement le temps machine.
    assert ecoule >= 0.01
