"""Tests du regroupement en communications et de la déduction d'état.

Ce fichier vérifie la partie la plus délicate de la phase 2 : décider qu'une conversation
est « établie », « fermée » ou « incertaine ». Une erreur ici ne se voit pas à l'écran —
elle produit un tableau de bord plausible et faux.
"""

from __future__ import annotations

import datetime as dt

import pytest

from agent import flows, parser

# --------------------------------------------------------------------------- #
#  Outils
# --------------------------------------------------------------------------- #
BASE = dt.datetime(2026, 10, 5, 12, 0, 0, tzinfo=dt.timezone.utc)


def fiche(paquet, seconde: float = 0.0) -> dict:
    """Analyse un paquet forgé en lui donnant un horodatage choisi."""
    return parser.analyser(paquet, BASE + dt.timedelta(seconds=seconde))


def suivi() -> flows.SuiviCommunications:
    return flows.SuiviCommunications()


# --------------------------------------------------------------------------- #
#  Clé normalisée
# --------------------------------------------------------------------------- #
def test_cle_identique_dans_les_deux_sens():
    """Le point le plus important du module : A→B et B→A doivent donner la même clé.

    Sans cette normalisation, chaque connexion compterait deux fois et toutes les
    statistiques seraient fausses d'un facteur deux.
    """
    aller = flows.cle_normalisee("192.168.1.5", 49703, "93.184.216.34", 443, "TCP")
    retour = flows.cle_normalisee("93.184.216.34", 443, "192.168.1.5", 49703, "TCP")

    assert aller == retour


def test_cle_differente_si_le_port_change():
    """Même couple de machines, deux services : ce sont deux communications."""
    une = flows.cle_normalisee("10.0.0.1", 50000, "10.0.0.2", 443, "TCP")
    autre = flows.cle_normalisee("10.0.0.1", 50001, "10.0.0.2", 80, "TCP")

    assert une != autre


def test_cle_sans_port():
    """ICMP n'a pas de port : la clé doit rester comparable, sans `None`."""
    cle = flows.cle_normalisee("10.0.0.1", None, "10.0.0.2", None, "ICMP")

    assert None not in cle
    assert cle == flows.cle_normalisee("10.0.0.2", None, "10.0.0.1", None, "ICMP")


# --------------------------------------------------------------------------- #
#  Regroupement
# --------------------------------------------------------------------------- #
def test_poignee_de_main_regroupee_en_une_communication(poignee_de_main):
    """Trois paquets, une seule communication, et les compteurs par sens sont justes."""
    table = suivi()
    for indice, paquet in enumerate(poignee_de_main):
        table.ajouter(fiche(paquet, indice * 0.05))

    actives = table.actives()
    assert len(actives) == 1
    communication = actives[0]
    assert communication.paquets_total == 3
    # Le SYN part du poste local, le SYN-ACK revient : deux dans un sens, un dans l'autre.
    assert communication.paquets_a_vers_b == 2
    assert communication.paquets_b_vers_a == 1
    assert communication.debut < communication.dernier_paquet


def test_octets_comptes_par_sens(poignee_de_main):
    table = suivi()
    for indice, paquet in enumerate(poignee_de_main):
        table.ajouter(fiche(paquet, indice * 0.05))

    communication = table.actives()[0]
    assert communication.octets_a_vers_b > 0
    assert communication.octets_total == communication.octets_a_vers_b + communication.octets_b_vers_a


def test_le_sens_du_premier_paquet_designe_l_initiateur(poignee_de_main):
    """C'est le client qui envoie le premier SYN : c'est lui qu'on désigne."""
    table = suivi()
    table.ajouter(fiche(poignee_de_main[0]))

    communication = table.actives()[0]
    assert communication.initiateur == "192.168.1.5"
    assert communication.ip_a == "192.168.1.5"


def test_deux_conversations_sur_des_ports_differents(poignee_de_main, dns_requete, dns_reponse):
    """Un échange TCP et un échange DNS ne doivent pas se mélanger."""
    table = suivi()
    table.ajouter(fiche(poignee_de_main[0], 0))
    table.ajouter(fiche(dns_requete, 1))
    table.ajouter(fiche(dns_reponse, 1.1))

    assert len(table.actives()) == 2
    protocoles = {c.protocole for c in table.actives()}
    assert protocoles == {"TCP", "UDP"}


def test_arp_forme_une_communication(arp_demande):
    """ARP a des adresses mais pas de port : c'est bien une communication.

    Elle se regroupe donc par (protocole, adresses), sans état de connexion — une
    question et sa réponse, sans ouverture ni fermeture à déduire.
    """
    table = suivi()

    communication = table.ajouter(fiche(arp_demande))

    assert communication is not None
    assert communication.protocole == "ARP"
    assert communication.etat == flows.ETAT_EN_COURS
    assert "connexion" not in communication.note_etat


def test_trame_sans_adresse_ip_ignore(ethernet_seul):
    """Une trame tronquée n'a pas de couple source/destination : aucune communication.

    Sans cette règle, un paquet incompris créerait une communication fantôme entre deux
    chaînes vides, et le nombre de communications deviendrait faux.
    """
    table = suivi()

    assert table.ajouter(fiche(ethernet_seul)) is None
    assert table.actives() == []


def test_icmp_regroupe(icmp_echo, icmp_reponse):
    table = suivi()
    table.ajouter(fiche(icmp_echo, 0))
    table.ajouter(fiche(icmp_reponse, 0.02))

    assert len(table.actives()) == 1
    communication = table.actives()[0]
    assert communication.protocole == "ICMP"
    assert communication.paquets_total == 2


# --------------------------------------------------------------------------- #
#  Déduction d'état — TCP
# --------------------------------------------------------------------------- #
def test_ouverture_complete_etablie(poignee_de_main):
    """SYN, SYN-ACK, ACK : la connexion est établie, et c'est certain."""
    table = suivi()
    for indice, paquet in enumerate(poignee_de_main):
        table.ajouter(fiche(paquet, indice * 0.05))

    communication = table.actives()[0]
    assert communication.etat == flows.ETAT_ETABLIE
    assert communication.etat_certain is True
    assert communication.vu_depuis_le_debut is True
    assert "SYN" in communication.indicateurs and "ACK" in communication.indicateurs


def test_syn_sans_reponse_est_un_echec_probable(syn):
    """Un SYN resté sans réponse doit être signalé — après le délai, pas avant."""
    table = suivi()
    table.ajouter(fiche(syn, 0))

    # Juste après : on ne peut encore rien affirmer.
    communication = table.actives()[0]
    assert communication.etat == flows.ETAT_TENTATIVE

    # Trois secondes plus tard, sans réponse : l'échec est probable.
    flows.maj_etat(communication, BASE + dt.timedelta(seconds=4))
    assert communication.etat == flows.ETAT_ECHEC
    assert communication.etat_certain is True
    assert "filtré" in communication.note_etat or "fermé" in communication.note_etat


def test_reinitialisation_ferme_la_conversation(rst):
    """Un RST est une fin explicite, et elle est certaine."""
    table = suivi()
    table.ajouter(fiche(rst, 0))

    communication = table.actives()[0]
    assert communication.etat == flows.ETAT_FERMEE
    assert communication.etat_certain is True
    assert "RST" in communication.note_etat or "refusée" in communication.note_etat


def test_un_seul_fin_ne_prouve_pas_la_fermeture(poignee_de_main, fin):
    """Un FIN vu d'un seul côté : l'état est « fermée », mais marqué incertain.

    L'autre côté peut encore transmettre. Annoncer « terminée » avec assurance serait
    une déduction présentée comme un fait.
    """
    table = suivi()
    for indice, paquet in enumerate(poignee_de_main):
        table.ajouter(fiche(paquet, indice * 0.05))
    table.ajouter(fiche(fin, 1.0))

    communication = table.actives()[0]
    assert communication.etat == flows.ETAT_FERMEE
    assert communication.etat_certain is False
    assert "un seul côté" in communication.note_etat


def test_flow_vu_en_cours_de_route_est_incertain(syn_ack):
    """La capture commence par un SYN-ACK : on n'a pas vu le début, et on le dit.

    C'est le cas le plus fréquent en capture réelle, et le plus facile à travestir : rien
    n'interdit d'afficher « établie ». Ce serait une affirmation non fondée.
    """
    table = suivi()
    table.ajouter(fiche(syn_ack, 0))

    communication = table.actives()[0]
    assert communication.vu_depuis_le_debut is False
    assert communication.etat_certain is False
    assert "après le début" in communication.note_etat


def test_un_paquet_de_donnees_n_est_pas_un_debut(charge_utile_binaire):
    """Un paquet de données signifie qu'on est arrivé en cours de conversation."""
    table = suivi()
    table.ajouter(fiche(charge_utile_binaire, 0))

    communication = table.actives()[0]
    assert communication.vu_depuis_le_debut is False
    assert communication.etat_certain is False


def test_protocole_inconnu(protocole_inconnu):
    table = suivi()
    table.ajouter(fiche(protocole_inconnu, 0))

    communication = table.actives()[0]
    assert communication.etat == flows.ETAT_INCONNUE
    assert communication.etat_certain is False


def test_udp_en_cours(udp_quelconque):
    table = suivi()
    table.ajouter(fiche(udp_quelconque, 0))

    communication = table.actives()[0]
    assert communication.etat == flows.ETAT_EN_COURS


# --------------------------------------------------------------------------- #
#  Expiration
# --------------------------------------------------------------------------- #
def test_tcp_expire_apres_soixante_secondes(poignee_de_main):
    table = suivi()
    for indice, paquet in enumerate(poignee_de_main):
        table.ajouter(fiche(paquet, indice * 0.05))

    # Cinquante-neuf secondes : encore active.
    assert table.retirer_terminées(BASE + dt.timedelta(seconds=59)) == []
    assert len(table.actives()) == 1

    # Soixante et une secondes : terminée.
    terminees = table.retirer_terminées(BASE + dt.timedelta(seconds=61))
    assert len(terminees) == 1
    assert table.actives() == []


def test_udp_expire_plus_vite_que_tcp(dns_requete):
    """UDP n'a pas de connexion : trente secondes de silence suffisent."""
    table = suivi()
    table.ajouter(fiche(dns_requete, 0))

    assert table.retirer_terminées(BASE + dt.timedelta(seconds=29)) == []
    assert len(table.retirer_terminées(BASE + dt.timedelta(seconds=31))) == 1


def test_fermeture_explicite_expire_immediatement(poignee_de_main, fin):
    """Après un FIN, on n'attend pas une minute : la fin est connue."""
    table = suivi()
    for indice, paquet in enumerate(poignee_de_main):
        table.ajouter(fiche(paquet, indice * 0.05))
    table.ajouter(fiche(fin, 1.0))

    # Deux secondes après le FIN : sortie de la table, bien avant le délai TCP.
    assert len(table.retirer_terminées(BASE + dt.timedelta(seconds=3.5))) == 1


def test_delais_reglables():
    """Les délais dépendent du réseau observé : ils doivent être ajustables."""
    table = flows.SuiviCommunications(delai_tcp=5, delai_udp=2)

    assert table._delai_pour("TCP") == 5
    assert table._delai_pour("UDP") == 2


# --------------------------------------------------------------------------- #
#  Sortie
# --------------------------------------------------------------------------- #
def test_vers_dict_est_transmissible(poignee_de_main):
    """La forme transmise contient tout ce qui est nécessaire, et rien de plus."""
    table = suivi()
    for indice, paquet in enumerate(poignee_de_main):
        table.ajouter(fiche(paquet, indice * 0.05))

    d = table.actives()[0].vers_dict()

    attendus = {"cle", "protocole", "ip_a", "ip_b", "port_a", "port_b", "initiateur",
                "vu_depuis_le_debut", "debut", "dernier_paquet", "termine_le",
                "duree_secondes", "paquets_a_vers_b", "paquets_b_vers_a", "paquets_total",
                "octets_a_vers_b", "octets_b_vers_a", "octets_total", "indicateurs",
                "etat", "etat_certain", "note_etat"}
    assert set(d.keys()) == attendus
    assert isinstance(d["cle"], str)          # sérialisable en JSON
    assert d["duree_secondes"] >= 0


def test_resume_chiffre(poignee_de_main, syn_ack):
    table = suivi()
    for indice, paquet in enumerate(poignee_de_main):
        table.ajouter(fiche(paquet, indice * 0.05))

    # Une seconde communication doit être une *autre* conversation : le SYN-ACK de la
    # première porte la même clé normalisée, le réutiliser ne créerait rien de nouveau.
    # On la prend vue en cours de route — c'est le cas qui doit ressortir comme incertain.
    autre = syn_ack.copy()
    autre[2].dport = 51234
    table.ajouter(fiche(autre, 2.0))

    resume = flows.resume_chiffre(table.actives())

    assert resume["communications"] == 2
    # Un flow vu dès son SYN reste certain : « un SYN, pas encore de réponse » est une
    # observation sûre. L'incertitude vient de ce qu'on n'a pas vu commencer.
    assert resume["etats_incertains"] == 1
    assert resume["octets_total"] > 0


def test_vider_rend_tout(poignee_de_main):
    table = suivi()
    table.ajouter(fiche(poignee_de_main[0], 0))

    toutes = table.vider()

    assert len(toutes) == 1
    assert table.actives() == []
